#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.5' }
<#
        .SYNOPSIS
        Manages authentication servers, users, groups, one-time passwords, captive portal and SSO on Sophos Firewall.

        .DESCRIPTION
        PowerShell module for the CONFIGURE > Authentication area of the Sophos XGS / SFOS 22.0
        XML API.

        This module provides functions to create, read, update, and delete:
        - Authentication servers (Active Directory, LDAP, RADIUS, TACACS+, eDirectory)
        - Users and user groups (with membership management)
        - Guest users, clientless users and SMS gateways
        - One-time password settings and tokens
        - Firewall, admin, VPN, SSL VPN and web authentication
        - Captive portal appearance and the default captive portal
        - Azure AD SSO, STAS and live user sessions

        Total Functions: 98 (97 exported, 1 internal helper) - see README.md for the full
        cmdlet table.

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect to the firewall and list the configured LDAP servers
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosLDAPServer | Format-Table ServerName, ServerAddress, Port, BaseDN

        .EXAMPLE
        # Create a user and place it in a group. The user's own password is -AccountPassword;
        # -Password is the connection parameter and means something else entirely. The
        # password must not be a dictionary favourite either - the firewall rejects those
        # with a 510 whose text talks about deleting a referenced entity. See New-SfosUser.
        $securePw = ConvertTo-SecureString "Zz-Str0ng-Passw0rd!9" -AsPlainText -Force
        New-SfosUser -AccountName "jdoe" -Name "Jane Doe" -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group "Open Group"
        Add-SfosUserGroupMember -Name "Open Group" -Member "jdoe"

        .EXAMPLE
        # Read the one-time password settings and enrol a user
        Get-SfosOTPSettings
        Add-SfosOTPSettingsMember -Member "jdoe"

        .EXAMPLE
        # Inspect which authentication servers the firewall consults for VPN logins
        (Get-SfosVPNAuthentication).AuthenticationServerList

        .NOTES
        These cmdlets change who may log in to a live firewall and how. An update that drops
        an authentication server, or a group membership written to the wrong object, decides
        whether people can authenticate at all. Every Set-* cmdlet therefore reads the current
        object first and writes it back complete, so fields you do not pass keep their current
        value. Group membership lives on the user, not on the group: a user belongs to exactly
        one group, and adding it to a second one moves it out of the first. The authentication
        server lists of firewall, VPN and SSL VPN authentication cannot be emptied; the
        firewall refuses to remove the last entry.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>

#region AuthenticationServer

# The five authentication server types (ActiveDirectory, LDAPServer, RADIUSServer,
# TACACSServer, EDirectory) are children of the <AuthenticationServer> container. A <Get>
# on the standalone element name (e.g. <ActiveDirectory> directly under <Response>) answers
# '529 Input request module is Invalid'. Every function in this region therefore wraps its
# inner XML in <AuthenticationServer>.
#
# The status path depends on the operation, not only on the entity:
#
#   <Get>                    -> /Response/AuthenticationServer/<Type>/Status  (nested)
#   <Remove>                 -> /Response/AuthenticationServer/<Type>/Status  (nested)
#   <Set operation="add">    -> /Response/<Type>/Status                      (top-level)
#   <Set operation="update"> -> /Response/<Type>/Status                      (top-level)
#
# New-*/Set-* in this region pass -ObjectName as the bare type name (e.g. 'ActiveDirectory'),
# while Get-*/Remove-* keep the nested path (e.g. 'AuthenticationServer/ActiveDirectory').
# The nested path does not exist on add/update, so passing it there would make a failed
# write report as success.
#
# Field names differ from the CONFIGURE/Authentication documentation in three entities:
#
#   RADIUSServer: the address field is <ServerAddress> (not <ServerIP> as the Attribute/
#                 Parameter table names it), and the port field is <Port> (not
#                 <AuthenticationPort>). <Timeout> is mandatory and appears in neither the
#                 table nor the sample XML.
#   TACACSServer: the address field is <ServerAddress> (not <ServerIP>).
#   EDirectory:   the address field is <ServerIpDomain> (not <ServerAddress> as the table
#                 names it), and the username field is <Username> (not <EdirUsername>).
#
# ActiveDirectory and LDAPServer need no field-name correction. LDAPServer's
# GroupNameAttribute, ExpiryDateAttribute and BaseDN are unconditionally required even
# under LooseIntegration, contradicting the sample comment that scopes them to
# TightIntegration only.
#
# Two connection-parameter names collide with fields these entities also define on the
# wire: every entity has its own <Port>, and ActiveDirectory/LDAPServer/EDirectory each
# have their own <Password>. The connection parameters -Port and -Password are fixed by
# name and type and cannot be renamed, so the entity-level fields are exposed here as
# -ServerPort and -BindPassword. Neither carries a parameter alias back to
# 'Port'/'Password': PowerShell rejects a parameter alias that matches another parameter's
# own name on the same command. Instead, each Get-*'s output object carries an
# AliasProperty named ServerPort over its Port property, added via Add-Member after the
# object is built, so Get-* | Set-* still binds -ServerPort by property name while the
# property itself stays named Port. RADIUS's own port field goes through the same rename
# for the same reason, since its wire name (Port) also collides.
#
# Password/secret preservation on update:
#
#   - ActiveDirectory/LDAPServer/EDirectory <Password>: Get returns it hashed, e.g.
#     <Password hashform="mode1">$sfos$7$0$...</Password>. On <Set operation="update">, an
#     empty <Password></Password> is accepted and the stored password is left unchanged.
#     This is the one field in this API observed to violate the usual "the update replaces
#     the whole entity" rule; every Set-* here relies on that exception and sends an empty
#     element when -BindPassword is not supplied.
#   - RADIUS/TACACS <SharedSecret>: also returned hashed by Get, but this entity does not
#     tolerate an empty element - <Set operation="update"> with <SharedSecret></SharedSecret>
#     answers code 501 naming SharedSecret invalid. The only way to preserve it is to resend
#     the hash together with its hashform attribute. Get-SfosRADIUSServer/
#     Get-SfosTACACSServer therefore expose SharedSecretHash and SharedSecretHashForm (not
#     SharedSecret, to make clear neither is the plaintext), and Set-SfosRADIUSServer/
#     Set-SfosTACACSServer resend them when -SharedSecret is omitted.
#
# IntegrationType (ActiveDirectory/LDAPServer/RADIUS): Get never returns this field, even
# immediately after creating an object with -IntegrationType TightIntegration. Every Set-*
# here therefore resends whatever was passed, or an empty element when nothing was passed.
# An empty <IntegrationType></IntegrationType> on update does not disturb sibling fields
# scoped to TightIntegration, but the field cannot be round-tripped or verified through
# this API in either direction.

#region ActiveDirectory

<#
        .SYNOPSIS
        Retrieves ActiveDirectory authentication server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the ActiveDirectory servers configured as authentication sources on the
        firewall. Use this cmdlet to review the existing servers, or to feed them into
        Set-SfosActiveDirectoryServer through the pipeline. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ServerAddress, Port, NetBIOSDomain, ADSUsername,
        ConnectionSecurity, ValidCertReq, IntegrationType, DisplayNameAttribute,
        EmailAddressAttribute, DomainName and SearchQueries. The Port value is also available
        under the property name ServerPort, so the object binds directly to
        Set-SfosActiveDirectoryServer. Returns System.Xml.XmlElement when -AsXml is used, and
        an empty array when no server matches. The stored bind password is never included; the
        firewall does not return it.

        .EXAMPLE
        Get-SfosActiveDirectoryServer

        Lists every ActiveDirectory server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosActiveDirectoryServer -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosActiveDirectoryServer

        .LINK
        Set-SfosActiveDirectoryServer
#>
function Get-SfosActiveDirectoryServer {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AuthenticationServer><ActiveDirectory></ActiveDirectory></AuthenticationServer></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ActiveDirectory authentication server objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Nested ObjectName - see region header. Without it, a code="500" failure two levels
    # below AuthenticationServer is read as success.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/ActiveDirectory' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AuthenticationServer/ActiveDirectory[ServerName]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        $obj = [PSCustomObject]@{
            ServerName            = $node.ServerName
            ServerAddress         = $node.ServerAddress
            Port                  = $node.Port
            NetBIOSDomain         = $node.NetBIOSDomain
            ADSUsername           = $node.ADSUsername
            ConnectionSecurity    = $node.ConnectionSecurity
            ValidCertReq          = $node.ValidCertReq
            IntegrationType       = $node.IntegrationType
            DisplayNameAttribute  = $node.DisplayNameAttribute
            EmailAddressAttribute = $node.EmailAddressAttribute
            DomainName            = $node.DomainName
            SearchQueries         = [string[]]@($node.SearchQueries.Query | Where-Object { $_ })
        }
        # ServerPort is an AliasProperty on Port, not a second copy of the value: Set-SfosActiveDirectoryServer's
        # port parameter had to be renamed to -ServerPort to avoid colliding with the fixed connection -Port
        # parameter, and a matching parameter alias is not possible either (see New-/Set-SfosActiveDirectoryServer
        # .NOTES) - so without this, Get-SfosActiveDirectoryServer | Set-SfosActiveDirectoryServer silently drops
        # the port via ValueFromPipelineByPropertyName. The property name stays Port, per section 7.
        $obj | Add-Member -MemberType AliasProperty -Name ServerPort -Value Port
        $results += $obj
    }

    return $results
}

<#
        .SYNOPSIS
        Creates an ActiveDirectory authentication server on a Sophos Firewall.

        .DESCRIPTION
        Adds an ActiveDirectory server as an authentication source. Use this cmdlet to make an
        existing Active Directory reachable for firewall, VPN or admin logins. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to create authentication servers.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ServerAddress
        Required. IP address or domain name of the Active Directory server.

        .PARAMETER ServerPort
        Required. TCP port the server listens on, usually 389.

        .PARAMETER NetBIOSDomain
        Required. NetBIOS domain name of the directory.

        .PARAMETER ADSUsername
        Required. User name of the account the firewall uses to bind to the directory.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, no password is
        sent.

        .PARAMETER ConnectionSecurity
        Required. Security used when sending the user name and password to the server. Valid
        values: Simple, SSL, StartTLS.

        .PARAMETER ValidCertReq
        Optional. Whether the server certificate is validated when -ConnectionSecurity is SSL
        or StartTLS. Valid values: Enable, Disable. If omitted, the firewall default (Enable)
        applies.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the firewall default applies.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. Used with
        TightIntegration. If omitted, none is set.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. Used with
        TightIntegration. If omitted, the firewall default ('mail') applies.

        .PARAMETER DomainName
        Required. Domain name that the search query is added to.

        .PARAMETER SearchQueries
        Optional. One or more search queries for the directory. If omitted, none is set.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        $bindPw = ConvertTo-SecureString 'Zz-Str0ng-Bind-Pw!9' -AsPlainText -Force
        New-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'ad.example.com' -ServerPort 389 -NetBIOSDomain 'CORP' -ADSUsername 'svc-sfos' -BindPassword $bindPw -ConnectionSecurity Simple -DomainName 'example.com' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $bindPw = ConvertTo-SecureString 'Zz-Str0ng-Bind-Pw!9' -AsPlainText -Force
        New-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'ad.example.com' -ServerPort 389 -NetBIOSDomain 'CORP' -ADSUsername 'svc-sfos' -BindPassword $bindPw -ConnectionSecurity Simple -DomainName 'example.com'

        Creates an Active Directory server with simple bind.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosActiveDirectoryServer
#>
function New-SfosActiveDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [string]$ServerAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(Mandatory)]
        [string]$NetBIOSDomain,

        [Parameter(Mandatory)]
        [string]$ADSUsername,

        [SecureString]$BindPassword,

        [Parameter(Mandatory)]
        [ValidateSet('Simple', 'SSL', 'StartTLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidCertReq,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [string[]]$SearchQueries,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $ServerAddress
    $netBiosEsc = ConvertTo-SfosXmlEscaped -Text $NetBIOSDomain
    $adsUserEsc = ConvertTo-SfosXmlEscaped -Text $ADSUsername
    $domainNameEsc = ConvertTo-SfosXmlEscaped -Text $DomainName

    $bindPasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
        try {
            $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }
    $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain

    $fieldsXml = "<ServerName>$serverNameEsc</ServerName><ServerAddress>$serverAddressEsc</ServerAddress><Port>$ServerPort</Port><NetBIOSDomain>$netBiosEsc</NetBIOSDomain><ADSUsername>$adsUserEsc</ADSUsername>"
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $fieldsXml += "<Password>$bindPasswordEsc</Password>"
    }
    $fieldsXml += "<ConnectionSecurity>$ConnectionSecurity</ConnectionSecurity>"
    if ($PSBoundParameters.ContainsKey('ValidCertReq')) {
        $fieldsXml += "<ValidCertReq>$ValidCertReq</ValidCertReq>"
    }
    if ($PSBoundParameters.ContainsKey('IntegrationType')) {
        $fieldsXml += "<IntegrationType>$IntegrationType</IntegrationType>"
    }
    if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) {
        $fieldsXml += "<DisplayNameAttribute>$(ConvertTo-SfosXmlEscaped -Text $DisplayNameAttribute)</DisplayNameAttribute>"
    }
    if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) {
        $fieldsXml += "<EmailAddressAttribute>$(ConvertTo-SfosXmlEscaped -Text $EmailAddressAttribute)</EmailAddressAttribute>"
    }
    $fieldsXml += "<DomainName>$domainNameEsc</DomainName>"
    if ($PSBoundParameters.ContainsKey('SearchQueries')) {
        $queryXml = ''
        foreach ($query in $SearchQueries) {
            if ($query) {
                $queryXml += "<Query>$(ConvertTo-SfosXmlEscaped -Text $query)</Query>"
            }
        }
        $fieldsXml += "<SearchQueries>$queryXml</SearchQueries>"
    }

    $inner = @"
<Set operation="add">
  <AuthenticationServer>
    <ActiveDirectory>
      $fieldsXml
    </ActiveDirectory>
  </AuthenticationServer>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("ActiveDirectory authentication server '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating ActiveDirectory authentication server '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Unlike Get/Remove, <Set operation="add"> answers with the status at
    # /Response/ActiveDirectory/Status - NOT nested under AuthenticationServer. See the region
    # header for the full per-operation status-path table.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ActiveDirectory' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an ActiveDirectory authentication server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing ActiveDirectory server. The cmdlet reads the current server first
        and writes back a complete object: every field you pass replaces the current value,
        every field you omit keeps it. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly, and an account with permission to
        update authentication servers.

        If you omit -BindPassword, the firewall keeps the stored password unchanged; passing
        -BindPassword replaces it.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ServerAddress
        Optional. IP address or domain name of the server. If omitted, the current value is
        kept.

        .PARAMETER ServerPort
        Optional. TCP port the server listens on. If omitted, the current value is kept.

        .PARAMETER NetBIOSDomain
        Optional. NetBIOS domain name of the directory. If omitted, the current value is kept.

        .PARAMETER ADSUsername
        Optional. User name of the bind account. If omitted, the current value is kept.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, the current
        password is kept.

        .PARAMETER ConnectionSecurity
        Optional. Security used when sending the user name and password to the server. Valid
        values: Simple, SSL, StartTLS. If omitted, the current value is kept.

        .PARAMETER ValidCertReq
        Optional. Whether the server certificate is validated. Valid values: Enable, Disable.
        If omitted, the current value is kept.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the current value is kept.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. If omitted, the
        current value is kept.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. If omitted, the
        current value is kept.

        .PARAMETER DomainName
        Optional. Domain name that the search query is added to. If omitted, the current value
        is kept.

        .PARAMETER SearchQueries
        Optional. One or more search queries for the directory. Replaces the current list. If
        omitted, the current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosActiveDirectoryServer, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosActiveDirectoryServer -ServerName 'CorpAD' -DomainName 'corp.example.com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosActiveDirectoryServer -ServerName 'CorpAD' -DomainName 'corp.example.com'

        Updates the domain name; every other field, including the bind password, keeps its
        current value.

        .EXAMPLE
        Get-SfosActiveDirectoryServer -ServerNameLike 'CorpAD' | Set-SfosActiveDirectoryServer -ConnectionSecurity SSL

        Reads the matching server and switches it to SSL, keeping every other field.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosActiveDirectoryServer
#>
function Set-SfosActiveDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ServerAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NetBIOSDomain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ADSUsername,

        [SecureString]$BindPassword,

        [ValidateSet('Simple', 'SSL', 'StartTLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidCertReq,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,
        [string]$DomainName,
        [string[]]$SearchQueries,

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
        $existing = @(Get-SfosActiveDirectoryServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The ActiveDirectory authentication server '$ServerName' was not found."
        }

        $targetServerAddress = if ($PSBoundParameters.ContainsKey('ServerAddress')) { $ServerAddress } else { [string]$existing[0].ServerAddress }
        $targetServerPort = if ($PSBoundParameters.ContainsKey('ServerPort')) { $ServerPort } else { [int]$existing[0].Port }
        $targetNetBIOSDomain = if ($PSBoundParameters.ContainsKey('NetBIOSDomain')) { $NetBIOSDomain } else { [string]$existing[0].NetBIOSDomain }
        $targetADSUsername = if ($PSBoundParameters.ContainsKey('ADSUsername')) { $ADSUsername } else { [string]$existing[0].ADSUsername }
        $targetConnectionSecurity = if ($PSBoundParameters.ContainsKey('ConnectionSecurity')) { $ConnectionSecurity } else { [string]$existing[0].ConnectionSecurity }
        $targetValidCertReq = if ($PSBoundParameters.ContainsKey('ValidCertReq')) { $ValidCertReq } else { [string]$existing[0].ValidCertReq }
        $targetIntegrationType = if ($PSBoundParameters.ContainsKey('IntegrationType')) { $IntegrationType } else { [string]$existing[0].IntegrationType }
        $targetDisplayNameAttribute = if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) { $DisplayNameAttribute } else { [string]$existing[0].DisplayNameAttribute }
        $targetEmailAddressAttribute = if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) { $EmailAddressAttribute } else { [string]$existing[0].EmailAddressAttribute }
        $targetDomainName = if ($PSBoundParameters.ContainsKey('DomainName')) { $DomainName } else { [string]$existing[0].DomainName }
        # @() wraps the whole if/else: a one-element array from a branch unrolls to a scalar
        # on assignment.
        $targetSearchQueries = @(if ($PSBoundParameters.ContainsKey('SearchQueries')) { $SearchQueries } else { $existing[0].SearchQueries })

        # An empty <Password> on update is accepted and preserves the existing bind
        # password (see the .DESCRIPTION) - so no warning is needed when -BindPassword is
        # omitted, unlike the RADIUS/TACACS SharedSecret case where an empty value is rejected.
        $bindPasswordPlain = ''
        if ($PSBoundParameters.ContainsKey('BindPassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
            try {
                $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetServerAddress
        $netBiosEsc = ConvertTo-SfosXmlEscaped -Text $targetNetBIOSDomain
        $adsUserEsc = ConvertTo-SfosXmlEscaped -Text $targetADSUsername
        $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain
        $displayNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDisplayNameAttribute
        $emailAttrEsc = ConvertTo-SfosXmlEscaped -Text $targetEmailAddressAttribute
        $domainNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDomainName

        $queryXml = ''
        foreach ($query in $targetSearchQueries) {
            if ($query) {
                $queryXml += "<Query>$(ConvertTo-SfosXmlEscaped -Text $query)</Query>"
            }
        }

        $inner = @"
<Set operation="update">
  <AuthenticationServer>
    <ActiveDirectory>
      <ServerName>$serverNameEsc</ServerName>
      <ServerAddress>$serverAddressEsc</ServerAddress>
      <Port>$targetServerPort</Port>
      <NetBIOSDomain>$netBiosEsc</NetBIOSDomain>
      <ADSUsername>$adsUserEsc</ADSUsername>
      <Password>$bindPasswordEsc</Password>
      <ConnectionSecurity>$targetConnectionSecurity</ConnectionSecurity>
      <ValidCertReq>$targetValidCertReq</ValidCertReq>
      <IntegrationType>$targetIntegrationType</IntegrationType>
      <DisplayNameAttribute>$displayNameEsc</DisplayNameAttribute>
      <EmailAddressAttribute>$emailAttrEsc</EmailAddressAttribute>
      <DomainName>$domainNameEsc</DomainName>
      <SearchQueries>$queryXml</SearchQueries>
    </ActiveDirectory>
  </AuthenticationServer>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ActiveDirectory authentication server '$ServerName' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating ActiveDirectory authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # <Set operation="update"> answers at /Response/ActiveDirectory/Status too,
        # same as add - see the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ActiveDirectory' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an ActiveDirectory authentication server from a Sophos Firewall.

        .DESCRIPTION
        Deletes an ActiveDirectory server object. Use this cmdlet to remove a directory that is
        no longer used as an authentication source. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosActiveDirectoryServer -ServerName 'CorpAD' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosActiveDirectoryServer -ServerName 'CorpAD'

        Removes the server named 'CorpAD'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosActiveDirectoryServer
#>
function Remove-SfosActiveDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("ActiveDirectory authentication server '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AuthenticationServer>
    <ActiveDirectory>
      <ServerName>$nameEsc</ServerName>
    </ActiveDirectory>
  </AuthenticationServer>
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
            throw "Error removing ActiveDirectory authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/ActiveDirectory' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion ActiveDirectory

#region LDAPServer

<#
        .SYNOPSIS
        Retrieves LDAP authentication server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the LDAP servers configured as authentication sources on the firewall. Use
        this cmdlet to review the existing servers, or to feed them into Set-SfosLDAPServer
        through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ServerAddress, Port, Version, AnonymousLogin, Administrator,
        AppendBaseDN, ConnectionSecurity, ValidateServerCertificate, ClientCertificate,
        BaseDN, AuthenticationAttribute, IntegrationType, DisplayNameAttribute,
        EmailAddressAttribute, GroupNameAttribute and ExpiryDateAttribute. The Port value is
        also available under the property name ServerPort, so the object binds directly to
        Set-SfosLDAPServer. Returns System.Xml.XmlElement when -AsXml is used, and an empty
        array when no server matches. The stored bind password is never included; the firewall
        does not return it.

        .EXAMPLE
        Get-SfosLDAPServer

        Lists every LDAP server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosLDAPServer -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosLDAPServer

        .LINK
        Set-SfosLDAPServer
#>
function Get-SfosLDAPServer {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AuthenticationServer><LDAPServer></LDAPServer></AuthenticationServer></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving LDAPServer authentication server objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/LDAPServer' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AuthenticationServer/LDAPServer[ServerName]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        $obj = [PSCustomObject]@{
            ServerName                = $node.ServerName
            ServerAddress             = $node.ServerAddress
            Port                      = $node.Port
            Version                   = $node.Version
            AnonymousLogin            = $node.AnonymousLogin
            Administrator             = $node.Administrator
            AppendBaseDN              = $node.AppendBaseDN
            ConnectionSecurity        = $node.ConnectionSecurity
            ValidateServerCertificate = $node.ValidateServerCertificate
            ClientCertificate         = $node.ClientCertificate
            BaseDN                    = $node.BaseDN
            AuthenticationAttribute   = $node.AuthenticationAttribute
            IntegrationType           = $node.IntegrationType
            DisplayNameAttribute      = $node.DisplayNameAttribute
            EmailAddressAttribute     = $node.EmailAddressAttribute
            GroupNameAttribute        = $node.GroupNameAttribute
            ExpiryDateAttribute       = $node.ExpiryDateAttribute
        }
        # ServerPort is an AliasProperty on Port, not a second copy of the value - see the
        # matching comment in Get-SfosActiveDirectoryServer for why this is required.
        $obj | Add-Member -MemberType AliasProperty -Name ServerPort -Value Port
        $results += $obj
    }

    return $results
}

<#
        .SYNOPSIS
        Creates an LDAP authentication server on a Sophos Firewall.

        .DESCRIPTION
        Adds an LDAP server as an authentication source. Use this cmdlet to make an existing
        directory reachable for firewall, VPN or admin logins. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to create authentication servers.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ServerAddress
        Required. IP address or domain name of the LDAP server.

        .PARAMETER ServerPort
        Required. TCP port the server listens on, usually 389.

        .PARAMETER Version
        Required. LDAP protocol version. Valid values: 2, 3.

        .PARAMETER AnonymousLogin
        Required. Whether to bind without a user name and password. Valid values: Enable,
        Disable.

        .PARAMETER Administrator
        Optional. User name of the bind account. Required when -AnonymousLogin is Disable; the
        cmdlet throws before calling the firewall if it is missing in that case.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, no password is
        sent.

        .PARAMETER AppendBaseDN
        Optional. Whether the base DN is appended during the bind. Valid values: Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER ConnectionSecurity
        Required. Security used when sending the user credentials. Valid values: Simple, SSL,
        STARTTLS.

        .PARAMETER ValidateServerCertificate
        Optional. Whether the server certificate is validated. Valid values: Enable, Disable.
        If omitted, the firewall default (Enable) applies.

        .PARAMETER ClientCertificate
        Optional. Client certificate used for the secured connection. If omitted, none is set.

        .PARAMETER BaseDN
        Required. Base distinguished name of the directory.

        .PARAMETER AuthenticationAttribute
        Required. Directory attribute used for the user search.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the firewall default applies.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. If omitted, none
        is set.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. If omitted, the
        firewall default ('mail') applies.

        .PARAMETER GroupNameAttribute
        Required. Directory attribute shown to the user as the group name.

        .PARAMETER ExpiryDateAttribute
        Required. Directory attribute shown to the user as the account expiry date.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosLDAPServer -ServerName 'CorpLDAP' -ServerAddress 'ldap.example.com' -ServerPort 389 -Version 3 -AnonymousLogin Enable -ConnectionSecurity Simple -AuthenticationAttribute 'uid' -BaseDN 'dc=corp,dc=example,dc=com' -GroupNameAttribute 'memberOf' -ExpiryDateAttribute 'accountExpires' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosLDAPServer -ServerName 'CorpLDAP' -ServerAddress 'ldap.example.com' -ServerPort 389 -Version 3 -AnonymousLogin Enable -ConnectionSecurity Simple -AuthenticationAttribute 'uid' -BaseDN 'dc=corp,dc=example,dc=com' -GroupNameAttribute 'memberOf' -ExpiryDateAttribute 'accountExpires'

        Creates an LDAP server with anonymous bind.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosLDAPServer
#>
function New-SfosLDAPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [string]$ServerAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(Mandatory)]
        [ValidateSet('2', '3')]
        [string]$Version,

        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$AnonymousLogin,

        [string]$Administrator,
        [SecureString]$BindPassword,

        [ValidateSet('Enable', 'Disable')]
        [string]$AppendBaseDN,

        [Parameter(Mandatory)]
        [ValidateSet('Simple', 'SSL', 'STARTTLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidateServerCertificate,

        [string]$ClientCertificate,

        [Parameter(Mandatory)]
        [string]$BaseDN,

        [Parameter(Mandatory)]
        [string]$AuthenticationAttribute,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,

        [Parameter(Mandatory)]
        [string]$GroupNameAttribute,

        [Parameter(Mandatory)]
        [string]$ExpiryDateAttribute,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # With -AnonymousLogin Disable, an add that omits
    # -Administrator answers code="501" (Configuration parameters validation failed), even
    # though the Attribute/Parameter table does not mark Administrator as mandatory. With
    # -AnonymousLogin Enable the same add succeeds without -Administrator. -BindPassword was
    # also tested and is NOT part of this condition: an add with -AnonymousLogin Disable and
    # -Administrator set, but no -BindPassword, succeeds (code 200).
    if ($AnonymousLogin -eq 'Disable' -and [string]::IsNullOrWhiteSpace($Administrator)) {
        throw "New-SfosLDAPServer: -Administrator is required for LDAPServer authentication server '$ServerName' when -AnonymousLogin is 'Disable'; the firewall rejects the request without it."
    }

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $ServerAddress
    $authAttrEsc = ConvertTo-SfosXmlEscaped -Text $AuthenticationAttribute
    $baseDnEsc = ConvertTo-SfosXmlEscaped -Text $BaseDN
    $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $GroupNameAttribute
    $expiryDateEsc = ConvertTo-SfosXmlEscaped -Text $ExpiryDateAttribute

    $bindPasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
        try {
            $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }
    $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain

    $fieldsXml = "<ServerName>$serverNameEsc</ServerName><ServerAddress>$serverAddressEsc</ServerAddress><Port>$ServerPort</Port><Version>$Version</Version><AnonymousLogin>$AnonymousLogin</AnonymousLogin>"
    if ($PSBoundParameters.ContainsKey('Administrator')) {
        $fieldsXml += "<Administrator>$(ConvertTo-SfosXmlEscaped -Text $Administrator)</Administrator>"
    }
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $fieldsXml += "<Password>$bindPasswordEsc</Password>"
    }
    if ($PSBoundParameters.ContainsKey('AppendBaseDN')) {
        $fieldsXml += "<AppendBaseDN>$AppendBaseDN</AppendBaseDN>"
    }
    $fieldsXml += "<ConnectionSecurity>$ConnectionSecurity</ConnectionSecurity>"
    if ($PSBoundParameters.ContainsKey('ValidateServerCertificate')) {
        $fieldsXml += "<ValidateServerCertificate>$ValidateServerCertificate</ValidateServerCertificate>"
    }
    if ($PSBoundParameters.ContainsKey('ClientCertificate')) {
        $fieldsXml += "<ClientCertificate>$(ConvertTo-SfosXmlEscaped -Text $ClientCertificate)</ClientCertificate>"
    }
    $fieldsXml += "<BaseDN>$baseDnEsc</BaseDN>"
    $fieldsXml += "<AuthenticationAttribute>$authAttrEsc</AuthenticationAttribute>"
    if ($PSBoundParameters.ContainsKey('IntegrationType')) {
        $fieldsXml += "<IntegrationType>$IntegrationType</IntegrationType>"
    }
    if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) {
        $fieldsXml += "<DisplayNameAttribute>$(ConvertTo-SfosXmlEscaped -Text $DisplayNameAttribute)</DisplayNameAttribute>"
    }
    if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) {
        $fieldsXml += "<EmailAddressAttribute>$(ConvertTo-SfosXmlEscaped -Text $EmailAddressAttribute)</EmailAddressAttribute>"
    }
    $fieldsXml += "<GroupNameAttribute>$groupNameEsc</GroupNameAttribute>"
    $fieldsXml += "<ExpiryDateAttribute>$expiryDateEsc</ExpiryDateAttribute>"

    $inner = @"
<Set operation="add">
  <AuthenticationServer>
    <LDAPServer>
      $fieldsXml
    </LDAPServer>
  </AuthenticationServer>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("LDAPServer authentication server '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating LDAPServer authentication server '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # <Set operation="add"> answers at /Response/LDAPServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LDAPServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an LDAP authentication server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing LDAP server. The cmdlet reads the current server first and writes
        back a complete object: every field you pass replaces the current value, every field
        you omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        authentication servers.

        If you omit -BindPassword, the firewall keeps the stored password unchanged; passing
        -BindPassword replaces it. If the resulting -AnonymousLogin is Disable and no
        Administrator value is available, the cmdlet throws before calling the firewall.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ServerAddress
        Optional. IP address or domain name of the server. If omitted, the current value is
        kept.

        .PARAMETER ServerPort
        Optional. TCP port the server listens on. If omitted, the current value is kept.

        .PARAMETER Version
        Optional. LDAP protocol version. Valid values: 2, 3. If omitted, the current value is
        kept.

        .PARAMETER AnonymousLogin
        Optional. Whether to bind without a user name and password. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER Administrator
        Optional. User name of the bind account. If omitted, the current value is kept.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, the current
        password is kept.

        .PARAMETER AppendBaseDN
        Optional. Whether the base DN is appended during the bind. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER ConnectionSecurity
        Optional. Security used when sending the user credentials. Valid values: Simple, SSL,
        STARTTLS. If omitted, the current value is kept.

        .PARAMETER ValidateServerCertificate
        Optional. Whether the server certificate is validated. Valid values: Enable, Disable.
        If omitted, the current value is kept.

        .PARAMETER ClientCertificate
        Optional. Client certificate used for the secured connection. If omitted, the current
        value is kept.

        .PARAMETER BaseDN
        Optional. Base distinguished name of the directory. If omitted, the current value is
        kept.

        .PARAMETER AuthenticationAttribute
        Optional. Directory attribute used for the user search. If omitted, the current value
        is kept.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the current value is kept.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. If omitted, the
        current value is kept.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. If omitted, the
        current value is kept.

        .PARAMETER GroupNameAttribute
        Optional. Directory attribute shown to the user as the group name. If omitted, the
        current value is kept.

        .PARAMETER ExpiryDateAttribute
        Optional. Directory attribute shown to the user as the account expiry date. If
        omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosLDAPServer, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosLDAPServer -ServerName 'CorpLDAP' -BaseDN 'dc=corp,dc=example,dc=com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosLDAPServer -ServerName 'CorpLDAP' -BaseDN 'dc=corp,dc=example,dc=com'

        Updates the base DN; every other field, including the bind password, keeps its current
        value.

        .EXAMPLE
        Get-SfosLDAPServer -ServerNameLike 'CorpLDAP' | Set-SfosLDAPServer -ConnectionSecurity SSL

        Reads the matching server and switches it to SSL, keeping every other field.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosLDAPServer
#>
function Set-SfosLDAPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ServerAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [ValidateSet('2', '3')]
        [string]$Version,

        [ValidateSet('Enable', 'Disable')]
        [string]$AnonymousLogin,

        [string]$Administrator,
        [SecureString]$BindPassword,

        [ValidateSet('Enable', 'Disable')]
        [string]$AppendBaseDN,

        [ValidateSet('Simple', 'SSL', 'STARTTLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidateServerCertificate,

        [string]$ClientCertificate,
        [string]$BaseDN,
        [string]$AuthenticationAttribute,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,
        [string]$GroupNameAttribute,
        [string]$ExpiryDateAttribute,

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
        $existing = @(Get-SfosLDAPServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The LDAPServer authentication server '$ServerName' was not found."
        }

        $targetServerAddress = if ($PSBoundParameters.ContainsKey('ServerAddress')) { $ServerAddress } else { [string]$existing[0].ServerAddress }
        $targetServerPort = if ($PSBoundParameters.ContainsKey('ServerPort')) { $ServerPort } else { [int]$existing[0].Port }
        $targetVersion = if ($PSBoundParameters.ContainsKey('Version')) { $Version } else { [string]$existing[0].Version }
        $targetAnonymousLogin = if ($PSBoundParameters.ContainsKey('AnonymousLogin')) { $AnonymousLogin } else { [string]$existing[0].AnonymousLogin }
        $targetAdministrator = if ($PSBoundParameters.ContainsKey('Administrator')) { $Administrator } else { [string]$existing[0].Administrator }
        $targetAppendBaseDN = if ($PSBoundParameters.ContainsKey('AppendBaseDN')) { $AppendBaseDN } else { [string]$existing[0].AppendBaseDN }
        $targetConnectionSecurity = if ($PSBoundParameters.ContainsKey('ConnectionSecurity')) { $ConnectionSecurity } else { [string]$existing[0].ConnectionSecurity }
        $targetValidateServerCertificate = if ($PSBoundParameters.ContainsKey('ValidateServerCertificate')) { $ValidateServerCertificate } else { [string]$existing[0].ValidateServerCertificate }
        $targetClientCertificate = if ($PSBoundParameters.ContainsKey('ClientCertificate')) { $ClientCertificate } else { [string]$existing[0].ClientCertificate }
        $targetBaseDN = if ($PSBoundParameters.ContainsKey('BaseDN')) { $BaseDN } else { [string]$existing[0].BaseDN }
        $targetAuthenticationAttribute = if ($PSBoundParameters.ContainsKey('AuthenticationAttribute')) { $AuthenticationAttribute } else { [string]$existing[0].AuthenticationAttribute }
        $targetIntegrationType = if ($PSBoundParameters.ContainsKey('IntegrationType')) { $IntegrationType } else { [string]$existing[0].IntegrationType }
        $targetDisplayNameAttribute = if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) { $DisplayNameAttribute } else { [string]$existing[0].DisplayNameAttribute }
        $targetEmailAddressAttribute = if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) { $EmailAddressAttribute } else { [string]$existing[0].EmailAddressAttribute }
        $targetGroupNameAttribute = if ($PSBoundParameters.ContainsKey('GroupNameAttribute')) { $GroupNameAttribute } else { [string]$existing[0].GroupNameAttribute }
        $targetExpiryDateAttribute = if ($PSBoundParameters.ContainsKey('ExpiryDateAttribute')) { $ExpiryDateAttribute } else { [string]$existing[0].ExpiryDateAttribute }

        # This condition applies to Set-* as well as New-*.
        # An update that resolves to AnonymousLogin=Disable with no Administrator (neither
        # passed nor already stored on the object) answers code="501". Checked against the
        # merged target values, not the raw parameters, because read-modify-write can supply
        # Administrator from the existing object even when -Administrator was not passed here.
        if ($targetAnonymousLogin -eq 'Disable' -and [string]::IsNullOrWhiteSpace($targetAdministrator)) {
            throw "Set-SfosLDAPServer: -Administrator is required for LDAPServer authentication server '$ServerName' when -AnonymousLogin is 'Disable'; the firewall rejects the request without it."
        }

        # An empty <Password> on update is accepted and preserves the existing bind
        # password (see the .DESCRIPTION) - so no warning is needed when -BindPassword is
        # omitted, unlike the RADIUS/TACACS SharedSecret case where an empty value is rejected.
        $bindPasswordPlain = ''
        if ($PSBoundParameters.ContainsKey('BindPassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
            try {
                $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetServerAddress
        $administratorEsc = ConvertTo-SfosXmlEscaped -Text $targetAdministrator
        $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain
        $clientCertEsc = ConvertTo-SfosXmlEscaped -Text $targetClientCertificate
        $baseDnEsc = ConvertTo-SfosXmlEscaped -Text $targetBaseDN
        $authAttrEsc = ConvertTo-SfosXmlEscaped -Text $targetAuthenticationAttribute
        $displayNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDisplayNameAttribute
        $emailAttrEsc = ConvertTo-SfosXmlEscaped -Text $targetEmailAddressAttribute
        $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $targetGroupNameAttribute
        $expiryDateEsc = ConvertTo-SfosXmlEscaped -Text $targetExpiryDateAttribute

        $inner = @"
<Set operation="update">
  <AuthenticationServer>
    <LDAPServer>
      <ServerName>$serverNameEsc</ServerName>
      <ServerAddress>$serverAddressEsc</ServerAddress>
      <Port>$targetServerPort</Port>
      <Version>$targetVersion</Version>
      <AnonymousLogin>$targetAnonymousLogin</AnonymousLogin>
      <Administrator>$administratorEsc</Administrator>
      <Password>$bindPasswordEsc</Password>
      <AppendBaseDN>$targetAppendBaseDN</AppendBaseDN>
      <ConnectionSecurity>$targetConnectionSecurity</ConnectionSecurity>
      <ValidateServerCertificate>$targetValidateServerCertificate</ValidateServerCertificate>
      <ClientCertificate>$clientCertEsc</ClientCertificate>
      <BaseDN>$baseDnEsc</BaseDN>
      <AuthenticationAttribute>$authAttrEsc</AuthenticationAttribute>
      <IntegrationType>$targetIntegrationType</IntegrationType>
      <DisplayNameAttribute>$displayNameEsc</DisplayNameAttribute>
      <EmailAddressAttribute>$emailAttrEsc</EmailAddressAttribute>
      <GroupNameAttribute>$groupNameEsc</GroupNameAttribute>
      <ExpiryDateAttribute>$expiryDateEsc</ExpiryDateAttribute>
    </LDAPServer>
  </AuthenticationServer>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("LDAPServer authentication server '$ServerName' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating LDAPServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # <Set operation="update"> answers at /Response/LDAPServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LDAPServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an LDAP authentication server from a Sophos Firewall.

        .DESCRIPTION
        Deletes an LDAP server object. Use this cmdlet to remove a directory that is no longer
        used as an authentication source. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosLDAPServer -ServerName 'CorpLDAP' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosLDAPServer -ServerName 'CorpLDAP'

        Removes the server named 'CorpLDAP'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosLDAPServer
#>
function Remove-SfosLDAPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("LDAPServer authentication server '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AuthenticationServer>
    <LDAPServer>
      <ServerName>$nameEsc</ServerName>
    </LDAPServer>
  </AuthenticationServer>
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
            throw "Error removing LDAPServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/LDAPServer' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion LDAPServer

#region RADIUSServer

<#
        .SYNOPSIS
        Retrieves RADIUS authentication server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the RADIUS servers configured as authentication sources on the firewall. Use
        this cmdlet to review the existing servers, or to feed them into Set-SfosRADIUSServer
        through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ServerAddress, Port, Timeout, AccountingPort, DomainName,
        IntegrationType and GroupNameAttribute. The Port value is also available under the
        property name ServerPort, so the object binds directly to Set-SfosRADIUSServer. Two
        further properties, SharedSecretHash and SharedSecretHashForm, carry the firewall's
        hashed form of the shared secret, not the plaintext; Set-SfosRADIUSServer resends them
        to keep the secret unchanged when -SharedSecret is not passed. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no server matches.

        .EXAMPLE
        Get-SfosRADIUSServer

        Lists every RADIUS server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosRADIUSServer -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosRADIUSServer

        .LINK
        Set-SfosRADIUSServer
#>
function Get-SfosRADIUSServer {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AuthenticationServer><RADIUSServer></RADIUSServer></AuthenticationServer></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving RADIUSServer authentication server objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/RADIUSServer' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AuthenticationServer/RADIUSServer[ServerName]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        # Addressed through SelectSingleNode, not $node.SharedSecret: a missing element makes
        # the property $null, and a present one without attributes comes back as a plain
        # string, so calling GetAttribute on either throws. A server whose secret the firewall
        # does not return would otherwise kill the whole Get instead of leaving the field
        # empty - and it is Set-SfosRADIUSServer that has to report the missing hash, with a
        # message telling the caller to pass -SharedSecret.
        $secretNode = $node.SelectSingleNode('SharedSecret')
        $obj = [PSCustomObject]@{
            ServerName         = $node.ServerName
            ServerAddress      = $node.ServerAddress
            Port               = $node.Port
            Timeout            = $node.Timeout
            AccountingPort     = $node.AccountingPort
            DomainName         = $node.DomainName
            IntegrationType    = $node.IntegrationType
            GroupNameAttribute = $node.GroupNameAttribute
            # Unlike ActiveDirectory/LDAPServer/EDirectory's <Password>, RADIUS
            # rejects an empty <SharedSecret></SharedSecret> on update with a 501
            # 'Configuration parameters validation failed.' naming SharedSecret as invalid.
            # The only way Set-SfosRADIUSServer can preserve an unchanged secret is to resend
            # this hashed value together with its hashform attribute, which the firewall
            # accepts (200) - confirmed live. Not the real secret; write-only for that.
            SharedSecretHash     = if ($secretNode) { $secretNode.InnerText } else { '' }
            SharedSecretHashForm = if ($secretNode) { $secretNode.GetAttribute('hashform') } else { '' }
        }
        # ServerPort is an AliasProperty on Port, not a second copy of the value - see the
        # matching comment in Get-SfosActiveDirectoryServer for why this is required.
        $obj | Add-Member -MemberType AliasProperty -Name ServerPort -Value Port
        $results += $obj
    }

    return $results
}

<#
        .SYNOPSIS
        Creates a RADIUS authentication server on a Sophos Firewall.

        .DESCRIPTION
        Adds a RADIUS server as an authentication source. Use this cmdlet to make an existing
        RADIUS service reachable for firewall, VPN or admin logins. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to create authentication servers.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ServerAddress
        Required. IP address of the RADIUS server.

        .PARAMETER ServerPort
        Required. TCP port the server listens on, usually 1812.

        .PARAMETER Timeout
        Required. Request timeout in seconds. 1 to 60.

        .PARAMETER AccountingPort
        Optional. Accounting port. Send this only if RADIUS accounting is to be enabled. If
        omitted, accounting stays disabled.

        .PARAMETER SharedSecret
        Required. Shared secret used to encrypt traffic between the firewall and the server, as
        a SecureString.

        .PARAMETER DomainName
        Optional. Domain name of the users. If omitted, none is set.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the firewall default applies.

        .PARAMETER GroupNameAttribute
        Required. RADIUS attribute that carries the group name.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Shared-Secr3t!9' -AsPlainText -Force
        New-SfosRADIUSServer -ServerName 'CorpRadius' -ServerAddress '203.0.113.10' -ServerPort 1812 -Timeout 60 -SharedSecret $secret -GroupNameAttribute 'memberOf' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Shared-Secr3t!9' -AsPlainText -Force
        New-SfosRADIUSServer -ServerName 'CorpRadius' -ServerAddress '203.0.113.10' -ServerPort 1812 -Timeout 60 -SharedSecret $secret -GroupNameAttribute 'memberOf'

        Creates a RADIUS server.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosRADIUSServer
#>
function New-SfosRADIUSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [string]$ServerAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(Mandatory)]
        [ValidateRange(1, 60)]
        [int]$Timeout,

        [ValidateRange(1, 65535)]
        [int]$AccountingPort,

        [Parameter(Mandatory)]
        [SecureString]$SharedSecret,

        [string]$DomainName,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [Parameter(Mandatory)]
        [string]$GroupNameAttribute,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $ServerAddress
    $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $GroupNameAttribute

    $sharedSecretBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
    try {
        $sharedSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($sharedSecretBstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($sharedSecretBstr)
    }
    $sharedSecretEsc = ConvertTo-SfosXmlEscaped -Text $sharedSecretPlain

    $fieldsXml = "<ServerName>$serverNameEsc</ServerName><ServerAddress>$serverAddressEsc</ServerAddress><Port>$ServerPort</Port><Timeout>$Timeout</Timeout>"
    if ($PSBoundParameters.ContainsKey('AccountingPort')) {
        $fieldsXml += "<AccountingPort>$AccountingPort</AccountingPort>"
    }
    $fieldsXml += "<SharedSecret>$sharedSecretEsc</SharedSecret>"
    if ($PSBoundParameters.ContainsKey('DomainName')) {
        $fieldsXml += "<DomainName>$(ConvertTo-SfosXmlEscaped -Text $DomainName)</DomainName>"
    }
    if ($PSBoundParameters.ContainsKey('IntegrationType')) {
        $fieldsXml += "<IntegrationType>$IntegrationType</IntegrationType>"
    }
    $fieldsXml += "<GroupNameAttribute>$groupNameEsc</GroupNameAttribute>"

    $inner = @"
<Set operation="add">
  <AuthenticationServer>
    <RADIUSServer>
      $fieldsXml
    </RADIUSServer>
  </AuthenticationServer>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("RADIUSServer authentication server '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating RADIUSServer authentication server '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # <Set operation="add"> answers at /Response/RADIUSServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RADIUSServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates a RADIUS authentication server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing RADIUS server. The cmdlet reads the current server first and
        writes back a complete object: every field you pass replaces the current value, every
        field you omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        authentication servers.

        If you omit -SharedSecret, the cmdlet resends the stored secret so it stays unchanged.
        If no stored secret can be read back, the cmdlet throws and asks for -SharedSecret
        explicitly.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ServerAddress
        Optional. IP address of the server. If omitted, the current value is kept.

        .PARAMETER ServerPort
        Optional. TCP port the server listens on. If omitted, the current value is kept.

        .PARAMETER Timeout
        Optional. Request timeout in seconds. 1 to 60. If omitted, the current value is kept.

        .PARAMETER AccountingPort
        Optional. Accounting port. If omitted, the current value is kept.

        .PARAMETER SharedSecret
        Optional. Shared secret, as a SecureString. If omitted, the current secret is kept.

        .PARAMETER DomainName
        Optional. Domain name of the users. If omitted, the current value is kept.

        .PARAMETER IntegrationType
        Optional. Integration type used for group membership lookups. Valid values:
        LooseIntegration, TightIntegration. If omitted, the current value is kept.

        .PARAMETER GroupNameAttribute
        Optional. RADIUS attribute that carries the group name. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosRADIUSServer, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosRADIUSServer -ServerName 'CorpRadius' -DomainName 'corp.example.com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosRADIUSServer -ServerName 'CorpRadius' -DomainName 'corp.example.com'

        Updates the domain name; every other field, including the shared secret, keeps its
        current value.

        .EXAMPLE
        Get-SfosRADIUSServer -ServerNameLike 'CorpRadius' | Set-SfosRADIUSServer -Timeout 30

        Reads the matching server and changes its timeout, keeping every other field.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosRADIUSServer
#>
function Set-SfosRADIUSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ServerAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [ValidateRange(1, 60)]
        [int]$Timeout,

        [ValidateRange(1, 65535)]
        [int]$AccountingPort,

        [SecureString]$SharedSecret,
        [string]$DomainName,

        [ValidateSet('LooseIntegration', 'TightIntegration')]
        [string]$IntegrationType,

        [string]$GroupNameAttribute,

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
        $existing = @(Get-SfosRADIUSServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The RADIUSServer authentication server '$ServerName' was not found."
        }

        $targetServerAddress = if ($PSBoundParameters.ContainsKey('ServerAddress')) { $ServerAddress } else { [string]$existing[0].ServerAddress }
        $targetServerPort = if ($PSBoundParameters.ContainsKey('ServerPort')) { $ServerPort } else { [int]$existing[0].Port }
        $targetTimeout = if ($PSBoundParameters.ContainsKey('Timeout')) { $Timeout } else { [int]$existing[0].Timeout }
        $targetAccountingPort = if ($PSBoundParameters.ContainsKey('AccountingPort')) { $AccountingPort } else { $existing[0].AccountingPort }
        $targetDomainName = if ($PSBoundParameters.ContainsKey('DomainName')) { $DomainName } else { [string]$existing[0].DomainName }
        $targetIntegrationType = if ($PSBoundParameters.ContainsKey('IntegrationType')) { $IntegrationType } else { [string]$existing[0].IntegrationType }
        $targetGroupNameAttribute = if ($PSBoundParameters.ContainsKey('GroupNameAttribute')) { $GroupNameAttribute } else { [string]$existing[0].GroupNameAttribute }

        # An empty <SharedSecret> is rejected outright for this entity (code 501),
        # unlike Password on ActiveDirectory/LDAPServer/EDirectory. So when the caller does not
        # supply -SharedSecret, resend the hashed value Get-SfosRADIUSServer read back, with its
        # hashform attribute - the firewall accepts that as "unchanged" (confirmed live).
        $sharedSecretXml = ''
        if ($PSBoundParameters.ContainsKey('SharedSecret')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
            try {
                $sharedSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
            $sharedSecretXml = "<SharedSecret>$(ConvertTo-SfosXmlEscaped -Text $sharedSecretPlain)</SharedSecret>"
        }
        elseif ($existing[0].SharedSecretHash) {
            $hashEsc = ConvertTo-SfosXmlEscaped -Text $existing[0].SharedSecretHash
            $hashFormEsc = ConvertTo-SfosXmlEscaped -Text $existing[0].SharedSecretHashForm
            $sharedSecretXml = "<SharedSecret hashform=`"$hashFormEsc`">$hashEsc</SharedSecret>"
        }
        else {
            throw "Set-SfosRADIUSServer cannot preserve the shared secret of '$ServerName': Get-SfosRADIUSServer returned no existing hash to resend. Pass -SharedSecret explicitly."
        }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetServerAddress
        $domainNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDomainName
        $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $targetGroupNameAttribute

        $accountingPortXml = ''
        if ($targetAccountingPort) {
            $accountingPortXml = "<AccountingPort>$targetAccountingPort</AccountingPort>"
        }

        $inner = @"
<Set operation="update">
  <AuthenticationServer>
    <RADIUSServer>
      <ServerName>$serverNameEsc</ServerName>
      <ServerAddress>$serverAddressEsc</ServerAddress>
      <Port>$targetServerPort</Port>
      <Timeout>$targetTimeout</Timeout>
      $accountingPortXml
      $sharedSecretXml
      <DomainName>$domainNameEsc</DomainName>
      <IntegrationType>$targetIntegrationType</IntegrationType>
      <GroupNameAttribute>$groupNameEsc</GroupNameAttribute>
    </RADIUSServer>
  </AuthenticationServer>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("RADIUSServer authentication server '$ServerName' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating RADIUSServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # <Set operation="update"> answers at /Response/RADIUSServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RADIUSServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a RADIUS authentication server from a Sophos Firewall.

        .DESCRIPTION
        Deletes a RADIUS server object. Use this cmdlet to remove a server that is no longer
        used as an authentication source. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosRADIUSServer -ServerName 'CorpRadius' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosRADIUSServer -ServerName 'CorpRadius'

        Removes the server named 'CorpRadius'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosRADIUSServer
#>
function Remove-SfosRADIUSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("RADIUSServer authentication server '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AuthenticationServer>
    <RADIUSServer>
      <ServerName>$nameEsc</ServerName>
    </RADIUSServer>
  </AuthenticationServer>
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
            throw "Error removing RADIUSServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/RADIUSServer' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion RADIUSServer

#region TACACSServer

<#
        .SYNOPSIS
        Retrieves TACACS+ authentication server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the TACACS+ servers configured as authentication sources on the firewall. Use
        this cmdlet to review the existing servers, or to feed them into Set-SfosTACACSServer
        through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ServerAddress and Port. The Port value is also available under
        the property name ServerPort, so the object binds directly to Set-SfosTACACSServer.
        Two further properties, SharedSecretHash and SharedSecretHashForm, carry the
        firewall's hashed form of the shared secret, not the plaintext; Set-SfosTACACSServer
        resends them to keep the secret unchanged when -SharedSecret is not passed. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no server matches.

        .EXAMPLE
        Get-SfosTACACSServer

        Lists every TACACS+ server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosTACACSServer -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosTACACSServer

        .LINK
        Set-SfosTACACSServer
#>
function Get-SfosTACACSServer {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AuthenticationServer><TACACSServer></TACACSServer></AuthenticationServer></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving TACACSServer authentication server objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/TACACSServer' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AuthenticationServer/TACACSServer[ServerName]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        # SelectSingleNode rather than $node.SharedSecret - see the matching comment in
        # Get-SfosRADIUSServer: a missing or attribute-less element makes GetAttribute throw
        # and would take down the whole Get.
        $secretNode = $node.SelectSingleNode('SharedSecret')
        $obj = [PSCustomObject]@{
            ServerName           = $node.ServerName
            ServerAddress        = $node.ServerAddress
            Port                 = $node.Port
            # See the .NOTES: hashed shared secret, used only so Set-SfosTACACSServer can
            # preserve an unchanged secret across an update - not the plaintext.
            SharedSecretHash     = if ($secretNode) { $secretNode.InnerText } else { '' }
            SharedSecretHashForm = if ($secretNode) { $secretNode.GetAttribute('hashform') } else { '' }
        }
        # ServerPort is an AliasProperty on Port, not a second copy of the value - see the
        # matching comment in Get-SfosActiveDirectoryServer for why this is required.
        $obj | Add-Member -MemberType AliasProperty -Name ServerPort -Value Port
        $results += $obj
    }

    return $results
}

<#
        .SYNOPSIS
        Creates a TACACS+ authentication server on a Sophos Firewall.

        .DESCRIPTION
        Adds a TACACS+ server as an authentication source. Use this cmdlet to make an existing
        TACACS+ service reachable for firewall, VPN or admin logins. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to create authentication servers.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ServerAddress
        Required. IP address of the TACACS+ server.

        .PARAMETER ServerPort
        Required. TCP port the server listens on, usually 49.

        .PARAMETER SharedSecret
        Required. Shared secret used to encrypt traffic between the firewall and the server, as
        a SecureString.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Shared-Secr3t!9' -AsPlainText -Force
        New-SfosTACACSServer -ServerName 'CorpTacacs' -ServerAddress '203.0.113.20' -ServerPort 49 -SharedSecret $secret -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Shared-Secr3t!9' -AsPlainText -Force
        New-SfosTACACSServer -ServerName 'CorpTacacs' -ServerAddress '203.0.113.20' -ServerPort 49 -SharedSecret $secret

        Creates a TACACS+ server.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosTACACSServer
#>
function New-SfosTACACSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [string]$ServerAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(Mandatory)]
        [SecureString]$SharedSecret,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $ServerAddress

    $sharedSecretBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
    try {
        $sharedSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($sharedSecretBstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($sharedSecretBstr)
    }
    $sharedSecretEsc = ConvertTo-SfosXmlEscaped -Text $sharedSecretPlain

    $inner = @"
<Set operation="add">
  <AuthenticationServer>
    <TACACSServer>
      <ServerName>$serverNameEsc</ServerName>
      <ServerAddress>$serverAddressEsc</ServerAddress>
      <Port>$ServerPort</Port>
      <SharedSecret>$sharedSecretEsc</SharedSecret>
    </TACACSServer>
  </AuthenticationServer>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("TACACSServer authentication server '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating TACACSServer authentication server '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # <Set operation="add"> answers at /Response/TACACSServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TACACSServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates a TACACS+ authentication server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing TACACS+ server. The cmdlet reads the current server first and
        writes back a complete object: every field you pass replaces the current value, every
        field you omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        authentication servers.

        If you omit -SharedSecret, the cmdlet resends the stored secret so it stays unchanged.
        If no stored secret can be read back, the cmdlet throws and asks for -SharedSecret
        explicitly.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ServerAddress
        Optional. IP address of the server. If omitted, the current value is kept.

        .PARAMETER ServerPort
        Optional. TCP port the server listens on. If omitted, the current value is kept.

        .PARAMETER SharedSecret
        Optional. Shared secret, as a SecureString. If omitted, the current secret is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosTACACSServer, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosTACACSServer -ServerName 'CorpTacacs' -ServerAddress '203.0.113.21' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosTACACSServer -ServerName 'CorpTacacs' -ServerAddress '203.0.113.21'

        Updates the address; the shared secret and every other field keep their current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosTACACSServer
#>
function Set-SfosTACACSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ServerAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [SecureString]$SharedSecret,

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
        $existing = @(Get-SfosTACACSServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The TACACSServer authentication server '$ServerName' was not found."
        }

        $targetServerAddress = if ($PSBoundParameters.ContainsKey('ServerAddress')) { $ServerAddress } else { [string]$existing[0].ServerAddress }
        $targetServerPort = if ($PSBoundParameters.ContainsKey('ServerPort')) { $ServerPort } else { [int]$existing[0].Port }

        # An empty <SharedSecret> is rejected outright for this entity (code 501),
        # unlike Password on ActiveDirectory/LDAPServer/EDirectory. So when the caller does not
        # supply -SharedSecret, resend the hashed value Get-SfosTACACSServer read back, with its
        # hashform attribute - the firewall accepts that as "unchanged" (confirmed live).
        $sharedSecretXml = ''
        if ($PSBoundParameters.ContainsKey('SharedSecret')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
            try {
                $sharedSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
            $sharedSecretXml = "<SharedSecret>$(ConvertTo-SfosXmlEscaped -Text $sharedSecretPlain)</SharedSecret>"
        }
        elseif ($existing[0].SharedSecretHash) {
            $hashEsc = ConvertTo-SfosXmlEscaped -Text $existing[0].SharedSecretHash
            $hashFormEsc = ConvertTo-SfosXmlEscaped -Text $existing[0].SharedSecretHashForm
            $sharedSecretXml = "<SharedSecret hashform=`"$hashFormEsc`">$hashEsc</SharedSecret>"
        }
        else {
            throw "Set-SfosTACACSServer cannot preserve the shared secret of '$ServerName': Get-SfosTACACSServer returned no existing hash to resend. Pass -SharedSecret explicitly."
        }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $serverAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetServerAddress

        $inner = @"
<Set operation="update">
  <AuthenticationServer>
    <TACACSServer>
      <ServerName>$serverNameEsc</ServerName>
      <ServerAddress>$serverAddressEsc</ServerAddress>
      <Port>$targetServerPort</Port>
      $sharedSecretXml
    </TACACSServer>
  </AuthenticationServer>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("TACACSServer authentication server '$ServerName' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating TACACSServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # <Set operation="update"> answers at /Response/TACACSServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TACACSServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a TACACS+ authentication server from a Sophos Firewall.

        .DESCRIPTION
        Deletes a TACACS+ server object. Use this cmdlet to remove a server that is no longer
        used as an authentication source. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosTACACSServer -ServerName 'CorpTacacs' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosTACACSServer -ServerName 'CorpTacacs'

        Removes the server named 'CorpTacacs'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosTACACSServer
#>
function Remove-SfosTACACSServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("TACACSServer authentication server '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AuthenticationServer>
    <TACACSServer>
      <ServerName>$nameEsc</ServerName>
    </TACACSServer>
  </AuthenticationServer>
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
            throw "Error removing TACACSServer authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/TACACSServer' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion TACACSServer

#region EDirectory

<#
        .SYNOPSIS
        Retrieves eDirectory authentication server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the eDirectory servers configured as authentication sources on the firewall.
        Use this cmdlet to review the existing servers, or to feed them into
        Set-SfosEDirectoryServer through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ServerIpDomain, Port, EdirUsername, BaseDN,
        ConnectionSecurity, ValidateServerCertificate, ClientCertificate,
        DisplayNameAttribute and EmailAddressAttribute. The Port value is also available under
        the property name ServerPort, so the object binds directly to
        Set-SfosEDirectoryServer. Returns System.Xml.XmlElement when -AsXml is used, and an
        empty array when no server matches. The stored bind password is never included; the
        firewall does not return it.

        .EXAMPLE
        Get-SfosEDirectoryServer

        Lists every eDirectory server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosEDirectoryServer -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosEDirectoryServer

        .LINK
        Set-SfosEDirectoryServer
#>
function Get-SfosEDirectoryServer {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AuthenticationServer><EDirectory></EDirectory></AuthenticationServer></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving EDirectory authentication server objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/EDirectory' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AuthenticationServer/EDirectory[ServerName]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        $obj = [PSCustomObject]@{
            ServerName                = $node.ServerName
            ServerIpDomain            = $node.ServerIpDomain
            Port                      = $node.Port
            EdirUsername              = $node.Username
            BaseDN                    = $node.BaseDN
            ConnectionSecurity        = $node.ConnectionSecurity
            ValidateServerCertificate = $node.ValidateServerCertificate
            ClientCertificate         = $node.ClientCertificate
            DisplayNameAttribute      = $node.DisplayNameAttribute
            EmailAddressAttribute     = $node.EmailAddressAttribute
        }
        # ServerPort is an AliasProperty on Port, not a second copy of the value - see the
        # matching comment in Get-SfosActiveDirectoryServer for why this is required.
        $obj | Add-Member -MemberType AliasProperty -Name ServerPort -Value Port
        $results += $obj
    }

    return $results
}

<#
        .SYNOPSIS
        Creates an eDirectory authentication server on a Sophos Firewall.

        .DESCRIPTION
        Adds an eDirectory server as an authentication source. Use this cmdlet to make an
        existing directory reachable for firewall, VPN or admin logins. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to create authentication servers.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ServerIpDomain
        Required. IP address or domain name of the eDirectory server.

        .PARAMETER ServerPort
        Required. TCP port the server listens on, usually 389.

        .PARAMETER EdirUsername
        Required. User name of the account the firewall uses to bind to the directory.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, no password is
        sent.

        .PARAMETER BaseDN
        Optional. Base distinguished name of the directory. If omitted, none is set.

        .PARAMETER ConnectionSecurity
        Required. Security used when sending the user name and password to the server. Valid
        values: Simple, SSL, TLS.

        .PARAMETER ValidateServerCertificate
        Optional. Whether the server certificate is validated. Valid values: Enable, Disable.
        If omitted, the firewall default (Enable) applies.

        .PARAMETER ClientCertificate
        Optional. Client certificate used for the secured connection. If omitted, none is set.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. If omitted, the
        firewall default ('fullName') applies.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. If omitted, the
        firewall default ('mail') applies.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        $bindPw = ConvertTo-SecureString 'Zz-Str0ng-Bind-Pw!9' -AsPlainText -Force
        New-SfosEDirectoryServer -ServerName 'CorpEdir' -ServerIpDomain 'edir.example.com' -ServerPort 389 -EdirUsername 'svc-sfos' -BindPassword $bindPw -ConnectionSecurity Simple -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $bindPw = ConvertTo-SecureString 'Zz-Str0ng-Bind-Pw!9' -AsPlainText -Force
        New-SfosEDirectoryServer -ServerName 'CorpEdir' -ServerIpDomain 'edir.example.com' -ServerPort 389 -EdirUsername 'svc-sfos' -BindPassword $bindPw -ConnectionSecurity Simple

        Creates an eDirectory server.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosEDirectoryServer
#>
function New-SfosEDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [string]$ServerIpDomain,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(Mandatory)]
        [string]$EdirUsername,

        [SecureString]$BindPassword,
        [string]$BaseDN,

        [Parameter(Mandatory)]
        [ValidateSet('Simple', 'SSL', 'TLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidateServerCertificate,

        [string]$ClientCertificate,
        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $serverIpDomainEsc = ConvertTo-SfosXmlEscaped -Text $ServerIpDomain
    $edirUserEsc = ConvertTo-SfosXmlEscaped -Text $EdirUsername

    $bindPasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
        try {
            $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }
    $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain

    $fieldsXml = "<ServerName>$serverNameEsc</ServerName><ServerIpDomain>$serverIpDomainEsc</ServerIpDomain><Port>$ServerPort</Port><Username>$edirUserEsc</Username>"
    if ($PSBoundParameters.ContainsKey('BindPassword')) {
        $fieldsXml += "<Password>$bindPasswordEsc</Password>"
    }
    if ($PSBoundParameters.ContainsKey('BaseDN')) {
        $fieldsXml += "<BaseDN>$(ConvertTo-SfosXmlEscaped -Text $BaseDN)</BaseDN>"
    }
    $fieldsXml += "<ConnectionSecurity>$ConnectionSecurity</ConnectionSecurity>"
    if ($PSBoundParameters.ContainsKey('ValidateServerCertificate')) {
        $fieldsXml += "<ValidateServerCertificate>$ValidateServerCertificate</ValidateServerCertificate>"
    }
    if ($PSBoundParameters.ContainsKey('ClientCertificate')) {
        $fieldsXml += "<ClientCertificate>$(ConvertTo-SfosXmlEscaped -Text $ClientCertificate)</ClientCertificate>"
    }
    if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) {
        $fieldsXml += "<DisplayNameAttribute>$(ConvertTo-SfosXmlEscaped -Text $DisplayNameAttribute)</DisplayNameAttribute>"
    }
    if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) {
        $fieldsXml += "<EmailAddressAttribute>$(ConvertTo-SfosXmlEscaped -Text $EmailAddressAttribute)</EmailAddressAttribute>"
    }

    $inner = @"
<Set operation="add">
  <AuthenticationServer>
    <EDirectory>
      $fieldsXml
    </EDirectory>
  </AuthenticationServer>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("EDirectory authentication server '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating EDirectory authentication server '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # <Set operation="add"> answers at /Response/EDirectory/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EDirectory' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an eDirectory authentication server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing eDirectory server. The cmdlet reads the current server first and
        writes back a complete object: every field you pass replaces the current value, every
        field you omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        authentication servers.

        If you omit -BindPassword, the firewall keeps the stored password unchanged; passing
        -BindPassword replaces it.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ServerIpDomain
        Optional. IP address or domain name of the server. If omitted, the current value is
        kept.

        .PARAMETER ServerPort
        Optional. TCP port the server listens on. If omitted, the current value is kept.

        .PARAMETER EdirUsername
        Optional. User name of the bind account. If omitted, the current value is kept.

        .PARAMETER BindPassword
        Optional. Password of the bind account, as a SecureString. If omitted, the current
        password is kept.

        .PARAMETER BaseDN
        Optional. Base distinguished name of the directory. If omitted, the current value is
        kept.

        .PARAMETER ConnectionSecurity
        Optional. Security used when sending the user name and password to the server. Valid
        values: Simple, SSL, TLS. If omitted, the current value is kept.

        .PARAMETER ValidateServerCertificate
        Optional. Whether the server certificate is validated. Valid values: Enable, Disable.
        If omitted, the current value is kept.

        .PARAMETER ClientCertificate
        Optional. Client certificate used for the secured connection. If omitted, the current
        value is kept.

        .PARAMETER DisplayNameAttribute
        Optional. Directory attribute shown to the user as the display name. If omitted, the
        current value is kept.

        .PARAMETER EmailAddressAttribute
        Optional. Directory attribute shown to the user as the email address. If omitted, the
        current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosEDirectoryServer, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosEDirectoryServer -ServerName 'CorpEdir' -BaseDN 'o=corp' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosEDirectoryServer -ServerName 'CorpEdir' -BaseDN 'o=corp'

        Updates the base DN; every other field, including the bind password, keeps its current
        value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosEDirectoryServer
#>
function Set-SfosEDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ServerIpDomain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ServerPort,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$EdirUsername,

        [SecureString]$BindPassword,
        [string]$BaseDN,

        [ValidateSet('Simple', 'SSL', 'TLS')]
        [string]$ConnectionSecurity,

        [ValidateSet('Enable', 'Disable')]
        [string]$ValidateServerCertificate,

        [string]$ClientCertificate,
        [string]$DisplayNameAttribute,
        [string]$EmailAddressAttribute,

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
        $existing = @(Get-SfosEDirectoryServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The EDirectory authentication server '$ServerName' was not found."
        }

        $targetServerIpDomain = if ($PSBoundParameters.ContainsKey('ServerIpDomain')) { $ServerIpDomain } else { [string]$existing[0].ServerIpDomain }
        $targetServerPort = if ($PSBoundParameters.ContainsKey('ServerPort')) { $ServerPort } else { [int]$existing[0].Port }
        $targetEdirUsername = if ($PSBoundParameters.ContainsKey('EdirUsername')) { $EdirUsername } else { [string]$existing[0].EdirUsername }
        $targetBaseDN = if ($PSBoundParameters.ContainsKey('BaseDN')) { $BaseDN } else { [string]$existing[0].BaseDN }
        $targetConnectionSecurity = if ($PSBoundParameters.ContainsKey('ConnectionSecurity')) { $ConnectionSecurity } else { [string]$existing[0].ConnectionSecurity }
        $targetValidateServerCertificate = if ($PSBoundParameters.ContainsKey('ValidateServerCertificate')) { $ValidateServerCertificate } else { [string]$existing[0].ValidateServerCertificate }
        $targetClientCertificate = if ($PSBoundParameters.ContainsKey('ClientCertificate')) { $ClientCertificate } else { [string]$existing[0].ClientCertificate }
        $targetDisplayNameAttribute = if ($PSBoundParameters.ContainsKey('DisplayNameAttribute')) { $DisplayNameAttribute } else { [string]$existing[0].DisplayNameAttribute }
        $targetEmailAddressAttribute = if ($PSBoundParameters.ContainsKey('EmailAddressAttribute')) { $EmailAddressAttribute } else { [string]$existing[0].EmailAddressAttribute }

        # An empty <Password> on update is accepted and preserves the existing bind
        # password (see the .DESCRIPTION) - so no warning is needed when -BindPassword is
        # omitted, unlike the RADIUS/TACACS SharedSecret case where an empty value is rejected.
        $bindPasswordPlain = ''
        if ($PSBoundParameters.ContainsKey('BindPassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BindPassword)
            try {
                $bindPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $serverIpDomainEsc = ConvertTo-SfosXmlEscaped -Text $targetServerIpDomain
        $edirUserEsc = ConvertTo-SfosXmlEscaped -Text $targetEdirUsername
        $bindPasswordEsc = ConvertTo-SfosXmlEscaped -Text $bindPasswordPlain
        $baseDnEsc = ConvertTo-SfosXmlEscaped -Text $targetBaseDN
        $clientCertEsc = ConvertTo-SfosXmlEscaped -Text $targetClientCertificate
        $displayNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDisplayNameAttribute
        $emailAttrEsc = ConvertTo-SfosXmlEscaped -Text $targetEmailAddressAttribute

        $inner = @"
<Set operation="update">
  <AuthenticationServer>
    <EDirectory>
      <ServerName>$serverNameEsc</ServerName>
      <ServerIpDomain>$serverIpDomainEsc</ServerIpDomain>
      <Port>$targetServerPort</Port>
      <Username>$edirUserEsc</Username>
      <Password>$bindPasswordEsc</Password>
      <BaseDN>$baseDnEsc</BaseDN>
      <ConnectionSecurity>$targetConnectionSecurity</ConnectionSecurity>
      <ValidateServerCertificate>$targetValidateServerCertificate</ValidateServerCertificate>
      <ClientCertificate>$clientCertEsc</ClientCertificate>
      <DisplayNameAttribute>$displayNameEsc</DisplayNameAttribute>
      <EmailAddressAttribute>$emailAttrEsc</EmailAddressAttribute>
    </EDirectory>
  </AuthenticationServer>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("EDirectory authentication server '$ServerName' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating EDirectory authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # <Set operation="update"> answers at /Response/EDirectory/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EDirectory' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an eDirectory authentication server from a Sophos Firewall.

        .DESCRIPTION
        Deletes an eDirectory server object. Use this cmdlet to remove a directory that is no
        longer used as an authentication source. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosEDirectoryServer -ServerName 'CorpEdir' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosEDirectoryServer -ServerName 'CorpEdir'

        Removes the server named 'CorpEdir'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosEDirectoryServer
#>
function Remove-SfosEDirectoryServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("EDirectory authentication server '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AuthenticationServer>
    <EDirectory>
      <ServerName>$nameEsc</ServerName>
    </EDirectory>
  </AuthenticationServer>
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
            throw "Error removing EDirectory authentication server '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationServer/EDirectory' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion EDirectory

#endregion AuthenticationServer

#region User

<#
        .SYNOPSIS
        Retrieves user accounts from a Sophos Firewall.

        .DESCRIPTION
        Returns the local user accounts (administrator and standard user) defined on the
        firewall. Use this cmdlet to review the existing accounts, or to feed them into
        Set-SfosUser or Remove-SfosUser through the pipeline. The cmdlet only reads; nothing
        on the firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        You can combine both filters. -UsernameLike is also sent to the firewall as a
        pre-filter; -NameLike is always evaluated on the client. The result matches both
        filters you gave.

        .PARAMETER UsernameLike
        Optional. Returns only accounts whose user name contains the given text anywhere. This
        is a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the user name is not used to filter.

        .PARAMETER NameLike
        Optional. Returns only accounts whose display name contains the given text anywhere.
        Applied on the client. If omitted, the display name is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for user
        objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per user, with the properties
        Username, AccountName (a duplicate of Username, so the object binds to New-/Set-/
        Remove-SfosUser's -AccountName parameter), Name, PasswordHash, Description, UserType,
        Profile, EmailList, Group, SurfingQuotaPolicy, AccessTimePolicy, DataTransferPolicy,
        QoSPolicy, SSLVPNPolicy, SSLVPNIPv4Address, SSLVPNIPv6Address, ClientlessPolicy,
        Status, L2TP, PPTP, CISCO, QuarantineDigest, MACBinding, LoginRestriction,
        ScheduleForApplianceAccess, LoginRestrictionForAppliance, IsEncryptCert and
        SimultaneousLoginsGlobal. Returns System.Xml.XmlElement when -AsXml is used, and an
        empty array when no account matches. The clear-text password is never included; the
        firewall does not return it, only PasswordHash.

        .EXAMPLE
        Get-SfosUser

        Lists every user account on the firewall of the current connection.

        .EXAMPLE
        Get-SfosUser -UsernameLike 'jdoe'

        Lists all accounts whose user name contains 'jdoe'.

        .EXAMPLE
        Get-SfosUser -UsernameLike 'jdoe' -AsXml

        Returns the raw XML of the matching account, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosUser

        .LINK
        Set-SfosUser
#>
function Get-SfosUser {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$UsernameLike,
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

    # Server-side pre-filter: SFOS evaluates only the first <key> of the first <Filter>. The
    # entity key is Username, not Name, so that is the field sent server-side; NameLike is
    # always applied client-side below.
    #
    # The firewall lowercases Username on storage regardless
    # of the case supplied at creation ("ZZTest-user1" is stored and returned as
    # "zztest-user1"), but the server-side "like" filter on Username is case-SENSITIVE - a
    # filter value of "ZZTest-user1" matches nothing even though "zztest-user1" exists.
    # Lowercasing the value sent server-side avoids a false empty result; the client-side
    # -like match below stays case-insensitive as usual, so callers can pass any casing.
    $filterXml = ''
    if ($UsernameLike) {
        $usernameLikeEsc = ConvertTo-SfosXmlEscaped -Text $UsernameLike.ToLowerInvariant()
        $filterXml = ('<Filter><key name="Username" criteria="like">{0}</key></Filter>' -f $usernameLikeEsc)
    }

    $inner = @"
<Get>
  <User>
    $filterXml
  </User>
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
        throw "Error retrieving User objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A code-less status of exactly "No. of records Zero." is an empty result, not an error.
    # Anything else without a code is treated as an error by Assert-SfosApiReturnSuccess.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'User' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/User[Username]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND.
    if ($UsernameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Username -like "*$UsernameLike*" })
    }
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $userObjects = @()
    foreach ($node in $nodes) {
        $userObjects += [PSCustomObject]@{
            Username                     = $node.Username
            # Duplicate of Username under a second name: New-/Set-/Remove-SfosUser cannot
            # name their identifying parameter -Username, because that name is already the
            # fixed connection parameter (Section 4) and PowerShell rejects two parameters of
            # the same name on one command. AccountName exists purely so
            # "Get-SfosUser | Set-SfosUser" / "| Remove-SfosUser" still bind by pipeline
            # property name.
            AccountName                  = $node.Username
            Name                         = $node.Name
            PasswordHash                 = $node.PasswordHash
            Description                  = $node.Description
            UserType                     = $node.UserType
            Profile                      = $node.Profile
            EmailList                    = [string[]]@($node.EmailList | Select-Object -ExpandProperty EmailID -ErrorAction SilentlyContinue)
            Group                        = $node.Group
            SurfingQuotaPolicy           = $node.SurfingQuotaPolicy
            AccessTimePolicy             = $node.AccessTimePolicy
            DataTransferPolicy           = $node.DataTransferPolicy
            QoSPolicy                    = $node.QoSPolicy
            SSLVPNPolicy                 = $node.SSLVPNPolicy
            SSLVPNIPv4Address            = $node.SSLVPNIPv4Address
            SSLVPNIPv6Address            = $node.SSLVPNIPv6Address
            ClientlessPolicy             = $node.ClientlessPolicy
            Status                       = $node.Status
            L2TP                         = $node.L2TP
            PPTP                         = $node.PPTP
            CISCO                        = $node.CISCO
            QuarantineDigest             = $node.QuarantineDigest
            MACBinding                   = $node.MACBinding
            LoginRestriction             = $node.LoginRestriction
            ScheduleForApplianceAccess   = $node.ScheduleForApplianceAccess
            LoginRestrictionForAppliance = $node.LoginRestrictionForAppliance
            IsEncryptCert                = $node.IsEncryptCert
            SimultaneousLoginsGlobal     = $node.SimultaneousLoginsGlobal
        }
    }

    return $userObjects
}

<#
        .SYNOPSIS
        Creates a user account on a Sophos Firewall.

        .DESCRIPTION
        Adds a local user or administrator account. Use this cmdlet to create the account
        before assigning it to a group or granting it VPN or admin access. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to create users.

        The account password is checked by the firewall against an undocumented complexity
        rule. A common or dictionary-style password is rejected; choose a long, non-obvious
        one.

        .PARAMETER AccountName
        Required. User name that identifies the account. 1 to 50 characters, must not contain
        a comma.

        .PARAMETER Name
        Required. Display name of the user. 1 to 50 characters, must not contain a comma.

        .PARAMETER UserType
        Optional. Account type. Valid values: Administrator, User. If omitted, the firewall
        default (User) applies.

        .PARAMETER ProfileName
        Optional. Administrator profile. Required when -UserType is Administrator. If
        omitted, none is set.

        .PARAMETER AccountPassword
        Required. Password for the account, as a SecureString.

        .PARAMETER AccountPasswordHash
        Optional. Pre-hashed password, as an alternative to -AccountPassword. If omitted, none
        is sent.

        .PARAMETER Description
        Optional. Free-text description. If omitted, none is set.

        .PARAMETER EmailList
        Optional. One or more email addresses for the user. If omitted, none is set.

        .PARAMETER Group
        Optional. Name of the user group to add the account to. If omitted, none is set.

        .PARAMETER SurfingQuotaPolicy
        Optional. Name of the surfing quota policy. If omitted, the value is inherited from
        the group.

        .PARAMETER AccessTimePolicy
        Optional. Name of the access time policy. If omitted, the value is inherited from the
        group.

        .PARAMETER DataTransferPolicy
        Optional. Name of the data transfer policy. If omitted, the value is inherited from
        the group.

        .PARAMETER QoSPolicy
        Optional. Name of the QoS (bandwidth) policy. If omitted, the value is inherited from
        the group.

        .PARAMETER SSLVPNPolicy
        Optional. Name of the SSL VPN policy. If omitted, none is set.

        .PARAMETER SSLVPNIPv4Address
        Optional. Reserved static IPv4 address for SSL VPN, from the SSL VPN global settings
        range. If omitted, none is set.

        .PARAMETER SSLVPNIPv6Address
        Optional. Reserved static IPv6 address for SSL VPN, from the SSL VPN global settings
        range. If omitted, none is set.

        .PARAMETER ClientlessPolicy
        Optional. Name of the clientless access policy. If omitted, none is set.

        .PARAMETER L2TP
        Optional. Whether L2TP access is allowed. Valid values: Enable, Disable. If omitted,
        the firewall default applies.

        .PARAMETER PPTP
        Optional. Whether PPTP access is allowed. Valid values: Enable, Disable. If omitted,
        the firewall default applies.

        .PARAMETER CISCO
        Optional. Whether CISCO (IPsec) access is allowed. Valid values: Enable, Disable. If
        omitted, the firewall default applies.

        .PARAMETER QuarantineDigest
        Optional. Whether the daily quarantine digest email is sent. Valid values: Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER MACBinding
        Optional. Whether the user is bound to a set of MAC addresses. Valid values: Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER IsEncryptCert
        Optional. Whether per-user certificate encryption is used. Valid values: Enable,
        Disable. Applies only when PerUserCertificate is enabled in the SSL/TLS tunnel access
        settings. If omitted, the firewall default applies.

        .PARAMETER SimultaneousLoginsGlobal
        Optional. Whether simultaneous logins are allowed. Valid values: Enable, Disable. If
        omitted, the firewall default applies.

        .PARAMETER LoginRestriction
        Required. Which network nodes the account may log in from. Valid values: AnyNode,
        UserGroupNode.

        .PARAMETER ScheduleForApplianceAccess
        Optional. Name of the schedule for appliance (web admin) access. Applies to
        administrator accounts only. If omitted, none is set.

        .PARAMETER LoginRestrictionForAppliance
        Optional. Which network nodes may use appliance (web admin) access. Valid value:
        AnyNode. If omitted, none is set.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create user
        objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        $securePw = ConvertTo-SecureString 'Zz-Str0ng-Passw0rd!9' -AsPlainText -Force
        New-SfosUser -AccountName 'jdoe' -Name 'Jane Doe' -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group 'Open Group' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $securePw = ConvertTo-SecureString 'Zz-Str0ng-Passw0rd!9' -AsPlainText -Force
        New-SfosUser -AccountName 'jdoe' -Name 'Jane Doe' -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group 'Open Group'

        Creates a standard user and adds it to the 'Open Group' user group.

        .EXAMPLE
        $securePw = ConvertTo-SecureString 'Zz-Str0ng-Passw0rd!9' -AsPlainText -Force
        New-SfosUser -AccountName 'admin2' -Name 'Second Admin' -UserType Administrator -ProfileName 'Administrator' -AccountPassword $securePw -LoginRestriction AnyNode

        Creates an administrator account.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUser
#>
function New-SfosUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Named AccountName, not Username: the connection parameter -Username below already
        # owns that name (Section 4, fixed) and PowerShell rejects duplicate parameter names
        # in one command. The wire element is still <Username>.
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Administrator', 'User')]
        [string]$UserType,

        # Named ProfileName, not Profile: $Profile is an automatic PowerShell variable and
        # a parameter of that name would shadow it inside the function. The wire element
        # stays <Profile>; the alias keeps the Sophos spelling available to callers.
        [Alias('Profile')]
        [string]$ProfileName,

        # Named AccountPassword/AccountPasswordHash, not Password/PasswordHash: the connection
        # parameter -Password below already owns that name (Section 4, fixed). The wire
        # elements sent to the firewall are still <Password> and <PasswordHash>.
        #
        # Mandatory despite the doc table marking Password "No": omitting both Password and
        # PasswordHash on Add User answers 510 "PasswdComplexityMisMatch" every time, even with
        # a valid LoginRestriction present -
        # a blank password evidently fails the complexity check by definition.
        [Parameter(Mandatory)]
        [SecureString]$AccountPassword,
        [SecureString]$AccountPasswordHash,

        [string]$Description,
        [string[]]$EmailList,
        [string]$Group,
        [string]$SurfingQuotaPolicy,
        [string]$AccessTimePolicy,
        [string]$DataTransferPolicy,
        [string]$QoSPolicy,
        [string]$SSLVPNPolicy,
        [string]$SSLVPNIPv4Address,
        [string]$SSLVPNIPv6Address,
        [string]$ClientlessPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$L2TP,

        [ValidateSet('Enable', 'Disable')]
        [string]$PPTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$CISCO,

        [ValidateSet('Enable', 'Disable')]
        [string]$QuarantineDigest,

        [ValidateSet('Enable', 'Disable')]
        [string]$MACBinding,

        [ValidateSet('Enable', 'Disable')]
        [string]$IsEncryptCert,

        [ValidateSet('Enable', 'Disable')]
        [string]$SimultaneousLoginsGlobal,

        # Mandatory despite not even appearing in the doc's Add User attribute table at all
        # (LoginRestrictionForAppliance is listed there, LoginRestriction is not). Password +
        # Group + LoginRestrictionForAppliance without LoginRestriction answers 500; adding
        # LoginRestriction alone (without LoginRestrictionForAppliance) succeeds.
        # LoginRestriction, not LoginRestrictionForAppliance, is the field the firewall
        # actually requires.
        [Parameter(Mandatory)]
        [ValidateSet('AnyNode', 'UserGroupNode')]
        [string]$LoginRestriction,

        [string]$ScheduleForApplianceAccess,

        [ValidateSet('AnyNode')]
        [string]$LoginRestrictionForAppliance,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($UserType -eq 'Administrator' -and -not $ProfileName) {
        throw "New-SfosUser: -ProfileName is required when -UserType is 'Administrator'."
    }

    $usernameEsc = ConvertTo-SfosXmlEscaped -Text $AccountName
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Password / PasswordHash are SecureString and must never be logged or round-tripped from
    # a Get-* response - the firewall never returns them in clear text. If neither is supplied
    # the element is left out of the request entirely.
    $passwordXml = ''
    $passwordBstr = [IntPtr]::Zero
    $passwordHashBstr = [IntPtr]::Zero
    try {
        if ($PSBoundParameters.ContainsKey('AccountPassword')) {
            $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccountPassword)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
            $passwordXml += "<Password>$(ConvertTo-SfosXmlEscaped -Text $plainPassword)</Password>"
        }
        if ($PSBoundParameters.ContainsKey('AccountPasswordHash')) {
            $passwordHashBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccountPasswordHash)
            $plainPasswordHash = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordHashBstr)
            $passwordXml += "<PasswordHash>$(ConvertTo-SfosXmlEscaped -Text $plainPasswordHash)</PasswordHash>"
        }

        $profileXml = ''
        if ($ProfileName) {
            $profileXml = "<Profile>$(ConvertTo-SfosXmlEscaped -Text $ProfileName)</Profile>"
        }

        $emailXml = ''
        foreach ($email in $EmailList) {
            if (-not $email) {
                continue
            }
            $emailXml += "<EmailID>$(ConvertTo-SfosXmlEscaped -Text $email)</EmailID>"
        }

        # Leaving QuarantineDigest empty or omitting it
        # entirely at create time makes the firewall store the literal value "0" - not
        # "Enable" or "Disable" as the doc's stated default ("Enable") implies, and not a
        # value the API accepts back on a later update (a subsequent Set with QuarantineDigest
        # "0" fails 501, InvalidParams pointing at QuarantineDigest). Every other Enable/
        # Disable field in this entity does default correctly to "Disable" when left empty;
        # this one measurably does not, so New-* always sends an explicit value for it.
        $quarantineDigestValue = if ($PSBoundParameters.ContainsKey('QuarantineDigest')) { $QuarantineDigest } else { 'Disable' }

        $inner = @"
<Set operation="add">
  <User>
    <Username>$usernameEsc</Username>
    <Name>$nameEsc</Name>
    $passwordXml
    <UserType>$(ConvertTo-SfosXmlEscaped -Text $UserType)</UserType>
    $profileXml
    <EmailList>
        $emailXml
    </EmailList>
    <Group>$(ConvertTo-SfosXmlEscaped -Text $Group)</Group>
    <Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>
    <SurfingQuotaPolicy>$(ConvertTo-SfosXmlEscaped -Text $SurfingQuotaPolicy)</SurfingQuotaPolicy>
    <AccessTimePolicy>$(ConvertTo-SfosXmlEscaped -Text $AccessTimePolicy)</AccessTimePolicy>
    <DataTransferPolicy>$(ConvertTo-SfosXmlEscaped -Text $DataTransferPolicy)</DataTransferPolicy>
    <QoSPolicy>$(ConvertTo-SfosXmlEscaped -Text $QoSPolicy)</QoSPolicy>
    <SSLVPNPolicy>$(ConvertTo-SfosXmlEscaped -Text $SSLVPNPolicy)</SSLVPNPolicy>
    <SSLVPNIPv4Address>$(ConvertTo-SfosXmlEscaped -Text $SSLVPNIPv4Address)</SSLVPNIPv4Address>
    <SSLVPNIPv6Address>$(ConvertTo-SfosXmlEscaped -Text $SSLVPNIPv6Address)</SSLVPNIPv6Address>
    <ClientlessPolicy>$(ConvertTo-SfosXmlEscaped -Text $ClientlessPolicy)</ClientlessPolicy>
    <L2TP>$(ConvertTo-SfosXmlEscaped -Text $L2TP)</L2TP>
    <PPTP>$(ConvertTo-SfosXmlEscaped -Text $PPTP)</PPTP>
    <IsEncryptCert>$(ConvertTo-SfosXmlEscaped -Text $IsEncryptCert)</IsEncryptCert>
    <CISCO>$(ConvertTo-SfosXmlEscaped -Text $CISCO)</CISCO>
    <QuarantineDigest>$(ConvertTo-SfosXmlEscaped -Text $quarantineDigestValue)</QuarantineDigest>
    <SimultaneousLoginsGlobal>$(ConvertTo-SfosXmlEscaped -Text $SimultaneousLoginsGlobal)</SimultaneousLoginsGlobal>
    <MACBinding>$(ConvertTo-SfosXmlEscaped -Text $MACBinding)</MACBinding>
    <LoginRestriction>$(ConvertTo-SfosXmlEscaped -Text $LoginRestriction)</LoginRestriction>
    <ScheduleForApplianceAccess>$(ConvertTo-SfosXmlEscaped -Text $ScheduleForApplianceAccess)</ScheduleForApplianceAccess>
    <LoginRestrictionForAppliance>$(ConvertTo-SfosXmlEscaped -Text $LoginRestrictionForAppliance)</LoginRestrictionForAppliance>
  </User>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("User '$AccountName' on $($params.Firewall)", 'Create')) {
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
            throw "Error creating User object '$AccountName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'User' -Action 'create' -Target $AccountName
    }
    finally {
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
        }
        if ($passwordHashBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordHashBstr)
        }
    }
}

<#
        .SYNOPSIS
        Updates a user account on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing user or administrator account. The cmdlet reads the current
        account first and writes back a complete object: every field you pass replaces the
        current value, every field you omit keeps it. To clear a field, pass it explicitly
        with an empty value. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        users.

        The firewall never returns the stored password or password hash, so this cmdlet
        cannot read either back. If you omit -AccountPassword and -AccountPasswordHash, the
        request is sent without a password element at all.

        .PARAMETER AccountName
        Required. User name of the account to update.

        .PARAMETER Name
        Optional. Display name of the user. If omitted, the current value is kept.

        .PARAMETER UserType
        Optional. Account type. Valid values: Administrator, User. If omitted, the current
        value is kept.

        .PARAMETER ProfileName
        Optional. Administrator profile. If omitted, the current value is kept.

        .PARAMETER AccountPassword
        Optional. New password, as a SecureString. If omitted, no password element is sent.

        .PARAMETER AccountPasswordHash
        Optional. New pre-hashed password, as an alternative to -AccountPassword. If omitted,
        no password hash element is sent.

        .PARAMETER Description
        Optional. Free-text description. If omitted, the current value is kept.

        .PARAMETER EmailList
        Optional. One or more email addresses for the user. Replaces the current list. If
        omitted, the current list is kept.

        .PARAMETER Group
        Optional. Name of the user group. If omitted, the current value is kept.

        .PARAMETER SurfingQuotaPolicy
        Optional. Name of the surfing quota policy. If omitted, the current value is kept.

        .PARAMETER AccessTimePolicy
        Optional. Name of the access time policy. If omitted, the current value is kept.

        .PARAMETER DataTransferPolicy
        Optional. Name of the data transfer policy. If omitted, the current value is kept.

        .PARAMETER QoSPolicy
        Optional. Name of the QoS (bandwidth) policy. If omitted, the current value is kept.

        .PARAMETER SSLVPNPolicy
        Optional. Name of the SSL VPN policy. If omitted, the current value is kept.

        .PARAMETER SSLVPNIPv4Address
        Optional. Reserved static IPv4 address for SSL VPN. If omitted, the current value is
        kept.

        .PARAMETER SSLVPNIPv6Address
        Optional. Reserved static IPv6 address for SSL VPN. If omitted, the current value is
        kept.

        .PARAMETER ClientlessPolicy
        Optional. Name of the clientless access policy. If omitted, the current value is kept.

        .PARAMETER L2TP
        Optional. Whether L2TP access is allowed. Valid values: Enable, Disable. If omitted,
        the current value is kept.

        .PARAMETER PPTP
        Optional. Whether PPTP access is allowed. Valid values: Enable, Disable. If omitted,
        the current value is kept.

        .PARAMETER CISCO
        Optional. Whether CISCO (IPsec) access is allowed. Valid values: Enable, Disable. If
        omitted, the current value is kept.

        .PARAMETER QuarantineDigest
        Optional. Whether the daily quarantine digest email is sent. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER MACBinding
        Optional. Whether the user is bound to a set of MAC addresses. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER IsEncryptCert
        Optional. Whether per-user certificate encryption is used. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER SimultaneousLoginsGlobal
        Optional. Whether simultaneous logins are allowed. Valid values: Enable, Disable. If
        omitted, the current value is kept.

        .PARAMETER LoginRestriction
        Optional. Which network nodes the account may log in from. Valid values: AnyNode,
        UserGroupNode. If omitted, the current value is kept.

        .PARAMETER ScheduleForApplianceAccess
        Optional. Name of the schedule for appliance (web admin) access. If omitted, the
        current value is kept.

        .PARAMETER LoginRestrictionForAppliance
        Optional. Which network nodes may use appliance (web admin) access. Valid value:
        AnyNode. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update user
        objects. If omitted, the value from the current connection is used.

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
        System.String. AccountName, and any of the other property names of the object returned
        by Get-SfosUser, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosUser -AccountName 'jdoe' -Description 'Updated via PowerShell' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosUser -AccountName 'jdoe' -Description 'Updated via PowerShell'

        Updates the description; every other field keeps its current value.

        .EXAMPLE
        Get-SfosUser -UsernameLike 'jdoe' | Set-SfosUser -SurfingQuotaPolicy 'Unlimited Internet Access'

        Reads the matching account and assigns a different surfing quota policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUser
#>
function Set-SfosUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Named AccountName, not Username: the connection parameter -Username below already
        # owns that name (Section 4, fixed) and PowerShell rejects duplicate parameter names
        # in one command. The wire element is still <Username>; Get-SfosUser exposes an
        # AccountName property alongside Username so Get-SfosUser | Set-SfosUser still binds.
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$AccountName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Administrator', 'User')]
        [string]$UserType,

        # Named ProfileName, not Profile: $Profile is an automatic PowerShell variable and
        # a parameter of that name would shadow it inside the function. The wire element
        # stays <Profile>; the alias keeps the Sophos spelling available to callers.
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Profile')]
        [string]$ProfileName,

        # Named AccountPassword/AccountPasswordHash, not Password/PasswordHash: the connection
        # parameter -Password below already owns that name (Section 4, fixed). The wire
        # elements sent to the firewall are still <Password> and <PasswordHash>.
        [SecureString]$AccountPassword,
        [SecureString]$AccountPasswordHash,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$EmailList,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Group,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SurfingQuotaPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AccessTimePolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DataTransferPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$QoSPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SSLVPNPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SSLVPNIPv4Address,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SSLVPNIPv6Address,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ClientlessPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$L2TP,

        [ValidateSet('Enable', 'Disable')]
        [string]$PPTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$CISCO,

        [ValidateSet('Enable', 'Disable')]
        [string]$QuarantineDigest,

        [ValidateSet('Enable', 'Disable')]
        [string]$MACBinding,

        [ValidateSet('Enable', 'Disable')]
        [string]$IsEncryptCert,

        [ValidateSet('Enable', 'Disable')]
        [string]$SimultaneousLoginsGlobal,

        [ValidateSet('AnyNode', 'UserGroupNode')]
        [string]$LoginRestriction,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ScheduleForApplianceAccess,

        [ValidateSet('AnyNode')]
        [string]$LoginRestrictionForAppliance,

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
        $usernameEsc = ConvertTo-SfosXmlEscaped -Text $AccountName

        $existing = @(Get-SfosUser -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -UsernameLike $AccountName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Username -eq $AccountName })

        if ($existing.Count -eq 0) {
            throw "The User object '$AccountName' was not found."
        }

        $targetName = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { [string]$existing[0].Name }
        $targetUserType = if ($PSBoundParameters.ContainsKey('UserType')) { $UserType } else { [string]$existing[0].UserType }
        $targetProfile = if ($PSBoundParameters.ContainsKey('ProfileName')) { $ProfileName } else { [string]$existing[0].Profile }
        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetEmailList = @(if ($PSBoundParameters.ContainsKey('EmailList')) { $EmailList } else { $existing[0].EmailList })
        $targetGroup = if ($PSBoundParameters.ContainsKey('Group')) { $Group } else { [string]$existing[0].Group }
        $targetSurfingQuotaPolicy = if ($PSBoundParameters.ContainsKey('SurfingQuotaPolicy')) { $SurfingQuotaPolicy } else { [string]$existing[0].SurfingQuotaPolicy }
        $targetAccessTimePolicy = if ($PSBoundParameters.ContainsKey('AccessTimePolicy')) { $AccessTimePolicy } else { [string]$existing[0].AccessTimePolicy }
        $targetDataTransferPolicy = if ($PSBoundParameters.ContainsKey('DataTransferPolicy')) { $DataTransferPolicy } else { [string]$existing[0].DataTransferPolicy }
        $targetQoSPolicy = if ($PSBoundParameters.ContainsKey('QoSPolicy')) { $QoSPolicy } else { [string]$existing[0].QoSPolicy }
        $targetSSLVPNPolicy = if ($PSBoundParameters.ContainsKey('SSLVPNPolicy')) { $SSLVPNPolicy } else { [string]$existing[0].SSLVPNPolicy }
        $targetSSLVPNIPv4Address = if ($PSBoundParameters.ContainsKey('SSLVPNIPv4Address')) { $SSLVPNIPv4Address } else { [string]$existing[0].SSLVPNIPv4Address }
        $targetSSLVPNIPv6Address = if ($PSBoundParameters.ContainsKey('SSLVPNIPv6Address')) { $SSLVPNIPv6Address } else { [string]$existing[0].SSLVPNIPv6Address }
        $targetClientlessPolicy = if ($PSBoundParameters.ContainsKey('ClientlessPolicy')) { $ClientlessPolicy } else { [string]$existing[0].ClientlessPolicy }
        $targetL2TP = if ($PSBoundParameters.ContainsKey('L2TP')) { $L2TP } else { [string]$existing[0].L2TP }
        $targetPPTP = if ($PSBoundParameters.ContainsKey('PPTP')) { $PPTP } else { [string]$existing[0].PPTP }
        $targetCISCO = if ($PSBoundParameters.ContainsKey('CISCO')) { $CISCO } else { [string]$existing[0].CISCO }

        # A User created without an explicit QuarantineDigest
        # carries the literal value "0" instead of "Enable"/"Disable" (see New-SfosUser
        # NOTES), and the API rejects "0" on update with 501. Normalising it here means a
        # plain Set-SfosUser on such an object (that does not itself touch QuarantineDigest)
        # heals the field instead of perpetuating a write that always fails.
        $targetQuarantineDigest = if ($PSBoundParameters.ContainsKey('QuarantineDigest')) {
            $QuarantineDigest
        }
        elseif ([string]$existing[0].QuarantineDigest -in @('Enable', 'Disable')) {
            [string]$existing[0].QuarantineDigest
        }
        else {
            'Disable'
        }
        $targetMACBinding = if ($PSBoundParameters.ContainsKey('MACBinding')) { $MACBinding } else { [string]$existing[0].MACBinding }
        $targetIsEncryptCert = if ($PSBoundParameters.ContainsKey('IsEncryptCert')) { $IsEncryptCert } else { [string]$existing[0].IsEncryptCert }
        $targetSimultaneousLoginsGlobal = if ($PSBoundParameters.ContainsKey('SimultaneousLoginsGlobal')) { $SimultaneousLoginsGlobal } else { [string]$existing[0].SimultaneousLoginsGlobal }
        $targetLoginRestriction = if ($PSBoundParameters.ContainsKey('LoginRestriction')) { $LoginRestriction } else { [string]$existing[0].LoginRestriction }
        $targetScheduleForApplianceAccess = if ($PSBoundParameters.ContainsKey('ScheduleForApplianceAccess')) { $ScheduleForApplianceAccess } else { [string]$existing[0].ScheduleForApplianceAccess }
        $targetLoginRestrictionForAppliance = if ($PSBoundParameters.ContainsKey('LoginRestrictionForAppliance')) { $LoginRestrictionForAppliance } else { [string]$existing[0].LoginRestrictionForAppliance }

        # Password / PasswordHash are never read back from Get-SfosUser (the firewall never
        # returns them). If not supplied here, the element is left out of the request.
        $passwordXml = ''
        $passwordBstr = [IntPtr]::Zero
        $passwordHashBstr = [IntPtr]::Zero
        try {
            if ($PSBoundParameters.ContainsKey('AccountPassword')) {
                $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccountPassword)
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
                $passwordXml += "<Password>$(ConvertTo-SfosXmlEscaped -Text $plainPassword)</Password>"
            }
            if ($PSBoundParameters.ContainsKey('AccountPasswordHash')) {
                $passwordHashBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccountPasswordHash)
                $plainPasswordHash = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordHashBstr)
                $passwordXml += "<PasswordHash>$(ConvertTo-SfosXmlEscaped -Text $plainPasswordHash)</PasswordHash>"
            }

            $profileXml = ''
            if ($targetProfile) {
                $profileXml = "<Profile>$(ConvertTo-SfosXmlEscaped -Text $targetProfile)</Profile>"
            }

            $emailXml = ''
            foreach ($email in $targetEmailList) {
                if (-not $email) {
                    continue
                }
                $emailXml += "<EmailID>$(ConvertTo-SfosXmlEscaped -Text $email)</EmailID>"
            }

            $inner = @"
<Set operation="update">
  <User>
    <Username>$usernameEsc</Username>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $targetName)</Name>
    $passwordXml
    <UserType>$(ConvertTo-SfosXmlEscaped -Text $targetUserType)</UserType>
    $profileXml
    <EmailList>
        $emailXml
    </EmailList>
    <Group>$(ConvertTo-SfosXmlEscaped -Text $targetGroup)</Group>
    <Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>
    <SurfingQuotaPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetSurfingQuotaPolicy)</SurfingQuotaPolicy>
    <AccessTimePolicy>$(ConvertTo-SfosXmlEscaped -Text $targetAccessTimePolicy)</AccessTimePolicy>
    <DataTransferPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetDataTransferPolicy)</DataTransferPolicy>
    <QoSPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetQoSPolicy)</QoSPolicy>
    <SSLVPNPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetSSLVPNPolicy)</SSLVPNPolicy>
    <SSLVPNIPv4Address>$(ConvertTo-SfosXmlEscaped -Text $targetSSLVPNIPv4Address)</SSLVPNIPv4Address>
    <SSLVPNIPv6Address>$(ConvertTo-SfosXmlEscaped -Text $targetSSLVPNIPv6Address)</SSLVPNIPv6Address>
    <ClientlessPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetClientlessPolicy)</ClientlessPolicy>
    <L2TP>$(ConvertTo-SfosXmlEscaped -Text $targetL2TP)</L2TP>
    <PPTP>$(ConvertTo-SfosXmlEscaped -Text $targetPPTP)</PPTP>
    <IsEncryptCert>$(ConvertTo-SfosXmlEscaped -Text $targetIsEncryptCert)</IsEncryptCert>
    <CISCO>$(ConvertTo-SfosXmlEscaped -Text $targetCISCO)</CISCO>
    <QuarantineDigest>$(ConvertTo-SfosXmlEscaped -Text $targetQuarantineDigest)</QuarantineDigest>
    <SimultaneousLoginsGlobal>$(ConvertTo-SfosXmlEscaped -Text $targetSimultaneousLoginsGlobal)</SimultaneousLoginsGlobal>
    <MACBinding>$(ConvertTo-SfosXmlEscaped -Text $targetMACBinding)</MACBinding>
    <LoginRestriction>$(ConvertTo-SfosXmlEscaped -Text $targetLoginRestriction)</LoginRestriction>
    <ScheduleForApplianceAccess>$(ConvertTo-SfosXmlEscaped -Text $targetScheduleForApplianceAccess)</ScheduleForApplianceAccess>
    <LoginRestrictionForAppliance>$(ConvertTo-SfosXmlEscaped -Text $targetLoginRestrictionForAppliance)</LoginRestrictionForAppliance>
  </User>
</Set>
"@

            if (-not $PSCmdlet.ShouldProcess("User '$AccountName' on $($params.Firewall)", 'Edit')) {
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
                throw "Error updating User object '$AccountName': $($_.Exception.Message)"
            }

            $XmlResponse = [xml]$response.Content
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'User' -Action 'edit' -Target $AccountName
        }
        finally {
            if ($passwordBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
            }
            if ($passwordHashBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordHashBstr)
            }
        }
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a user account from a Sophos Firewall.

        .DESCRIPTION
        Deletes a local user or administrator account. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete users.

        .PARAMETER AccountName
        Required. User name of the account to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete user
        objects. If omitted, the value from the current connection is used.

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
        System.String. AccountName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosUser -AccountName 'jdoe' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUser -AccountName 'jdoe'

        Removes the account named 'jdoe'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUser
#>
function Remove-SfosUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Named AccountName, not Username: the connection parameter -Username below already
        # owns that name (Section 4, fixed) and PowerShell rejects duplicate parameter names
        # in one command. The wire element is still <Username>; Get-SfosUser exposes an
        # AccountName property alongside Username so Get-SfosUser | Remove-SfosUser still binds.
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$AccountName,

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
        if (-not $PSCmdlet.ShouldProcess("User '$AccountName' on $($params.Firewall)", 'Remove')) {
            return
        }

        # Delete User matches <Name> case-sensitively against
        # the firewall's stored value, which is always lowercase regardless of the case used
        # at creation (see Get-SfosUser NOTES). Sending the caller's original casing here
        # answers <Status code="200"> - a false success - and removes nothing, reproduced live
        # with a mixed-case AccountName against an object that demonstrably existed.
        $usernameEsc = ConvertTo-SfosXmlEscaped -Text $AccountName.ToLowerInvariant()

        # The Delete User operation's own doc page states
        # the syntax as "<Name><username></Name>" despite the attribute table calling the
        # parameter "Username" - and the firewall genuinely only honours <Name> here. Sending
        # <Username> (matching every other User request) answers 500 "Operation could not be
        # performed on Entity" for an object that demonstrably exists.
        $inner = @"
<Remove>
  <User>
    <Name>$usernameEsc</Name>
  </User>
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
            throw "Error removing User object '$AccountName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'User' -Action 'remove' -Target $AccountName

        # Defensive read-back: UserGroup's Remove operation answers <Status code="200">
        # unconditionally, even for a group that never existed (see Remove-SfosUserGroup
        # NOTES). The same guard is applied here as a precaution, since the case-sensitivity
        # defect above can produce the same "200 and nothing changed" shape for User too.
        $stillThere = @(Get-SfosUser -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -UsernameLike $AccountName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Username -eq $AccountName })

        if ($stillThere.Count -gt 0) {
            throw "Remove-SfosUser: the firewall reported success but User '$AccountName' is still present."
        }
    }
    end {
    }
}

#endregion

#region UserGroup

<#
        .SYNOPSIS
        Retrieves user group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the user groups defined on the firewall. Use this cmdlet to review the
        existing groups, or to feed them into Set-SfosUserGroup through the pipeline. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        The firewall does not filter this entity server-side. -NameLike is always evaluated
        on the client, as a substring match. Group membership is derived by reading every user
        account and matching its group field, which costs one extra API call.

        .PARAMETER NameLike
        Optional. Returns only groups whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
        characters. If omitted, all groups are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for user
        group and user objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per group, with the properties
        Name, GroupType, After, SurfingQuotaPolicy, AccessTimePolicy, DataTransferPolicy,
        QoSPolicy, SSLVPNPolicy, ClientlessPolicy, QuarantineDigest, MACBinding, L2TP, PPTP,
        SophosConnectClient, LoginRestriction and UserList (the user names that currently
        belong to the group). Returns System.Xml.XmlElement when -AsXml is used, and an empty
        array when no group matches.

        .EXAMPLE
        Get-SfosUserGroup

        Lists every user group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosUserGroup -NameLike 'Guest'

        Lists all groups whose name contains 'Guest'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosUserGroup

        .LINK
        Set-SfosUserGroup
#>
function Get-SfosUserGroup {
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

    # No server-side filter is sent at all: any <Filter> on this entity answers a
    # successful but empty response, regardless of whether the value would match. See
    # .DESCRIPTION.
    $inner = @'
<Get>
  <UserGroup>
  </UserGroup>
</Get>
'@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving UserGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserGroup' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/UserGroup/GroupDetail[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Membership lives on the User object's own <Group> field, not on <GroupMembers> here -
    # see .NOTES. Fetch every user once and derive each group's UserList by matching
    # User.Group against this group's Name.
    $allUsers = @(Get-SfosUser -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck)

    $userGroupObjects = @()
    foreach ($node in $nodes) {
        $groupName = $node.Name
        $groupMembers = [string[]]@($allUsers | Where-Object -FilterScript { $_.Group -eq $groupName } | Select-Object -ExpandProperty Username)

        $userGroupObjects += [PSCustomObject]@{
            Name                = $node.Name
            GroupType           = $node.GroupType
            After               = $node.After.Name
            SurfingQuotaPolicy  = $node.SurfingQuotaPolicy
            AccessTimePolicy    = $node.AccessTimePolicy
            DataTransferPolicy  = $node.DataTransferPolicy
            QoSPolicy           = $node.QoSPolicy
            SSLVPNPolicy        = $node.SSLVPNPolicy
            ClientlessPolicy    = $node.ClientlessPolicy
            QuarantineDigest    = $node.QuarantineDigest
            MACBinding          = $node.MACBinding
            L2TP                = $node.L2TP
            PPTP                = $node.PPTP
            SophosConnectClient = $node.SophosConnectClient
            LoginRestriction    = $node.LoginRestriction
            UserList            = $groupMembers
        }
    }

    return $userGroupObjects
}

<#
        .SYNOPSIS
        Creates a user group on a Sophos Firewall.

        .DESCRIPTION
        Adds a user group. Use this cmdlet to define a set of policies that can then be
        applied to many user accounts at once. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to create user groups.

        .PARAMETER Name
        Required. Name of the group. 1 to 256 characters, must not contain a comma.

        .PARAMETER GroupType
        Required. Group type. Valid values: Normal, Clienless (this is the spelling the
        firewall uses).

        .PARAMETER After
        Optional. Name of the group after which the new group is positioned in the group list.
        If omitted, the firewall places it at its own default position.

        .PARAMETER QoSPolicy
        Required. Name of the QoS (bandwidth) policy.

        .PARAMETER SurfingQuotaPolicy
        Required. Name of the surfing quota policy. Applies to groups of type Normal.

        .PARAMETER AccessTimePolicy
        Required. Name of the access time policy. Applies to groups of type Normal.

        .PARAMETER DataTransferPolicy
        Optional. Name of the data transfer policy. Applies to groups of type Normal. If
        omitted, none is set.

        .PARAMETER SSLVPNPolicy
        Optional. Name of the SSL VPN policy. Applies to groups of type Normal. If omitted,
        none is set.

        .PARAMETER ClientlessPolicy
        Optional. Name of the clientless access policy. Applies to groups of type Normal. If
        omitted, none is set.

        .PARAMETER QuarantineDigest
        Optional. Whether the daily quarantine digest email is sent to group members. Valid
        values: Enable, Disable. If omitted, the firewall default applies.

        .PARAMETER MACBinding
        Optional. Whether group members are bound to a set of MAC addresses. Valid values:
        Enable, Disable. If omitted, the firewall default applies.

        .PARAMETER L2TP
        Optional. Whether L2TP access is allowed for group members. Valid values: Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER PPTP
        Optional. Whether PPTP access is allowed for group members. Valid values: Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER SophosConnectClient
        Optional. Whether access through the Sophos Connect client is allowed. Valid values:
        Enable, Disable. If omitted, the firewall default applies.

        .PARAMETER LoginRestriction
        Required. Which network nodes group members may log in from. Valid value: AnyNode.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create user
        group objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosUserGroup -Name 'Sales' -GroupType Normal -QoSPolicy 'None' -SurfingQuotaPolicy 'Unlimited Internet Access' -AccessTimePolicy 'Allowed all the time' -LoginRestriction AnyNode -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosUserGroup -Name 'Sales' -GroupType Normal -QoSPolicy 'None' -SurfingQuotaPolicy 'Unlimited Internet Access' -AccessTimePolicy 'Allowed all the time' -LoginRestriction AnyNode

        Creates a group of type Normal.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserGroup
#>
function New-SfosUserGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 256)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Mandatory despite the doc table marking it optional: a create with GroupType
        # omitted or empty and LoginRestriction=AnyNode fails with 501, InvalidParams
        # pointing at LoginRestriction instead of GroupType - an empty GroupType appears to
        # make the firewall validate LoginRestriction against the wrong (or an undefined)
        # group-type schema. Sending GroupType explicitly avoids that.
        [Parameter(Mandatory)]
        [ValidateSet('Normal', 'Clienless')]
        [string]$GroupType,

        [string]$After,

        [Parameter(Mandatory)]
        [string]$QoSPolicy,

        # Mandatory despite the doc table marking both "No": a GroupType Normal create with
        # Name+GroupType+QoSPolicy+LoginRestriction alone fails with a generic 500; adding
        # both SurfingQuotaPolicy and AccessTimePolicy together produces 200. Which of the
        # two alone would suffice was not narrowed down further - both are required here,
        # the safer of the two possible readings.
        [Parameter(Mandatory)]
        [string]$SurfingQuotaPolicy,
        [Parameter(Mandatory)]
        [string]$AccessTimePolicy,
        [string]$DataTransferPolicy,
        [string]$SSLVPNPolicy,
        [string]$ClientlessPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$QuarantineDigest,

        [ValidateSet('Enable', 'Disable')]
        [string]$MACBinding,

        [ValidateSet('Enable', 'Disable')]
        [string]$L2TP,

        [ValidateSet('Enable', 'Disable')]
        [string]$PPTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$SophosConnectClient,

        [Parameter(Mandatory)]
        [ValidateSet('AnyNode')]
        [string]$LoginRestriction,

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

    $afterXml = ''
    if ($After) {
        $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $After)</Name></After>"
    }

    $inner = @"
<Set operation="add">
  <UserGroup>
    <GroupDetail>
      <Name>$nameEsc</Name>
      $afterXml
      <GroupType>$(ConvertTo-SfosXmlEscaped -Text $GroupType)</GroupType>
      <SurfingQuotaPolicy>$(ConvertTo-SfosXmlEscaped -Text $SurfingQuotaPolicy)</SurfingQuotaPolicy>
      <AccessTimePolicy>$(ConvertTo-SfosXmlEscaped -Text $AccessTimePolicy)</AccessTimePolicy>
      <DataTransferPolicy>$(ConvertTo-SfosXmlEscaped -Text $DataTransferPolicy)</DataTransferPolicy>
      <QoSPolicy>$(ConvertTo-SfosXmlEscaped -Text $QoSPolicy)</QoSPolicy>
      <SSLVPNPolicy>$(ConvertTo-SfosXmlEscaped -Text $SSLVPNPolicy)</SSLVPNPolicy>
      <ClientlessPolicy>$(ConvertTo-SfosXmlEscaped -Text $ClientlessPolicy)</ClientlessPolicy>
      <QuarantineDigest>$(ConvertTo-SfosXmlEscaped -Text $QuarantineDigest)</QuarantineDigest>
      <MACBinding>$(ConvertTo-SfosXmlEscaped -Text $MACBinding)</MACBinding>
      <L2TP>$(ConvertTo-SfosXmlEscaped -Text $L2TP)</L2TP>
      <PPTP>$(ConvertTo-SfosXmlEscaped -Text $PPTP)</PPTP>
      <SophosConnectClient>$(ConvertTo-SfosXmlEscaped -Text $SophosConnectClient)</SophosConnectClient>
      <LoginRestriction>$(ConvertTo-SfosXmlEscaped -Text $LoginRestriction)</LoginRestriction>
    </GroupDetail>
  </UserGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("UserGroup '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating UserGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A <Set> on UserGroup answers with a bare <GroupDetail>
    # as the direct child of <Response> - NOT wrapped in <UserGroup> the way <Get> responses
    # are. -ObjectName 'UserGroup' here would search /Response/UserGroup/Status, find
    # nothing, fall back to /Response/Status, find nothing there either, and silently report
    # success: a duplicate-name create with the wrong ObjectName returned no exception although
    # the firewall answered a real error.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates a user group on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing user group. The cmdlet reads the current group first and writes
        back a complete object: every field you pass replaces the current value, every field
        you omit keeps it. To clear a field, pass it explicitly with an empty value. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update user groups.

        This cmdlet only changes the group's own fields; it never sends a membership list, so
        membership set through Add-SfosUserGroupMember or Remove-SfosUserGroupMember is
        unaffected by a plain call.

        .PARAMETER Name
        Required. Name of the group to update.

        .PARAMETER GroupType
        Optional. Group type. Valid values: Normal, Clienless (this is the spelling the
        firewall uses). If omitted, the current value is kept.

        .PARAMETER After
        Optional. Name of the group after which this group is positioned. If omitted, the
        current value is kept.

        .PARAMETER QoSPolicy
        Optional. Name of the QoS (bandwidth) policy. If omitted, the current value is kept.

        .PARAMETER SurfingQuotaPolicy
        Optional. Name of the surfing quota policy. If omitted, the current value is kept.

        .PARAMETER AccessTimePolicy
        Optional. Name of the access time policy. If omitted, the current value is kept.

        .PARAMETER DataTransferPolicy
        Optional. Name of the data transfer policy. If omitted, the current value is kept.

        .PARAMETER SSLVPNPolicy
        Optional. Name of the SSL VPN policy. If omitted, the current value is kept.

        .PARAMETER ClientlessPolicy
        Optional. Name of the clientless access policy. If omitted, the current value is kept.

        .PARAMETER QuarantineDigest
        Optional. Whether the daily quarantine digest email is sent. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER MACBinding
        Optional. Whether group members are bound to a set of MAC addresses. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER L2TP
        Optional. Whether L2TP access is allowed. Valid values: Enable, Disable. If omitted,
        the current value is kept.

        .PARAMETER PPTP
        Optional. Whether PPTP access is allowed. Valid values: Enable, Disable. If omitted,
        the current value is kept.

        .PARAMETER SophosConnectClient
        Optional. Whether access through the Sophos Connect client is allowed. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER LoginRestriction
        Optional. Which network nodes group members may log in from. Valid value: AnyNode. If
        omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update user
        group objects. If omitted, the value from the current connection is used.

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
        System.String. Name, and any of the other property names of the object returned by
        Get-SfosUserGroup, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosUserGroup -Name 'Sales' -QoSPolicy 'Unlimited' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosUserGroup -Name 'Sales' -QoSPolicy 'Unlimited'

        Updates the QoS policy; every other field keeps its current value.

        .EXAMPLE
        Get-SfosUserGroup -NameLike 'Sales' | Set-SfosUserGroup -L2TP Enable

        Reads the matching group and enables L2TP access for its members.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserGroup
#>
function Set-SfosUserGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 256)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Normal', 'Clienless')]
        [string]$GroupType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$After,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$QoSPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SurfingQuotaPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AccessTimePolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DataTransferPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SSLVPNPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ClientlessPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$QuarantineDigest,

        [ValidateSet('Enable', 'Disable')]
        [string]$MACBinding,

        [ValidateSet('Enable', 'Disable')]
        [string]$L2TP,

        [ValidateSet('Enable', 'Disable')]
        [string]$PPTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$SophosConnectClient,

        [ValidateSet('AnyNode')]
        [string]$LoginRestriction,

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

        $existing = @(Get-SfosUserGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The UserGroup object '$Name' was not found."
        }

        $targetGroupType = if ($PSBoundParameters.ContainsKey('GroupType')) { $GroupType } else { [string]$existing[0].GroupType }
        $targetAfter = if ($PSBoundParameters.ContainsKey('After')) { $After } else { [string]$existing[0].After }
        $targetQoSPolicy = if ($PSBoundParameters.ContainsKey('QoSPolicy')) { $QoSPolicy } else { [string]$existing[0].QoSPolicy }
        $targetSurfingQuotaPolicy = if ($PSBoundParameters.ContainsKey('SurfingQuotaPolicy')) { $SurfingQuotaPolicy } else { [string]$existing[0].SurfingQuotaPolicy }
        $targetAccessTimePolicy = if ($PSBoundParameters.ContainsKey('AccessTimePolicy')) { $AccessTimePolicy } else { [string]$existing[0].AccessTimePolicy }
        $targetDataTransferPolicy = if ($PSBoundParameters.ContainsKey('DataTransferPolicy')) { $DataTransferPolicy } else { [string]$existing[0].DataTransferPolicy }
        $targetSSLVPNPolicy = if ($PSBoundParameters.ContainsKey('SSLVPNPolicy')) { $SSLVPNPolicy } else { [string]$existing[0].SSLVPNPolicy }
        $targetClientlessPolicy = if ($PSBoundParameters.ContainsKey('ClientlessPolicy')) { $ClientlessPolicy } else { [string]$existing[0].ClientlessPolicy }
        # Defensive normalisation, same reasoning as Set-SfosUser: a QuarantineDigest value
        # other than Enable/Disable (observed as literal "0" on the User entity when the
        # field was never set explicitly) is not accepted back by the API on update. Not
        # independently confirmed for UserGroup - applied as a precaution since it is a
        # one-line, no-risk guard if the defect turns out to be User-only.
        $targetQuarantineDigest = if ($PSBoundParameters.ContainsKey('QuarantineDigest')) {
            $QuarantineDigest
        }
        elseif ([string]$existing[0].QuarantineDigest -in @('Enable', 'Disable')) {
            [string]$existing[0].QuarantineDigest
        }
        else {
            'Disable'
        }
        $targetMACBinding = if ($PSBoundParameters.ContainsKey('MACBinding')) { $MACBinding } else { [string]$existing[0].MACBinding }
        $targetL2TP = if ($PSBoundParameters.ContainsKey('L2TP')) { $L2TP } else { [string]$existing[0].L2TP }
        $targetPPTP = if ($PSBoundParameters.ContainsKey('PPTP')) { $PPTP } else { [string]$existing[0].PPTP }
        $targetSophosConnectClient = if ($PSBoundParameters.ContainsKey('SophosConnectClient')) { $SophosConnectClient } else { [string]$existing[0].SophosConnectClient }
        $targetLoginRestriction = if ($PSBoundParameters.ContainsKey('LoginRestriction')) { $LoginRestriction } else { [string]$existing[0].LoginRestriction }

        $afterXml = ''
        if ($targetAfter) {
            $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $targetAfter)</Name></After>"
        }

        $inner = @"
<Set operation="update">
  <UserGroup>
    <GroupDetail>
      <Name>$nameEsc</Name>
      $afterXml
      <GroupType>$(ConvertTo-SfosXmlEscaped -Text $targetGroupType)</GroupType>
      <SurfingQuotaPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetSurfingQuotaPolicy)</SurfingQuotaPolicy>
      <AccessTimePolicy>$(ConvertTo-SfosXmlEscaped -Text $targetAccessTimePolicy)</AccessTimePolicy>
      <DataTransferPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetDataTransferPolicy)</DataTransferPolicy>
      <QoSPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetQoSPolicy)</QoSPolicy>
      <SSLVPNPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetSSLVPNPolicy)</SSLVPNPolicy>
      <ClientlessPolicy>$(ConvertTo-SfosXmlEscaped -Text $targetClientlessPolicy)</ClientlessPolicy>
      <QuarantineDigest>$(ConvertTo-SfosXmlEscaped -Text $targetQuarantineDigest)</QuarantineDigest>
      <MACBinding>$(ConvertTo-SfosXmlEscaped -Text $targetMACBinding)</MACBinding>
      <L2TP>$(ConvertTo-SfosXmlEscaped -Text $targetL2TP)</L2TP>
      <PPTP>$(ConvertTo-SfosXmlEscaped -Text $targetPPTP)</PPTP>
      <SophosConnectClient>$(ConvertTo-SfosXmlEscaped -Text $targetSophosConnectClient)</SophosConnectClient>
      <LoginRestriction>$(ConvertTo-SfosXmlEscaped -Text $targetLoginRestriction)</LoginRestriction>
    </GroupDetail>
  </UserGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("UserGroup '$Name' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating UserGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # A <Set> on UserGroup answers with a bare
        # <GroupDetail>, not wrapped in <UserGroup> - see New-SfosUserGroup NOTES for the
        # silent-success defect this avoids.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a user group from a Sophos Firewall.

        .DESCRIPTION
        Deletes a user group. The firewall answers a success status even when the named group
        does not exist, so this cmdlet reads the group list back afterwards and throws if the
        group is still present. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to delete user
        groups.

        .PARAMETER Name
        Required. Name of the group to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete user
        group objects. If omitted, the value from the current connection is used.

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
        System.String. Name is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output. It raises an error if the firewall rejects the
        removal, or if the group is still present after a reported success.

        .EXAMPLE
        Remove-SfosUserGroup -Name 'Sales' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUserGroup -Name 'Sales'

        Removes the group named 'Sales'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserGroup
#>
function Remove-SfosUserGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 256)]
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
        if (-not $PSCmdlet.ShouldProcess("UserGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # <Name> must be wrapped in <GroupDetail>; the flat
        # <Remove><UserGroup><Name>...</Name></UserGroup></Remove> shape used by every other
        # entity in this suite answers a blank Login-only response and removes nothing here.
        # See module NOTES.
        $inner = @"
<Remove>
  <UserGroup>
    <GroupDetail>
      <Name>$nameEsc</Name>
    </GroupDetail>
  </UserGroup>
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
            throw "Error removing UserGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Compound ObjectName: the successful response nests Status one level deeper here
        # than every other entity (/Response/UserGroup/GroupDetail/Status). See module NOTES.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserGroup/GroupDetail' -Action 'remove' -Target $Name

        # The firewall answers <Status code="200"> even when the named group never
        # existed - identical response for a real removal and a no-op. A status code can
        # never prove the removal actually happened for this entity, so read the group back
        # and throw if it is still there rather than reporting a false success.
        $stillThere = @(Get-SfosUserGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($stillThere.Count -gt 0) {
            throw "Remove-SfosUserGroup: the firewall reported success but UserGroup '$Name' is still present. Remove on this entity answers code 200 unconditionally, even for a group that never existed, so a status code alone cannot confirm removal."
        }
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds users to a user group on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more existing user accounts to a user group. Membership is stored on each
        user's own group field, so this cmdlet updates that field on every named user and
        reads each one back afterwards to confirm. Because a user can belong to only one group
        at a time, adding a user to this group removes it from whatever group it belonged to
        before. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update user objects.

        .PARAMETER Name
        Required. Name of the group. Must already exist.

        .PARAMETER Members
        Required. One or more user names to add to the group. Each must already exist as a
        user account.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update user
        objects. If omitted, the value from the current connection is used.

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
        System.String. Name is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output. It raises an error if the group or a named user
        does not exist, if the update fails, or if a member's group still does not match this
        group after the write.

        .EXAMPLE
        Add-SfosUserGroupMember -Name 'Sales' -Members 'jdoe', 'asmith' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosUserGroupMember -Name 'Sales' -Members 'jdoe', 'asmith'

        Adds the accounts 'jdoe' and 'asmith' to the 'Sales' group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserGroup

        .LINK
        Remove-SfosUserGroupMember
#>
function Add-SfosUserGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 256)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

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
        $userGroup = @(Get-SfosUserGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($userGroup.Count -eq 0) {
            throw "The UserGroup object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("UserGroup '$Name' on $($params.Firewall)", 'Add members')) {
            return
        }

        $resolvedMembers = @()
        foreach ($member in $Members) {
            if (-not $member) {
                continue
            }

            $existingUser = @(Get-SfosUser -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -UsernameLike $member `
                    -SkipCertificateCheck:$params.SkipCertificateCheck |
                    Where-Object -FilterScript { $_.Username -eq $member.ToLowerInvariant() })

            if ($existingUser.Count -eq 0) {
                throw "Add-SfosUserGroupMember: User '$member' was not found; cannot add it to UserGroup '$Name'."
            }

            try {
                Set-SfosUser -AccountName $existingUser[0].Username `
                    -Group $Name `
                    -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck `
                    -Confirm:$false -ErrorAction Stop
            }
            catch {
                throw "Error adding member '$member' to UserGroup '$Name': $($_.Exception.Message)"
            }

            $resolvedMembers += $existingUser[0].Username
        }

        # A status code cannot be trusted for this write path - the equivalent <GroupMembers>
        # write reported success while changing nothing (see .DESCRIPTION). Read every added
        # member back and throw if its Group does not actually match this group's name.
        $stillMissing = @()
        foreach ($resolvedUsername in $resolvedMembers) {
            $afterWrite = @(Get-SfosUser -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -UsernameLike $resolvedUsername `
                    -SkipCertificateCheck:$params.SkipCertificateCheck |
                    Where-Object -FilterScript { $_.Username -eq $resolvedUsername })

            if ($afterWrite.Count -eq 0 -or $afterWrite[0].Group -ne $Name) {
                $stillMissing += $resolvedUsername
            }
        }

        if ($stillMissing.Count -gt 0) {
            throw "Add-SfosUserGroupMember: the firewall reported success but user(s) '$($stillMissing -join ', ')' are not members of UserGroup '$Name' after the write."
        }
    }
}

<#
        .SYNOPSIS
        Removes users from a user group on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more user accounts from a user group. Membership is stored on each
        user's own group field, so this cmdlet clears that field on every named user whose
        group currently matches, and reads each one back afterwards to confirm. A user who is
        not currently a member is left untouched, not treated as an error. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to update user objects.

        .PARAMETER Name
        Required. Name of the group.

        .PARAMETER Members
        Required. One or more user names to remove from the group. Each must already exist as
        a user account.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update user
        objects. If omitted, the value from the current connection is used.

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
        System.String. Name is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output. It raises an error if a named user does not exist,
        if the update fails, or if a member's group still matches this group after the write.

        .EXAMPLE
        Remove-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUserGroupMember -Name 'Sales' -Members 'jdoe'

        Removes the account 'jdoe' from the 'Sales' group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserGroup

        .LINK
        Add-SfosUserGroupMember
#>
function Remove-SfosUserGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 256)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

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
        if (-not $PSCmdlet.ShouldProcess("UserGroup '$Name' on $($params.Firewall)", 'Remove members')) {
            return
        }

        $resolvedMembers = @()
        foreach ($member in $Members) {
            if (-not $member) {
                continue
            }

            $existingUser = @(Get-SfosUser -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -UsernameLike $member `
                    -SkipCertificateCheck:$params.SkipCertificateCheck |
                    Where-Object -FilterScript { $_.Username -eq $member.ToLowerInvariant() })

            if ($existingUser.Count -eq 0) {
                throw "Remove-SfosUserGroupMember: User '$member' was not found; cannot remove it from UserGroup '$Name'."
            }

            if ($existingUser[0].Group -ne $Name) {
                # Not currently a member of this group - nothing to do.
                continue
            }

            try {
                Set-SfosUser -AccountName $existingUser[0].Username `
                    -Group '' `
                    -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck `
                    -Confirm:$false -ErrorAction Stop
            }
            catch {
                throw "Error removing member '$member' from UserGroup '$Name': $($_.Exception.Message)"
            }

            $resolvedMembers += $existingUser[0].Username
        }

        # A status code cannot be trusted for this write path - see .DESCRIPTION and
        # Add-SfosUserGroupMember NOTES for the <GroupMembers> defect this replaces. Read
        # every removed member back and throw if its Group still matches this group.
        $stillMember = @()
        foreach ($resolvedUsername in $resolvedMembers) {
            $afterWrite = @(Get-SfosUser -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -UsernameLike $resolvedUsername `
                    -SkipCertificateCheck:$params.SkipCertificateCheck |
                    Where-Object -FilterScript { $_.Username -eq $resolvedUsername })

            if ($afterWrite.Count -gt 0 -and $afterWrite[0].Group -eq $Name) {
                $stillMember += $resolvedUsername
            }
        }

        if ($stillMember.Count -gt 0) {
            throw "Remove-SfosUserGroupMember: the firewall reported success but user(s) '$($stillMember -join ', ')' are still members of UserGroup '$Name'."
        }
    }
}

#endregion

#region GuestUser

# GuestUser objects cannot be updated through the API on this firmware. Both
# <Set operation="update"> (identified by <Username> or by <Name>) and the undocumented
# <Set operation="edit"> fail to update the existing object; operation="edit" instead
# creates a second, new object with the submitted fields and leaves the original
# unchanged. This matches the vendor documentation, which lists only Add, Add Multiple and
# Delete for GuestUser - no edit/update operation is documented. No Set-SfosGuestUser
# cmdlet exists in this module; to change a guest user's fields, remove and recreate it
# with Remove-SfosGuestUser + New-SfosGuestUser.

<#
        .SYNOPSIS
        Retrieves guest user objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the guest user accounts defined on the firewall. Use this cmdlet to review the
        existing guest accounts, or to feed them into Remove-SfosGuestUser through the
        pipeline. The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        You can combine both filters. -NameLike is also sent to the firewall as a pre-filter;
        -EmailLike is always evaluated on the client. The result matches both filters you gave.

        .PARAMETER NameLike
        Optional. Returns only guest users whose name contains the given text anywhere. This
        is a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the name is not used to filter.

        .PARAMETER EmailLike
        Optional. Returns only guest users whose email address contains the given text
        anywhere. Applied on the client. If omitted, the email address is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for guest
        user objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per guest user, with the
        properties Username (the firewall-assigned login, distinct from the display Name),
        AccountName (an alias for Username, so the object binds to Remove-SfosGuestUser's
        -AccountName parameter), Name, Email, UserValidity, Group, SurfingQuotaPolicy,
        AccessTimePolicy, DataTransferPolicy, QoSPolicy, SSLVPNPolicy, CreateDate,
        ExpireDate, L2TP, PPTP, QuarantineDigest, MACBinding, LoginRestriction and
        ScheduleForApplianceAccess. Returns System.Xml.XmlElement when -AsXml is used, and an
        empty array when no guest user matches.

        .EXAMPLE
        Get-SfosGuestUser

        Lists every guest user on the firewall of the current connection.

        .EXAMPLE
        Get-SfosGuestUser -NameLike 'visitor'

        Lists all guest users whose name contains 'visitor'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosGuestUser

        .LINK
        Remove-SfosGuestUser
#>
function Get-SfosGuestUser {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$EmailLike,

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
  <GuestUser>
    $filterXml
  </GuestUser>
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
        throw "Error retrieving GuestUser objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GuestUser' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/GuestUser[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($EmailLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.EmailList.EmailID -like "*$EmailLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $guestUserObjects = @()
    foreach ($node in $nodes) {
        $email = $null
        if ($node.EmailList -and $node.EmailList.EmailID) {
            $email = [string]$node.EmailList.EmailID
        }

        $obj = [PSCustomObject]@{
            Username                    = $node.Username
            Name                        = $node.Name
            Email                       = $email
            UserValidity                = $node.UserValidity
            Group                       = $node.Group
            SurfingQuotaPolicy          = $node.SurfingQuotaPolicy
            AccessTimePolicy            = $node.AccessTimePolicy
            DataTransferPolicy          = $node.DataTransferPolicy
            QoSPolicy                   = $node.QoSPolicy
            SSLVPNPolicy                = $node.SSLVPNPolicy
            CreateDate                  = $node.CreateDate
            ExpireDate                  = $node.ExpireDate
            L2TP                        = $node.L2TP
            PPTP                        = $node.PPTP
            QuarantineDigest            = $node.QuarantineDigest
            MACBinding                  = $node.MACBinding
            LoginRestriction            = $node.LoginRestriction
            ScheduleForApplianceAccess  = $node.ScheduleForApplianceAccess
        }
        # AccountName is an AliasProperty on Username, not a second copy of the value - see
        # Remove-SfosGuestUser for why the identifying parameter had to be renamed.
        $obj | Add-Member -MemberType AliasProperty -Name AccountName -Value Username
        $guestUserObjects += $obj
    }

    return $guestUserObjects
}

<#
        .SYNOPSIS
        Creates a guest user on a Sophos Firewall.

        .DESCRIPTION
        Adds a guest user account. The firewall assigns its own login user name (for example
        'guest-00001'), independent of the display name you pass; read it back with
        Get-SfosGuestUser before removing or referencing the account. There is no update
        operation for this entity, so changing a guest user means removing and recreating it.
        This cmdlet needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to create guest users.

        .PARAMETER Name
        Required. Display name of the guest user.

        .PARAMETER UserValidity
        Required. Validity period in days, as a string. The firewall stores and returns this
        value in hours, so piping the output of Get-SfosGuestUser back into this parameter
        multiplies the validity by 24 on every pass; pass the intended number of days as a
        literal instead.

        .PARAMETER Email
        Optional. Email address of the guest user. If omitted, none is set.

        .PARAMETER ValidityStart
        Optional. When the validity period starts. Valid values: Immediately,
        AfterFirstLogin. If omitted, the firewall default applies.

        .PARAMETER NoOfUsers
        Optional. Number of auto-generated guest users to create in this call. 1 to 100. Only
        meaningful when the guest user settings use automatic name generation. If omitted, a
        single guest user is created.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create guest
        user objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosGuestUser -Name 'visitor1' -UserValidity '1' -Email 'visitor1@example.com' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosGuestUser -Name 'visitor1' -UserValidity '1' -Email 'visitor1@example.com'

        Creates a guest user valid for one day.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosGuestUser
#>
function New-SfosGuestUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserValidity,

        [string]$Email,

        [ValidateSet('Immediately', 'AfterFirstLogin')]
        [string]$ValidityStart,

        [ValidateRange(1, 100)]
        [int]$NoOfUsers,

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
    $validityEsc = ConvertTo-SfosXmlEscaped -Text $UserValidity

    $optionalXml = ''
    if ($PSBoundParameters.ContainsKey('Email')) {
        $emailEsc = ConvertTo-SfosXmlEscaped -Text $Email
        $optionalXml += "<Email>$emailEsc</Email>"
    }
    if ($PSBoundParameters.ContainsKey('ValidityStart')) {
        $optionalXml += "<ValidityStart>$ValidityStart</ValidityStart>"
    }
    if ($PSBoundParameters.ContainsKey('NoOfUsers')) {
        $optionalXml += "<NoOfUsers>$NoOfUsers</NoOfUsers>"
    }

    $inner = @"
<Set operation="add">
  <GuestUser>
    <Name>$nameEsc</Name>
    <UserValidity>$validityEsc</UserValidity>
    $optionalXml
  </GuestUser>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("GuestUser '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating GuestUser object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GuestUser' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Removes a guest user from a Sophos Firewall.

        .DESCRIPTION
        Deletes a guest user account, addressed by its firewall-assigned login user name, not
        by the display name used to create it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete guest users.

        .PARAMETER AccountName
        Required. Login user name of the guest user, as shown in the Username property of
        Get-SfosGuestUser (for example 'guest-00001') - not the display name used at creation.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete guest
        user objects. If omitted, the value from the current connection is used.

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
        System.String. AccountName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosGuestUser -AccountName 'guest-00001' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosGuestUser -NameLike 'visitor1' | Remove-SfosGuestUser

        Removes the guest user whose display name contains 'visitor1'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosGuestUser
#>
function Remove-SfosGuestUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,

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
        if (-not $PSCmdlet.ShouldProcess("GuestUser '$AccountName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $accountEsc = ConvertTo-SfosXmlEscaped -Text $AccountName

        $inner = @"
<Remove>
  <GuestUser>
    <Username>$accountEsc</Username>
  </GuestUser>
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
            throw "Error removing GuestUser object '$AccountName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GuestUser' -Action 'remove' -Target $AccountName
    }
    end {
    }
}

#endregion

#region GuestUserSettings

<#
        .SYNOPSIS
        Retrieves the guest user settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide guest user settings. There is exactly one instance of this
        object per firewall. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        A write through Set-SfosGuestUserSettings can permanently break this cmdlet's own read
        path, with no reboot recovery. See Set-SfosGuestUserSettings before calling it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for guest
        user settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        AllowGuestUserSettings, SMSGateway, GuestUserSettingsName, UserNamePrefix, Days,
        AutoPurgeOnExpiry, UserGroup, CountryCode, CAPTCHVerification, PasswordLength,
        PasswordComplexity and Disclaimer. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosGuestUserSettings

        Returns the current guest user settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosGuestUserSettings
#>
function Get-SfosGuestUserSettings {
    # PSUseSingularNouns is suppressed on purpose: <GuestUserSettings> is the entity's own
    # singleton name, not a plural container - it has no singular child element, so the
    # Sophos wire spelling is used as-is.
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

    $inner = '<Get><GuestUserSettings></GuestUserSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving GuestUserSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GuestUserSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/GuestUserSettings')
    if (-not $node) {
        throw 'GuestUserSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $days = $null
    if ($node.UserValidity -and $node.UserValidity.Days) {
        $days = [int]$node.UserValidity.Days
    }

    return [PSCustomObject]@{
        AllowGuestUserSettings = [string]$node.AllowGuestUserSettings
        SMSGateway              = [string]$node.SMSGateway
        GuestUserSettingsName   = [string]$node.GuestUserSettingsName
        UserNamePrefix          = [string]$node.UserNamePrefix
        Days                    = $days
        AutoPurgeOnExpiry       = [string]$node.AutoPurgeOnExpiry
        UserGroup               = [string]$node.UserGroup
        CountryCode             = [string]$node.CountryCode
        CAPTCHVerification      = [string]$node.CAPTCHVerification
        PasswordLength          = [string]$node.PasswordLength
        PasswordComplexity      = [string]$node.PasswordComplexity
        Disclaimer              = [string]$node.Disclaimer
    }
}

<#
        .SYNOPSIS
        Updates the guest user settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide guest user settings. The cmdlet reads the current settings
        first and writes back a complete object: every field you pass replaces the current
        value, every field you omit keeps it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to update guest user settings.

        .PARAMETER AllowGuestUserSettings
        Optional. Whether secured internet access is offered to guest users. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER SMSGateway
        Optional. Name of the SMS gateway used when -GuestUserSettingsName is CellNumber. If
        omitted, the current value is kept.

        .PARAMETER GuestUserSettingsName
        Optional. Method for generating the guest user name. Valid values: CellNumber,
        AutoGenerate. If omitted, the current value is kept.

        .PARAMETER UserNamePrefix
        Optional. Prefix used for auto-generated user names. 1 to 10 characters. If omitted,
        the current value is kept.

        .PARAMETER Days
        Optional. Guest user validity period in days. If omitted, the current value is kept.

        .PARAMETER AutoPurgeOnExpiry
        Optional. Whether guest user details are purged automatically on expiry. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER UserGroup
        Optional. User group assigned to guest users. If omitted, the current value is kept.

        .PARAMETER CountryCode
        Optional. Default country code. If omitted, the current value is kept.

        .PARAMETER CAPTCHVerification
        Optional. Whether CAPTCHA verification is required. Valid values: Enable, Disable. If
        omitted, the current value is kept.

        .PARAMETER PasswordLength
        Optional. Length of the auto-generated password. 3 to 50. If omitted, the current
        value is kept.

        .PARAMETER PasswordComplexity
        Optional. Complexity of the auto-generated password. If omitted, the current value is
        kept.

        .PARAMETER Disclaimer
        Optional. Disclaimer text shown to guest users. Pass an empty string to clear it. If
        omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update guest
        user settings. If omitted, the value from the current connection is used.

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
        Set-SfosGuestUserSettings -Days 14 -AutoPurgeOnExpiry Enable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosGuestUserSettings -Days 14 -AutoPurgeOnExpiry Enable

        Sets the guest user validity to 14 days and enables automatic purging on expiry. The
        cmdlet asks for confirmation before it writes.

        .EXAMPLE
        Set-SfosGuestUserSettings -Days 14 -Confirm:$false

        Sets the guest user validity without asking for confirmation, for use in scripts.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosGuestUserSettings
#>
function Set-SfosGuestUserSettings {
    # PSUseSingularNouns is suppressed on purpose: <GuestUserSettings> is the entity's own
    # singleton name, not a plural container - it has no singular child element, so the
    # Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives: -PasswordComplexity is a policy selector for auto-generated guest
    # passwords (e.g. 'AlphanumericPassword'), not a credential, and the fixed connection
    # -Password parameter is already a SecureString.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordComplexity')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$AllowGuestUserSettings,

        [string]$SMSGateway,

        [ValidateSet('CellNumber', 'AutoGenerate')]
        [string]$GuestUserSettingsName,

        [ValidateLength(1, 10)]
        [string]$UserNamePrefix,

        [ValidateRange(1, 999)]
        [int]$Days,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoPurgeOnExpiry,

        [string]$UserGroup,

        [string]$CountryCode,

        [ValidateSet('Enable', 'Disable')]
        [string]$CAPTCHVerification,

        [ValidateRange(3, 50)]
        [int]$PasswordLength,

        [ValidateSet('AlphanumericPassword', 'AlphabeticPassword', 'NumericPassword', 'AlphaNumericWithSpecialCharacterPassword')]
        [string]$PasswordComplexity,

        [string]$Disclaimer,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosGuestUserSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetAllow = if ($PSBoundParameters.ContainsKey('AllowGuestUserSettings')) { $AllowGuestUserSettings } else { $existing.AllowGuestUserSettings }
    $targetSmsGateway = if ($PSBoundParameters.ContainsKey('SMSGateway')) { $SMSGateway } else { $existing.SMSGateway }
    $targetSettingsName = if ($PSBoundParameters.ContainsKey('GuestUserSettingsName')) { $GuestUserSettingsName } else { $existing.GuestUserSettingsName }
    $targetPrefix = if ($PSBoundParameters.ContainsKey('UserNamePrefix')) { $UserNamePrefix } else { $existing.UserNamePrefix }
    $targetDays = if ($PSBoundParameters.ContainsKey('Days')) { $Days } else { $existing.Days }
    $targetPurge = if ($PSBoundParameters.ContainsKey('AutoPurgeOnExpiry')) { $AutoPurgeOnExpiry } else { $existing.AutoPurgeOnExpiry }
    $targetUserGroup = if ($PSBoundParameters.ContainsKey('UserGroup')) { $UserGroup } else { $existing.UserGroup }
    $targetCountryCode = if ($PSBoundParameters.ContainsKey('CountryCode')) { $CountryCode } else { $existing.CountryCode }
    $targetCaptcha = if ($PSBoundParameters.ContainsKey('CAPTCHVerification')) { $CAPTCHVerification } else { $existing.CAPTCHVerification }
    $targetPwLength = if ($PSBoundParameters.ContainsKey('PasswordLength')) { $PasswordLength } else { $existing.PasswordLength }
    $targetPwComplexity = if ($PSBoundParameters.ContainsKey('PasswordComplexity')) { $PasswordComplexity } else { $existing.PasswordComplexity }
    $targetDisclaimer = if ($PSBoundParameters.ContainsKey('Disclaimer')) { $Disclaimer } else { $existing.Disclaimer }

    if (-not $PSCmdlet.ShouldProcess("GuestUserSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $smsGatewayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetSmsGateway)
    $prefixEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetPrefix)
    $userGroupEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetUserGroup)
    $countryCodeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetCountryCode)
    $disclaimerEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetDisclaimer)

    $smsGatewayXml = ''
    if ($targetSmsGateway) {
        $smsGatewayXml = "<SMSGateway>$smsGatewayEsc</SMSGateway>"
    }

    $inner = @"
<Set operation="update">
  <GuestUserSettings>
    <AllowGuestUserSettings>$targetAllow</AllowGuestUserSettings>
    $smsGatewayXml
    <GuestUserSettingsName>$targetSettingsName</GuestUserSettingsName>
    <UserNamePrefix>$prefixEsc</UserNamePrefix>
    <UserValidity>
      <Days>$targetDays</Days>
    </UserValidity>
    <AutoPurgeOnExpiry>$targetPurge</AutoPurgeOnExpiry>
    <UserGroup>$userGroupEsc</UserGroup>
    <CountryCode>$countryCodeEsc</CountryCode>
    <CAPTCHVerification>$targetCaptcha</CAPTCHVerification>
    <PasswordLength>$targetPwLength</PasswordLength>
    <PasswordComplexity>$targetPwComplexity</PasswordComplexity>
    <Disclaimer>$disclaimerEsc</Disclaimer>
  </GuestUserSettings>
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
        throw "Error updating GuestUserSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GuestUserSettings' -Action 'update'
}

#endregion

#region ClientlessUser

# Not exported. The response body for ClientlessUser operations can carry the root entity
# element's 'transactionid' attribute twice
# (<ClientlessUser transactionid="" transactionid="">...</ClientlessUser>), which makes
# System.Xml.XmlDocument reject the whole response ("'transactionid' is a duplicate
# attribute name") before Assert-SfosApiReturnSuccess ever sees the real status. This is a
# response-formatting defect independent of whether the write itself succeeds. Collapsing
# the duplicate attribute only fixes parsing; it does not change which status codes count
# as success - Assert-SfosApiReturnSuccess still throws on a genuine embedded failure
# status, now with the real message instead of an XML parser exception.
function ConvertTo-SfosClientlessUserSanitizedXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    return ($Content -replace '(<ClientlessUser)(\s+transactionid="[^"]*")(\s+transactionid="[^"]*")+', '$1$2')
}

<#
        .SYNOPSIS
        Retrieves clientless user objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the clientless user accounts defined on the firewall. A clientless user
        reaches the internet by IP address, without a client login. Use this cmdlet to review
        the existing accounts, or to feed them into Set-SfosClientlessUser or
        Remove-SfosClientlessUser through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        You can combine all filters. -NameLike is also sent to the firewall as a pre-filter;
        the others are always evaluated on the client. The result matches every filter you
        gave.

        .PARAMETER NameLike
        Optional. Returns only accounts whose display name contains the given text anywhere.
        This is a substring match, not a wildcard pattern; the characters * and ? are treated
        as ordinary characters. If omitted, the display name is not used to filter.

        .PARAMETER AccountNameLike
        Optional. Returns only accounts whose login user name contains the given text
        anywhere. Applied on the client. If omitted, the login user name is not used to
        filter.

        .PARAMETER IPAddressLike
        Optional. Returns only accounts whose IP address contains the given text anywhere.
        Applied on the client. If omitted, the address is not used to filter.

        .PARAMETER ClientLessGroupLike
        Optional. Returns only accounts whose group contains the given text anywhere. Applied
        on the client. If omitted, the group is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        clientless user objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per account, with the
        properties UserName, AccountName (an alias for UserName, so the object binds to
        Set-SfosClientlessUser and Remove-SfosClientlessUser), Name, IPAddress,
        ClientLessGroup, Email, Description, QuarantineDigest, QoSPolicy and Status. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no account matches.

        .EXAMPLE
        Get-SfosClientlessUser

        Lists every clientless user on the firewall of the current connection.

        .EXAMPLE
        Get-SfosClientlessUser -AccountNameLike 'jdoe'

        Lists all accounts whose login user name contains 'jdoe'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosClientlessUser

        .LINK
        Set-SfosClientlessUser
#>
function Get-SfosClientlessUser {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$AccountNameLike,
        [string]$IPAddressLike,
        [string]$ClientLessGroupLike,

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
  <ClientlessUser>
    $filterXml
  </ClientlessUser>
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
        throw "Error retrieving ClientlessUser objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml](ConvertTo-SfosClientlessUserSanitizedXml -Content $response.Content)
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ClientlessUser' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ClientlessUser[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($AccountNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.UserName -like "*$AccountNameLike*" })
    }
    if ($IPAddressLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.IPAddress -like "*$IPAddressLike*" })
    }
    if ($ClientLessGroupLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ClientLessGroup -like "*$ClientLessGroupLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $clientlessUserObjects = @()
    foreach ($node in $nodes) {
        $obj = [PSCustomObject]@{
            UserName        = $node.UserName
            Name            = $node.Name
            IPAddress       = $node.IPAddress
            ClientLessGroup = $node.ClientLessGroup
            Email           = $node.Email
            Description     = $node.Description
            QuarantineDigest = $node.QuarantineDigest
            QoSPolicy       = $node.QoSPolicy
            Status          = $node.Status
        }
        # AccountName is an AliasProperty on UserName, not a second copy of the value - see
        # the fragment header comment on Get-SfosGuestUser for why the rename exists.
        $obj | Add-Member -MemberType AliasProperty -Name AccountName -Value UserName
        $clientlessUserObjects += $obj
    }

    return $clientlessUserObjects
}

<#
        .SYNOPSIS
        Creates a clientless user on a Sophos Firewall.

        .DESCRIPTION
        Adds a clientless user account. A clientless user reaches the internet by IP address,
        without a client login. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to create
        clientless users.

        .PARAMETER AccountName
        Required. Login user name of the clientless user.

        .PARAMETER Name
        Required. Display name of the user.

        .PARAMETER ClientLessGroup
        Required. Group the user is added to.

        .PARAMETER Email
        Required. Email address of the user.

        .PARAMETER IPAddress
        Optional. IPv4 or IPv6 address of the user. If omitted, none is set.

        .PARAMETER Description
        Optional. Free-text description. If omitted, none is set.

        .PARAMETER QuarantineDigest
        Optional. Spam/quarantine digest option. Valid values: ApplyGroupSettings, Enable,
        Disable. If omitted, the firewall default applies.

        .PARAMETER Status
        Optional. Account status. Valid values: Active, Inactive. If omitted, the firewall
        default applies.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        clientless user objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosClientlessUser -AccountName 'jdoe' -Name 'John Doe' -ClientLessGroup 'Clientless Group' -Email 'jdoe@example.com' -IPAddress '203.0.113.10' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosClientlessUser -AccountName 'jdoe' -Name 'John Doe' -ClientLessGroup 'Clientless Group' -Email 'jdoe@example.com' -IPAddress '203.0.113.10'

        Creates a clientless user bound to a specific IP address.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosClientlessUser
#>
function New-SfosClientlessUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientLessGroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Email,

        [string]$IPAddress,

        [string]$Description,

        [ValidateSet('ApplyGroupSettings', 'Enable', 'Disable')]
        [string]$QuarantineDigest,

        [ValidateSet('Active', 'Inactive')]
        [string]$Status,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $accountEsc = ConvertTo-SfosXmlEscaped -Text $AccountName
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $groupEsc = ConvertTo-SfosXmlEscaped -Text $ClientLessGroup
    $emailEsc = ConvertTo-SfosXmlEscaped -Text $Email

    $optionalXml = ''
    if ($PSBoundParameters.ContainsKey('IPAddress')) {
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress
        $optionalXml += "<IPAddress>$ipEsc</IPAddress>"
    }
    if ($PSBoundParameters.ContainsKey('Description')) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $optionalXml += "<Description>$descEsc</Description>"
    }
    if ($PSBoundParameters.ContainsKey('QuarantineDigest')) {
        $optionalXml += "<QuarantineDigest>$QuarantineDigest</QuarantineDigest>"
    }
    if ($PSBoundParameters.ContainsKey('Status')) {
        $optionalXml += "<Status>$Status</Status>"
    }

    $inner = @"
<Set operation="add">
  <ClientlessUser>
    <UserName>$accountEsc</UserName>
    <Name>$nameEsc</Name>
    <ClientLessGroup>$groupEsc</ClientLessGroup>
    <Email>$emailEsc</Email>
    $optionalXml
  </ClientlessUser>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("ClientlessUser '$AccountName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating ClientlessUser object '$AccountName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml](ConvertTo-SfosClientlessUserSanitizedXml -Content $response.Content)
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ClientlessUser' -Action 'create' -Target $AccountName
}

<#
        .SYNOPSIS
        Updates a clientless user on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing clientless user account. The cmdlet reads the current account
        first and writes back a complete object: every field you pass replaces the current
        value, every field you omit keeps it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to update clientless users.

        .PARAMETER AccountName
        Required. Login user name of the account to update.

        .PARAMETER Name
        Optional. Display name of the user. If omitted, the current value is kept.

        .PARAMETER ClientLessGroup
        Optional. Group the user belongs to. If omitted, the current value is kept.

        .PARAMETER Email
        Optional. Email address of the user. If omitted, the current value is kept.

        .PARAMETER IPAddress
        Optional. IPv4 or IPv6 address of the user. If omitted, the current value is kept.

        .PARAMETER Description
        Optional. Free-text description. If omitted, the current value is kept.

        .PARAMETER QuarantineDigest
        Optional. Spam/quarantine digest option. Valid values: ApplyGroupSettings, Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER QoSPolicy
        Optional. QoS policy. If omitted, the current value is kept.

        .PARAMETER Status
        Optional. Account status. Valid values: Active, Inactive. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        clientless user objects. If omitted, the value from the current connection is used.

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
        System.String. AccountName, and any of the other property names of the object returned
        by Get-SfosClientlessUser, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosClientlessUser -AccountName 'jdoe' -Status Inactive -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosClientlessUser -AccountName 'jdoe' -Status Inactive

        Deactivates the account; every other field keeps its current value.

        .EXAMPLE
        Get-SfosClientlessUser -AccountNameLike 'jdoe' | Set-SfosClientlessUser -Description 'Contractor access'

        Reads the matching account and updates its description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosClientlessUser
#>
function Set-SfosClientlessUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ClientLessGroup,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Email,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$IPAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [ValidateSet('ApplyGroupSettings', 'Enable', 'Disable')]
        [string]$QuarantineDigest,

        [string]$QoSPolicy,

        [ValidateSet('Active', 'Inactive')]
        [string]$Status,

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
        $accountEsc = ConvertTo-SfosXmlEscaped -Text $AccountName

        # No confirmed server-side filter key for UserName, so the full set is fetched and
        # matched client-side - an unsupported server-side filter key is ignored, not rejected.
        $existing = @(Get-SfosClientlessUser -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.UserName -eq $AccountName })

        if ($existing.Count -eq 0) {
            throw "The ClientlessUser object '$AccountName' was not found."
        }

        $targetName = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { [string]$existing[0].Name }
        $targetGroup = if ($PSBoundParameters.ContainsKey('ClientLessGroup')) { $ClientLessGroup } else { [string]$existing[0].ClientLessGroup }
        $targetEmail = if ($PSBoundParameters.ContainsKey('Email')) { $Email } else { [string]$existing[0].Email }
        $targetIp = if ($PSBoundParameters.ContainsKey('IPAddress')) { $IPAddress } else { [string]$existing[0].IPAddress }
        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetDigest = if ($PSBoundParameters.ContainsKey('QuarantineDigest')) { $QuarantineDigest } else { [string]$existing[0].QuarantineDigest }
        $targetQos = if ($PSBoundParameters.ContainsKey('QoSPolicy')) { $QoSPolicy } else { [string]$existing[0].QoSPolicy }
        $targetStatus = if ($PSBoundParameters.ContainsKey('Status')) { $Status } else { [string]$existing[0].Status }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $targetName
        $groupEsc = ConvertTo-SfosXmlEscaped -Text $targetGroup
        $emailEsc = ConvertTo-SfosXmlEscaped -Text $targetEmail
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $targetIp
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $digestXml = ''
        if ($targetDigest) {
            $digestXml = "<QuarantineDigest>$targetDigest</QuarantineDigest>"
        }
        $qosXml = ''
        if ($targetQos) {
            $qosEsc = ConvertTo-SfosXmlEscaped -Text $targetQos
            $qosXml = "<QoSPolicy>$qosEsc</QoSPolicy>"
        }
        $statusXml = ''
        if ($targetStatus) {
            $statusXml = "<Status>$targetStatus</Status>"
        }

        $inner = @"
<Set operation="update">
  <ClientlessUser>
    <UserName>$accountEsc</UserName>
    <Name>$nameEsc</Name>
    <ClientLessGroup>$groupEsc</ClientLessGroup>
    <Email>$emailEsc</Email>
    <IPAddress>$ipEsc</IPAddress>
    <Description>$descEsc</Description>
    $digestXml
    $qosXml
    $statusXml
  </ClientlessUser>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ClientlessUser '$AccountName' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating ClientlessUser object '$AccountName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml](ConvertTo-SfosClientlessUserSanitizedXml -Content $response.Content)
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ClientlessUser' -Action 'edit' -Target $AccountName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a clientless user from a Sophos Firewall.

        .DESCRIPTION
        Sends a request to delete a clientless user account. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete clientless users.

        .PARAMETER AccountName
        Required. Login user name of the account to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        clientless user objects. If omitted, the value from the current connection is used.

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
        System.String. AccountName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosClientlessUser -AccountName 'jdoe' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosClientlessUser -AccountName 'jdoe'

        Removes the clientless user account named 'jdoe'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosClientlessUser
#>
function Remove-SfosClientlessUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$AccountName,

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
        if (-not $PSCmdlet.ShouldProcess("ClientlessUser '$AccountName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $accountEsc = ConvertTo-SfosXmlEscaped -Text $AccountName

        $inner = @"
<Remove>
  <ClientlessUser>
    <UserName>$accountEsc</UserName>
  </ClientlessUser>
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
            throw "Error removing ClientlessUser object '$AccountName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml](ConvertTo-SfosClientlessUserSanitizedXml -Content $response.Content)
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ClientlessUser' -Action 'remove' -Target $AccountName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Creates a range of clientless users on a Sophos Firewall.

        .DESCRIPTION
        Adds one clientless user account per IP address in the given range, in a single call.
        The firewall's response to this call carries no object to read back, so use
        Get-SfosClientlessUser afterward to see the accounts it created. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to create clientless users.

        .PARAMETER FromIPAddress
        Optional. Starting IP address of the range. If omitted, none is set.

        .PARAMETER ToIPAddress
        Optional. Ending IP address of the range. If omitted, none is set.

        .PARAMETER ClientLessGroup
        Optional. Group assigned to the generated accounts. If omitted, none is set.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        clientless user objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosClientlessUserRange -FromIPAddress '203.0.113.10' -ToIPAddress '203.0.113.20' -ClientLessGroup 'Clientless Group' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosClientlessUserRange -FromIPAddress '203.0.113.10' -ToIPAddress '203.0.113.20' -ClientLessGroup 'Clientless Group'

        Creates one clientless user for every address from .10 to .20.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosClientlessUser
#>
function New-SfosClientlessUserRange {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$FromIPAddress,

        [string]$ToIPAddress,

        [string]$ClientLessGroup,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $bodyXml = ''
    if ($PSBoundParameters.ContainsKey('FromIPAddress')) {
        $fromEsc = ConvertTo-SfosXmlEscaped -Text $FromIPAddress
        $bodyXml += "<FromIPAddress>$fromEsc</FromIPAddress>"
    }
    if ($PSBoundParameters.ContainsKey('ToIPAddress')) {
        $toEsc = ConvertTo-SfosXmlEscaped -Text $ToIPAddress
        $bodyXml += "<ToIPAddress>$toEsc</ToIPAddress>"
    }
    if ($PSBoundParameters.ContainsKey('ClientLessGroup')) {
        $groupEsc = ConvertTo-SfosXmlEscaped -Text $ClientLessGroup
        $bodyXml += "<ClientLessGroup>$groupEsc</ClientLessGroup>"
    }

    $inner = @"
<Set operation="add">
  <ClientlessUserAddRange>
    $bodyXml
  </ClientlessUserAddRange>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("ClientlessUserAddRange '$FromIPAddress-$ToIPAddress' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating ClientlessUserAddRange '$FromIPAddress-$ToIPAddress': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ClientlessUserAddRange' -Action 'create' -Target "$FromIPAddress-$ToIPAddress"
}

#endregion

#region SMSGateway

<#
        .SYNOPSIS
        Retrieves SMS gateway profiles from a Sophos Firewall.

        .DESCRIPTION
        Returns the SMS gateway profiles defined on the firewall. These profiles describe how
        the firewall sends SMS messages, for example one-time passwords or guest credentials.
        Use this cmdlet to review the existing profiles, or to feed them into
        Set-SfosSMSGateway through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER NameLike
        Optional. Returns only profiles whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, all profiles are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for SMS
        gateway objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per profile, with the
        properties Name, URL, HTTPMethod, UseCountryCodeWithCellNumber, CellNumberPreFix,
        RequestParameterName, RequestParameterValue, ResponseFormat, ResponseParameterName
        and ResponseParameterValue. The request and response parameter names and values are
        parallel arrays: the name and value at the same index belong together. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no profile matches.

        .EXAMPLE
        Get-SfosSMSGateway

        Lists every SMS gateway profile on the firewall of the current connection.

        .EXAMPLE
        Get-SfosSMSGateway -NameLike 'Twilio'

        Lists all profiles whose name contains 'Twilio'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSMSGateway

        .LINK
        Set-SfosSMSGateway
#>
function Get-SfosSMSGateway {
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
  <SMSGateway>
    $filterXml
  </SMSGateway>
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
        throw "Error retrieving SMSGateway objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMSGateway' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SMSGateway[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $smsGatewayObjects = @()
    foreach ($node in $nodes) {
        $requestParamter = $node.RequestParamterList.RequestParamter
        $responseParamter = $node.ResponseParamterList.ResponseParamter

        $smsGatewayObjects += [PSCustomObject]@{
            Name                          = $node.Name
            URL                           = $node.URL
            HTTPMethod                    = $node.HTTPMethod
            UseCountryCodeWithCellNumber  = $node.UseCountryCodeWithCellNumber
            CellNumberPreFix              = $node.CellNumberPreFix
            RequestParameterName          = [string[]]@($requestParamter.ParameterName | Where-Object -FilterScript { $_ })
            RequestParameterValue         = [string[]]@($requestParamter.ParameterValue | Where-Object -FilterScript { $_ })
            ResponseFormat                = $node.ResponseFormat
            ResponseParameterName         = [string[]]@($responseParamter.ParameterName | Where-Object -FilterScript { $_ })
            ResponseParameterValue        = [string[]]@($responseParamter.ParameterValue | Where-Object -FilterScript { $_ })
        }
    }

    return $smsGatewayObjects
}

<#
        .SYNOPSIS
        Creates an SMS gateway profile on a Sophos Firewall.

        .DESCRIPTION
        Adds an SMS gateway profile that describes how the firewall sends SMS messages. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with permission to create SMS gateway objects.

        .PARAMETER Name
        Required. Name of the SMS gateway. 1 to 100 characters, must not contain a comma.

        .PARAMETER URL
        Required. URL the SMS request is sent to. Must start with ftp, http or https, or be an
        IPv4 address.

        .PARAMETER HTTPMethod
        Optional. HTTP method used for the request. Valid values: Get, Post. If omitted, the
        firewall default applies.

        .PARAMETER UseCountryCodeWithCellNumber
        Optional. Whether the cell number is prefixed with the country code. Valid values:
        Enable, Disable. If omitted, the firewall default applies.

        .PARAMETER CellNumberPreFix
        Optional. Prefix added to the cell number. If omitted, none is set.

        .PARAMETER RequestParameterName
        Optional. Request parameter names, matched by position with -RequestParameterValue. If
        omitted, none is sent.

        .PARAMETER RequestParameterValue
        Optional. Request parameter values, matched by position with -RequestParameterName.
        Must contain the same number of elements. If omitted, none is sent.

        .PARAMETER ResponseFormat
        Optional. Response format string. Maximum 255 characters. If omitted, none is set.

        .PARAMETER ResponseParameterName
        Optional. Response parameter names, matched by position with -ResponseParameterValue.
        Each name must be a numeric placeholder index ('0', '1', ...) matching {0}/{1} in
        -ResponseFormat; a free-text name is rejected. If omitted, none is sent.

        .PARAMETER ResponseParameterValue
        Optional. Response parameter values, matched by position with -ResponseParameterName.
        Must contain the same number of elements. If omitted, none is sent.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create SMS
        gateway objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosSMSGateway -Name 'ExampleGateway' -URL 'https://sms.example.com/send' -HTTPMethod Post -RequestParameterName 'to', 'msg' -RequestParameterValue '{mobileno}', '{msg}' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosSMSGateway -Name 'ExampleGateway' -URL 'https://sms.example.com/send' -HTTPMethod Post -RequestParameterName 'to', 'msg' -RequestParameterValue '{mobileno}', '{msg}'

        Creates an SMS gateway profile with two request parameters.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSMSGateway
#>
function New-SfosSMSGateway {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [ValidateSet('Get', 'Post')]
        [string]$HTTPMethod,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseCountryCodeWithCellNumber,

        [string]$CellNumberPreFix,

        [string[]]$RequestParameterName,

        [string[]]$RequestParameterValue,

        [ValidateLength(0, 255)]
        [string]$ResponseFormat,

        [string[]]$ResponseParameterName,

        [string[]]$ResponseParameterValue,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    if ($RequestParameterName -and $RequestParameterValue -and ($RequestParameterName.Count -ne $RequestParameterValue.Count)) {
        throw "SMSGateway object '$Name': -RequestParameterName and -RequestParameterValue must contain the same number of elements."
    }
    if ($ResponseParameterName -and $ResponseParameterValue -and ($ResponseParameterName.Count -ne $ResponseParameterValue.Count)) {
        throw "SMSGateway object '$Name': -ResponseParameterName and -ResponseParameterValue must contain the same number of elements."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $urlEsc = ConvertTo-SfosXmlEscaped -Text $URL

    $optionalXml = ''
    if ($PSBoundParameters.ContainsKey('HTTPMethod')) {
        $optionalXml += "<HTTPMethod>$HTTPMethod</HTTPMethod>"
    }
    if ($PSBoundParameters.ContainsKey('UseCountryCodeWithCellNumber')) {
        $optionalXml += "<UseCountryCodeWithCellNumber>$UseCountryCodeWithCellNumber</UseCountryCodeWithCellNumber>"
    }
    if ($PSBoundParameters.ContainsKey('CellNumberPreFix')) {
        $prefixEsc = ConvertTo-SfosXmlEscaped -Text $CellNumberPreFix
        $optionalXml += "<CellNumberPreFix>$prefixEsc</CellNumberPreFix>"
    }

    $requestListXml = ''
    if ($RequestParameterName) {
        $namesXml = ''
        foreach ($n in $RequestParameterName) {
            $nEsc = ConvertTo-SfosXmlEscaped -Text $n
            $namesXml += "<ParameterName>$nEsc</ParameterName>"
        }
        $valuesXml = ''
        foreach ($v in $RequestParameterValue) {
            $vEsc = ConvertTo-SfosXmlEscaped -Text $v
            $valuesXml += "<ParameterValue>$vEsc</ParameterValue>"
        }
        $requestListXml = "<RequestParamterList><RequestParamter>$namesXml $valuesXml</RequestParamter></RequestParamterList>"
    }

    if ($PSBoundParameters.ContainsKey('ResponseFormat')) {
        $responseFormatEsc = ConvertTo-SfosXmlEscaped -Text $ResponseFormat
        $optionalXml += "<ResponseFormat>$responseFormatEsc</ResponseFormat>"
    }

    $responseListXml = ''
    if ($ResponseParameterName) {
        $namesXml = ''
        foreach ($n in $ResponseParameterName) {
            $nEsc = ConvertTo-SfosXmlEscaped -Text $n
            $namesXml += "<ParameterName>$nEsc</ParameterName>"
        }
        $valuesXml = ''
        foreach ($v in $ResponseParameterValue) {
            $vEsc = ConvertTo-SfosXmlEscaped -Text $v
            $valuesXml += "<ParameterValue>$vEsc</ParameterValue>"
        }
        $responseListXml = "<ResponseParamterList><ResponseParamter>$namesXml $valuesXml</ResponseParamter></ResponseParamterList>"
    }

    $inner = @"
<Set operation="add">
  <SMSGateway>
    <Name>$nameEsc</Name>
    <URL>$urlEsc</URL>
    $optionalXml
    $requestListXml
    $responseListXml
  </SMSGateway>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("SMSGateway '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating SMSGateway object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMSGateway' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an SMS gateway profile on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing SMS gateway profile. The cmdlet reads the current profile first
        and writes back a complete object: every field you pass replaces the current value,
        every field you omit keeps it. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly, and an account with permission to
        update SMS gateway objects.

        .PARAMETER Name
        Required. Name of the profile to update.

        .PARAMETER URL
        Optional. URL the SMS request is sent to. If omitted, the current value is kept.

        .PARAMETER HTTPMethod
        Optional. HTTP method used for the request. Valid values: Get, Post. If omitted, the
        current value is kept.

        .PARAMETER UseCountryCodeWithCellNumber
        Optional. Whether the cell number is prefixed with the country code. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER CellNumberPreFix
        Optional. Prefix added to the cell number. If omitted, the current value is kept.

        .PARAMETER RequestParameterName
        Optional. Request parameter names, matched by position with -RequestParameterValue. If
        neither this nor -RequestParameterValue is passed, the current list is kept.

        .PARAMETER RequestParameterValue
        Optional. Request parameter values, matched by position with -RequestParameterName.
        Must contain the same number of elements.

        .PARAMETER ResponseFormat
        Optional. Response format string. Maximum 255 characters. If omitted, the current
        value is kept.

        .PARAMETER ResponseParameterName
        Optional. Response parameter names, matched by position with -ResponseParameterValue.
        Each name must be a numeric placeholder index ('0', '1', ...) matching {0}/{1} in
        -ResponseFormat; a free-text name is rejected. If neither this nor
        -ResponseParameterValue is passed, the current list is kept.

        .PARAMETER ResponseParameterValue
        Optional. Response parameter values, matched by position with -ResponseParameterName.
        Must contain the same number of elements.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update SMS
        gateway objects. If omitted, the value from the current connection is used.

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
        System.String. Name, and any of the other property names of the object returned by
        Get-SfosSMSGateway, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSMSGateway -Name 'ExampleGateway' -CellNumberPreFix '+1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSMSGateway -Name 'ExampleGateway' -CellNumberPreFix '+1'

        Updates the cell number prefix; every other field keeps its current value.

        .EXAMPLE
        Get-SfosSMSGateway -NameLike 'ExampleGateway' | Set-SfosSMSGateway -HTTPMethod Get

        Reads the matching profile and switches its HTTP method to Get.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSMSGateway
#>
function Set-SfosSMSGateway {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$URL,

        [ValidateSet('Get', 'Post')]
        [string]$HTTPMethod,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseCountryCodeWithCellNumber,

        [string]$CellNumberPreFix,

        [string[]]$RequestParameterName,

        [string[]]$RequestParameterValue,

        [ValidateLength(0, 255)]
        [string]$ResponseFormat,

        [string[]]$ResponseParameterName,

        [string[]]$ResponseParameterValue,

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
        if ($RequestParameterName -and $RequestParameterValue -and ($RequestParameterName.Count -ne $RequestParameterValue.Count)) {
            throw "SMSGateway object '$Name': -RequestParameterName and -RequestParameterValue must contain the same number of elements."
        }
        if ($ResponseParameterName -and $ResponseParameterValue -and ($ResponseParameterName.Count -ne $ResponseParameterValue.Count)) {
            throw "SMSGateway object '$Name': -ResponseParameterName and -ResponseParameterValue must contain the same number of elements."
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $existing = @(Get-SfosSMSGateway -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SMSGateway object '$Name' was not found."
        }

        $targetUrl = if ($PSBoundParameters.ContainsKey('URL')) { $URL } else { [string]$existing[0].URL }
        $targetMethod = if ($PSBoundParameters.ContainsKey('HTTPMethod')) { $HTTPMethod } else { [string]$existing[0].HTTPMethod }
        $targetCountryCode = if ($PSBoundParameters.ContainsKey('UseCountryCodeWithCellNumber')) { $UseCountryCodeWithCellNumber } else { [string]$existing[0].UseCountryCodeWithCellNumber }
        $targetPrefix = if ($PSBoundParameters.ContainsKey('CellNumberPreFix')) { $CellNumberPreFix } else { [string]$existing[0].CellNumberPreFix }
        $targetResponseFormat = if ($PSBoundParameters.ContainsKey('ResponseFormat')) { $ResponseFormat } else { [string]$existing[0].ResponseFormat }

        $targetRequestNames = if ($PSBoundParameters.ContainsKey('RequestParameterName') -or $PSBoundParameters.ContainsKey('RequestParameterValue')) {
            @($RequestParameterName)
        }
        else {
            @($existing[0].RequestParameterName)
        }
        $targetRequestValues = if ($PSBoundParameters.ContainsKey('RequestParameterName') -or $PSBoundParameters.ContainsKey('RequestParameterValue')) {
            @($RequestParameterValue)
        }
        else {
            @($existing[0].RequestParameterValue)
        }
        $targetResponseNames = if ($PSBoundParameters.ContainsKey('ResponseParameterName') -or $PSBoundParameters.ContainsKey('ResponseParameterValue')) {
            @($ResponseParameterName)
        }
        else {
            @($existing[0].ResponseParameterName)
        }
        $targetResponseValues = if ($PSBoundParameters.ContainsKey('ResponseParameterName') -or $PSBoundParameters.ContainsKey('ResponseParameterValue')) {
            @($ResponseParameterValue)
        }
        else {
            @($existing[0].ResponseParameterValue)
        }

        $urlEsc = ConvertTo-SfosXmlEscaped -Text $targetUrl
        $prefixEsc = ConvertTo-SfosXmlEscaped -Text $targetPrefix
        $responseFormatEsc = ConvertTo-SfosXmlEscaped -Text $targetResponseFormat

        $methodXml = ''
        if ($targetMethod) {
            $methodXml = "<HTTPMethod>$targetMethod</HTTPMethod>"
        }
        $countryCodeXml = ''
        if ($targetCountryCode) {
            $countryCodeXml = "<UseCountryCodeWithCellNumber>$targetCountryCode</UseCountryCodeWithCellNumber>"
        }

        $requestListXml = ''
        if ($targetRequestNames) {
            $namesXml = ''
            foreach ($n in $targetRequestNames) {
                if (-not $n) { continue }
                $nEsc = ConvertTo-SfosXmlEscaped -Text $n
                $namesXml += "<ParameterName>$nEsc</ParameterName>"
            }
            $valuesXml = ''
            foreach ($v in $targetRequestValues) {
                if (-not $v) { continue }
                $vEsc = ConvertTo-SfosXmlEscaped -Text $v
                $valuesXml += "<ParameterValue>$vEsc</ParameterValue>"
            }
            if ($namesXml) {
                $requestListXml = "<RequestParamterList><RequestParamter>$namesXml $valuesXml</RequestParamter></RequestParamterList>"
            }
        }

        $responseListXml = ''
        if ($targetResponseNames) {
            $namesXml = ''
            foreach ($n in $targetResponseNames) {
                if (-not $n) { continue }
                $nEsc = ConvertTo-SfosXmlEscaped -Text $n
                $namesXml += "<ParameterName>$nEsc</ParameterName>"
            }
            $valuesXml = ''
            foreach ($v in $targetResponseValues) {
                if (-not $v) { continue }
                $vEsc = ConvertTo-SfosXmlEscaped -Text $v
                $valuesXml += "<ParameterValue>$vEsc</ParameterValue>"
            }
            if ($namesXml) {
                $responseListXml = "<ResponseParamterList><ResponseParamter>$namesXml $valuesXml</ResponseParamter></ResponseParamterList>"
            }
        }

        $inner = @"
<Set operation="update">
  <SMSGateway>
    <Name>$nameEsc</Name>
    <URL>$urlEsc</URL>
    $methodXml
    $countryCodeXml
    <CellNumberPreFix>$prefixEsc</CellNumberPreFix>
    $requestListXml
    <ResponseFormat>$responseFormatEsc</ResponseFormat>
    $responseListXml
  </SMSGateway>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("SMSGateway '$Name' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating SMSGateway object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMSGateway' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an SMS gateway profile from a Sophos Firewall.

        .DESCRIPTION
        Deletes an SMS gateway profile. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete SMS gateway objects.

        .PARAMETER Name
        Required. Name of the profile to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete SMS
        gateway objects. If omitted, the value from the current connection is used.

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
        System.String. Name is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSMSGateway -Name 'ExampleGateway' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosSMSGateway -Name 'ExampleGateway'

        Removes the profile named 'ExampleGateway'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSMSGateway
#>
function Remove-SfosSMSGateway {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
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
        if (-not $PSCmdlet.ShouldProcess("SMSGateway '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SMSGateway>
    <Name>$nameEsc</Name>
  </SMSGateway>
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
            throw "Error removing SMSGateway object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMSGateway' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion

#region OTPSettings

<#
        .SYNOPSIS
        Retrieves the one-time password settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide one-time password (OTP) configuration. There is exactly one
        instance of this object per firewall. The cmdlet only reads; nothing on the firewall
        is changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for OTP
        settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties Otp,
        AllUsers, OtpUsers, TokenAutoCreation, OtpUserPortal, OtpVPNPortal, OtpSSLVPN,
        OtpWebAdmin, OtpIPsec, Algorithm, DefaultTimeStep, MaxTimeStepsInterval and
        MaxInitialTimeStepDiff. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosOTPSettings

        Returns the current OTP settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosOTPSettings
#>
function Get-SfosOTPSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <OTPSettings>, a singleton
    # holding one configuration, and it has no <OTPSetting> child. The Sophos spelling
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

    $inner = '<Get><OTPSettings></OTPSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving OTPSettings settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/OTPSettings')
    if (-not $node) {
        throw 'OTPSettings settings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    # otpUsers is only present on the wire when it has at least one <user> child - the live
    # object observed with allUsers=1 (and therefore an empty explicit user list) omits the
    # <otpUsers> element entirely. $node.otpUsers is $null in that case, and $null.user does
    # not throw, so the array below comes out empty rather than $null.
    $otpUsers = [string[]]@($node.otpUsers.user | Where-Object -FilterScript { $_ })

    return [PSCustomObject]@{
        Otp                     = [string]$node.otp
        AllUsers                = [string]$node.allUsers
        OtpUsers                = $otpUsers
        TokenAutoCreation       = [string]$node.tokenAutoCreation
        OtpUserPortal           = [string]$node.otpUserPortal
        OtpVPNPortal            = [string]$node.otpVPNPortal
        OtpSSLVPN               = [string]$node.otpSSLVPN
        OtpWebAdmin             = [string]$node.otpWebAdmin
        OtpIPsec                = [string]$node.otpIPsec
        Algorithm               = [string]$node.algorithm
        DefaultTimeStep         = [string]$node.defaultTimeStep
        MaxTimeStepsInterval    = [string]$node.maxTimeStepsInterval
        MaxInitialTimeStepDiff  = [string]$node.maxInitialTimeStepDiff
    }
}

<#
        .SYNOPSIS
        Updates the one-time password settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide one-time password (OTP) configuration. The cmdlet reads the
        current settings first and writes back a complete object: every field you pass
        replaces the current value, every field you omit keeps it. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to update OTP settings.

        Enabling OTP for the web admin console without a working token already configured for
        the account you use can lock that account out of both the web admin console and the
        API. Verify on a console or another out-of-band access path before setting
        -OtpWebAdmin to '1'.

        .PARAMETER Otp
        Optional. Switches OTP on ('1') or off ('0') globally. If omitted, the current value is
        kept.

        .PARAMETER AllUsers
        Optional. Whether OTP is required for all users ('1') or only for the users and groups
        it was explicitly enabled for ('0'). If omitted, the current value is kept.

        .PARAMETER Members
        Optional. User names that must use OTP when -AllUsers is '0'. Replaces the current
        list. If omitted, the current list is kept. Prefer Add-SfosOTPSettingsMember or
        Remove-SfosOTPSettingsMember for incremental changes.

        .PARAMETER TokenAutoCreation
        Optional. Whether a user's OTP token is generated automatically when the user is
        created ('1' or '0'). If omitted, the current value is kept.

        .PARAMETER OtpUserPortal
        Optional. Whether OTP is required for the User Portal ('1' or '0'). If omitted, the
        current value is kept.

        .PARAMETER OtpVPNPortal
        Optional. Whether OTP is required for the VPN Portal ('1' or '0'). If omitted, the
        current value is kept.

        .PARAMETER OtpSSLVPN
        Optional. Whether OTP is required for SSL VPN sign-in ('1' or '0'). If omitted, the
        current value is kept.

        .PARAMETER OtpWebAdmin
        Optional. Whether OTP is required for web admin sign-in ('1' or '0'). See the warning
        in the description before setting this to '1'. If omitted, the current value is kept.

        .PARAMETER OtpIPsec
        Optional. Whether OTP is required for IPsec remote access ('1' or '0'). If omitted, the
        current value is kept.

        .PARAMETER Algorithm
        Optional. Hash algorithm used to generate OTPs. Valid values: SHA1, SHA256, SHA512. If
        omitted, the current value is kept.

        .PARAMETER DefaultTimeStep
        Optional. Length, in seconds, of the interval during which an OTP is valid. 10 to 300.
        If omitted, the current value is kept.

        .PARAMETER MaxTimeStepsInterval
        Optional. Number of time steps to search backward and forward for a matching OTP, to
        compensate for clock drift. 0 to 10. If omitted, the current value is kept.

        .PARAMETER MaxInitialTimeStepDiff
        Optional. Number of time steps to search backward and forward for the first use of a
        token, to compensate for missing clock synchronization. 0 to 600. If omitted, the
        current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update OTP
        settings. If omitted, the value from the current connection is used.

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
        Set-SfosOTPSettings -DefaultTimeStep 60 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosOTPSettings -DefaultTimeStep 60

        Changes the OTP validity window; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPSettings
#>
function Set-SfosOTPSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <OTPSettings>, a singleton
    # holding one configuration, and it has no <OTPSetting> child. The Sophos spelling
    # goes above PowerShell habit here; the singular concession is reserved
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('0', '1')]
        [string]$Otp,

        [ValidateSet('0', '1')]
        [string]$AllUsers,

        [Alias('OtpUsers')]
        [string[]]$Members,

        [ValidateSet('0', '1')]
        [string]$TokenAutoCreation,

        [ValidateSet('0', '1')]
        [string]$OtpUserPortal,

        [ValidateSet('0', '1')]
        [string]$OtpVPNPortal,

        [ValidateSet('0', '1')]
        [string]$OtpSSLVPN,

        [ValidateSet('0', '1')]
        [string]$OtpWebAdmin,

        [ValidateSet('0', '1')]
        [string]$OtpIPsec,

        [ValidateSet('SHA1', 'SHA256', 'SHA512')]
        [string]$Algorithm,

        [ValidateRange(10, 300)]
        [int]$DefaultTimeStep,

        [ValidateRange(0, 10)]
        [int]$MaxTimeStepsInterval,

        [ValidateRange(0, 600)]
        [int]$MaxInitialTimeStepDiff,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosOTPSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetOtp = if ($PSBoundParameters.ContainsKey('Otp')) { $Otp } else { $existing.Otp }
    $targetAllUsers = if ($PSBoundParameters.ContainsKey('AllUsers')) { $AllUsers } else { $existing.AllUsers }
    $targetMembers = @(if ($PSBoundParameters.ContainsKey('Members')) { $Members } else { $existing.OtpUsers })
    $targetTokenAutoCreation = if ($PSBoundParameters.ContainsKey('TokenAutoCreation')) { $TokenAutoCreation } else { $existing.TokenAutoCreation }
    $targetOtpUserPortal = if ($PSBoundParameters.ContainsKey('OtpUserPortal')) { $OtpUserPortal } else { $existing.OtpUserPortal }
    $targetOtpVPNPortal = if ($PSBoundParameters.ContainsKey('OtpVPNPortal')) { $OtpVPNPortal } else { $existing.OtpVPNPortal }
    $targetOtpSSLVPN = if ($PSBoundParameters.ContainsKey('OtpSSLVPN')) { $OtpSSLVPN } else { $existing.OtpSSLVPN }
    $targetOtpWebAdmin = if ($PSBoundParameters.ContainsKey('OtpWebAdmin')) { $OtpWebAdmin } else { $existing.OtpWebAdmin }
    $targetOtpIPsec = if ($PSBoundParameters.ContainsKey('OtpIPsec')) { $OtpIPsec } else { $existing.OtpIPsec }
    $targetAlgorithm = if ($PSBoundParameters.ContainsKey('Algorithm')) { $Algorithm } else { $existing.Algorithm }
    $targetDefaultTimeStep = if ($PSBoundParameters.ContainsKey('DefaultTimeStep')) { $DefaultTimeStep } else { $existing.DefaultTimeStep }
    $targetMaxTimeStepsInterval = if ($PSBoundParameters.ContainsKey('MaxTimeStepsInterval')) { $MaxTimeStepsInterval } else { $existing.MaxTimeStepsInterval }
    $targetMaxInitialTimeStepDiff = if ($PSBoundParameters.ContainsKey('MaxInitialTimeStepDiff')) { $MaxInitialTimeStepDiff } else { $existing.MaxInitialTimeStepDiff }

    if (-not $PSCmdlet.ShouldProcess("OTPSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $xmlOtpUsersMembers = ''
    foreach ($member in $targetMembers) {
        if (-not $member) {
            continue
        }
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlOtpUsersMembers += "<user>$memberEsc</user>"
    }

    $otpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtp)
    $allUsersEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetAllUsers)
    $tokenAutoCreationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetTokenAutoCreation)
    $otpUserPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtpUserPortal)
    $otpVPNPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtpVPNPortal)
    $otpSSLVPNEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtpSSLVPN)
    $otpWebAdminEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtpWebAdmin)
    $otpIPsecEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetOtpIPsec)
    $algorithmEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetAlgorithm)
    $defaultTimeStepEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetDefaultTimeStep)
    $maxTimeStepsIntervalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetMaxTimeStepsInterval)
    $maxInitialTimeStepDiffEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetMaxInitialTimeStepDiff)

    $inner = @"
<Set operation="update">
  <OTPSettings>
    <otp>$otpEsc</otp>
    <allUsers>$allUsersEsc</allUsers>
    <otpUsers>
      $xmlOtpUsersMembers
    </otpUsers>
    <tokenAutoCreation>$tokenAutoCreationEsc</tokenAutoCreation>
    <otpUserPortal>$otpUserPortalEsc</otpUserPortal>
    <otpVPNPortal>$otpVPNPortalEsc</otpVPNPortal>
    <otpSSLVPN>$otpSSLVPNEsc</otpSSLVPN>
    <otpWebAdmin>$otpWebAdminEsc</otpWebAdmin>
    <otpIPsec>$otpIPsecEsc</otpIPsec>
    <algorithm>$algorithmEsc</algorithm>
    <defaultTimeStep>$defaultTimeStepEsc</defaultTimeStep>
    <maxTimeStepsInterval>$maxTimeStepsIntervalEsc</maxTimeStepsInterval>
    <maxInitialTimeStepDiff>$maxInitialTimeStepDiffEsc</maxInitialTimeStepDiff>
  </OTPSettings>
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
        throw "Error updating OTPSettings settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPSettings' -Action 'update'
}

<#
        .SYNOPSIS
        Adds users to the explicit OTP user list on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more user names to the list of users required to use OTP when -AllUsers is
        '0' on the OTP settings. The cmdlet reads the current list first and merges the new
        names into it, rather than replacing it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to update OTP settings.

        A user name that does not exist on the firewall is silently dropped from the list; the
        call still answers success. This cmdlet does not check the user names against the
        existing accounts first, so verify with Get-SfosOTPSettings afterward.

        .PARAMETER Members
        Required. One or more user names to add to the list. Duplicates are reduced to a
        single entry.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update OTP
        settings. If omitted, the value from the current connection is used.

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
        Add-SfosOTPSettingsMember -Members 'jdoe', 'asmith' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosOTPSettingsMember -Members 'jdoe', 'asmith'

        Adds 'jdoe' and 'asmith' to the explicit OTP user list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPSettings

        .LINK
        Remove-SfosOTPSettingsMember
#>
function Add-SfosOTPSettingsMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosOTPSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $mergedMembers = @()
    $mergedMembers += $existing.OtpUsers
    $mergedMembers += $Members
    $mergedMembers = @($mergedMembers | Where-Object -FilterScript { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("OTPSettings on $($params.Firewall)", 'Add members')) {
        return
    }

    $xmlOtpUsersMembers = ''
    foreach ($member in $mergedMembers) {
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlOtpUsersMembers += "<user>$memberEsc</user>"
    }

    $otpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.Otp)
    $allUsersEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.AllUsers)
    $tokenAutoCreationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.TokenAutoCreation)
    $otpUserPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpUserPortal)
    $otpVPNPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpVPNPortal)
    $otpSSLVPNEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpSSLVPN)
    $otpWebAdminEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpWebAdmin)
    $otpIPsecEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpIPsec)
    $algorithmEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.Algorithm)
    $defaultTimeStepEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.DefaultTimeStep)
    $maxTimeStepsIntervalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.MaxTimeStepsInterval)
    $maxInitialTimeStepDiffEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.MaxInitialTimeStepDiff)

    $inner = @"
<Set operation="update">
  <OTPSettings>
    <otp>$otpEsc</otp>
    <allUsers>$allUsersEsc</allUsers>
    <otpUsers>
      $xmlOtpUsersMembers
    </otpUsers>
    <tokenAutoCreation>$tokenAutoCreationEsc</tokenAutoCreation>
    <otpUserPortal>$otpUserPortalEsc</otpUserPortal>
    <otpVPNPortal>$otpVPNPortalEsc</otpVPNPortal>
    <otpSSLVPN>$otpSSLVPNEsc</otpSSLVPN>
    <otpWebAdmin>$otpWebAdminEsc</otpWebAdmin>
    <otpIPsec>$otpIPsecEsc</otpIPsec>
    <algorithm>$algorithmEsc</algorithm>
    <defaultTimeStep>$defaultTimeStepEsc</defaultTimeStep>
    <maxTimeStepsInterval>$maxTimeStepsIntervalEsc</maxTimeStepsInterval>
    <maxInitialTimeStepDiff>$maxInitialTimeStepDiffEsc</maxInitialTimeStepDiff>
  </OTPSettings>
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
        throw "Error adding members to OTPSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPSettings' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes users from the explicit OTP user list on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more user names from the list of users required to use OTP on the OTP
        settings. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update OTP settings.

        This list only accepts a full replacement, not a partial removal: the firewall accepts
        a request that removes some names from a non-empty list without complaint, but leaves
        the list unchanged. The only removal that takes effect is one that empties the list
        completely. This cmdlet reads the list back after writing and throws if the requested
        names are still present, instead of reporting a false success.

        .PARAMETER Members
        Required. One or more user names to remove from the list.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update OTP
        settings. If omitted, the value from the current connection is used.

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
        None. The cmdlet writes no output. It raises an error if the firewall rejects the
        update, or if the named users are still present in the list afterward.

        .EXAMPLE
        Remove-SfosOTPSettingsMember -Members 'jdoe' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosOTPSettingsMember -Members 'jdoe'

        Removes 'jdoe' from the explicit OTP user list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPSettings

        .LINK
        Add-SfosOTPSettingsMember
#>
function Remove-SfosOTPSettingsMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosOTPSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.OtpUsers).Count -eq 0) {
        # Nothing to remove
        return
    }

    $remainingMembers = [Collections.ArrayList]@()
    $remainingMembers.AddRange([string[]]@($existing.OtpUsers))

    foreach ($member in $Members) {
        [int]$indexMember = $remainingMembers.IndexOf($member)
        if ($indexMember -ne -1) {
            $remainingMembers.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("OTPSettings on $($params.Firewall)", 'Remove members')) {
        return
    }

    # <otpUsers> is append-only on a normal update: a shorter, non-empty list
    # is silently ignored and the existing entries survive. The only way found to actually
    # clear entries is a single empty <user/> child, which empties the whole list - so that
    # exact form is used when nothing should remain; a partial removal is sent as a normal
    # list and caught by the post-write guard below instead, since the firewall is expected
    # to leave it unchanged.
    if ($remainingMembers.Count -eq 0) {
        $xmlOtpUsersMembers = '<user/>'
    }
    else {
        $xmlOtpUsersMembers = ''
        foreach ($member in $remainingMembers) {
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlOtpUsersMembers += "<user>$memberEsc</user>"
        }
    }

    $otpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.Otp)
    $allUsersEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.AllUsers)
    $tokenAutoCreationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.TokenAutoCreation)
    $otpUserPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpUserPortal)
    $otpVPNPortalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpVPNPortal)
    $otpSSLVPNEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpSSLVPN)
    $otpWebAdminEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpWebAdmin)
    $otpIPsecEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.OtpIPsec)
    $algorithmEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.Algorithm)
    $defaultTimeStepEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.DefaultTimeStep)
    $maxTimeStepsIntervalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.MaxTimeStepsInterval)
    $maxInitialTimeStepDiffEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.MaxInitialTimeStepDiff)

    $inner = @"
<Set operation="update">
  <OTPSettings>
    <otp>$otpEsc</otp>
    <allUsers>$allUsersEsc</allUsers>
    <otpUsers>
      $xmlOtpUsersMembers
    </otpUsers>
    <tokenAutoCreation>$tokenAutoCreationEsc</tokenAutoCreation>
    <otpUserPortal>$otpUserPortalEsc</otpUserPortal>
    <otpVPNPortal>$otpVPNPortalEsc</otpVPNPortal>
    <otpSSLVPN>$otpSSLVPNEsc</otpSSLVPN>
    <otpWebAdmin>$otpWebAdminEsc</otpWebAdmin>
    <otpIPsec>$otpIPsecEsc</otpIPsec>
    <algorithm>$algorithmEsc</algorithm>
    <defaultTimeStep>$defaultTimeStepEsc</defaultTimeStep>
    <maxTimeStepsInterval>$maxTimeStepsIntervalEsc</maxTimeStepsInterval>
    <maxInitialTimeStepDiff>$maxInitialTimeStepDiffEsc</maxInitialTimeStepDiff>
  </OTPSettings>
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
        throw "Error removing members from OTPSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPSettings' -Action 'remove members'

    # A 200 here does not guarantee the removal actually happened - <otpUsers> is append-only
    # for anything short of clearing the whole list (see .DESCRIPTION), so a request that asked
    # to drop one username out of several is answered with success while nothing changes. Read
    # the object back and throw if any of the requested usernames are still present, rather than
    # reporting success for a write that did nothing.
    $verify = Get-SfosOTPSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $stillPresent = @($Members | Where-Object -FilterScript { $verify.OtpUsers -contains $_ })
    if ($stillPresent.Count -gt 0) {
        throw "Removing member(s) '$($stillPresent -join ', ')' from OTPSettings answered success but the firewall left them in place. The otpUsers list only accepts a full clear, not a partial removal."
    }
}

#endregion

#region OTPTokens

<#
        .SYNOPSIS
        Retrieves one-time password tokens from a Sophos Firewall.

        .DESCRIPTION
        Returns the OTP tokens defined on the firewall. Use this cmdlet to review the existing
        tokens, or to feed them into Set-SfosOTPTokens or Remove-SfosOTPTokens through the
        pipeline. The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        You can combine both filters. -TokenIdLike is also sent to the firewall as a
        pre-filter; -UserLike is always evaluated on the client. The result matches both
        filters you gave.

        .PARAMETER TokenIdLike
        Optional. Returns only tokens whose token ID contains the given text anywhere. This is
        a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the token ID is not used to filter.

        .PARAMETER UserLike
        Optional. Returns only tokens whose associated user name contains the given text
        anywhere. Applied on the client. If omitted, the user name is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for OTP token
        objects. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show, such as
        the token's hashed secret.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per token, with the properties
        TokenId, UseCustomTokenTimeStep, TimeStepOffset, Algorithm, LastLogin, TimeOffset,
        ExtraCodes, Active, AutoCreated, User and Comment. The token secret is never included
        in the standard output; use -AsXml to see its hashed form. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no token matches.

        .EXAMPLE
        Get-SfosOTPTokens

        Lists every OTP token on the firewall of the current connection.

        .EXAMPLE
        Get-SfosOTPTokens -UserLike 'jdoe'

        Lists all tokens associated with a user name that contains 'jdoe'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosOTPTokens

        .LINK
        Set-SfosOTPTokens
#>
function Get-SfosOTPTokens {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$TokenIdLike,
        [string]$UserLike,

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

    # Server-side pre-filter: SFOS evaluates only the first <key> of the first <Filter>. No
    # live OTPTokens object exists to confirm 'tokenid' is a supported filter key - if it is
    # not, SFOS is documented to ignore it and return every record, which the client-side
    # filter below still narrows down correctly.
    $filterXml = ''
    if ($TokenIdLike) {
        $tokenIdLikeEsc = ConvertTo-SfosXmlEscaped -Text $TokenIdLike
        $filterXml = ('<Filter><key name="tokenid" criteria="like">{0}</key></Filter>' -f $tokenIdLikeEsc)
    }

    $inner = @"
<Get>
  <OTPTokens>
    $filterXml
  </OTPTokens>
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
        throw "Error retrieving OTPTokens objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPTokens' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/OTPTokens[tokenid]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND.
    if ($TokenIdLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.tokenid -like "*$TokenIdLike*" })
    }
    if ($UserLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.user -like "*$UserLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $otpTokenObjects = @()
    foreach ($node in $nodes) {
        $otpTokenObjects += [PSCustomObject]@{
            TokenId                = [string]$node.tokenid
            UseCustomTokenTimeStep = [string]$node.useCustomTokenTimeStep
            TimeStepOffset         = [string]$node.timeStepOffset
            Algorithm              = [string]$node.algorithm
            LastLogin              = [string]$node.lastLogin
            TimeOffset             = [string]$node.timeOffset
            ExtraCodes             = [string]$node.extraCodes
            Active                 = [string]$node.active
            AutoCreated            = [string]$node.autoCreated
            User                   = [string]$node.user
            Comment                = [string]$node.comment
        }
    }

    return $otpTokenObjects
}

<#
        .SYNOPSIS
        Creates a one-time password token on a Sophos Firewall.

        .DESCRIPTION
        Adds an OTP token and associates it with a user. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to create OTP token objects.

        .PARAMETER TokenId
        Optional. Token identifier. 1 to 32 characters. If omitted, it is not sent; what the
        firewall then assigns as the identifier is not covered by this cmdlet's own testing.

        .PARAMETER User
        Required. User name the token is associated with.

        .PARAMETER Secret
        Required. OTP shared secret, as a SecureString. Must be hexadecimal digits (0-9,
        a-f/A-F), 32 to 120 characters long.

        .PARAMETER Algorithm
        Optional. Hash algorithm used to generate OTPs for this token. Valid values: SHA1,
        SHA256, SHA512. If omitted, the firewall default applies.

        .PARAMETER UseCustomTokenTimeStep
        Optional. Whether this token uses a custom time step instead of the device-wide
        default. If omitted, the firewall default applies.

        .PARAMETER TimeStepOffset
        Optional. OTP time step offset. If omitted, the firewall default applies.

        .PARAMETER TimeOffset
        Optional. Time offset used to adjust clock skew. If omitted, the firewall default
        applies.

        .PARAMETER ExtraCodes
        Optional. One-time codes usable if the secret is temporarily unavailable. Maximum 69
        characters. If omitted, none is set.

        .PARAMETER Active
        Optional. Whether the token is enabled ('1') or disabled ('0'). If omitted, the
        firewall default applies.

        .PARAMETER AutoCreated
        Optional. Whether the token is flagged as auto-created ('1') or not ('0'). If omitted,
        the firewall default applies.

        .PARAMETER LastLogin
        Optional. Timestamp of the last successful OTP login. If omitted, none is set.

        .PARAMETER Comment
        Optional. Free-text comment for the token. If omitted, none is set.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create OTP
        token objects. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        $secret = ConvertTo-SecureString '0123456789abcdef0123456789abcdef' -AsPlainText -Force
        New-SfosOTPTokens -User 'jdoe' -Secret $secret -Algorithm SHA1 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $secret = ConvertTo-SecureString '0123456789abcdef0123456789abcdef' -AsPlainText -Force
        New-SfosOTPTokens -User 'jdoe' -Secret $secret -Algorithm SHA1

        Creates a token for 'jdoe' with a hexadecimal secret.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPTokens
#>
function New-SfosOTPTokens {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateLength(1, 32)]
        [string]$TokenId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory)]
        [SecureString]$Secret,

        [ValidateSet('SHA1', 'SHA256', 'SHA512')]
        [string]$Algorithm,

        [string]$UseCustomTokenTimeStep,

        [int]$TimeStepOffset,

        [int]$TimeOffset,

        [ValidateLength(0, 69)]
        [string]$ExtraCodes,

        [ValidateSet('0', '1')]
        [string]$Active,

        [ValidateSet('0', '1')]
        [string]$AutoCreated,

        [int]$LastLogin,

        [string]$Comment,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $xmlTokenId = ''
    if ($PSBoundParameters.ContainsKey('TokenId')) {
        $xmlTokenId = "<tokenid>$(ConvertTo-SfosXmlEscaped -Text $TokenId)</tokenid>"
    }

    # User is Mandatory, so this is always sent.
    $xmlUser = "<user>$(ConvertTo-SfosXmlEscaped -Text $User)</user>"

    $xmlAlgorithm = ''
    if ($PSBoundParameters.ContainsKey('Algorithm')) {
        $xmlAlgorithm = "<algorithm>$(ConvertTo-SfosXmlEscaped -Text $Algorithm)</algorithm>"
    }

    $xmlUseCustomTokenTimeStep = ''
    if ($PSBoundParameters.ContainsKey('UseCustomTokenTimeStep')) {
        $xmlUseCustomTokenTimeStep = "<useCustomTokenTimeStep>$(ConvertTo-SfosXmlEscaped -Text $UseCustomTokenTimeStep)</useCustomTokenTimeStep>"
    }

    $xmlTimeStepOffset = ''
    if ($PSBoundParameters.ContainsKey('TimeStepOffset')) {
        $xmlTimeStepOffset = "<timeStepOffset>$(ConvertTo-SfosXmlEscaped -Text ([string]$TimeStepOffset))</timeStepOffset>"
    }

    $xmlTimeOffset = ''
    if ($PSBoundParameters.ContainsKey('TimeOffset')) {
        $xmlTimeOffset = "<timeOffset>$(ConvertTo-SfosXmlEscaped -Text ([string]$TimeOffset))</timeOffset>"
    }

    $xmlExtraCodes = ''
    if ($PSBoundParameters.ContainsKey('ExtraCodes')) {
        $xmlExtraCodes = "<extraCodes>$(ConvertTo-SfosXmlEscaped -Text $ExtraCodes)</extraCodes>"
    }

    $xmlActive = ''
    if ($PSBoundParameters.ContainsKey('Active')) {
        $xmlActive = "<active>$(ConvertTo-SfosXmlEscaped -Text $Active)</active>"
    }

    $xmlAutoCreated = ''
    if ($PSBoundParameters.ContainsKey('AutoCreated')) {
        $xmlAutoCreated = "<autoCreated>$(ConvertTo-SfosXmlEscaped -Text $AutoCreated)</autoCreated>"
    }

    $xmlLastLogin = ''
    if ($PSBoundParameters.ContainsKey('LastLogin')) {
        $xmlLastLogin = "<lastLogin>$(ConvertTo-SfosXmlEscaped -Text ([string]$LastLogin))</lastLogin>"
    }

    $xmlComment = ''
    if ($PSBoundParameters.ContainsKey('Comment')) {
        $xmlComment = "<comment>$(ConvertTo-SfosXmlEscaped -Text $Comment)</comment>"
    }

    # Secret is a SecureString per the global rule for shared secrets. Marshal to plaintext
    # only for the duration of building the request, and free the BSTR again - same pattern
    # Invoke-SfosApi itself uses for the connection password.
    #
    # The vendor documentation's 32-120 character length constraint is
    # necessary but not sufficient. A 16-character Base32 value and a 20-character hex value
    # were both rejected with 501 naming only "/OTPTokens/secret" - no reason given - while
    # 32/40/64-character hexadecimal values were accepted. The hex-digit requirement is not
    # documented anywhere; this module's own error message states both constraints so the
    # caller is not left guessing at what the firewall's field-only error meant.
    $secretBstr = [IntPtr]::Zero
    try {
        $secretBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        $secretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretBstr)
        if ($secretPlain -notmatch '^[0-9a-fA-F]+$' -or $secretPlain.Length -lt 32 -or $secretPlain.Length -gt 120) {
            throw "The Secret for OTPTokens object must be hexadecimal digits (0-9, a-f/A-F), 32 to 120 characters long. Was $($secretPlain.Length) characters, hexadecimal: $($secretPlain -match '^[0-9a-fA-F]+$')."
        }
        $xmlSecret = "<secret>$(ConvertTo-SfosXmlEscaped -Text $secretPlain)</secret>"
    }
    finally {
        if ($secretBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeBSTR($secretBstr)
        }
        $secretPlain = $null
    }

    $targetName = if ($PSBoundParameters.ContainsKey('TokenId')) { $TokenId } else { $User }

    if (-not $PSCmdlet.ShouldProcess("OTPTokens '$targetName' on $($params.Firewall)", 'Create')) {
        return
    }

    # Element order matches a live OTPTokens object: tokenid, useCustomTokenTimeStep,
    # timeStepOffset, algorithm, secret, lastLogin, timeOffset, extraCodes, active,
    # autoCreated, user, comment.
    $inner = @"
<Set operation="add">
  <OTPTokens>
    $xmlTokenId
    $xmlUseCustomTokenTimeStep
    $xmlTimeStepOffset
    $xmlAlgorithm
    $xmlSecret
    $xmlLastLogin
    $xmlTimeOffset
    $xmlExtraCodes
    $xmlActive
    $xmlAutoCreated
    $xmlUser
    $xmlComment
  </OTPTokens>
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
        throw "Error creating OTPTokens object '$targetName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPTokens' -Action 'create' -Target $targetName
}

<#
        .SYNOPSIS
        Updates a one-time password token on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing OTP token. The cmdlet reads the current token first and writes
        back a complete object: every field you pass replaces the current value, every field
        you omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update OTP
        token objects.

        This cmdlet has no -Secret parameter; the update leaves the stored secret unchanged.
        To change a token's secret, remove and recreate it with New-SfosOTPTokens.

        .PARAMETER TokenId
        Required. Token identifier of the token to update.

        .PARAMETER User
        Optional. User name the token is associated with. If omitted, the current value is
        kept.

        .PARAMETER Algorithm
        Optional. Hash algorithm used to generate OTPs for this token. Valid values: SHA1,
        SHA256, SHA512. If omitted, the current value is kept.

        .PARAMETER UseCustomTokenTimeStep
        Optional. Whether this token uses a custom time step instead of the device-wide
        default. If omitted, the current value is kept.

        .PARAMETER TimeStepOffset
        Optional. OTP time step offset. If omitted, the current value is kept.

        .PARAMETER TimeOffset
        Optional. Time offset used to adjust clock skew. If omitted, the current value is
        kept.

        .PARAMETER ExtraCodes
        Optional. One-time codes usable if the secret is temporarily unavailable. Maximum 69
        characters. If omitted, the current value is kept.

        .PARAMETER Active
        Optional. Whether the token is enabled ('1') or disabled ('0'). If omitted, the
        current value is kept.

        .PARAMETER AutoCreated
        Optional. Whether the token is flagged as auto-created ('1') or not ('0'). If omitted,
        the current value is kept.

        .PARAMETER LastLogin
        Optional. Timestamp of the last successful OTP login. If omitted, the current value is
        kept.

        .PARAMETER Comment
        Optional. Free-text comment for the token. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update OTP
        token objects. If omitted, the value from the current connection is used.

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
        System.String. TokenId, and any of the other property names of the object returned by
        Get-SfosOTPTokens, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosOTPTokens -TokenId 'ABC123' -Active 0 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosOTPTokens -TokenId 'ABC123' -Active 0

        Disables the token; every other field keeps its current value.

        .EXAMPLE
        Get-SfosOTPTokens -TokenIdLike 'ABC' | Set-SfosOTPTokens -Comment 'Reissued'

        Reads the matching token and updates its comment.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPTokens
#>
function Set-SfosOTPTokens {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 32)]
        [string]$TokenId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$User,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('SHA1', 'SHA256', 'SHA512')]
        [string]$Algorithm,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$UseCustomTokenTimeStep,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$TimeStepOffset,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$TimeOffset,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 69)]
        [string]$ExtraCodes,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('0', '1')]
        [string]$Active,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('0', '1')]
        [string]$AutoCreated,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$LastLogin,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Comment,

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
        $existing = @(Get-SfosOTPTokens -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -TokenIdLike $TokenId `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.TokenId -eq $TokenId })

        if ($existing.Count -eq 0) {
            throw "The OTPTokens object '$TokenId' was not found."
        }
        $existing = $existing[0]

        $targetUser = if ($PSBoundParameters.ContainsKey('User')) { $User } else { $existing.User }
        $targetAlgorithm = if ($PSBoundParameters.ContainsKey('Algorithm')) { $Algorithm } else { $existing.Algorithm }
        $targetUseCustomTokenTimeStep = if ($PSBoundParameters.ContainsKey('UseCustomTokenTimeStep')) { $UseCustomTokenTimeStep } else { $existing.UseCustomTokenTimeStep }
        $targetTimeStepOffset = if ($PSBoundParameters.ContainsKey('TimeStepOffset')) { $TimeStepOffset } else { $existing.TimeStepOffset }
        $targetTimeOffset = if ($PSBoundParameters.ContainsKey('TimeOffset')) { $TimeOffset } else { $existing.TimeOffset }
        $targetExtraCodes = if ($PSBoundParameters.ContainsKey('ExtraCodes')) { $ExtraCodes } else { $existing.ExtraCodes }
        $targetActive = if ($PSBoundParameters.ContainsKey('Active')) { $Active } else { $existing.Active }
        $targetAutoCreated = if ($PSBoundParameters.ContainsKey('AutoCreated')) { $AutoCreated } else { $existing.AutoCreated }
        $targetLastLogin = if ($PSBoundParameters.ContainsKey('LastLogin')) { $LastLogin } else { $existing.LastLogin }
        $targetComment = if ($PSBoundParameters.ContainsKey('Comment')) { $Comment } else { $existing.Comment }

        if (-not $PSCmdlet.ShouldProcess("OTPTokens '$TokenId' on $($params.Firewall)", 'Update')) {
            return
        }

        $tokenIdEsc = ConvertTo-SfosXmlEscaped -Text $TokenId
        $userEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetUser)
        $algorithmEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetAlgorithm)
        $useCustomTokenTimeStepEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetUseCustomTokenTimeStep)
        $timeStepOffsetEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetTimeStepOffset)
        $timeOffsetEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetTimeOffset)
        $extraCodesEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetExtraCodes)
        $activeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetActive)
        $autoCreatedEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetAutoCreated)
        $lastLoginEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetLastLogin)
        $commentEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetComment)

        # Element order matches a live OTPTokens object: tokenid, useCustomTokenTimeStep,
        # timeStepOffset, algorithm, lastLogin, timeOffset, extraCodes, active, autoCreated,
        # user, comment. No <secret> - see .NOTES.
        $inner = @"
<Set operation="update">
  <OTPTokens>
    <tokenid>$tokenIdEsc</tokenid>
    <useCustomTokenTimeStep>$useCustomTokenTimeStepEsc</useCustomTokenTimeStep>
    <timeStepOffset>$timeStepOffsetEsc</timeStepOffset>
    <algorithm>$algorithmEsc</algorithm>
    <lastLogin>$lastLoginEsc</lastLogin>
    <timeOffset>$timeOffsetEsc</timeOffset>
    <extraCodes>$extraCodesEsc</extraCodes>
    <active>$activeEsc</active>
    <autoCreated>$autoCreatedEsc</autoCreated>
    <user>$userEsc</user>
    <comment>$commentEsc</comment>
  </OTPTokens>
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
            throw "Error updating OTPTokens object '$TokenId': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPTokens' -Action 'update' -Target $TokenId
    }
}

<#
        .SYNOPSIS
        Removes a one-time password token from a Sophos Firewall.

        .DESCRIPTION
        Deletes an OTP token identified by its token ID. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete OTP token objects.

        .PARAMETER TokenId
        Required. Token identifier of the token to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete OTP
        token objects. If omitted, the value from the current connection is used.

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
        System.String. TokenId is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosOTPTokens -TokenId 'ABC123' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosOTPTokens -TokenIdLike 'ABC' | Remove-SfosOTPTokens

        Removes every token whose ID contains 'ABC'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosOTPTokens
#>
function Remove-SfosOTPTokens {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 32)]
        [string]$TokenId,

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
        if (-not $PSCmdlet.ShouldProcess("OTPTokens '$TokenId' on $($params.Firewall)", 'Remove')) {
            return
        }

        $tokenIdEsc = ConvertTo-SfosXmlEscaped -Text $TokenId

        $inner = @"
<Remove>
  <OTPTokens>
    <tokenid>$tokenIdEsc</tokenid>
  </OTPTokens>
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
            throw "Error removing OTPTokens object '$TokenId': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'OTPTokens' -Action 'remove' -Target $TokenId
    }
}

#endregion

#region FirewallAuthenticationGlobalSettings

<#
        .SYNOPSIS
        Retrieves the firewall authentication global settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide session and login limits used for firewall authentication.
        There is exactly one instance of this object per firewall. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        SimultaneousLogins and MaximumSessionTimeoutMinutes. Either property reads as the
        literal text 'Unlimited' when no limit is configured. Returns System.Xml.XmlElement
        when -AsXml is used.

        .EXAMPLE
        Get-SfosFirewallAuthenticationGlobalSettings

        Returns the current session and login limits.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosFirewallAuthenticationGlobalSettings
#>
function Get-SfosFirewallAuthenticationGlobalSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationGlobalSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication GlobalSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Malformed Filter and malformed sub-child sent under <Get>
    # <FirewallAuthentication><GlobalSettings>...: SFOS never returned a Status node at all
    # for these - Get on this entity is lenient and simply ignores anything it does not
    # recognise. <Get><FirewallAuthentication/></Get> is also the only valid Get endpoint for
    # this entity (a standalone <Get><GlobalSettings/></Get> answers a flat
    # code="529" Input request module is Invalid). 'FirewallAuthentication' is therefore the
    # correct ObjectName for every Get-* in this fragment - not the nested per-block path.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/GlobalSettings')
    if (-not $node) {
        throw 'FirewallAuthentication GlobalSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        SimultaneousLogins            = [string]$node.SimultaneousLogins
        MaximumSessionTimeoutMinutes  = [string]$node.MaximumSessionTimeoutMinutes
    }
}

<#
        .SYNOPSIS
        Updates the firewall authentication global settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide session and login limits used for firewall authentication.
        The cmdlet reads the current settings first and writes back a complete object: every
        field you pass replaces the current value, every field you omit keeps it. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update firewall authentication settings.

        .PARAMETER SimultaneousLogins
        Optional. Maximum number of simultaneous logins per user. 1 to 99, or the literal text
        'Unlimited'. If omitted, the current value is kept.

        .PARAMETER MaximumSessionTimeoutMinutes
        Optional. Maximum session duration in minutes after which the user is logged out. 3 to
        1440, or the literal text 'Unlimited'. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosFirewallAuthenticationGlobalSettings -MaximumSessionTimeoutMinutes 30 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallAuthenticationGlobalSettings -MaximumSessionTimeoutMinutes 30

        Caps the session duration at 30 minutes; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationGlobalSettings
#>
function Set-SfosFirewallAuthenticationGlobalSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationGlobalSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidatePattern('^(Unlimited|[0-9]{1,2})$')]
        [string]$SimultaneousLogins,

        [ValidatePattern('^(Unlimited|[0-9]{1,4})$')]
        [string]$MaximumSessionTimeoutMinutes,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationGlobalSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetSimultaneousLogins = if ($PSBoundParameters.ContainsKey('SimultaneousLogins')) {
        $SimultaneousLogins
    }
    else {
        [string]$existing.SimultaneousLogins
    }

    $targetMaxTimeout = if ($PSBoundParameters.ContainsKey('MaximumSessionTimeoutMinutes')) {
        $MaximumSessionTimeoutMinutes
    }
    else {
        [string]$existing.MaximumSessionTimeoutMinutes
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication GlobalSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $simLoginsEsc = ConvertTo-SfosXmlEscaped -Text $targetSimultaneousLogins
    $maxTimeoutEsc = ConvertTo-SfosXmlEscaped -Text $targetMaxTimeout

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <GlobalSettings>
      <SimultaneousLogins>$simLoginsEsc</SimultaneousLogins>
      <MaximumSessionTimeoutMinutes>$maxTimeoutEsc</MaximumSessionTimeoutMinutes>
    </GlobalSettings>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication GlobalSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Forcing a 501 (SimultaneousLogins out of range) put the Status at
    # /Response/GlobalSettings/Status - top level, NOT nested under FirewallAuthentication.
    # A no-op round trip with valid values answered code="200" at the same top-level path.
    # Using the nested path here would be a fail-open: Core would find no Status node,
    # fall back to /Response/Status, find nothing there either, and return silently -
    # reporting success on a 501 that changed nothing.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GlobalSettings' -Action 'update'
}

#endregion

#region FirewallAuthenticationMethods

<#
        .SYNOPSIS
        Retrieves the firewall authentication method configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the settings that control which authentication server or servers, and which
        default group, are used when an administrator or user logs in to the firewall itself.
        There is exactly one instance of this object per firewall. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        A wrong value in this block, written through Set-SfosFirewallAuthenticationMethods or
        the related member cmdlets, can lock every account out of the firewall, including the
        account this module uses. Read this object and understand the current configuration
        before changing it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        DefaultGroup and AuthenticationServerList (the authentication servers in priority
        order). Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosFirewallAuthenticationMethods

        Returns the current firewall authentication method configuration.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosFirewallAuthenticationMethods
#>
function Get-SfosFirewallAuthenticationMethods {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationMethods> is the
    # entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication AuthenticationMethods: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosFirewallAuthenticationGlobalSettings: 'FirewallAuthentication' is the
    # ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/AuthenticationMethods')
    if (-not $node) {
        throw 'FirewallAuthentication AuthenticationMethods could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $servers = [string[]]@($node.SelectNodes('AuthenticationServerList/AuthenticationServer') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })

    return [PSCustomObject]@{
        DefaultGroup             = [string]$node.DefaultGroup
        AuthenticationServerList = $servers
    }
}

<#
        .SYNOPSIS
        Updates the firewall authentication method configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes which authentication server or servers, and which default group, are used
        when an administrator or user logs in to the firewall itself. The cmdlet reads the
        current settings first and writes back a complete object: every field you pass
        replaces the current value, every field you omit keeps it. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to update firewall authentication settings.

        Removing every server, or pointing the default group at a group that does not exist,
        can lock every account out of the firewall, including the account this module uses.
        Read the current configuration with Get-SfosFirewallAuthenticationMethods and use
        -WhatIf before writing.

        .PARAMETER DefaultGroup
        Optional. Default group assigned to users authenticated through this configuration. If
        omitted, the current value is kept.

        .PARAMETER AuthenticationServer
        Optional. One or more authentication server names to use for login, in priority order.
        Replaces the current list. If omitted, the current list is kept. Prefer
        Add-SfosFirewallAuthenticationMethodsMember or
        Remove-SfosFirewallAuthenticationMethodsMember for incremental changes.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosFirewallAuthenticationMethods -DefaultGroup 'Open Group' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallAuthenticationMethods -DefaultGroup 'Open Group'

        Changes the default group; the server list keeps its current value. The cmdlet asks
        for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationMethods
#>
function Set-SfosFirewallAuthenticationMethods {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationMethods> is the
    # entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DefaultGroup,

        [Alias('AuthenticationServerList')]
        [string[]]$AuthenticationServer,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationMethods -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetDefaultGroup = if ($PSBoundParameters.ContainsKey('DefaultGroup')) {
        $DefaultGroup
    }
    else {
        [string]$existing.DefaultGroup
    }

    $targetServers = if ($PSBoundParameters.ContainsKey('AuthenticationServer')) {
        @($AuthenticationServer)
    }
    else {
        @($existing.AuthenticationServerList)
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication AuthenticationMethods on $($params.Firewall)", 'Update')) {
        return
    }

    $defaultGroupEsc = ConvertTo-SfosXmlEscaped -Text $targetDefaultGroup

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <AuthenticationMethods>
      <DefaultGroup>$defaultGroupEsc</DefaultGroup>
      <AuthenticationServerList>
        $xmlServers
      </AuthenticationServerList>
    </AuthenticationMethods>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication AuthenticationMethods: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # An invalid DefaultGroup value fails validation before anything is written, and the
    # Status lands at /Response/AuthenticationMethods/Status - top level, matching every
    # other Set-* in this region, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the firewall authentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the server list used for firewall logins,
        keeping the existing servers and default group in place. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to update firewall authentication settings.

        This list governs how administrators and users log in to the firewall itself. A
        mistake here can lock every account out, including the account this module uses.

        .PARAMETER Members
        Required. One or more authentication server names to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Add-SfosFirewallAuthenticationMethodsMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosFirewallAuthenticationMethodsMember -Members 'RADIUS-Server1'

        Adds 'RADIUS-Server1' alongside the existing servers. The cmdlet asks for confirmation
        before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationMethods

        .LINK
        Remove-SfosFirewallAuthenticationMethodsMember
#>
function Add-SfosFirewallAuthenticationMethodsMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationMethods -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetServers = @()
    $targetServers += $existing.AuthenticationServerList
    $targetServers += $Members
    $targetServers = @($targetServers | Where-Object { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication AuthenticationMethods on $($params.Firewall)", 'Add members')) {
        return
    }

    $defaultGroupEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.DefaultGroup)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <AuthenticationMethods>
      <DefaultGroup>$defaultGroupEsc</DefaultGroup>
      <AuthenticationServerList>
        $xmlServers
      </AuthenticationServerList>
    </AuthenticationMethods>
  </FirewallAuthentication>
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
        throw "Error adding members to FirewallAuthentication AuthenticationMethods: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosFirewallAuthenticationMethods - Status lands at
    # /Response/AuthenticationMethods/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the firewall authentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the server list used for firewall
        logins, keeping the default group and every remaining server in place. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update firewall authentication settings.

        Removing every server can lock every account out of the firewall, including the
        account this module uses.

        .PARAMETER Members
        Required. One or more authentication server names to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Remove-SfosFirewallAuthenticationMethodsMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosFirewallAuthenticationMethodsMember -Members 'RADIUS-Server1'

        Removes 'RADIUS-Server1' from the server list. The cmdlet asks for confirmation before
        it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationMethods

        .LINK
        Add-SfosFirewallAuthenticationMethodsMember
#>
function Remove-SfosFirewallAuthenticationMethodsMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationMethods -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.AuthenticationServerList).Count -eq 0) {
        # Nothing to remove
        return
    }

    $targetServers = [Collections.ArrayList]@()
    $targetServers.AddRange([string[]]@($existing.AuthenticationServerList))

    foreach ($member in $Members) {
        [int]$indexMember = $targetServers.IndexOf($member)
        if ($indexMember -ne -1) {
            $targetServers.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication AuthenticationMethods on $($params.Firewall)", 'Remove members')) {
        return
    }

    $defaultGroupEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.DefaultGroup)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <AuthenticationMethods>
      <DefaultGroup>$defaultGroupEsc</DefaultGroup>
      <AuthenticationServerList>
        $xmlServers
      </AuthenticationServerList>
    </AuthenticationMethods>
  </FirewallAuthentication>
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
        throw "Error removing members from FirewallAuthentication AuthenticationMethods: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosFirewallAuthenticationMethods - Status lands at
    # /Response/AuthenticationMethods/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'remove members'
}

#endregion

#region FirewallAuthenticationNTLMSettings

<#
        .SYNOPSIS
        Retrieves the NTLM authentication settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide NTLM authentication timeout settings. There is exactly one
        instance of this object per firewall. The cmdlet only reads; nothing on the firewall
        is changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        NTLMInActivtyTime, NTLMDataTransferThreshold and NTLMChallegeRedirect. Returns
        System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosFirewallAuthenticationNTLMSettings

        Returns the current NTLM authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosFirewallAuthenticationNTLMSettings
#>
function Get-SfosFirewallAuthenticationNTLMSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationNTLMSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication NTLMSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosFirewallAuthenticationGlobalSettings: 'FirewallAuthentication' is the
    # ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/NTLMSettings')
    if (-not $node) {
        throw 'FirewallAuthentication NTLMSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        NTLMInActivtyTime        = [int]$node.NTLMInActivtyTime
        NTLMDataTransferThreshold = [long]$node.NTLMDataTransferThreshold
        NTLMChallegeRedirect     = [string]$node.NTLMChallegeRedirect
    }
}

<#
        .SYNOPSIS
        Updates the NTLM authentication settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide NTLM authentication timeout settings. The cmdlet reads the
        current settings first and writes back a complete object: every field you pass
        replaces the current value, every field you omit keeps it. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with permission to update firewall authentication settings.

        .PARAMETER NTLMInActivtyTime
        Optional. Inactivity time in minutes after which the NTLM user is logged out and must
        re-authenticate. 6 to 1440. If omitted, the current value is kept.

        .PARAMETER NTLMDataTransferThreshold
        Optional. Minimum data in bytes that must be transferred within
        -NTLMInActivtyTime for the session to count as active. If omitted, the current value
        is kept.

        .PARAMETER NTLMChallegeRedirect
        Optional. Whether the NTLM challenge redirect is enabled. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosFirewallAuthenticationNTLMSettings -NTLMChallegeRedirect Disable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallAuthenticationNTLMSettings -NTLMChallegeRedirect Disable

        Disables the NTLM challenge redirect; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationNTLMSettings
#>
function Set-SfosFirewallAuthenticationNTLMSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationNTLMSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(6, 1440)]
        [int]$NTLMInActivtyTime,

        [ValidateRange(0, 9999999999)]
        [long]$NTLMDataTransferThreshold,

        [ValidateSet('Enable', 'Disable')]
        [string]$NTLMChallegeRedirect,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationNTLMSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetInActivityTime = if ($PSBoundParameters.ContainsKey('NTLMInActivtyTime')) {
        $NTLMInActivtyTime
    }
    else {
        $existing.NTLMInActivtyTime
    }

    $targetThreshold = if ($PSBoundParameters.ContainsKey('NTLMDataTransferThreshold')) {
        $NTLMDataTransferThreshold
    }
    else {
        $existing.NTLMDataTransferThreshold
    }

    $targetChallengeRedirect = if ($PSBoundParameters.ContainsKey('NTLMChallegeRedirect')) {
        $NTLMChallegeRedirect
    }
    else {
        [string]$existing.NTLMChallegeRedirect
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication NTLMSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $challengeRedirectEsc = ConvertTo-SfosXmlEscaped -Text $targetChallengeRedirect

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <NTLMSettings>
      <NTLMInActivtyTime>$targetInActivityTime</NTLMInActivtyTime>
      <NTLMDataTransferThreshold>$targetThreshold</NTLMDataTransferThreshold>
      <NTLMChallegeRedirect>$challengeRedirectEsc</NTLMChallegeRedirect>
    </NTLMSettings>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication NTLMSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Out-of-range NTLMInActivtyTime forced a 501: Status landed at
    # /Response/NTLMSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NTLMSettings' -Action 'update'
}

#endregion

#region FirewallAuthenticationCTASSettings

<#
        .SYNOPSIS
        Retrieves the CTAS authentication settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide CTAS (Client Transparent Authentication Suite) timeout
        settings. There is exactly one instance of this object per firewall. The cmdlet only
        reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        The firewall only returns CTASInActivtyTime and CTASDataTransferThreshold once
        CTASUserInactivity is enabled; with it disabled, both properties come back empty.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        CTASUserInactivity, CTASInActivtyTime and CTASDataTransferThreshold. Returns
        System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosFirewallAuthenticationCTASSettings

        Returns the current CTAS authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosFirewallAuthenticationCTASSettings
#>
function Get-SfosFirewallAuthenticationCTASSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationCTASSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication CTASSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosFirewallAuthenticationGlobalSettings: 'FirewallAuthentication' is the
    # ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/CTASSettings')
    if (-not $node) {
        throw 'FirewallAuthentication CTASSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        CTASUserInactivity        = [string]$node.CTASUserInactivity
        CTASInActivtyTime         = [string]$node.CTASInActivtyTime
        CTASDataTransferThreshold = [string]$node.CTASDataTransferThreshold
    }
}

<#
        .SYNOPSIS
        Updates the CTAS authentication settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide CTAS (Client Transparent Authentication Suite) timeout
        settings. The cmdlet reads the current settings first and writes back a complete
        object: every field you pass replaces the current value, every field you omit keeps
        it. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update firewall
        authentication settings.

        .PARAMETER CTASUserInactivity
        Optional. Whether the CTAS user inactivity timeout is enabled. Valid values: Enable,
        Disable. If omitted, the current value is kept.

        .PARAMETER CTASInActivtyTime
        Optional. Inactivity time in minutes after which the CTAS user is logged out and must
        re-authenticate. 3 to 1440. If omitted, the current value is kept.

        .PARAMETER CTASDataTransferThreshold
        Optional. Minimum data in bytes that must be transferred within -CTASInActivtyTime for
        the session to count as active. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosFirewallAuthenticationCTASSettings -CTASUserInactivity Enable -CTASInActivtyTime 10 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallAuthenticationCTASSettings -CTASUserInactivity Enable -CTASInActivtyTime 10

        Enables the CTAS inactivity timeout with a 10-minute limit.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationCTASSettings
#>
function Set-SfosFirewallAuthenticationCTASSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationCTASSettings> is
    # the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$CTASUserInactivity,

        [ValidateRange(3, 1440)]
        [int]$CTASInActivtyTime,

        [ValidateRange(0, 9999999999)]
        [long]$CTASDataTransferThreshold,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationCTASSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetUserInactivity = if ($PSBoundParameters.ContainsKey('CTASUserInactivity')) {
        $CTASUserInactivity
    }
    else {
        [string]$existing.CTASUserInactivity
    }

    $targetInActivityTime = if ($PSBoundParameters.ContainsKey('CTASInActivtyTime')) {
        [string]$CTASInActivtyTime
    }
    else {
        [string]$existing.CTASInActivtyTime
    }

    $targetThreshold = if ($PSBoundParameters.ContainsKey('CTASDataTransferThreshold')) {
        [string]$CTASDataTransferThreshold
    }
    else {
        [string]$existing.CTASDataTransferThreshold
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication CTASSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $userInactivityEsc = ConvertTo-SfosXmlEscaped -Text $targetUserInactivity
    $inActivityTimeEsc = ConvertTo-SfosXmlEscaped -Text $targetInActivityTime
    $thresholdEsc = ConvertTo-SfosXmlEscaped -Text $targetThreshold

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <CTASSettings>
      <CTASUserInactivity>$userInactivityEsc</CTASUserInactivity>
      <CTASInActivtyTime>$inActivityTimeEsc</CTASInActivtyTime>
      <CTASDataTransferThreshold>$thresholdEsc</CTASDataTransferThreshold>
    </CTASSettings>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication CTASSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Out-of-range CTASInActivtyTime forced a 501: Status landed at
    # /Response/CTASSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CTASSettings' -Action 'update'
}

#endregion

#region FirewallAuthenticationiOSWebClientSettings

<#
        .SYNOPSIS
        Retrieves the iOS web client authentication settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide timeout settings for the iOS web client authentication method.
        There is exactly one instance of this object per firewall. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        iOSWebClientInActivtyTime and iOSWebClientDataTransferThreshold. Returns
        System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosFirewallAuthenticationiOSWebClientSettings

        Returns the current iOS web client authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosFirewallAuthenticationiOSWebClientSettings
#>
function Get-SfosFirewallAuthenticationiOSWebClientSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationiOSWebClientSettings>
    # is the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication iOSWebClientSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosFirewallAuthenticationGlobalSettings: 'FirewallAuthentication' is the
    # ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/iOSWebClientSettings')
    if (-not $node) {
        throw 'FirewallAuthentication iOSWebClientSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        iOSWebClientInActivtyTime        = [int]$node.iOSWebClientInActivtyTime
        iOSWebClientDataTransferThreshold = [long]$node.iOSWebClientDataTransferThreshold
    }
}

<#
        .SYNOPSIS
        Updates the iOS web client authentication settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide timeout settings for the iOS web client authentication method.
        The cmdlet reads the current settings first and writes back a complete object: every
        field you pass replaces the current value, every field you omit keeps it. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update firewall authentication settings.

        .PARAMETER iOSWebClientInActivtyTime
        Optional. Inactivity time in minutes after which the iOS web client user is logged out
        and must re-authenticate. 6 to 1440. If omitted, the current value is kept.

        .PARAMETER iOSWebClientDataTransferThreshold
        Optional. Minimum data in bytes that must be transferred within
        -iOSWebClientInActivtyTime for the session to count as active. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosFirewallAuthenticationiOSWebClientSettings -iOSWebClientInActivtyTime 20 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallAuthenticationiOSWebClientSettings -iOSWebClientInActivtyTime 20

        Raises the inactivity timeout to 20 minutes; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallAuthenticationiOSWebClientSettings
#>
function Set-SfosFirewallAuthenticationiOSWebClientSettings {
    # PSUseSingularNouns is suppressed on purpose: <FirewallAuthenticationiOSWebClientSettings>
    # is the entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(6, 1440)]
        [int]$iOSWebClientInActivtyTime,

        [ValidateRange(1, 4294967295)]
        [long]$iOSWebClientDataTransferThreshold,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosFirewallAuthenticationiOSWebClientSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetInActivityTime = if ($PSBoundParameters.ContainsKey('iOSWebClientInActivtyTime')) {
        $iOSWebClientInActivtyTime
    }
    else {
        $existing.iOSWebClientInActivtyTime
    }

    $targetThreshold = if ($PSBoundParameters.ContainsKey('iOSWebClientDataTransferThreshold')) {
        $iOSWebClientDataTransferThreshold
    }
    else {
        $existing.iOSWebClientDataTransferThreshold
    }

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication iOSWebClientSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <iOSWebClientSettings>
      <iOSWebClientInActivtyTime>$targetInActivityTime</iOSWebClientInActivtyTime>
      <iOSWebClientDataTransferThreshold>$targetThreshold</iOSWebClientDataTransferThreshold>
    </iOSWebClientSettings>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication iOSWebClientSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Out-of-range iOSWebClientInActivtyTime forced a 501: Status landed at
    # /Response/iOSWebClientSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'iOSWebClientSettings' -Action 'update'
}

#endregion

#region SSORadiusAccount

<#
        .SYNOPSIS
        Retrieves the RADIUS accounting single sign-on configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the RADIUS accounting clients configured for single sign-on. The cmdlet only
        reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per configured RADIUS
        accounting client, with the properties ClientIP and SharedSecret. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when nothing is
        configured.

        .EXAMPLE
        Get-SfosSSORadiusAccount

        Returns the current RADIUS accounting single sign-on configuration, if any.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosSSORadiusAccount
#>
function Get-SfosSSORadiusAccount {
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

    $inner = '<Get><FirewallAuthentication></FirewallAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FirewallAuthentication SSORadiusAccount: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosFirewallAuthenticationGlobalSettings: 'FirewallAuthentication' is the
    # ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $containerNode = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/SSORadiusAccount')
    if (-not $containerNode) {
        # Not present when unconfigured - treated the same as an empty result, not as an
        # error.
        if ($AsXml) {
            return @()
        }
        return @()
    }

    $radiusNodes = @($containerNode.SelectNodes('Radius'))

    if ($AsXml) {
        return @($radiusNodes)
    }

    $accounts = @()
    foreach ($radiusNode in $radiusNodes) {
        $clientIPs = [string[]]@($radiusNode.SelectNodes('ClientIP') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })
        $accounts += [PSCustomObject]@{
            ClientIP     = $clientIPs
            SharedSecret = [string]$radiusNode.SharedSecret
        }
    }

    return $accounts
}

<#
        .SYNOPSIS
        Sets the RADIUS accounting single sign-on configuration on a Sophos Firewall.

        .DESCRIPTION
        Writes a single RADIUS accounting client entry - one or more IP addresses sharing one
        secret - as the RADIUS accounting single sign-on configuration. The call replaces the
        whole configuration with exactly this one entry; no other entry is preserved. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update firewall authentication settings.

        .PARAMETER ClientIP
        Required. One or more RADIUS client IP addresses that this shared secret applies to.

        .PARAMETER SharedSecret
        Required. Shared secret for the RADIUS accounting client, as a SecureString.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update firewall
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosSSORadiusAccount -ClientIP '203.0.113.10' -SharedSecret (Read-Host -AsSecureString) -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSSORadiusAccount -ClientIP '203.0.113.10' -SharedSecret (Read-Host -AsSecureString)

        Configures a single RADIUS accounting client.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSORadiusAccount
#>
function Set-SfosSSORadiusAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ClientIP,

        [Parameter(Mandatory)]
        [SecureString]$SharedSecret,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("FirewallAuthentication SSORadiusAccount on $($params.Firewall)", 'Update')) {
        return
    }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
    try {
        $sharedSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $sharedSecretEsc = ConvertTo-SfosXmlEscaped -Text $sharedSecretPlain

    $xmlClientIPs = ''
    foreach ($ip in $ClientIP) {
        if (-not $ip) {
            continue
        }
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $ip
        $xmlClientIPs += "<ClientIP>$ipEsc</ClientIP>"
    }

    $inner = @"
<Set operation="update">
  <FirewallAuthentication>
    <SSORadiusAccount>
      <Radius>
        $xmlClientIPs
        <SharedSecret>$sharedSecretEsc</SharedSecret>
      </Radius>
    </SSORadiusAccount>
  </FirewallAuthentication>
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
        throw "Error updating FirewallAuthentication SSORadiusAccount: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Diagnostic-only invalid ClientIP forced a 501 without writing anything -
    # <InvalidParams> even named the field, confirming the Radius/ClientIP nesting is correct: # Status landed at /Response/SSORadiusAccount/Status - top level, not nested under
    # FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSORadiusAccount' -Action 'update'
}

#endregion

#region AdminAuthentication

<#
        .SYNOPSIS
        Retrieves the administrator authentication configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the settings that control which authentication server or servers an
        administrator uses when logging in to the web admin console or the API. There is
        exactly one instance of this object per firewall. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        This configuration governs the login path this module's own API session uses. Reading
        it is safe; see Set-SfosAdminAuthentication and the member cmdlets before writing to
        it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for admin
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        AuthenticationMethods and AuthenticationServerList (the authentication servers in
        priority order). Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosAdminAuthentication

        Returns the current administrator authentication configuration.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosAdminAuthentication
#>
function Get-SfosAdminAuthentication {
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

    $inner = '<Get><AdminAuthentication></AdminAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AdminAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A successful Get carries no Status node at all under
    # /Response/AdminAuthentication - Assert-SfosApiReturnSuccess finds nothing and returns,
    # which is the correct outcome here (confirmed by an actual successful call).
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/AdminAuthentication')
    if (-not $node) {
        throw 'AdminAuthentication could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $servers = [string[]]@($node.SelectNodes('AuthenticationServerList/AuthenticationServer') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })

    return [PSCustomObject]@{
        AuthenticationMethods    = [string]$node.AuthenticationMethods
        AuthenticationServerList = $servers
    }
}

<#
        .SYNOPSIS
        Updates the administrator authentication configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes which authentication server or servers, and which method, an administrator
        uses to log in to the web admin console or the API. The cmdlet reads the current
        configuration first and writes back a complete object: every field you pass replaces
        the current value, every field you omit keeps it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to update admin authentication settings.

        A wrong authentication method, or an emptied server list, can lock every administrator
        out of the firewall, including the account this module uses. Read the current
        configuration with Get-SfosAdminAuthentication and use -WhatIf before writing.

        .PARAMETER AuthenticationMethods
        Optional. Admin authentication method. If omitted, the current value is kept.

        .PARAMETER AuthenticationServer
        Optional. One or more authentication server names to use for admin login, in priority
        order. Replaces the current list. If omitted, the current list is kept. Prefer
        Add-SfosAdminAuthenticationMember or Remove-SfosAdminAuthenticationMember for
        incremental changes.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update admin
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosAdminAuthentication -AuthenticationMethods 'Custom' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosAdminAuthentication -AuthenticationMethods 'Custom' -Confirm:$false

        Sets the authentication method without asking for confirmation, for use in scripts.
        This cmdlet asks for confirmation by default because a mistake can lock every
        administrator out.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAdminAuthentication
#>
function Set-SfosAdminAuthentication {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$AuthenticationMethods,

        [Alias('AuthenticationServerList')]
        [string[]]$AuthenticationServer,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetMethods = if ($PSBoundParameters.ContainsKey('AuthenticationMethods')) {
        $AuthenticationMethods
    }
    else {
        [string]$existing.AuthenticationMethods
    }

    $targetServers = if ($PSBoundParameters.ContainsKey('AuthenticationServer')) {
        @($AuthenticationServer)
    }
    else {
        @($existing.AuthenticationServerList)
    }

    if (-not $PSCmdlet.ShouldProcess("AdminAuthentication on $($params.Firewall)", 'Update')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text $targetMethods

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <AdminAuthentication>
    <AuthenticationServerList>
        $xmlServers
    </AuthenticationServerList>
    <AuthenticationMethods>$methodsEsc</AuthenticationMethods>
  </AdminAuthentication>
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
        throw "Error updating AdminAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Not exercised against a real appliance: these fields carry the credentials the API
    # session itself authenticates with, and a wrong value can lock out administrative
    # access. The status path is inferred by analogy with Set-SfosVPNAuthentication /
    # Set-SfosSSLVPNAuthentication in this region, which place Status at
    # /Response/<Entity>/Status for operation="update".
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the administrator authentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the server list used for administrator
        logins, keeping the existing servers and authentication method in place. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update admin authentication settings.

        This list governs the login path this module's own API session uses.

        .PARAMETER Members
        Required. One or more authentication server names to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update admin
        authentication settings. If omitted, the value from the current connection is used.

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
        Add-SfosAdminAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosAdminAuthenticationMember -Members 'RADIUS-Server1' -Confirm:$false

        Adds 'RADIUS-Server1' without asking for confirmation, for use in scripts. This cmdlet
        asks for confirmation by default because it changes the login path this module's own
        API session uses.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAdminAuthentication

        .LINK
        Remove-SfosAdminAuthenticationMember
#>
function Add-SfosAdminAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetServers = @()
    $targetServers += $existing.AuthenticationServerList
    $targetServers += $Members
    $targetServers = @($targetServers | Where-Object { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("AdminAuthentication on $($params.Firewall)", 'Add members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.AuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <AdminAuthentication>
    <AuthenticationServerList>
        $xmlServers
    </AuthenticationServerList>
    <AuthenticationMethods>$methodsEsc</AuthenticationMethods>
  </AdminAuthentication>
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
        throw "Error adding members to AdminAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Not exercised against a real appliance - see Set-SfosAdminAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the administrator authentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the server list used for
        administrator logins, keeping the authentication method and every remaining server in
        place. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update admin
        authentication settings.

        Removing every server can lock every administrator out of the firewall, including the
        account this module uses.

        .PARAMETER Members
        Required. One or more authentication server names to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update admin
        authentication settings. If omitted, the value from the current connection is used.

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
        Remove-SfosAdminAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosAdminAuthenticationMember -Members 'RADIUS-Server1' -Confirm:$false

        Removes 'RADIUS-Server1' without asking for confirmation, for use in scripts. This
        cmdlet asks for confirmation by default because removing the last server locks every
        administrator out.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAdminAuthentication

        .LINK
        Add-SfosAdminAuthenticationMember
#>
function Remove-SfosAdminAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.AuthenticationServerList).Count -eq 0) {
        # Nothing to remove
        return
    }

    $targetServers = [Collections.ArrayList]@()
    $targetServers.AddRange([string[]]@($existing.AuthenticationServerList))

    foreach ($member in $Members) {
        [int]$indexMember = $targetServers.IndexOf($member)
        if ($indexMember -ne -1) {
            $targetServers.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("AdminAuthentication on $($params.Firewall)", 'Remove members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.AuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <AdminAuthentication>
    <AuthenticationServerList>
        $xmlServers
    </AuthenticationServerList>
    <AuthenticationMethods>$methodsEsc</AuthenticationMethods>
  </AdminAuthentication>
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
        throw "Error removing members from AdminAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Not exercised against a real appliance - see Set-SfosAdminAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'remove members'
}

#endregion

#region VPNAuthentication

<#
        .SYNOPSIS
        Retrieves the VPN authentication configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the settings that control which authentication server or servers a VPN user
        uses to log in. There is exactly one instance of this object per firewall. The cmdlet
        only reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        VPNAuthenticationMethods and VPNAuthenticationServerList (the authentication servers
        in priority order). Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosVPNAuthentication

        Returns the current VPN authentication configuration.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosVPNAuthentication
#>
function Get-SfosVPNAuthentication {
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

    $inner = '<Get><VPNAuthentication></VPNAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving VPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A successful Get carries no Status node at all under
    # /Response/VPNAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/VPNAuthentication')
    if (-not $node) {
        throw 'VPNAuthentication could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $servers = [string[]]@($node.SelectNodes('VPNAuthenticationServerList/AuthenticationServer') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })

    return [PSCustomObject]@{
        VPNAuthenticationMethods    = [string]$node.VPNAuthenticationMethods
        VPNAuthenticationServerList = $servers
    }
}

<#
        .SYNOPSIS
        Updates the VPN authentication configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes which authentication server or servers, and which method, a VPN user uses to
        log in. The cmdlet reads the current configuration first and writes back a complete
        object: every field you pass replaces the current value, every field you omit keeps
        it. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update VPN
        authentication settings.

        .PARAMETER VPNAuthenticationMethods
        Optional. VPN authentication method. If omitted, the current value is kept.

        .PARAMETER AuthenticationServer
        Optional. One or more authentication server names to use for VPN login, in priority
        order. Replaces the current list. If omitted, the current list is kept. Prefer
        Add-SfosVPNAuthenticationMember or Remove-SfosVPNAuthenticationMember for incremental
        changes.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosVPNAuthentication -VPNAuthenticationMethods 'Custom' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosVPNAuthentication -VPNAuthenticationMethods 'Custom'

        Sets the VPN authentication method; the server list keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosVPNAuthentication
#>
function Set-SfosVPNAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$VPNAuthenticationMethods,

        [Alias('VPNAuthenticationServerList')]
        [string[]]$AuthenticationServer,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetMethods = if ($PSBoundParameters.ContainsKey('VPNAuthenticationMethods')) {
        $VPNAuthenticationMethods
    }
    else {
        [string]$existing.VPNAuthenticationMethods
    }

    $targetServers = if ($PSBoundParameters.ContainsKey('AuthenticationServer')) {
        @($AuthenticationServer)
    }
    else {
        @($existing.VPNAuthenticationServerList)
    }

    if (-not $PSCmdlet.ShouldProcess("VPNAuthentication on $($params.Firewall)", 'Update')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text $targetMethods

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <VPNAuthentication>
    <VPNAuthenticationMethods>$methodsEsc</VPNAuthenticationMethods>
    <VPNAuthenticationServerList>
        $xmlServers
    </VPNAuthenticationServerList>
  </VPNAuthentication>
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
        throw "Error updating VPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Status lands at /Response/VPNAuthentication/Status for
    # both the success and the 501 case.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the VPN authentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the server list used for VPN logins,
        keeping the existing servers and authentication method in place. Adding a server name
        already on the list is harmless; the firewall keeps a single entry. Adding a name that
        does not correspond to a configured authentication server is rejected and the list
        stays unchanged. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update VPN
        authentication settings.

        .PARAMETER Members
        Required. One or more authentication server names to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Add-SfosVPNAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosVPNAuthenticationMember -Members 'RADIUS-Server1'

        Adds 'RADIUS-Server1' alongside the existing servers.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosVPNAuthentication

        .LINK
        Remove-SfosVPNAuthenticationMember
#>
function Add-SfosVPNAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetServers = @()
    $targetServers += $existing.VPNAuthenticationServerList
    $targetServers += $Members
    $targetServers = @($targetServers | Where-Object { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("VPNAuthentication on $($params.Firewall)", 'Add members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.VPNAuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <VPNAuthentication>
    <VPNAuthenticationMethods>$methodsEsc</VPNAuthenticationMethods>
    <VPNAuthenticationServerList>
        $xmlServers
    </VPNAuthenticationServerList>
  </VPNAuthentication>
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
        throw "Error adding members to VPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosVPNAuthentication - Status lands at
    # /Response/VPNAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the VPN authentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the server list used for VPN logins,
        keeping the authentication method and every remaining server in place. The firewall
        refuses to remove the last server from the list; that call fails and the list stays
        unchanged. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update VPN
        authentication settings.

        .PARAMETER Members
        Required. One or more authentication server names to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Remove-SfosVPNAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosVPNAuthenticationMember -Members 'RADIUS-Server1'

        Removes 'RADIUS-Server1' from the server list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosVPNAuthentication

        .LINK
        Add-SfosVPNAuthenticationMember
#>
function Remove-SfosVPNAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.VPNAuthenticationServerList).Count -eq 0) {
        # Nothing to remove
        return
    }

    $targetServers = [Collections.ArrayList]@()
    $targetServers.AddRange([string[]]@($existing.VPNAuthenticationServerList))

    foreach ($member in $Members) {
        [int]$indexMember = $targetServers.IndexOf($member)
        if ($indexMember -ne -1) {
            $targetServers.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("VPNAuthentication on $($params.Firewall)", 'Remove members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.VPNAuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <VPNAuthentication>
    <VPNAuthenticationMethods>$methodsEsc</VPNAuthenticationMethods>
    <VPNAuthenticationServerList>
        $xmlServers
    </VPNAuthenticationServerList>
  </VPNAuthentication>
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
        throw "Error removing members from VPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosVPNAuthentication - Status lands at
    # /Response/VPNAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'remove members'
}

#endregion

#region SSLVPNAuthentication

<#
        .SYNOPSIS
        Retrieves the SSL VPN authentication configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the settings that control which authentication server or servers an SSL VPN
        user uses to log in. There is exactly one instance of this object per firewall. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for SSL VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        SSLVPNAuthenticationMethods and SSLVPNAuthenticationServerList (the authentication
        servers in priority order). Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosSSLVPNAuthentication

        Returns the current SSL VPN authentication configuration.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosSSLVPNAuthentication
#>
function Get-SfosSSLVPNAuthentication {
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

    $inner = '<Get><SSLVPNAuthentication></SSLVPNAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SSLVPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A successful Get carries no Status node at all under
    # /Response/SSLVPNAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SSLVPNAuthentication')
    if (-not $node) {
        throw 'SSLVPNAuthentication could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $servers = [string[]]@($node.SelectNodes('SSLVPNAuthenticationServerList/AuthenticationServer') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })

    return [PSCustomObject]@{
        SSLVPNAuthenticationMethods    = [string]$node.SSLVPNAuthenticationMethods
        SSLVPNAuthenticationServerList = $servers
    }
}

<#
        .SYNOPSIS
        Updates the SSL VPN authentication configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes which authentication server or servers, and which method, an SSL VPN user
        uses to log in. The cmdlet reads the current configuration first and writes back a
        complete object: every field you pass replaces the current value, every field you omit
        keeps it. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update SSL VPN
        authentication settings.

        .PARAMETER SSLVPNAuthenticationMethods
        Optional. SSL VPN authentication method. If omitted, the current value is kept.

        .PARAMETER AuthenticationServer
        Optional. One or more authentication server names to use for SSL VPN login, in
        priority order. Replaces the current list. If omitted, the current list is kept.
        Prefer Add-SfosSSLVPNAuthenticationMember or Remove-SfosSSLVPNAuthenticationMember for
        incremental changes.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update SSL VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosSSLVPNAuthentication -SSLVPNAuthenticationMethods 'Custom' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSSLVPNAuthentication -SSLVPNAuthenticationMethods 'Custom'

        Sets the SSL VPN authentication method; the server list keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLVPNAuthentication
#>
function Set-SfosSSLVPNAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$SSLVPNAuthenticationMethods,

        [Alias('SSLVPNAuthenticationServerList')]
        [string[]]$AuthenticationServer,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSSLVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetMethods = if ($PSBoundParameters.ContainsKey('SSLVPNAuthenticationMethods')) {
        $SSLVPNAuthenticationMethods
    }
    else {
        [string]$existing.SSLVPNAuthenticationMethods
    }

    $targetServers = if ($PSBoundParameters.ContainsKey('AuthenticationServer')) {
        @($AuthenticationServer)
    }
    else {
        @($existing.SSLVPNAuthenticationServerList)
    }

    if (-not $PSCmdlet.ShouldProcess("SSLVPNAuthentication on $($params.Firewall)", 'Update')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text $targetMethods

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <SSLVPNAuthentication>
    <SSLVPNAuthenticationMethods>$methodsEsc</SSLVPNAuthenticationMethods>
    <SSLVPNAuthenticationServerList>
        $xmlServers
    </SSLVPNAuthenticationServerList>
  </SSLVPNAuthentication>
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
        throw "Error updating SSLVPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Status lands at /Response/SSLVPNAuthentication/Status for
    # both the success and the 501 case.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the SSL VPN authentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the server list used for SSL VPN logins,
        keeping the existing servers and authentication method in place. Adding a server name
        already on the list is harmless; the firewall keeps a single entry. Adding a name that
        does not correspond to a configured authentication server is rejected and the list
        stays unchanged. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update SSL
        VPN authentication settings.

        .PARAMETER Members
        Required. One or more authentication server names to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update SSL VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Add-SfosSSLVPNAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosSSLVPNAuthenticationMember -Members 'RADIUS-Server1'

        Adds 'RADIUS-Server1' alongside the existing servers.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLVPNAuthentication

        .LINK
        Remove-SfosSSLVPNAuthenticationMember
#>
function Add-SfosSSLVPNAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSSLVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetServers = @()
    $targetServers += $existing.SSLVPNAuthenticationServerList
    $targetServers += $Members
    $targetServers = @($targetServers | Where-Object { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("SSLVPNAuthentication on $($params.Firewall)", 'Add members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.SSLVPNAuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <SSLVPNAuthentication>
    <SSLVPNAuthenticationMethods>$methodsEsc</SSLVPNAuthenticationMethods>
    <SSLVPNAuthenticationServerList>
        $xmlServers
    </SSLVPNAuthenticationServerList>
  </SSLVPNAuthentication>
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
        throw "Error adding members to SSLVPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosSSLVPNAuthentication - Status lands at
    # /Response/SSLVPNAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the SSL VPN authentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the server list used for SSL VPN
        logins, keeping the authentication method and every remaining server in place. The
        firewall refuses to remove the last server from the list; that call fails and the
        list stays unchanged. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update SSL
        VPN authentication settings.

        .PARAMETER Members
        Required. One or more authentication server names to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update SSL VPN
        authentication settings. If omitted, the value from the current connection is used.

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
        Remove-SfosSSLVPNAuthenticationMember -Members 'RADIUS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosSSLVPNAuthenticationMember -Members 'RADIUS-Server1'

        Removes 'RADIUS-Server1' from the server list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLVPNAuthentication

        .LINK
        Add-SfosSSLVPNAuthenticationMember
#>
function Remove-SfosSSLVPNAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSSLVPNAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.SSLVPNAuthenticationServerList).Count -eq 0) {
        # Nothing to remove
        return
    }

    $targetServers = [Collections.ArrayList]@()
    $targetServers.AddRange([string[]]@($existing.SSLVPNAuthenticationServerList))

    foreach ($member in $Members) {
        [int]$indexMember = $targetServers.IndexOf($member)
        if ($indexMember -ne -1) {
            $targetServers.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("SSLVPNAuthentication on $($params.Firewall)", 'Remove members')) {
        return
    }

    $methodsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.SSLVPNAuthenticationMethods)

    $xmlServers = ''
    foreach ($server in $targetServers) {
        if (-not $server) {
            continue
        }
        $serverEsc = ConvertTo-SfosXmlEscaped -Text $server
        $xmlServers += "<AuthenticationServer>$serverEsc</AuthenticationServer>"
    }

    $inner = @"
<Set operation="update">
  <SSLVPNAuthentication>
    <SSLVPNAuthenticationMethods>$methodsEsc</SSLVPNAuthenticationMethods>
    <SSLVPNAuthenticationServerList>
        $xmlServers
    </SSLVPNAuthenticationServerList>
  </SSLVPNAuthentication>
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
        throw "Error removing members from SSLVPNAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosSSLVPNAuthentication - Status lands at
    # /Response/SSLVPNAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'remove members'
}

#endregion

#region WebAuthenticationSettings

<#
        .SYNOPSIS
        Retrieves the web authentication settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide settings for the end-user captive portal login flow. There is
        exactly one instance of this object per firewall. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for web
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        DisplayCaptivePortalLink, UseHTTPS, LogOutUserSetting, DisplayUserPortalLink,
        DisplayWebpageAfterLogin, UseKerberosForADSSO, OpenWebpageInNewWindow and
        WebpageToDisplay. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosWebAuthenticationSettings

        Returns the current web authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosWebAuthenticationSettings
#>
function Get-SfosWebAuthenticationSettings {
    # PSUseSingularNouns is suppressed on purpose: <WebAuthenticationSettings> is the
    # entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
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

    $inner = '<Get><WebAuthentication></WebAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebAuthentication WebAuthenticationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Malformed sub-element sent under <Get><WebAuthentication>...: SFOS
    # never returns a Status node at all on a successful Get of this entity - Get is lenient
    # and simply ignores anything it does not recognise. A genuinely wrong entity name (e.g.
    # a typo of 'WebAuthentication' itself) answers a flat code="529" at
    # /Response/<WrongName>/Status, which the ObjectName below still catches because it names
    # the actual top-level entity. 'WebAuthentication' is therefore the correct ObjectName for
    # both Get-* cmdlets in this fragment that read from the shared container - not a nested
    # per-block path.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebAuthentication/WebAuthenticationSettings')
    if (-not $node) {
        throw 'WebAuthentication WebAuthenticationSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        DisplayCaptivePortalLink  = [string]$node.DisplayCaptivePortalLink
        UseHTTPS                  = [string]$node.UseHTTPS
        LogOutUserSetting         = [string]$node.LogOutUserSetting
        DisplayUserPortalLink     = [string]$node.DisplayUserPortalLink
        DisplayWebpageAfterLogin  = [string]$node.DisplayWebpageAfterLogin
        UseKerberosForADSSO       = [string]$node.UseKerberosForADSSO
        OpenWebpageInNewWindow    = [string]$node.OpenWebpageInNewWindow
        WebpageToDisplay          = [string]$node.WebpageToDisplay
    }
}

<#
        .SYNOPSIS
        Updates the web authentication settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide settings for the end-user captive portal login flow. The
        cmdlet reads the current settings first and writes back a complete object: every field
        you pass replaces the current value, every field you omit keeps it. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to update web authentication settings.

        These settings govern the end-user captive portal, not the web admin console or API
        access this module itself uses. -UseHTTPS toggles HTTPS for the captive portal
        service, unrelated to the management HTTPS port.

        Setting -OpenWebpageInNewWindow to 'Disable' is rejected by the firewall, even though
        every other field of this object accepts both Enable and Disable; the cause is not
        established.

        .PARAMETER DisplayCaptivePortalLink
        Optional. Whether a link to the captive portal is shown on the disconnected/block
        pages. Valid values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER UseHTTPS
        Optional. Whether the captive portal login page is served over HTTPS instead of HTTP.
        Valid values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER LogOutUserSetting
        Optional. Controls when a captive-portal-authenticated user is logged out. If omitted,
        the current value is kept.

        .PARAMETER DisplayUserPortalLink
        Optional. Whether a link to the User Portal is shown on the captive portal login page.
        Valid values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER DisplayWebpageAfterLogin
        Optional. Whether a webpage is shown to the user immediately after a successful
        captive portal login. Valid values: Enable, Disable. If omitted, the current value is
        kept.

        .PARAMETER UseKerberosForADSSO
        Optional. Whether Kerberos is used for Active Directory single sign-on during web
        authentication. Valid values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER OpenWebpageInNewWindow
        Optional. Whether the post-login webpage opens in a new browser window. Valid values:
        Enable, Disable. If omitted, the current value is kept.

        .PARAMETER WebpageToDisplay
        Optional. Which webpage to show after login. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update web
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosWebAuthenticationSettings -DisplayUserPortalLink Disable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebAuthenticationSettings -DisplayUserPortalLink Disable

        Hides the User Portal link on the captive portal login page; every other field keeps
        its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebAuthenticationSettings
#>
function Set-SfosWebAuthenticationSettings {
    # PSUseSingularNouns is suppressed on purpose: <WebAuthenticationSettings> is the
    # entity's own singleton name, not a plural container - it has no singular child
    # element, so the Sophos wire spelling is used as-is.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$DisplayCaptivePortalLink,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseHTTPS,

        [ValidateNotNullOrEmpty()]
        [string]$LogOutUserSetting,

        [ValidateSet('Enable', 'Disable')]
        [string]$DisplayUserPortalLink,

        [ValidateSet('Enable', 'Disable')]
        [string]$DisplayWebpageAfterLogin,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseKerberosForADSSO,

        [ValidateSet('Enable', 'Disable')]
        [string]$OpenWebpageInNewWindow,

        [ValidateNotNullOrEmpty()]
        [string]$WebpageToDisplay,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebAuthenticationSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetDisplayCaptivePortalLink = if ($PSBoundParameters.ContainsKey('DisplayCaptivePortalLink')) { $DisplayCaptivePortalLink } else { [string]$existing.DisplayCaptivePortalLink }
    $targetUseHTTPS                 = if ($PSBoundParameters.ContainsKey('UseHTTPS')) { $UseHTTPS } else { [string]$existing.UseHTTPS }
    $targetLogOutUserSetting        = if ($PSBoundParameters.ContainsKey('LogOutUserSetting')) { $LogOutUserSetting } else { [string]$existing.LogOutUserSetting }
    $targetDisplayUserPortalLink    = if ($PSBoundParameters.ContainsKey('DisplayUserPortalLink')) { $DisplayUserPortalLink } else { [string]$existing.DisplayUserPortalLink }
    $targetDisplayWebpageAfterLogin = if ($PSBoundParameters.ContainsKey('DisplayWebpageAfterLogin')) { $DisplayWebpageAfterLogin } else { [string]$existing.DisplayWebpageAfterLogin }
    $targetUseKerberosForADSSO      = if ($PSBoundParameters.ContainsKey('UseKerberosForADSSO')) { $UseKerberosForADSSO } else { [string]$existing.UseKerberosForADSSO }
    $targetOpenWebpageInNewWindow   = if ($PSBoundParameters.ContainsKey('OpenWebpageInNewWindow')) { $OpenWebpageInNewWindow } else { [string]$existing.OpenWebpageInNewWindow }
    $targetWebpageToDisplay         = if ($PSBoundParameters.ContainsKey('WebpageToDisplay')) { $WebpageToDisplay } else { [string]$existing.WebpageToDisplay }

    if (-not $PSCmdlet.ShouldProcess("WebAuthentication WebAuthenticationSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $displayCaptivePortalLinkEsc  = ConvertTo-SfosXmlEscaped -Text $targetDisplayCaptivePortalLink
    $useHTTPSEsc                  = ConvertTo-SfosXmlEscaped -Text $targetUseHTTPS
    $logOutUserSettingEsc         = ConvertTo-SfosXmlEscaped -Text $targetLogOutUserSetting
    $displayUserPortalLinkEsc     = ConvertTo-SfosXmlEscaped -Text $targetDisplayUserPortalLink
    $displayWebpageAfterLoginEsc  = ConvertTo-SfosXmlEscaped -Text $targetDisplayWebpageAfterLogin
    $useKerberosForADSSOEsc       = ConvertTo-SfosXmlEscaped -Text $targetUseKerberosForADSSO
    $openWebpageInNewWindowEsc    = ConvertTo-SfosXmlEscaped -Text $targetOpenWebpageInNewWindow
    $webpageToDisplayEsc          = ConvertTo-SfosXmlEscaped -Text $targetWebpageToDisplay

    $inner = @"
<Set operation="update">
  <WebAuthentication>
    <WebAuthenticationSettings>
      <DisplayCaptivePortalLink>$displayCaptivePortalLinkEsc</DisplayCaptivePortalLink>
      <UseHTTPS>$useHTTPSEsc</UseHTTPS>
      <LogOutUserSetting>$logOutUserSettingEsc</LogOutUserSetting>
      <DisplayUserPortalLink>$displayUserPortalLinkEsc</DisplayUserPortalLink>
      <DisplayWebpageAfterLogin>$displayWebpageAfterLoginEsc</DisplayWebpageAfterLogin>
      <UseKerberosForADSSO>$useKerberosForADSSOEsc</UseKerberosForADSSO>
      <OpenWebpageInNewWindow>$openWebpageInNewWindowEsc</OpenWebpageInNewWindow>
      <WebpageToDisplay>$webpageToDisplayEsc</WebpageToDisplay>
    </WebAuthenticationSettings>
  </WebAuthentication>
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
        throw "Error updating WebAuthentication WebAuthenticationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Forcing a 501 via an invalid UseHTTPS value: Status landed at
    # /Response/WebAuthenticationSettings/Status - top level, NOT nested under
    # WebAuthentication. Using the nested path here would be a fail-open: Core would find no
    # Status node there, fall back to /Response/Status, find nothing either, and return
    # silently - reporting success on a 501 that changed nothing.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebAuthenticationSettings' -Action 'update'
}

#endregion

#region CaptivePortalAppearance

<#
        .SYNOPSIS
        Retrieves the captive portal appearance settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the branding of the captive portal login page: logo, colours and field
        labels. There is exactly one instance of this object per firewall. The cmdlet only
        reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        The object holds two sets of fields, one for the default layout and one for a custom
        layout, selected by UseCustomLayout. Only the fields of the inactive layout read back
        empty; both sets are always present on the returned object.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for web
        authentication settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        UseCustomLayout, Logo, LogoImage, LogoLink, LoginPageHeaderHTML, UserPrompt,
        UsernameFieldLabel, PasswordFieldLabel, LoginButtonLabel, LogoutButtonLabel,
        UserPortalLinkLabel, RegistrationLinkLabel, SsoButtonLabel, LoginPageFooterHTML,
        BackgroundColor, UserPromptFontColor, PageTitleBackgroundColor,
        HeaderFooterFontColor, UserPortalLinkFontColor, UserDefinedTemplate and
        SystemGeneratedHtml. SystemGeneratedHtml is read-only; there is no way to set it.
        Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosCaptivePortalAppearance

        Returns the current captive portal branding.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosCaptivePortalAppearance
#>
function Get-SfosCaptivePortalAppearance {
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

    $inner = '<Get><WebAuthentication></WebAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebAuthentication CaptivePortalAppearance: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See Get-SfosWebAuthenticationSettings: 'WebAuthentication' is the ObjectName
    # for both Get-* cmdlets reading from the shared container in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebAuthentication/CaptivePortalAppearance')
    if (-not $node) {
        throw 'WebAuthentication CaptivePortalAppearance could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $layout = $node.SelectSingleNode('DefaultLayout')
    $customLayout = $node.SelectSingleNode('CustomLayout')

    return [PSCustomObject]@{
        UseCustomLayout           = [string]$node.UseCustomLayout
        Logo                      = if ($layout) { [string]$layout.Logo } else { '' }
        LogoImage                 = if ($layout) { [string]$layout.LogoImage } else { '' }
        LogoLink                  = if ($layout) { [string]$layout.LogoLink } else { '' }
        LoginPageHeaderHTML       = if ($layout) { [string]$layout.LoginPageHeaderHTML } else { '' }
        UserPrompt                = if ($layout) { [string]$layout.UserPrompt } else { '' }
        UsernameFieldLabel        = if ($layout) { [string]$layout.UsernameFieldLabel } else { '' }
        PasswordFieldLabel        = if ($layout) { [string]$layout.PasswordFieldLabel } else { '' }
        LoginButtonLabel          = if ($layout) { [string]$layout.LoginButtonLabel } else { '' }
        LogoutButtonLabel         = if ($layout) { [string]$layout.LogoutButtonLabel } else { '' }
        UserPortalLinkLabel       = if ($layout) { [string]$layout.UserPortalLinkLabel } else { '' }
        RegistrationLinkLabel     = if ($layout) { [string]$layout.RegistrationLinkLabel } else { '' }
        SsoButtonLabel            = if ($layout) { [string]$layout.SsoButtonLabel } else { '' }
        LoginPageFooterHTML       = if ($layout) { [string]$layout.LoginPageFooterHTML } else { '' }
        BackgroundColor           = if ($layout) { [string]$layout.BackgroundColor } else { '' }
        UserPromptFontColor       = if ($layout) { [string]$layout.UserPromptFontColor } else { '' }
        PageTitleBackgroundColor  = if ($layout) { [string]$layout.PageTitleBackgroundColor } else { '' }
        HeaderFooterFontColor     = if ($layout) { [string]$layout.HeaderFooterFontColor } else { '' }
        UserPortalLinkFontColor   = if ($layout) { [string]$layout.UserPortalLinkFontColor } else { '' }
        UserDefinedTemplate       = if ($customLayout) { [string]$customLayout.UserDefinedTemplate } else { '' }
        SystemGeneratedHtml       = if ($customLayout) { [string]$customLayout.SystemGeneratedHtml } else { '' }
    }
}

<#
        .SYNOPSIS
        Updates the captive portal appearance settings on a Sophos Firewall.

        .DESCRIPTION
        Changes the branding of the captive portal login page: logo, colours and field
        labels. The cmdlet reads the current settings first and writes back a complete object:
        every field you pass replaces the current value, every field you omit keeps it. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with permission to update web authentication
        settings.

        This cmdlet always sends both the default-layout and the custom-layout fields,
        regardless of which one -UseCustomLayout currently selects. -UserDefinedTemplate is
        only actually stored while -UseCustomLayout is 'Enable'; sending it together with
        'Disable' is accepted but discarded.

        .PARAMETER UseCustomLayout
        Optional. Whether a custom captive portal layout is used instead of the built-in
        default. Valid values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER Logo
        Optional. Logo source for the captive portal page. If omitted, the current value is
        kept.

        .PARAMETER LogoImage
        Optional. Uploaded logo image reference. If omitted, the current value is kept.

        .PARAMETER LogoLink
        Optional. Target URL when the logo is clicked. If omitted, the current value is kept.

        .PARAMETER LoginPageHeaderHTML
        Optional. Custom HTML injected above the login form. If omitted, the current value is
        kept.

        .PARAMETER UserPrompt
        Optional. Prompt text shown above the login form. If omitted, the current value is
        kept.

        .PARAMETER UsernameFieldLabel
        Optional. Label of the username field. If omitted, the current value is kept.

        .PARAMETER PasswordFieldLabel
        Optional. Label of the password field. If omitted, the current value is kept.

        .PARAMETER LoginButtonLabel
        Optional. Label of the login button. If omitted, the current value is kept.

        .PARAMETER LogoutButtonLabel
        Optional. Label of the logout button. If omitted, the current value is kept.

        .PARAMETER UserPortalLinkLabel
        Optional. Label of the link to the User Portal. If omitted, the current value is kept.

        .PARAMETER RegistrationLinkLabel
        Optional. Label of the guest registration link. If omitted, the current value is kept.

        .PARAMETER SsoButtonLabel
        Optional. Label of the single sign-on button. If omitted, the current value is kept.

        .PARAMETER LoginPageFooterHTML
        Optional. Custom HTML injected below the login form. If omitted, the current value is
        kept.

        .PARAMETER BackgroundColor
        Optional. Page background colour, as a 6-digit hex string without '#'. If omitted, the
        current value is kept.

        .PARAMETER UserPromptFontColor
        Optional. Font colour of the prompt text, as a 6-digit hex string without '#'. If
        omitted, the current value is kept.

        .PARAMETER PageTitleBackgroundColor
        Optional. Background colour of the page title bar, as a 6-digit hex string without
        '#'. If omitted, the current value is kept.

        .PARAMETER HeaderFooterFontColor
        Optional. Font colour of the header/footer text, as a 6-digit hex string without '#'.
        If omitted, the current value is kept.

        .PARAMETER UserPortalLinkFontColor
        Optional. Font colour of the User Portal link, as a 6-digit hex string without '#'. If
        omitted, the current value is kept.

        .PARAMETER UserDefinedTemplate
        Optional. Raw HTML template used for the captive portal login page when
        -UseCustomLayout is 'Enable'. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update web
        authentication settings. If omitted, the value from the current connection is used.

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
        Set-SfosCaptivePortalAppearance -UserPrompt 'Please sign in' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosCaptivePortalAppearance -UserPrompt 'Please sign in'

        Changes the sign-in prompt text; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosCaptivePortalAppearance
#>
function Set-SfosCaptivePortalAppearance {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives: -PasswordFieldLabel is the caption text shown next to the password
    # input box on the captive portal login page, not a credential, and the fixed
    # connection -Password parameter is already a SecureString.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordFieldLabel')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$UseCustomLayout,

        [string]$Logo,
        [string]$LogoImage,
        [string]$LogoLink,
        [string]$LoginPageHeaderHTML,
        [string]$UserPrompt,
        [string]$UsernameFieldLabel,
        [string]$PasswordFieldLabel,
        [string]$LoginButtonLabel,
        [string]$LogoutButtonLabel,
        [string]$UserPortalLinkLabel,
        [string]$RegistrationLinkLabel,
        [string]$SsoButtonLabel,
        [string]$LoginPageFooterHTML,

        [ValidatePattern('^[0-9A-Fa-f]{6}$')]
        [string]$BackgroundColor,

        [ValidatePattern('^[0-9A-Fa-f]{6}$')]
        [string]$UserPromptFontColor,

        [ValidatePattern('^[0-9A-Fa-f]{6}$')]
        [string]$PageTitleBackgroundColor,

        [ValidatePattern('^[0-9A-Fa-f]{6}$')]
        [string]$HeaderFooterFontColor,

        [ValidatePattern('^[0-9A-Fa-f]{6}$')]
        [string]$UserPortalLinkFontColor,

        [string]$UserDefinedTemplate,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosCaptivePortalAppearance -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetUseCustomLayout          = if ($PSBoundParameters.ContainsKey('UseCustomLayout')) { $UseCustomLayout } else { [string]$existing.UseCustomLayout }
    $targetLogo                     = if ($PSBoundParameters.ContainsKey('Logo')) { $Logo } else { [string]$existing.Logo }
    $targetLogoImage                = if ($PSBoundParameters.ContainsKey('LogoImage')) { $LogoImage } else { [string]$existing.LogoImage }
    $targetLogoLink                 = if ($PSBoundParameters.ContainsKey('LogoLink')) { $LogoLink } else { [string]$existing.LogoLink }
    $targetLoginPageHeaderHTML      = if ($PSBoundParameters.ContainsKey('LoginPageHeaderHTML')) { $LoginPageHeaderHTML } else { [string]$existing.LoginPageHeaderHTML }
    $targetUserPrompt                = if ($PSBoundParameters.ContainsKey('UserPrompt')) { $UserPrompt } else { [string]$existing.UserPrompt }
    $targetUsernameFieldLabel       = if ($PSBoundParameters.ContainsKey('UsernameFieldLabel')) { $UsernameFieldLabel } else { [string]$existing.UsernameFieldLabel }
    $targetPasswordFieldLabel       = if ($PSBoundParameters.ContainsKey('PasswordFieldLabel')) { $PasswordFieldLabel } else { [string]$existing.PasswordFieldLabel }
    $targetLoginButtonLabel         = if ($PSBoundParameters.ContainsKey('LoginButtonLabel')) { $LoginButtonLabel } else { [string]$existing.LoginButtonLabel }
    $targetLogoutButtonLabel        = if ($PSBoundParameters.ContainsKey('LogoutButtonLabel')) { $LogoutButtonLabel } else { [string]$existing.LogoutButtonLabel }
    $targetUserPortalLinkLabel      = if ($PSBoundParameters.ContainsKey('UserPortalLinkLabel')) { $UserPortalLinkLabel } else { [string]$existing.UserPortalLinkLabel }
    $targetRegistrationLinkLabel    = if ($PSBoundParameters.ContainsKey('RegistrationLinkLabel')) { $RegistrationLinkLabel } else { [string]$existing.RegistrationLinkLabel }
    $targetSsoButtonLabel           = if ($PSBoundParameters.ContainsKey('SsoButtonLabel')) { $SsoButtonLabel } else { [string]$existing.SsoButtonLabel }
    $targetLoginPageFooterHTML      = if ($PSBoundParameters.ContainsKey('LoginPageFooterHTML')) { $LoginPageFooterHTML } else { [string]$existing.LoginPageFooterHTML }
    $targetBackgroundColor          = if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $BackgroundColor } else { [string]$existing.BackgroundColor }
    $targetUserPromptFontColor      = if ($PSBoundParameters.ContainsKey('UserPromptFontColor')) { $UserPromptFontColor } else { [string]$existing.UserPromptFontColor }
    $targetPageTitleBackgroundColor = if ($PSBoundParameters.ContainsKey('PageTitleBackgroundColor')) { $PageTitleBackgroundColor } else { [string]$existing.PageTitleBackgroundColor }
    $targetHeaderFooterFontColor    = if ($PSBoundParameters.ContainsKey('HeaderFooterFontColor')) { $HeaderFooterFontColor } else { [string]$existing.HeaderFooterFontColor }
    $targetUserPortalLinkFontColor  = if ($PSBoundParameters.ContainsKey('UserPortalLinkFontColor')) { $UserPortalLinkFontColor } else { [string]$existing.UserPortalLinkFontColor }
    $targetUserDefinedTemplate      = if ($PSBoundParameters.ContainsKey('UserDefinedTemplate')) { $UserDefinedTemplate } else { [string]$existing.UserDefinedTemplate }

    if (-not $PSCmdlet.ShouldProcess("WebAuthentication CaptivePortalAppearance on $($params.Firewall)", 'Update')) {
        return
    }

    $useCustomLayoutEsc          = ConvertTo-SfosXmlEscaped -Text $targetUseCustomLayout
    $logoEsc                     = ConvertTo-SfosXmlEscaped -Text $targetLogo
    $logoImageEsc                = ConvertTo-SfosXmlEscaped -Text $targetLogoImage
    $logoLinkEsc                 = ConvertTo-SfosXmlEscaped -Text $targetLogoLink
    $loginPageHeaderHTMLEsc      = ConvertTo-SfosXmlEscaped -Text $targetLoginPageHeaderHTML
    $userPromptEsc               = ConvertTo-SfosXmlEscaped -Text $targetUserPrompt
    $usernameFieldLabelEsc       = ConvertTo-SfosXmlEscaped -Text $targetUsernameFieldLabel
    $passwordFieldLabelEsc       = ConvertTo-SfosXmlEscaped -Text $targetPasswordFieldLabel
    $loginButtonLabelEsc         = ConvertTo-SfosXmlEscaped -Text $targetLoginButtonLabel
    $logoutButtonLabelEsc        = ConvertTo-SfosXmlEscaped -Text $targetLogoutButtonLabel
    $userPortalLinkLabelEsc      = ConvertTo-SfosXmlEscaped -Text $targetUserPortalLinkLabel
    $registrationLinkLabelEsc    = ConvertTo-SfosXmlEscaped -Text $targetRegistrationLinkLabel
    $ssoButtonLabelEsc           = ConvertTo-SfosXmlEscaped -Text $targetSsoButtonLabel
    $loginPageFooterHTMLEsc      = ConvertTo-SfosXmlEscaped -Text $targetLoginPageFooterHTML
    $backgroundColorEsc          = ConvertTo-SfosXmlEscaped -Text $targetBackgroundColor
    $userPromptFontColorEsc      = ConvertTo-SfosXmlEscaped -Text $targetUserPromptFontColor
    $pageTitleBackgroundColorEsc = ConvertTo-SfosXmlEscaped -Text $targetPageTitleBackgroundColor
    $headerFooterFontColorEsc    = ConvertTo-SfosXmlEscaped -Text $targetHeaderFooterFontColor
    $userPortalLinkFontColorEsc  = ConvertTo-SfosXmlEscaped -Text $targetUserPortalLinkFontColor
    $userDefinedTemplateEsc      = ConvertTo-SfosXmlEscaped -Text $targetUserDefinedTemplate

    $inner = @"
<Set operation="update">
  <WebAuthentication>
    <CaptivePortalAppearance>
      <UseCustomLayout>$useCustomLayoutEsc</UseCustomLayout>
      <DefaultLayout>
        <Logo>$logoEsc</Logo>
        <LogoImage>$logoImageEsc</LogoImage>
        <LogoLink>$logoLinkEsc</LogoLink>
        <LoginPageHeaderHTML>$loginPageHeaderHTMLEsc</LoginPageHeaderHTML>
        <UserPrompt>$userPromptEsc</UserPrompt>
        <UsernameFieldLabel>$usernameFieldLabelEsc</UsernameFieldLabel>
        <PasswordFieldLabel>$passwordFieldLabelEsc</PasswordFieldLabel>
        <LoginButtonLabel>$loginButtonLabelEsc</LoginButtonLabel>
        <LogoutButtonLabel>$logoutButtonLabelEsc</LogoutButtonLabel>
        <UserPortalLinkLabel>$userPortalLinkLabelEsc</UserPortalLinkLabel>
        <RegistrationLinkLabel>$registrationLinkLabelEsc</RegistrationLinkLabel>
        <SsoButtonLabel>$ssoButtonLabelEsc</SsoButtonLabel>
        <LoginPageFooterHTML>$loginPageFooterHTMLEsc</LoginPageFooterHTML>
        <BackgroundColor>$backgroundColorEsc</BackgroundColor>
        <UserPromptFontColor>$userPromptFontColorEsc</UserPromptFontColor>
        <PageTitleBackgroundColor>$pageTitleBackgroundColorEsc</PageTitleBackgroundColor>
        <HeaderFooterFontColor>$headerFooterFontColorEsc</HeaderFooterFontColor>
        <UserPortalLinkFontColor>$userPortalLinkFontColorEsc</UserPortalLinkFontColor>
      </DefaultLayout>
      <CustomLayout>
        <UserDefinedTemplate>$userDefinedTemplateEsc</UserDefinedTemplate>
      </CustomLayout>
    </CaptivePortalAppearance>
  </WebAuthentication>
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
        throw "Error updating WebAuthentication CaptivePortalAppearance: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Forcing a 501 via an invalid UseCustomLayout value: Status landed at
    # /Response/CaptivePortalAppearance/Status - top level, not nested under WebAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CaptivePortalAppearance' -Action 'update'
}

#endregion

#region DefaultCaptivePortal

<#
        .SYNOPSIS
        Retrieves the default captive portal wording from a Sophos Firewall.

        .DESCRIPTION
        Returns the labels, status messages and login page template used by the built-in
        captive portal. There is exactly one instance of this object per firewall. The cmdlet
        only reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for captive
        portal settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        UserPrompt, UsernameFieldLabel, PasswordFieldLabel, LoginButtonLabel,
        LogoutButtonLabel, UserPortalLinkLabel, RegistrationLinkLabel,
        CredentialLoginButtonLabel, UserDefinedTemplate, LoginPageHeaderHTML,
        LoginPageFooterHTML, DoNotClosePage, WillBeSignedOut, SsoSignedOut, SigningIn,
        EnterUsername and EnterPassword. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosDefaultCaptivePortal

        Returns the current captive portal wording and login page template.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosDefaultCaptivePortal
#>
function Get-SfosDefaultCaptivePortal {
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

    $inner = '<Get><DefaultCaptivePortal></DefaultCaptivePortal></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DefaultCaptivePortal: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # DefaultCaptivePortal is a top-level entity (not nested under WebAuthentication), and a
    # genuinely wrong entity name answers a flat code="529" at /Response/<Name>/Status.
    # 'DefaultCaptivePortal' is therefore the correct ObjectName.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultCaptivePortal' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DefaultCaptivePortal')
    if (-not $node) {
        throw 'DefaultCaptivePortal could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        UserPrompt                 = [string]$node.UserPrompt
        UsernameFieldLabel         = [string]$node.UsernameFieldLabel
        PasswordFieldLabel         = [string]$node.PasswordFieldLabel
        LoginButtonLabel           = [string]$node.LoginButtonLabel
        LogoutButtonLabel          = [string]$node.LogoutButtonLabel
        UserPortalLinkLabel        = [string]$node.UserPortalLinkLabel
        RegistrationLinkLabel      = [string]$node.RegistrationLinkLabel
        CredentialLoginButtonLabel = [string]$node.CredentialLoginButtonLabel
        UserDefinedTemplate        = [string]$node.UserDefinedTemplate
        LoginPageHeaderHTML        = [string]$node.LoginPageHeaderHTML
        LoginPageFooterHTML        = [string]$node.LoginPageFooterHTML
        DoNotClosePage             = [string]$node.DoNotClosePage
        WillBeSignedOut            = [string]$node.WillBeSignedOut
        SsoSignedOut               = [string]$node.SsoSignedOut
        SigningIn                  = [string]$node.SigningIn
        EnterUsername               = [string]$node.EnterUsername
        EnterPassword               = [string]$node.EnterPassword
    }
}

<#
        .SYNOPSIS
        Updates the default captive portal wording on a Sophos Firewall.

        .DESCRIPTION
        Changes the labels, status messages and login page template used by the built-in
        captive portal. The cmdlet reads the current configuration first and writes back a
        complete object: every field you pass replaces the current value, every field you omit
        keeps it. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to update captive portal
        settings.

        .PARAMETER UserPrompt
        Optional. Prompt text shown above the login form. If omitted, the current value is
        kept.

        .PARAMETER UsernameFieldLabel
        Optional. Label of the username field. If omitted, the current value is kept.

        .PARAMETER PasswordFieldLabel
        Optional. Label of the password field. If omitted, the current value is kept.

        .PARAMETER LoginButtonLabel
        Optional. Label of the login button. If omitted, the current value is kept.

        .PARAMETER LogoutButtonLabel
        Optional. Label of the logout button. If omitted, the current value is kept.

        .PARAMETER UserPortalLinkLabel
        Optional. Label of the link to the User Portal. If omitted, the current value is kept.

        .PARAMETER RegistrationLinkLabel
        Optional. Label of the guest registration link. If omitted, the current value is kept.

        .PARAMETER CredentialLoginButtonLabel
        Optional. Label of the credential login button. If omitted, the current value is kept.

        .PARAMETER UserDefinedTemplate
        Optional. Raw HTML template of the captive portal login page. If omitted, the current
        value is kept.

        .PARAMETER LoginPageHeaderHTML
        Optional. Custom HTML injected above the login form. If omitted, the current value is
        kept.

        .PARAMETER LoginPageFooterHTML
        Optional. Custom HTML injected below the login form. If omitted, the current value is
        kept.

        .PARAMETER DoNotClosePage
        Optional. Wording of the "do not close this page" notice. If omitted, the current
        value is kept.

        .PARAMETER WillBeSignedOut
        Optional. Wording warning the user they will be signed out if they close the page. If
        omitted, the current value is kept.

        .PARAMETER SsoSignedOut
        Optional. Wording of the single sign-on sign-out instructions. If omitted, the current
        value is kept.

        .PARAMETER SigningIn
        Optional. Wording shown while the sign-in is in progress. If omitted, the current
        value is kept.

        .PARAMETER EnterUsername
        Optional. Validation message shown when the username field is left empty. If omitted,
        the current value is kept.

        .PARAMETER EnterPassword
        Optional. Validation message shown when the password field is left empty. If omitted,
        the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update captive
        portal settings. If omitted, the value from the current connection is used.

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
        Set-SfosDefaultCaptivePortal -UserPrompt 'Please sign in to continue' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDefaultCaptivePortal -UserPrompt 'Please sign in to continue'

        Changes the sign-in prompt text; every other field keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDefaultCaptivePortal
#>
function Set-SfosDefaultCaptivePortal {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives: -PasswordFieldLabel, -CredentialLoginButtonLabel and -EnterPassword are
    # caption texts shown on the default captive portal login page, not credentials, and
    # the fixed connection -Password parameter is already a
    # SecureString.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordFieldLabel')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialLoginButtonLabel')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'EnterPassword')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$UserPrompt,
        [string]$UsernameFieldLabel,
        [string]$PasswordFieldLabel,
        [string]$LoginButtonLabel,
        [string]$LogoutButtonLabel,
        [string]$UserPortalLinkLabel,
        [string]$RegistrationLinkLabel,
        [string]$CredentialLoginButtonLabel,
        [string]$UserDefinedTemplate,
        [string]$LoginPageHeaderHTML,
        [string]$LoginPageFooterHTML,
        [string]$DoNotClosePage,
        [string]$WillBeSignedOut,
        [string]$SsoSignedOut,
        [string]$SigningIn,
        [string]$EnterUsername,
        [string]$EnterPassword,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDefaultCaptivePortal -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetUserPrompt                 = if ($PSBoundParameters.ContainsKey('UserPrompt')) { $UserPrompt } else { [string]$existing.UserPrompt }
    $targetUsernameFieldLabel         = if ($PSBoundParameters.ContainsKey('UsernameFieldLabel')) { $UsernameFieldLabel } else { [string]$existing.UsernameFieldLabel }
    $targetPasswordFieldLabel         = if ($PSBoundParameters.ContainsKey('PasswordFieldLabel')) { $PasswordFieldLabel } else { [string]$existing.PasswordFieldLabel }
    $targetLoginButtonLabel           = if ($PSBoundParameters.ContainsKey('LoginButtonLabel')) { $LoginButtonLabel } else { [string]$existing.LoginButtonLabel }
    $targetLogoutButtonLabel          = if ($PSBoundParameters.ContainsKey('LogoutButtonLabel')) { $LogoutButtonLabel } else { [string]$existing.LogoutButtonLabel }
    $targetUserPortalLinkLabel        = if ($PSBoundParameters.ContainsKey('UserPortalLinkLabel')) { $UserPortalLinkLabel } else { [string]$existing.UserPortalLinkLabel }
    $targetRegistrationLinkLabel      = if ($PSBoundParameters.ContainsKey('RegistrationLinkLabel')) { $RegistrationLinkLabel } else { [string]$existing.RegistrationLinkLabel }
    $targetCredentialLoginButtonLabel = if ($PSBoundParameters.ContainsKey('CredentialLoginButtonLabel')) { $CredentialLoginButtonLabel } else { [string]$existing.CredentialLoginButtonLabel }
    $targetUserDefinedTemplate        = if ($PSBoundParameters.ContainsKey('UserDefinedTemplate')) { $UserDefinedTemplate } else { [string]$existing.UserDefinedTemplate }
    $targetLoginPageHeaderHTML        = if ($PSBoundParameters.ContainsKey('LoginPageHeaderHTML')) { $LoginPageHeaderHTML } else { [string]$existing.LoginPageHeaderHTML }
    $targetLoginPageFooterHTML        = if ($PSBoundParameters.ContainsKey('LoginPageFooterHTML')) { $LoginPageFooterHTML } else { [string]$existing.LoginPageFooterHTML }
    $targetDoNotClosePage             = if ($PSBoundParameters.ContainsKey('DoNotClosePage')) { $DoNotClosePage } else { [string]$existing.DoNotClosePage }
    $targetWillBeSignedOut            = if ($PSBoundParameters.ContainsKey('WillBeSignedOut')) { $WillBeSignedOut } else { [string]$existing.WillBeSignedOut }
    $targetSsoSignedOut               = if ($PSBoundParameters.ContainsKey('SsoSignedOut')) { $SsoSignedOut } else { [string]$existing.SsoSignedOut }
    $targetSigningIn                  = if ($PSBoundParameters.ContainsKey('SigningIn')) { $SigningIn } else { [string]$existing.SigningIn }
    $targetEnterUsername              = if ($PSBoundParameters.ContainsKey('EnterUsername')) { $EnterUsername } else { [string]$existing.EnterUsername }
    $targetEnterPassword              = if ($PSBoundParameters.ContainsKey('EnterPassword')) { $EnterPassword } else { [string]$existing.EnterPassword }

    if (-not $PSCmdlet.ShouldProcess("DefaultCaptivePortal on $($params.Firewall)", 'Update')) {
        return
    }

    $userPromptEsc                 = ConvertTo-SfosXmlEscaped -Text $targetUserPrompt
    $usernameFieldLabelEsc         = ConvertTo-SfosXmlEscaped -Text $targetUsernameFieldLabel
    $passwordFieldLabelEsc         = ConvertTo-SfosXmlEscaped -Text $targetPasswordFieldLabel
    $loginButtonLabelEsc           = ConvertTo-SfosXmlEscaped -Text $targetLoginButtonLabel
    $logoutButtonLabelEsc          = ConvertTo-SfosXmlEscaped -Text $targetLogoutButtonLabel
    $userPortalLinkLabelEsc        = ConvertTo-SfosXmlEscaped -Text $targetUserPortalLinkLabel
    $registrationLinkLabelEsc      = ConvertTo-SfosXmlEscaped -Text $targetRegistrationLinkLabel
    $credentialLoginButtonLabelEsc = ConvertTo-SfosXmlEscaped -Text $targetCredentialLoginButtonLabel
    $userDefinedTemplateEsc        = ConvertTo-SfosXmlEscaped -Text $targetUserDefinedTemplate
    $loginPageHeaderHTMLEsc        = ConvertTo-SfosXmlEscaped -Text $targetLoginPageHeaderHTML
    $loginPageFooterHTMLEsc        = ConvertTo-SfosXmlEscaped -Text $targetLoginPageFooterHTML
    $doNotClosePageEsc             = ConvertTo-SfosXmlEscaped -Text $targetDoNotClosePage
    $willBeSignedOutEsc            = ConvertTo-SfosXmlEscaped -Text $targetWillBeSignedOut
    $ssoSignedOutEsc               = ConvertTo-SfosXmlEscaped -Text $targetSsoSignedOut
    $signingInEsc                  = ConvertTo-SfosXmlEscaped -Text $targetSigningIn
    $enterUsernameEsc              = ConvertTo-SfosXmlEscaped -Text $targetEnterUsername
    $enterPasswordEsc              = ConvertTo-SfosXmlEscaped -Text $targetEnterPassword

    $inner = @"
<Set operation="update">
  <DefaultCaptivePortal>
    <UserPrompt>$userPromptEsc</UserPrompt>
    <UsernameFieldLabel>$usernameFieldLabelEsc</UsernameFieldLabel>
    <PasswordFieldLabel>$passwordFieldLabelEsc</PasswordFieldLabel>
    <LoginButtonLabel>$loginButtonLabelEsc</LoginButtonLabel>
    <LogoutButtonLabel>$logoutButtonLabelEsc</LogoutButtonLabel>
    <UserPortalLinkLabel>$userPortalLinkLabelEsc</UserPortalLinkLabel>
    <RegistrationLinkLabel>$registrationLinkLabelEsc</RegistrationLinkLabel>
    <CredentialLoginButtonLabel>$credentialLoginButtonLabelEsc</CredentialLoginButtonLabel>
    <UserDefinedTemplate>$userDefinedTemplateEsc</UserDefinedTemplate>
    <LoginPageHeaderHTML>$loginPageHeaderHTMLEsc</LoginPageHeaderHTML>
    <LoginPageFooterHTML>$loginPageFooterHTMLEsc</LoginPageFooterHTML>
    <DoNotClosePage>$doNotClosePageEsc</DoNotClosePage>
    <WillBeSignedOut>$willBeSignedOutEsc</WillBeSignedOut>
    <SsoSignedOut>$ssoSignedOutEsc</SsoSignedOut>
    <SigningIn>$signingInEsc</SigningIn>
    <EnterUsername>$enterUsernameEsc</EnterUsername>
    <EnterPassword>$enterPasswordEsc</EnterPassword>
  </DefaultCaptivePortal>
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
        throw "Error updating DefaultCaptivePortal: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A Set carrying only an unrecognised element, no valid operation
    # attribute misuse: Status landed at /Response/DefaultCaptivePortal/Status - top level,
    # matching the entity's own top-level nesting.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultCaptivePortal' -Action 'update'
}

#endregion

#region DirectWebProxyAuthentication

<#
        .SYNOPSIS
        Retrieves the direct web proxy authentication configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the per-connection authentication setting for the direct (non-transparent) web
        proxy, together with the list of multi-user hosts (for example terminal servers) that
        are exempted from per-user session caching. There is exactly one instance of this
        object per firewall. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for direct
        web proxy authentication settings. If omitted, the value from the current connection
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        PerConnectionAuth and MultiUserHostList. MultiUserHostList is an empty array when no
        multi-user host is configured. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosDirectWebProxyAuthentication

        Returns the current direct web proxy authentication configuration.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosDirectWebProxyAuthentication
#>
function Get-SfosDirectWebProxyAuthentication {
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

    $inner = '<Get><DirectWebProxyAuthentication></DirectWebProxyAuthentication></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DirectWebProxyAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # DirectWebProxyAuthentication is a top-level entity. Same measurement basis as
    # Get-SfosDefaultCaptivePortal: a genuinely wrong entity name answers a flat code="529" at
    # /Response/<Name>/Status, so 'DirectWebProxyAuthentication' is the correct ObjectName.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DirectWebProxyAuthentication')
    if (-not $node) {
        throw 'DirectWebProxyAuthentication could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $hosts = [string[]]@($node.SelectNodes('MultiUserHosts/Host') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })

    return [PSCustomObject]@{
        PerConnectionAuth  = [string]$node.PerConnectionAuth
        MultiUserHostList  = $hosts
    }
}

<#
        .SYNOPSIS
        Updates the direct web proxy authentication configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes the per-connection authentication setting for the direct web proxy and its
        multi-user host list. The cmdlet reads the current configuration first and writes back
        a complete object: every field you pass replaces the current value, every field you
        omit keeps it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to update
        direct web proxy authentication settings.

        Setting -PerConnectionAuth to 'Enable' is rejected by the firewall; only 'Disable' and
        an unchanged resend of the current value succeed. Use Add-SfosDirectWebProxyAuthenticationMember
        or Remove-SfosDirectWebProxyAuthenticationMember to change the host list
        incrementally instead of replacing it outright.

        .PARAMETER PerConnectionAuth
        Optional. Whether authentication is required for every connection through the direct
        web proxy, rather than cached per session. Valid values: Enable, Disable. If omitted,
        the current value is kept.

        .PARAMETER MultiUserHost
        Optional. One or more host object names to treat as multi-user hosts, whose traffic is
        excluded from per-user session caching. Replaces the current list. If omitted, the
        current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update direct
        web proxy authentication settings. If omitted, the value from the current connection
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Disable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Disable

        Turns off per-connection authentication on the direct web proxy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDirectWebProxyAuthentication
#>
function Set-SfosDirectWebProxyAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$PerConnectionAuth,

        [string[]]$MultiUserHost,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDirectWebProxyAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetPerConnectionAuth = if ($PSBoundParameters.ContainsKey('PerConnectionAuth')) {
        $PerConnectionAuth
    }
    else {
        [string]$existing.PerConnectionAuth
    }

    $targetHosts = if ($PSBoundParameters.ContainsKey('MultiUserHost')) {
        @($MultiUserHost)
    }
    else {
        @($existing.MultiUserHostList)
    }

    if (-not $PSCmdlet.ShouldProcess("DirectWebProxyAuthentication on $($params.Firewall)", 'Update')) {
        return
    }

    $perConnectionAuthEsc = ConvertTo-SfosXmlEscaped -Text $targetPerConnectionAuth

    $xmlHosts = ''
    foreach ($hostName in $targetHosts) {
        if (-not $hostName) {
            continue
        }
        $hostEsc = ConvertTo-SfosXmlEscaped -Text $hostName
        $xmlHosts += "<Host>$hostEsc</Host>"
    }

    $multiUserHostsBlock = if ($xmlHosts) { "<MultiUserHosts>$xmlHosts</MultiUserHosts>" } else { '' }

    $inner = @"
<Set operation="update">
  <DirectWebProxyAuthentication>
    <PerConnectionAuth>$perConnectionAuthEsc</PerConnectionAuth>
    $multiUserHostsBlock
  </DirectWebProxyAuthentication>
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
        throw "Error updating DirectWebProxyAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Forcing a 501 via an invalid PerConnectionAuth value: Status landed at
    # /Response/DirectWebProxyAuthentication/Status - top level, matching the entity's own
    # top-level nesting.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds hosts to the direct web proxy multi-user host list.

        .DESCRIPTION
        Adds one or more host object names to the multi-user host list, keeping the existing
        hosts and the per-connection authentication setting in place. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to update direct web proxy authentication settings.

        .PARAMETER Members
        Required. One or more host object names to add to the multi-user host list.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update direct
        web proxy authentication settings. If omitted, the value from the current connection
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server1'

        Adds 'TS-Server1' to the multi-user host list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDirectWebProxyAuthentication

        .LINK
        Remove-SfosDirectWebProxyAuthenticationMember
#>
function Add-SfosDirectWebProxyAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDirectWebProxyAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetHosts = @()
    $targetHosts += $existing.MultiUserHostList
    $targetHosts += $Members
    $targetHosts = @($targetHosts | Where-Object { $_ } | Select-Object -Unique)

    if (-not $PSCmdlet.ShouldProcess("DirectWebProxyAuthentication on $($params.Firewall)", 'Add members')) {
        return
    }

    $perConnectionAuthEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.PerConnectionAuth)

    $xmlHosts = ''
    foreach ($hostName in $targetHosts) {
        $hostEsc = ConvertTo-SfosXmlEscaped -Text $hostName
        $xmlHosts += "<Host>$hostEsc</Host>"
    }

    $inner = @"
<Set operation="update">
  <DirectWebProxyAuthentication>
    <PerConnectionAuth>$perConnectionAuthEsc</PerConnectionAuth>
    <MultiUserHosts>$xmlHosts</MultiUserHosts>
  </DirectWebProxyAuthentication>
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
        throw "Error adding members to DirectWebProxyAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosDirectWebProxyAuthentication - Status lands at
    # /Response/DirectWebProxyAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes hosts from the direct web proxy multi-user host list.

        .DESCRIPTION
        Removes one or more host object names from the multi-user host list, keeping the
        per-connection authentication setting and every remaining host in place. After
        writing, this cmdlet reads the list back and throws if a host that was supposed to be
        removed is still present. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with permission to update
        direct web proxy authentication settings.

        .PARAMETER Members
        Required. One or more host object names to remove from the multi-user host list.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update direct
        web proxy authentication settings. If omitted, the value from the current connection
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output. It raises an error if the firewall rejects the
        update, or if a host that should have been removed is still present afterward.

        .EXAMPLE
        Remove-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server1'

        Removes 'TS-Server1' from the multi-user host list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDirectWebProxyAuthentication

        .LINK
        Add-SfosDirectWebProxyAuthenticationMember
#>
function Remove-SfosDirectWebProxyAuthenticationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDirectWebProxyAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (@($existing.MultiUserHostList).Count -eq 0) {
        # Nothing to remove
        return
    }

    $targetHosts = [Collections.ArrayList]@()
    $targetHosts.AddRange([string[]]@($existing.MultiUserHostList))

    foreach ($member in $Members) {
        [int]$indexMember = $targetHosts.IndexOf($member)
        if ($indexMember -ne -1) {
            $targetHosts.RemoveAt($indexMember)
        }
    }

    if (-not $PSCmdlet.ShouldProcess("DirectWebProxyAuthentication on $($params.Firewall)", 'Remove members')) {
        return
    }

    $perConnectionAuthEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.PerConnectionAuth)

    $xmlHosts = ''
    foreach ($hostName in $targetHosts) {
        if (-not $hostName) {
            continue
        }
        $hostEsc = ConvertTo-SfosXmlEscaped -Text $hostName
        $xmlHosts += "<Host>$hostEsc</Host>"
    }

    $inner = @"
<Set operation="update">
  <DirectWebProxyAuthentication>
    <PerConnectionAuth>$perConnectionAuthEsc</PerConnectionAuth>
    <MultiUserHosts>$xmlHosts</MultiUserHosts>
  </DirectWebProxyAuthentication>
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
        throw "Error removing members from DirectWebProxyAuthentication: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same Set operation="update" as Set-SfosDirectWebProxyAuthentication - Status lands at
    # /Response/DirectWebProxyAuthentication/Status.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'remove members'

    $reread = Get-SfosDirectWebProxyAuthentication -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $stillPresent = @($Members | Where-Object { $_ -in @($reread.MultiUserHostList) })
    if ($stillPresent.Count -gt 0) {
        throw "DirectWebProxyAuthentication reported success removing member(s) '$($stillPresent -join ', ')' but they are still present on the firewall - the MultiUserHosts list appears to be append-only on update, the same defect class as WebFilterCategory/URLList."
    }
}

#endregion

#region AzureADSSO
#
# Wire element is <AzureADSSO>, matching the cmdlet noun. The status path is the same
# top-level path for every operation (Get/Set add/Set update/Remove):
#   /Response/AzureADSSO/Status
# never nested under any wrapper, so every Assert-SfosApiReturnSuccess call below uses
# -ObjectName 'AzureADSSO'. Remove answers 200 at that path even when the ServerName does
# not exist, a known limitation described below.
#
# The RoleMapping profile field is 'profileid' on the wire, not 'profileidentifier' as the
# Attribute/Parameter table names it. identifiertype/identifiervalue are unchanged.
#
# RoleMapping is documented as a list (<RoleMapping> wrapping one-or-more
# <IdentifierTypeAndProfile>), but only a single entry survives on this firmware: an add
# with two <IdentifierTypeAndProfile> blocks inside one <RoleMapping> keeps only the
# first, the second is silently dropped. This cmdlet set therefore exposes RoleMapping as
# three scalar parameters (-RoleMappingIdentifierType/-RoleMappingIdentifierValue/
# -RoleMappingProfileID), not an array, matching what the firewall actually keeps.
#
# RoleMapping itself is only returned by <Get> when UserType is 'Administrator'.
# Get-SfosAzureADSSO therefore returns empty strings for the three RoleMapping properties
# whenever the stored object has no RoleMapping (either because UserType is 'User', or the
# field was never set) - this mirrors what the firewall itself does not return.
#
# ClientSecret is returned by <Get>, but only in hashed form:
# <ClientSecret hashform="mode1">$sfos$7$0$...</ClientSecret>, freshly salted on every
# read, so hash equality cannot be used to detect "unchanged". Get-SfosAzureADSSO exposes
# this as ClientSecretHash/ClientSecretHashForm, not as ClientSecret, to make clear
# neither is the plaintext - the same pattern used for RADIUSServer/TACACSServer
# SharedSecret. Resending the hash text together with its hashform attribute on
# <Set operation="update"> is accepted by the firewall; Set-SfosAzureADSSO uses exactly
# that to preserve an unchanged secret when -ClientSecret is not passed.
#
# DisplayName/EmailAddress accept only the keywords 'upn'/'name' (DisplayName) and 'email'
# (EmailAddress). The firewall itself does not enforce this constraint server-side, but
# ValidateSet is kept here because these are the only values with documented meaning.

<#
        .SYNOPSIS
        Retrieves Microsoft Entra ID (Azure AD) SSO server objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the Microsoft Entra ID single sign-on servers configured on the firewall. Use
        this cmdlet to review the existing servers, or to feed them into Set-SfosAzureADSSO
        through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        The firewall does not filter this entity server-side. -ServerNameLike is always
        evaluated on the client, as a substring match.

        .PARAMETER ServerNameLike
        Optional. Returns only servers whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, all servers are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per server, with the
        properties ServerName, ApplicationID, TenantID, ClientSecretHash,
        ClientSecretHashForm (the firewall's hashed form of the client secret, not the
        plaintext), RedirectURI, DisplayName, EmailAddress, FallbackUserGroup, UserType,
        RoleMappingIdentifierType, RoleMappingIdentifierValue and RoleMappingProfileID. The
        three RoleMapping properties are empty strings when the server has no role mapping.
        Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no server
        matches.

        .EXAMPLE
        Get-SfosAzureADSSO

        Lists every Microsoft Entra ID SSO server on the firewall of the current connection.

        .EXAMPLE
        Get-SfosAzureADSSO -ServerNameLike 'Corp'

        Lists all servers whose name contains 'Corp'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosAzureADSSO

        .LINK
        Set-SfosAzureADSSO
#>
function Get-SfosAzureADSSO {
    [CmdletBinding()]
    param(
        [string]$ServerNameLike,

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

    $inner = '<Get><AzureADSSO></AzureADSSO></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AzureADSSO objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AzureADSSO' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AzureADSSO[ServerName]' -ErrorAction SilentlyContinue |
        ForEach-Object -Process { $_.Node }

    if ($ServerNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.ServerName -like "*$ServerNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $results = @()
    foreach ($node in $nodes) {
        $roleMappingNode = $node.SelectSingleNode('RoleMapping/IdentifierTypeAndProfile')
        $results += [PSCustomObject]@{
            ServerName                  = [string]$node.ServerName
            ApplicationID                = [string]$node.ApplicationID
            TenantID                     = [string]$node.TenantID
            ClientSecretHash             = [string]$node.ClientSecret.InnerText
            ClientSecretHashForm         = [string]$node.ClientSecret.GetAttribute('hashform')
            RedirectURI                  = [string]$node.RedirectURI
            DisplayName                  = [string]$node.DisplayName
            EmailAddress                 = [string]$node.EmailAddress
            FallbackUserGroup            = [string]$node.FallbackUserGroup
            UserType                     = [string]$node.UserType
            RoleMappingIdentifierType    = if ($roleMappingNode) { [string]$roleMappingNode.identifiertype } else { '' }
            RoleMappingIdentifierValue   = if ($roleMappingNode) { [string]$roleMappingNode.identifiervalue } else { '' }
            RoleMappingProfileID         = if ($roleMappingNode) { [string]$roleMappingNode.profileid } else { '' }
        }
    }

    return $results
}

<#
        .SYNOPSIS
        Creates a Microsoft Entra ID (Azure AD) SSO server on a Sophos Firewall.

        .DESCRIPTION
        Adds a Microsoft Entra ID single sign-on server. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to create authentication servers.

        The firewall keeps only one role mapping entry per server, so this cmdlet exposes it
        as three scalar parameters rather than a list.

        .PARAMETER ServerName
        Required. Name that identifies the server. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER ApplicationID
        Required. Application (client) ID from Microsoft Entra ID App registrations. Maximum
        50 characters.

        .PARAMETER TenantID
        Required. Directory (tenant) ID from Microsoft Entra ID App registrations. Maximum 50
        characters.

        .PARAMETER ClientSecret
        Required. Client secret the firewall uses to authenticate with the Microsoft Entra ID
        application, as a SecureString.

        .PARAMETER RedirectURI
        Required. FQDN or IP address of this firewall, as registered in Microsoft Entra ID.
        Maximum 200 characters.

        .PARAMETER DisplayName
        Required. Attribute the firewall uses to retrieve the user's display name. Valid
        values: upn, name.

        .PARAMETER EmailAddress
        Required. Attribute the firewall uses to retrieve the user's email address. Valid
        value: email.

        .PARAMETER FallbackUserGroup
        Required. User group assigned when the firewall finds no matching local group.

        .PARAMETER UserType
        Required. Type of user this server authenticates. Valid values: User, Administrator.
        Role mapping only applies when this is Administrator.

        .PARAMETER RoleMappingIdentifierType
        Optional. Whether the role mapping matches on Entra ID app roles or groups. Valid
        values: roles, groups. Must be supplied together with -RoleMappingIdentifierValue and
        -RoleMappingProfileID. If omitted, no role mapping is set.

        .PARAMETER RoleMappingIdentifierValue
        Optional. The role or group value configured in Microsoft Entra ID to match on.
        Required together with -RoleMappingIdentifierType and -RoleMappingProfileID.

        .PARAMETER RoleMappingProfileID
        Optional. The administrator profile assigned when the mapping matches. Required
        together with -RoleMappingIdentifierType and -RoleMappingIdentifierValue.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to create
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Client-Secr3t!9' -AsPlainText -Force
        New-SfosAzureADSSO -ServerName 'CorpEntra' -ApplicationID 'fa7fc787-011e-4398-812f-3152d8843320' -TenantID '10657f8b-d541-41a5-8e25-a8d7cbb9d4dd' -ClientSecret $secret -RedirectURI 'fw.example.com' -DisplayName upn -EmailAddress email -FallbackUserGroup 'Open Group' -UserType User -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $secret = ConvertTo-SecureString 'Zz-Str0ng-Client-Secr3t!9' -AsPlainText -Force
        New-SfosAzureADSSO -ServerName 'CorpEntra' -ApplicationID 'fa7fc787-011e-4398-812f-3152d8843320' -TenantID '10657f8b-d541-41a5-8e25-a8d7cbb9d4dd' -ClientSecret $secret -RedirectURI 'fw.example.com' -DisplayName upn -EmailAddress email -FallbackUserGroup 'Open Group' -UserType User

        Creates a user-facing SSO server without a role mapping.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAzureADSSO
#>
function New-SfosAzureADSSO {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [string]$ApplicationID,

        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory)]
        [ValidateLength(1, 200)]
        [string]$RedirectURI,

        [Parameter(Mandatory)]
        [ValidateSet('upn', 'name')]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [ValidateSet('email')]
        [string]$EmailAddress,

        [Parameter(Mandatory)]
        [string]$FallbackUserGroup,

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Administrator')]
        [string]$UserType,

        [ValidateSet('roles', 'groups')]
        [string]$RoleMappingIdentifierType,
        [string]$RoleMappingIdentifierValue,
        [string]$RoleMappingProfileID,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $roleMappingParamsBound = @('RoleMappingIdentifierType', 'RoleMappingIdentifierValue', 'RoleMappingProfileID') | Where-Object { $PSBoundParameters.ContainsKey($_) }
    if ($roleMappingParamsBound.Count -gt 0 -and $roleMappingParamsBound.Count -lt 3) {
        throw "AzureADSSO object '$ServerName': -RoleMappingIdentifierType, -RoleMappingIdentifierValue and -RoleMappingProfileID must be supplied together."
    }

    $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
    $applicationIdEsc = ConvertTo-SfosXmlEscaped -Text $ApplicationID
    $tenantIdEsc = ConvertTo-SfosXmlEscaped -Text $TenantID
    $redirectUriEsc = ConvertTo-SfosXmlEscaped -Text $RedirectURI
    $fallbackGroupEsc = ConvertTo-SfosXmlEscaped -Text $FallbackUserGroup

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
    try {
        $clientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
    }
    $clientSecretEsc = ConvertTo-SfosXmlEscaped -Text $clientSecretPlain

    $roleMappingXml = ''
    if ($roleMappingParamsBound.Count -eq 3) {
        $idValEsc = ConvertTo-SfosXmlEscaped -Text $RoleMappingIdentifierValue
        $profileIdEsc = ConvertTo-SfosXmlEscaped -Text $RoleMappingProfileID
        $roleMappingXml = "<RoleMapping><IdentifierTypeAndProfile><identifiertype>$RoleMappingIdentifierType</identifiertype><identifiervalue>$idValEsc</identifiervalue><profileid>$profileIdEsc</profileid></IdentifierTypeAndProfile></RoleMapping>"
    }

    $inner = @"
<Set operation="add">
  <AzureADSSO>
    <ServerName>$serverNameEsc</ServerName>
    <ApplicationID>$applicationIdEsc</ApplicationID>
    <TenantID>$tenantIdEsc</TenantID>
    <ClientSecret>$clientSecretEsc</ClientSecret>
    <RedirectURI>$redirectUriEsc</RedirectURI>
    <DisplayName>$DisplayName</DisplayName>
    <EmailAddress>$EmailAddress</EmailAddress>
    <FallbackUserGroup>$fallbackGroupEsc</FallbackUserGroup>
    <UserType>$UserType</UserType>
    $roleMappingXml
  </AzureADSSO>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("AzureADSSO object '$ServerName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating AzureADSSO object '$ServerName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AzureADSSO' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates a Microsoft Entra ID (Azure AD) SSO server on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing Microsoft Entra ID SSO server. The cmdlet reads the current object
        first and writes back a complete object: every field you pass replaces the current
        value, every field you omit keeps it, including the nested role mapping. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to update authentication servers.

        If you omit -ClientSecret, the firewall keeps the stored secret unchanged; passing
        -ClientSecret replaces it.

        .PARAMETER ServerName
        Required. Name of the server to update.

        .PARAMETER ApplicationID
        Optional. Application (client) ID. If omitted, the current value is kept.

        .PARAMETER TenantID
        Optional. Directory (tenant) ID. If omitted, the current value is kept.

        .PARAMETER ClientSecret
        Optional. New client secret, as a SecureString. If omitted, the current secret is
        kept.

        .PARAMETER RedirectURI
        Optional. FQDN or IP address of this firewall. If omitted, the current value is kept.

        .PARAMETER DisplayName
        Optional. Attribute the firewall uses to retrieve the user's display name. Valid
        values: upn, name. If omitted, the current value is kept.

        .PARAMETER EmailAddress
        Optional. Attribute the firewall uses to retrieve the user's email address. Valid
        value: email. If omitted, the current value is kept.

        .PARAMETER FallbackUserGroup
        Optional. User group assigned when the firewall finds no matching local group. If
        omitted, the current value is kept.

        .PARAMETER UserType
        Optional. Type of user this server authenticates. Valid values: User, Administrator.
        If omitted, the current value is kept.

        .PARAMETER RoleMappingIdentifierType
        Optional. Whether the role mapping matches on Entra ID app roles or groups. Valid
        values: roles, groups. Must be supplied together with -RoleMappingIdentifierValue and
        -RoleMappingProfileID. If none of the three are passed, the current role mapping, if
        any, is kept.

        .PARAMETER RoleMappingIdentifierValue
        Optional. The role or group value configured in Microsoft Entra ID to match on.
        Required together with -RoleMappingIdentifierType and -RoleMappingProfileID.

        .PARAMETER RoleMappingProfileID
        Optional. The administrator profile assigned when the mapping matches. Required
        together with -RoleMappingIdentifierType and -RoleMappingIdentifierValue.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName, and any of the other property names of the object returned
        by Get-SfosAzureADSSO, are accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosAzureADSSO -ServerName 'CorpEntraAdmin' -RedirectURI 'fw2.example.com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosAzureADSSO -ServerName 'CorpEntraAdmin' -RedirectURI 'fw2.example.com'

        Updates the redirect URI; the client secret and role mapping keep their current
        values.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAzureADSSO
#>
function Set-SfosAzureADSSO {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

        [string]$ApplicationID,
        [string]$TenantID,
        [SecureString]$ClientSecret,
        [string]$RedirectURI,

        [ValidateSet('upn', 'name')]
        [string]$DisplayName,

        [ValidateSet('email')]
        [string]$EmailAddress,

        [string]$FallbackUserGroup,

        [ValidateSet('User', 'Administrator')]
        [string]$UserType,

        [ValidateSet('roles', 'groups')]
        [string]$RoleMappingIdentifierType,
        [string]$RoleMappingIdentifierValue,
        [string]$RoleMappingProfileID,

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
        $roleMappingParamsBound = @('RoleMappingIdentifierType', 'RoleMappingIdentifierValue', 'RoleMappingProfileID') | Where-Object { $PSBoundParameters.ContainsKey($_) }
        if ($roleMappingParamsBound.Count -gt 0 -and $roleMappingParamsBound.Count -lt 3) {
            throw "AzureADSSO object '$ServerName': -RoleMappingIdentifierType, -RoleMappingIdentifierValue and -RoleMappingProfileID must be supplied together."
        }

        $existing = @(Get-SfosAzureADSSO -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -ServerNameLike $ServerName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.ServerName -eq $ServerName })

        if ($existing.Count -eq 0) {
            throw "The AzureADSSO object '$ServerName' was not found."
        }

        $targetApplicationId = if ($PSBoundParameters.ContainsKey('ApplicationID')) { $ApplicationID } else { [string]$existing[0].ApplicationID }
        $targetTenantId = if ($PSBoundParameters.ContainsKey('TenantID')) { $TenantID } else { [string]$existing[0].TenantID }
        $targetRedirectUri = if ($PSBoundParameters.ContainsKey('RedirectURI')) { $RedirectURI } else { [string]$existing[0].RedirectURI }
        $targetDisplayName = if ($PSBoundParameters.ContainsKey('DisplayName')) { $DisplayName } else { [string]$existing[0].DisplayName }
        $targetEmailAddress = if ($PSBoundParameters.ContainsKey('EmailAddress')) { $EmailAddress } else { [string]$existing[0].EmailAddress }
        $targetFallbackGroup = if ($PSBoundParameters.ContainsKey('FallbackUserGroup')) { $FallbackUserGroup } else { [string]$existing[0].FallbackUserGroup }
        $targetUserType = if ($PSBoundParameters.ContainsKey('UserType')) { $UserType } else { [string]$existing[0].UserType }

        $serverNameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName
        $applicationIdEsc = ConvertTo-SfosXmlEscaped -Text $targetApplicationId
        $tenantIdEsc = ConvertTo-SfosXmlEscaped -Text $targetTenantId
        $redirectUriEsc = ConvertTo-SfosXmlEscaped -Text $targetRedirectUri
        $displayNameEsc = ConvertTo-SfosXmlEscaped -Text $targetDisplayName
        $emailAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetEmailAddress
        $fallbackGroupEsc = ConvertTo-SfosXmlEscaped -Text $targetFallbackGroup

        if ($PSBoundParameters.ContainsKey('ClientSecret')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            try {
                $clientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
            $clientSecretEsc = ConvertTo-SfosXmlEscaped -Text $clientSecretPlain
            $clientSecretXml = "<ClientSecret>$clientSecretEsc</ClientSecret>"
        }
        else {
            # Preserve the existing secret by resending its hashed form with its hashform
            # attribute - accepted as "unchanged" (see the region header).
            $hashEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing[0].ClientSecretHash)
            $hashFormEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing[0].ClientSecretHashForm)
            $clientSecretXml = "<ClientSecret hashform=`"$hashFormEsc`">$hashEsc</ClientSecret>"
        }

        $roleMappingXml = ''
        if ($roleMappingParamsBound.Count -eq 3) {
            $idValEsc = ConvertTo-SfosXmlEscaped -Text $RoleMappingIdentifierValue
            $profileIdEsc = ConvertTo-SfosXmlEscaped -Text $RoleMappingProfileID
            $roleMappingXml = "<RoleMapping><IdentifierTypeAndProfile><identifiertype>$RoleMappingIdentifierType</identifiertype><identifiervalue>$idValEsc</identifiervalue><profileid>$profileIdEsc</profileid></IdentifierTypeAndProfile></RoleMapping>"
        }
        elseif ($existing[0].RoleMappingIdentifierType) {
            # Preserve the existing nested RoleMapping unchanged - required explicitly by the
            # task: an update replaces the whole entity, and this sub-structure is no
            # exception.
            $idTypeExisting = [string]$existing[0].RoleMappingIdentifierType
            $idValEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing[0].RoleMappingIdentifierValue)
            $profileIdEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing[0].RoleMappingProfileID)
            $roleMappingXml = "<RoleMapping><IdentifierTypeAndProfile><identifiertype>$idTypeExisting</identifiertype><identifiervalue>$idValEsc</identifiervalue><profileid>$profileIdEsc</profileid></IdentifierTypeAndProfile></RoleMapping>"
        }

        if (-not $PSCmdlet.ShouldProcess("AzureADSSO object '$ServerName' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <AzureADSSO>
    <ServerName>$serverNameEsc</ServerName>
    <ApplicationID>$applicationIdEsc</ApplicationID>
    <TenantID>$tenantIdEsc</TenantID>
    $clientSecretXml
    <RedirectURI>$redirectUriEsc</RedirectURI>
    <DisplayName>$displayNameEsc</DisplayName>
    <EmailAddress>$emailAddressEsc</EmailAddress>
    <FallbackUserGroup>$fallbackGroupEsc</FallbackUserGroup>
    <UserType>$targetUserType</UserType>
    $roleMappingXml
  </AzureADSSO>
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
            throw "Error updating AzureADSSO object '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AzureADSSO' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a Microsoft Entra ID (Azure AD) SSO server from a Sophos Firewall.

        .DESCRIPTION
        Deletes a Microsoft Entra ID SSO server object. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to delete authentication servers.

        The firewall answers success even for a server name that does not exist; the caller
        cannot tell "removed" apart from "never existed" from the response alone.

        .PARAMETER ServerName
        Required. Name of the server to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to delete
        authentication server objects. If omitted, the value from the current connection is
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. ServerName is accepted from the pipeline by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosAzureADSSO -ServerName 'CorpEntra' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosAzureADSSO -ServerName 'CorpEntra'

        Removes the server named 'CorpEntra'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAzureADSSO
#>
function Remove-SfosAzureADSSO {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$ServerName,

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
        if (-not $PSCmdlet.ShouldProcess("AzureADSSO object '$ServerName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $ServerName

        $inner = @"
<Remove>
  <AzureADSSO>
    <ServerName>$nameEsc</ServerName>
  </AzureADSSO>
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
            throw "Error removing AzureADSSO object '$ServerName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AzureADSSO' -Action 'remove' -Target $ServerName
    }
    end {
    }
}

#endregion AzureADSSO

#region STAS
#
# Cmdlet noun is 'STAS' - the name used in the SFOS webadmin (Authentication > STAS) and in
# the Sophos API documentation page title ("Update STAS") - but the wire element is
# <AuthCTA> (Cyberoam-era naming: "Client Transparent Authentication").
#
# The status path is operation-dependent:
#   <Get><AuthCTA/></Get>            success -> no <Status> node at all (lenient Get)
#   <Set operation="update">          -> /Response/EnableDisable/Status - not nested under
#                                     AuthCTA, and not named 'AuthCTA' either
# Get-SfosSTAS therefore asserts with -ObjectName 'AuthCTA' (matches the lenient-Get
# pattern, tolerates zero Status nodes); Set-SfosSTAS asserts with -ObjectName
# 'EnableDisable'.
#
# The baseline shape is <AuthCTA><EnableDisable><ACTION>Disable</ACTION></EnableDisable>
# </AuthCTA>, with no Settings, Collector or VpnZone sub-blocks. Enabling STAS
# (ACTION=Enable) makes a Settings sub-block appear on the next Get, populated with
# firewall defaults (IdentityProbeTimeout 120, RestrictClientTraffic Yes, UserInactivity
# Disable) that were never sent in the request. Reverting to Disable makes the Settings
# block disappear again from Get.
#
# Collector/Settings/VpnZone are not implemented on Set-SfosSTAS: a combined update of an
# unchanged ACTION with a changed Settings field answers with two independent Status nodes
# in one response (/Response/EnableDisable/Status and /Response/Settings/Status), and
# Assert-SfosApiReturnSuccess checks exactly one -ObjectName per call. Extending
# Set-SfosSTAS to these sub-blocks would need per-sub-block status handling that is not
# implemented, so they are left out rather than shipped half-checked. Get-SfosSTAS still
# exposes whatever Settings/Collector/VpnZone fields are present on a given Get.
#
# Code 502 on this operation means "STAS is already in that state", per the STAS operation
# page's own Status Message Information table - not a defect.

<#
        .SYNOPSIS
        Retrieves the STAS configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the state of STAS (Single Agent Transparent Authentication Suite), the
        firewall's agent-based transparent user authentication. There is exactly one instance
        of this object per firewall. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        The collector, settings and VPN zone properties are populated only once STAS is
        enabled; they read as empty strings otherwise.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for STAS
        settings. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A single object with the properties
        ACTION, IdentityProbeTimeout, RestrictClientTraffic, UserInactivity, InactivityTimer,
        DataTransferThreshold, CollectorIp, CollectorPort, CollectorGroup, VPNSourceIP and
        VPNSourceMask. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosSTAS

        Returns the current STAS state.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosSTAS
#>
function Get-SfosSTAS {
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

    $inner = '<Get><AuthCTA></AuthCTA></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving STAS (AuthCTA) configuration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Get on this entity is lenient and returns no Status node at all on success - see the
    # region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthCTA' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/AuthCTA')
    if (-not $node) {
        throw 'STAS (AuthCTA) configuration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        ACTION                 = [string]$node.EnableDisable.ACTION
        IdentityProbeTimeout   = [string]$node.Settings.IdentityProbeTimeout
        RestrictClientTraffic  = [string]$node.Settings.RestrictClientTraffic
        UserInactivity         = [string]$node.Settings.UserInactivity
        InactivityTimer        = [string]$node.Settings.InactivityTimer
        DataTransferThreshold  = [string]$node.Settings.DataTransferThreshold
        CollectorIp            = [string]$node.Collector.CollectorIp
        CollectorPort          = [string]$node.Collector.CollectorPort
        CollectorGroup         = [string]$node.Collector.CollectorGroup
        VPNSourceIP            = [string]$node.VpnZone.VPNSourceIP
        VPNSourceMask          = [string]$node.VpnZone.VPNSourceMask
    }
}

<#
        .SYNOPSIS
        Enables or disables STAS on a Sophos Firewall.

        .DESCRIPTION
        Switches STAS (Single Agent Transparent Authentication Suite) on or off. Only the
        enable/disable state is implemented; the collector, settings and VPN zone sub-blocks
        are not writable through this cmdlet. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to update STAS settings.

        Sending the state STAS is already in is rejected by the firewall; toggle only when you
        are changing the state.

        .PARAMETER ACTION
        Required. Whether to enable or disable STAS. Valid values: Enable, Disable.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to update STAS
        settings. If omitted, the value from the current connection is used.

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
        Set-SfosSTAS -ACTION Enable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSTAS -ACTION Enable

        Enables STAS.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSTAS
#>
function Set-SfosSTAS {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$ACTION,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("STAS (AuthCTA) on $($params.Firewall)", "Set ACTION to $ACTION")) {
        return
    }

    $inner = @"
<Set operation="update">
  <AuthCTA>
    <EnableDisable>
      <ACTION>$ACTION</ACTION>
    </EnableDisable>
  </AuthCTA>
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
        throw "Error updating STAS (AuthCTA) ACTION to '$ACTION': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # The Status for this Set lands at /Response/EnableDisable/Status - see the
    # region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EnableDisable' -Action 'update'
}

#endregion STAS

#region LiveUser
#
# Connect-/Disconnect-SfosLiveUser log an end user in or out at the firewall's own
# transparent-authentication tracking (the "Live Users" list under Current Activities in
# the webadmin). They have nothing to do with Connect-SfosFirewall/Disconnect-SfosFirewall,
# which manage the API session this whole module authenticates with. That distinction is
# repeated in both functions' help.
#
# The operations are documented under APIUserLogin/APIUserLogout, not under a 'LiveUser' term:
#   https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogin/operations/APIUserLogin.html
#   https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogout/operations/APIUserLogout.html
# Both pages give a distinct root element - <LiveUserLogin> / <LiveUserLogout> - that is not
# wrapped in <Set>, plus an <Admin> block carrying a second, in-payload set of credentials
# alongside the session's own <Login> block. Sending the wrong root element, wrapping it in
# <Set>, or omitting <Admin> answers HTTP 200 with no <Status> node of any kind - the firewall
# never recognises the request as either operation.
#
# LiveUserLogin registers a record a follow-up <Get><LiveUser/></Get> shows, and
# LiveUserLogout removes it. The status node in each case sits at
# /Response/LiveUserLogin/Status and /Response/LiveUserLogout/Status respectively - a
# <Status code="..."> child of the operation's own root element, not of a generic
# 'LiveUser' object name - so -ObjectName below is set to the operation name, not the
# entity name. See each function's .NOTES.
#
# DeviceType: the Attribute/Parameter table on the APIUserLogin page states "Only 'iOS',
# 'Android' are allowed", but the page's own sample XML comment lists four options -
# "iOS/Android/iPhone/iPad" - and the firewall accepts all four. The ValidateSet below
# follows the sample, not the narrower table wording.

<#
        .SYNOPSIS
        Retrieves currently logged-in live users from a Sophos Firewall.

        .DESCRIPTION
        Returns the "Live Users" list under Current Activities in the web admin console: the
        end users currently tracked by transparent authentication, the same list
        Connect-SfosLiveUser and Disconnect-SfosLiveUser change. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        Both filters are evaluated on the client, as a substring match.

        .PARAMETER UserNameLike
        Optional. Returns only sessions whose user name contains the given text anywhere. If
        omitted, the user name is not used to filter.

        .PARAMETER HostIPLike
        Optional. Returns only sessions whose client IP address contains the given text
        anywhere. If omitted, the address is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for live
        user sessions. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per live session, with the
        properties UserID, UserName, LiveUserID, ClientType, HostIP, IPFamily, MAC, StartTime,
        Upload, Download, DataTransferRate and InternetUsageTime. UserName is also available
        under the property name LiveUserName, and HostIP under IPAddress, so the object binds
        directly to Disconnect-SfosLiveUser. Returns System.Xml.XmlElement when -AsXml is
        used, and an empty array when no session matches.

        .EXAMPLE
        Get-SfosLiveUser

        Lists every currently logged-in live user.

        .EXAMPLE
        Get-SfosLiveUser -HostIPLike '10.99.99.'

        Lists all sessions whose client IP address contains '10.99.99.'.

        .EXAMPLE
        Get-SfosLiveUser -UserNameLike 'jdoe' | Disconnect-SfosLiveUser

        Logs the matching user out again.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Connect-SfosLiveUser

        .LINK
        Disconnect-SfosLiveUser
#>
function Get-SfosLiveUser {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$UserNameLike,
        [string]$HostIPLike,

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

    # No server-side filter key is sent: server-side filtering for LiveUser has not been
    # verified, so both -UserNameLike and -HostIPLike are applied client-side only, below.
    $inner = @"
<Get>
  <LiveUser>
  </LiveUser>
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
        throw "Error retrieving LiveUser objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LiveUser' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/LiveUser[UserID]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    if ($UserNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.UserName -like "*$UserNameLike*" })
    }
    if ($HostIPLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.HostIP -like "*$HostIPLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $liveUserObjects = @()
    foreach ($node in $nodes) {
        $obj = [PSCustomObject]@{
            UserID            = $node.UserID
            UserName          = $node.UserName
            LiveUserID        = $node.LiveUserID
            ClientType        = $node.ClientType
            HostIP            = $node.HostIP
            IPFamily          = $node.IPFamily
            MAC               = $node.MAC
            StartTime         = $node.StartTime
            Upload            = $node.Upload
            Download          = $node.Download
            DataTransferRate  = $node.DataTransferRate
            InternetUsageTime = $node.InternetUsageTime
        }
        # LiveUserName/IPAddress are AliasProperty members, not a second copy of the value, so
        # that 'Get-SfosLiveUser | Connect-/Disconnect-SfosLiveUser' binds by property name.
        # Connect-/Disconnect-SfosLiveUser cannot declare a parameter [Alias('UserName')]
        # themselves - it collides case-insensitively with their own -Username connection
        # parameter and breaks the cmdlet outright (see their .PARAMETER LiveUserName), so the
        # alias is added here, on the output, instead.
        $obj | Add-Member -MemberType AliasProperty -Name LiveUserName -Value UserName
        $obj | Add-Member -MemberType AliasProperty -Name IPAddress -Value HostIP
        $liveUserObjects += $obj
    }

    return $liveUserObjects
}

<#
        .SYNOPSIS
        Logs an end user in at a Sophos Firewall's live user tracking.

        .DESCRIPTION
        Registers a user session in the firewall's "Live Users" tracking (Current Activities
        in the web admin console). This is unrelated to Connect-SfosFirewall, which
        establishes the API session this module itself uses; this cmdlet logs in an end user
        of the firewall's network services, not the PowerShell session. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        The call also creates a persistent user account for the given name if none already
        exists. Disconnect-SfosLiveUser ends only the live session, never that account; remove
        it separately with Remove-SfosUser if it is not wanted.

        The request carries a second, in-payload set of credentials alongside the API
        session's own login. By default this cmdlet reuses the resolved session credentials
        for both, so the ordinary call needs no extra parameters; -AdminUsername and
        -AdminPassword let the payload-level credentials be a different account.

        .PARAMETER LiveUserName
        Required. User name of the end user to log in.

        .PARAMETER IPAddress
        Required. IP address of the client the user is being logged in from.

        .PARAMETER MacAddress
        Optional. MAC address of the client device. If omitted, none is set.

        .PARAMETER GroupName
        Optional. Group to associate the session with. If omitted, none is set.

        .PARAMETER DeviceType
        Optional. Device type. Valid values: iOS, Android, iPhone, iPad. If omitted, none is
        set.

        .PARAMETER AdminUsername
        Optional. User name for the in-payload credential block. If omitted, the resolved
        session user name is used.

        .PARAMETER AdminPassword
        Optional. Password for the in-payload credential block, as a SecureString. If
        omitted, the resolved session password is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. LiveUserName and IPAddress are accepted from the pipeline by property
        name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        login or reports no status for it.

        .EXAMPLE
        Connect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55' -WhatIf

        Shows what the call would do without sending it to the firewall.

        .EXAMPLE
        Connect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55'

        Logs 'jdoe' in from the given IP address.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosLiveUser

        .LINK
        Disconnect-SfosLiveUser
#>
function Connect-SfosLiveUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # No [Alias('UserName')] here: an alias collides case-insensitively with the -Username
        # connection parameter below and breaks the whole cmdlet (Get-Help and every invocation
        # throw "parameter 'Username' cannot be specified because it conflicts with the
        # parameter alias of the same name" - the same failure
        # mode as -ServerPort). Pipeline binding by
        # property name instead relies on Get-SfosLiveUser exposing matching AliasProperty
        # members (LiveUserName, IPAddress) on its output - see that cmdlet's .NOTES.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$LiveUserName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$IPAddress,

        [string]$MacAddress,
        [string]$GroupName,

        [ValidateSet('iOS', 'Android', 'iPhone', 'iPad')]
        [string]$DeviceType,

        [string]$AdminUsername,
        [SecureString]$AdminPassword,

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
        if (-not $PSCmdlet.ShouldProcess("Live user '$LiveUserName' ($IPAddress) on $($params.Firewall)", 'Log in')) {
            return
        }

        $userNameEsc = ConvertTo-SfosXmlEscaped -Text $LiveUserName
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress

        $optionalXml = ''
        if ($PSBoundParameters.ContainsKey('MacAddress')) {
            $optionalXml += "<MacAddress>$(ConvertTo-SfosXmlEscaped -Text $MacAddress)</MacAddress>"
        }
        if ($PSBoundParameters.ContainsKey('GroupName')) {
            $optionalXml += "<GroupName>$(ConvertTo-SfosXmlEscaped -Text $GroupName)</GroupName>"
        }
        if ($PSBoundParameters.ContainsKey('DeviceType')) {
            $optionalXml += "<DeviceType>$(ConvertTo-SfosXmlEscaped -Text $DeviceType)</DeviceType>"
        }

        # The <Admin> block carries its own credentials inside the payload, in addition to the API
        # session's <Login> block Invoke-SfosApi already sends. Default to the resolved session
        # credentials so the ordinary call needs no extra parameters. Never logged, never put in an
        # error message - only interpolated straight into the request body and cleared afterwards.
        $adminUsernameEffective = if ($PSBoundParameters.ContainsKey('AdminUsername')) { $AdminUsername } else { $params.Username }
        $adminPasswordEffective = if ($PSBoundParameters.ContainsKey('AdminPassword')) { $AdminPassword } else { $params.Password }
        $adminUsernameEsc = ConvertTo-SfosXmlEscaped -Text $adminUsernameEffective
        $adminPasswordBstr = [IntPtr]::Zero

        try {
            $adminPasswordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPasswordEffective)
            $adminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($adminPasswordBstr)
            $adminPasswordEsc = ConvertTo-SfosXmlEscaped -Text $adminPasswordPlain

            $inner = @"
<LiveUserLogin>
  <Admin>
    <UserName>$adminUsernameEsc</UserName>
    <Password>$adminPasswordEsc</Password>
  </Admin>
  <UserName>$userNameEsc</UserName>
  <IPAddress>$ipEsc</IPAddress>
  $optionalXml
</LiveUserLogin>
"@
        }
        finally {
            if ($adminPasswordBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($adminPasswordBstr)
            }
            $adminPasswordPlain = $null
            $adminPasswordEsc = $null
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error logging in live user '$LiveUserName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # The status for this operation is a <Status code="..."> child of the
        # operation's own root element, /Response/LiveUserLogin/Status - not of a generic
        # 'LiveUser' object name.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LiveUserLogin' -Action 'log in' -Target $LiveUserName

        # Assert-SfosApiReturnSuccess treats a response with no matching <Status> node as success
        # by design (correct for entities that are legitimately silent, e.g. Get-SfosSTAS). That is
        # NOT the case here: every login attempt - success and both provoked failures
        # alike - answers with a <Status code="..."> under /Response/LiveUserLogin. If a future
        # firmware ever omits it, this call still refuses to report a success it cannot back up
        # (a missing status element is not success), instead of silently
        # passing through Assert-SfosApiReturnSuccess's lenient default.
        $statusList = @(Get-SfosApiStatus -Xml $XmlResponse -ObjectName 'LiveUserLogin' | Where-Object { $_ })
        if ($statusList.Count -eq 0) {
            throw "Sophos API returned no status for logging in live user '$LiveUserName' ($IPAddress) - the firewall accepted the request but did not confirm the effect."
        }
    }
    end {
    }
}

<#
        .SYNOPSIS
        Logs an end user out of a Sophos Firewall's live user tracking.

        .DESCRIPTION
        Removes a user session from the firewall's "Live Users" tracking (Current Activities
        in the web admin console). This is unrelated to Disconnect-SfosFirewall, which ends
        the API session this module itself uses; this cmdlet logs out an end user of the
        firewall's network services, not the PowerShell session. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly. On a shared
        firewall, target only a session you can positively identify; the wrong IP address logs
        out the wrong user.

        The request carries a second, in-payload set of credentials alongside the API
        session's own login. By default this cmdlet reuses the resolved session credentials
        for both, so the ordinary call needs no extra parameters; -AdminUsername and
        -AdminPassword let the payload-level credentials be a different account.

        .PARAMETER LiveUserName
        Required. User name of the end user to log out.

        .PARAMETER IPAddress
        Required. IP address of the client the user was logged in from.

        .PARAMETER AdminUsername
        Optional. User name for the in-payload credential block. If omitted, the resolved
        session user name is used.

        .PARAMETER AdminPassword
        Optional. Password for the in-payload credential block, as a SecureString. If
        omitted, the resolved session password is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.String. LiveUserName and IPAddress are accepted from the pipeline by property
        name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        logout or reports no status for it.

        .EXAMPLE
        Disconnect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55' -WhatIf

        Shows what the call would do without sending it to the firewall.

        .EXAMPLE
        Disconnect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55'

        Logs 'jdoe' out.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosLiveUser

        .LINK
        Connect-SfosLiveUser
#>
function Disconnect-SfosLiveUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # No [Alias('UserName')] here - see the matching comment in Connect-SfosLiveUser: it
        # collides case-insensitively with -Username below and breaks the whole cmdlet. Pipeline
        # binding by property name instead relies on Get-SfosLiveUser exposing matching
        # AliasProperty members (LiveUserName, IPAddress) on its output.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$LiveUserName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$IPAddress,

        [string]$AdminUsername,
        [SecureString]$AdminPassword,

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
        if (-not $PSCmdlet.ShouldProcess("Live user '$LiveUserName' ($IPAddress) on $($params.Firewall)", 'Log out')) {
            return
        }

        $userNameEsc = ConvertTo-SfosXmlEscaped -Text $LiveUserName
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress

        # See the matching comment in Connect-SfosLiveUser.
        $adminUsernameEffective = if ($PSBoundParameters.ContainsKey('AdminUsername')) { $AdminUsername } else { $params.Username }
        $adminPasswordEffective = if ($PSBoundParameters.ContainsKey('AdminPassword')) { $AdminPassword } else { $params.Password }
        $adminUsernameEsc = ConvertTo-SfosXmlEscaped -Text $adminUsernameEffective
        $adminPasswordBstr = [IntPtr]::Zero

        try {
            $adminPasswordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPasswordEffective)
            $adminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($adminPasswordBstr)
            $adminPasswordEsc = ConvertTo-SfosXmlEscaped -Text $adminPasswordPlain

            $inner = @"
<LiveUserLogout>
  <Admin>
    <UserName>$adminUsernameEsc</UserName>
    <Password>$adminPasswordEsc</Password>
  </Admin>
  <UserName>$userNameEsc</UserName>
  <IPAddress>$ipEsc</IPAddress>
</LiveUserLogout>
"@
        }
        finally {
            if ($adminPasswordBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($adminPasswordBstr)
            }
            $adminPasswordPlain = $null
            $adminPasswordEsc = $null
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error logging out live user '$LiveUserName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # The status for this operation is a <Status code="..."> child of the
        # operation's own root element, /Response/LiveUserLogout/Status - see the matching comment
        # in Connect-SfosLiveUser.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LiveUserLogout' -Action 'log out' -Target $LiveUserName

        # See the matching check and reasoning in Connect-SfosLiveUser.
        $statusList = @(Get-SfosApiStatus -Xml $XmlResponse -ObjectName 'LiveUserLogout' | Where-Object { $_ })
        if ($statusList.Count -eq 0) {
            throw "Sophos API returned no status for logging out live user '$LiveUserName' ($IPAddress) - the firewall accepted the request but did not confirm the effect."
        }
    }
    end {
    }
}

#endregion LiveUser

