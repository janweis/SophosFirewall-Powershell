#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }
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
        Module Name: SophosFirewall.Authentication
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 98 (97 exported, 1 internal helper)
        - 20 Authentication server functions (AD, LDAP, RADIUS, TACACS+, eDirectory)
        - 10 User and user group functions (including membership)
        - 15 Guest user, clientless user and SMS gateway functions
        - 8 One-time password functions
        - 14 Firewall authentication functions
        - 12 Admin, VPN and SSL VPN authentication functions
        - 10 Web authentication and captive portal functions
        - 9 SSO, STAS and live user functions

        These cmdlets change who may log in to a live firewall and how. An update that drops
        an authentication server, or a group membership written to the wrong object, decides
        whether people can authenticate at all. Every Set-* therefore reads the current object
        first and writes it back complete.

        Behaviour that differs from the vendor documentation was measured against a live
        appliance and is recorded in the .NOTES of the affected function. The most important
        ones:
        - The whole area has no documented Get operation, yet every root element answers one.
          Without that, the read-modify-write this module relies on would be impossible.
        - ActiveDirectory, LDAPServer, RADIUSServer, TACACSServer and EDirectory are children
          of the AuthenticationServer container. Sent as a root element they answer 529.
        - The XPath of the status node differs per entity AND per operation. For the five
          server types Get and Remove report it nested under AuthenticationServer, while Set
          reports it flat. FirewallAuthentication reports everything flat. Set on STAS reports
          it under EnableDisable. A wrong path makes a 500 read as success, so each one was
          measured with a provoked error rather than inferred.
        - Group membership lives on the user, not on the group: writing GroupMembers under
          UserGroup answers 200 and does nothing. The Group field of a user is a single value,
          so a user belongs to exactly one group and adding it to a second one moves it.
        - GuestUser has no working update. operation="update" is refused, and operation="edit"
          answers 200 while silently creating a duplicate, so this module ships no
          Set-SfosGuestUser.
        - The authentication server lists of firewall, VPN and SSL VPN authentication must not
          become empty; removing the last entry answers 500 and changes nothing.

        Functions that could not be confirmed against the lab appliance are marked as such in
        their own .NOTES. They are implemented faithful to the documentation rather than
        omitted, but nothing about them should be assumed to work.
#>

#region AuthenticationServer

# The five authentication server types (ActiveDirectory, LDAPServer, RADIUSServer,
# TACACSServer, EDirectory) are children of the <AuthenticationServer> container - a <Get>
# on the standalone element name (e.g. <ActiveDirectory> directly under <Response>) answers
# '529 Input request module is Invalid'. Every function in this region therefore wraps its
# inner XML in <AuthenticationServer>.
#
# THE STATUS PATH DEPENDS ON THE OPERATION, NOT ONLY ON THE ENTITY, measured for all five
# types by sending raw XML and locating the returned <Status> node:
#
#   <Get>                    -> /Response/AuthenticationServer/<Type>/Status  (nested)
#   <Remove>                 -> /Response/AuthenticationServer/<Type>/Status  (nested)
#   <Set operation="add">    -> /Response/<Type>/Status                      (top-level)
#   <Set operation="update"> -> /Response/<Type>/Status                      (top-level)
#
# Passing the nested path to add/update is a fail-open: Assert-SfosApiReturnSuccess finds
# nothing at the nested path, falls back to the bare /Response/Status, finds nothing there
# either, and returns without error - so a firewall answer of code="501" with a full
# <InvalidParams> list would be silently read as success. New-*/Set-* in this region
# therefore pass -ObjectName as the bare type name (e.g. 'ActiveDirectory'), while
# Get-*/Remove-* keep the nested path (e.g. 'AuthenticationServer/ActiveDirectory'). This is
# the single most important rule in this region: get it wrong for the wrong operation and a
# failed write is reported as a success.
#
# FIELD NAMES were corrected against the CONFIGURE/Authentication doc pages (Attribute/
# Parameter table and sample <xmp> XML) by sending an intentionally incomplete create request
# and reading the <InvalidParams> element it returns, which names each missing field by its
# full wire path:
#
#   RADIUSServer: the address field is <ServerAddress> (not <ServerIP> as the Attribute/
#                 Parameter table names it), and the port field is <Port> (not
#                 <AuthenticationPort>). A previously undocumented field, <Timeout>, is
#                 mandatory and appears in neither the table nor the sample XML.
#   TACACSServer: the address field is <ServerAddress> (not <ServerIP>).
#   EDirectory:   the address field is <ServerIpDomain> (not <ServerAddress> as the table
#                 names it), and the username field is <Username> (not <EdirUsername>).
#
# ActiveDirectory and LDAPServer needed no field-name correction. Mandatory-ness was
# corrected the same way: LDAPServer's GroupNameAttribute, ExpiryDateAttribute and BaseDN are
# unconditionally required even under LooseIntegration, contradicting the sample comment that
# scopes them to TightIntegration only - confirmed by sending a request that satisfied every
# other field and reading the shrinking <InvalidParams> list as each field was added.
#
# Two connection-parameter names collide with fields these entities also define on the wire:
# every entity has its own <Port>, and ActiveDirectory/LDAPServer/EDirectory each have their
# own <Password>. The connection parameters -Port and -Password are fixed by name and type
# and cannot be renamed, so the entity-level fields are exposed here as -ServerPort and
# -BindPassword. Neither carries a parameter alias back to 'Port'/'Password': PowerShell
# rejects a parameter alias that matches another parameter's own name on the same command -
# it makes the whole command's metadata fail to resolve. Instead, each Get-*'s output object
# carries an AliasProperty named ServerPort over its Port property, added via Add-Member
# after the object is built, so Get-* | Set-* still binds -ServerPort by property name while
# the property itself stays named Port. RADIUS's own port field went through the same rename
# for the same reason, since its wire name (Port) also collides.
#
# PASSWORD/SECRET PRESERVATION ON UPDATE, measured directly against a live firewall:
#
#   - ActiveDirectory/LDAPServer/EDirectory <Password>: Get returns it hashed, e.g.
#     <Password hashform="mode1">$sfos$7$0$...</Password>. On <Set operation="update">, an
#     EMPTY <Password></Password> is accepted (code 200) and the stored password is left
#     unchanged - confirmed by reading it back and seeing the same hash. This is the one field
#     in this API observed to violate the usual "the update replaces the whole entity" rule;
#     every Set-* here relies on that exception and sends an empty element when -BindPassword
#     is not supplied, without warning the caller. Resending the same hash text together with
#     its hashform attribute is independently accepted too, but is unnecessary here since the
#     empty-element path already works.
#   - RADIUS/TACACS <SharedSecret>: also returned hashed by Get, but this entity does NOT
#     tolerate an empty element - <Set operation="update"> with <SharedSecret></SharedSecret>
#     answers code 501 naming SharedSecret invalid. The only way to preserve it is to resend
#     the hash together with its hashform attribute, which the firewall does accept (code
#     200). Get-SfosRADIUSServer/Get-SfosTACACSServer therefore expose SharedSecretHash and
#     SharedSecretHashForm (not SharedSecret, to make clear neither is the plaintext), and
#     Set-SfosRADIUSServer/Set-SfosTACACSServer resend them when -SharedSecret is omitted.
#
# IntegrationType (ActiveDirectory/LDAPServer/RADIUS): Get never returns this field, even
# immediately after creating an object with -IntegrationType TightIntegration. Every Set-*
# here therefore resends whatever was passed, or an empty element when nothing was passed
# (existing[0].IntegrationType is always empty, since Get never had it to begin with). An
# empty <IntegrationType></IntegrationType> on update was confirmed not to disturb a sibling
# TightIntegration-only field (DisplayNameAttribute survived unchanged across the same
# update), so this is treated as harmless, but it cannot be round-tripped or verified through
# this API in either direction - a caller relying on Get-* to confirm IntegrationType has no
# way to.

#region ActiveDirectory

<#
        .SYNOPSIS
        Retrieves ActiveDirectory authentication server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ActiveDirectory servers configured under AuthenticationServer. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering on this nested container is unconfirmed against a live appliance (the lab firewall carries no ActiveDirectory servers to test filtering against), so no <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match (SFOS 'like' semantics: the value may match anywhere in the name).

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default), keyed on ServerName. System.Xml.XmlElement when -AsXml is specified. The port property is named Port, matching the API element (section 7); ServerPort is an AliasProperty on the same value, so piping into Set-SfosActiveDirectoryServer's -ServerPort parameter still binds by property name.

        .EXAMPLE
        # Retrieve all Active Directory servers
        Get-SfosActiveDirectoryServer

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosActiveDirectoryServer -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The cmdlet noun is 'ActiveDirectoryServer' for consistency with the other four authentication server cmdlets, but the wire element is <ActiveDirectory> - without "Server" - confirmed against a live firewall response (see the region header). This is a deliberate deviation from the Sophos wire spelling, kept for naming consistency with the other four authentication server cmdlets.
        The stored bind password is never exposed here: the firewall does not return it on <Get>.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ADSServer/ADSServer.html
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
        Creates a new ActiveDirectory authentication server on the Sophos Firewall.

        .DESCRIPTION
        Creates an ActiveDirectory authentication server object under AuthenticationServer using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas).

        .PARAMETER ServerAddress
        IP address or domain name of the Active Directory server [doc].

        .PARAMETER ServerPort
        Port through which the server communicates [doc]. Sophos documents a default of 389. Wire element is <Port>; renamed here to -ServerPort because -Port is already the fixed connection parameter and cannot be reused. No alias 'Port' is defined either: PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it makes the whole command's metadata fail to resolve. The generated XML still uses <Port> unchanged. Because there is no alias, Get-SfosActiveDirectoryServer's Port property (named after the wire element, per section 7) does not auto-bind here via ValueFromPipelineByPropertyName; pass -ServerPort explicitly.

        .PARAMETER NetBIOSDomain
        NetBIOS domain name [doc].

        .PARAMETER ADSUsername
        Admin username used to access the Active Directory server [doc].

        .PARAMETER BindPassword
        Admin password used to access the Active Directory server [doc]. Wire element is <Password>; renamed here to avoid colliding with the connection -Password parameter (see the region header). Optional per the documentation.

        .PARAMETER ConnectionSecurity
        Connection security used when sending the username and password to the server [doc]: Simple, SSL or StartTLS.

        .PARAMETER ValidCertReq
        Whether to validate the server's certificate [doc]: Enable or Disable. Relevant only when -ConnectionSecurity is SSL or StartTLS. If omitted, the firewall default (Enable) applies.

        .PARAMETER IntegrationType
        Integration type used when setting user group membership [doc]: LooseIntegration or TightIntegration.

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user for this server [doc]. Only relevant for TightIntegration per the sample configuration.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the configured email address [doc]. Sophos documents a default of 'mail'. Only relevant for TightIntegration per the sample configuration.

        .PARAMETER DomainName
        Domain name to which the search query is added [doc].

        .PARAMETER SearchQueries
        One or more search queries [doc]. Sent as <SearchQueries><Query>...</Query></SearchQueries>.

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
        # Create an Active Directory server with simple bind
        $bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        New-SfosActiveDirectoryServer -ServerName "CorpAD" -ServerAddress "ad.example.invalid" -ServerPort 389 -NetBIOSDomain "CORP" -ADSUsername "svc-sfos" -BindPassword $bindPw -ConnectionSecurity Simple -DomainName "example.invalid"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <ActiveDirectory> (no "Server") nested under <AuthenticationServer> - see the region header.
        ServerType, documented in the Attribute/Parameter table ("Only '1' are allowed") but absent from the sample XML for this entity, is not implemented.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ADSServer/operations/AddActiveDirectoryServer%26EditActiveDirectoryServer.html

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
    # Measured: unlike Get/Remove, <Set operation="add"> answers with the status at
    # /Response/ActiveDirectory/Status - NOT nested under AuthenticationServer. See the region
    # header for the full per-operation status-path table.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ActiveDirectory' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an existing ActiveDirectory authentication server on the Sophos Firewall.

        .DESCRIPTION
        Updates an ActiveDirectory authentication server object using the Sophos Firewall XML API. SFOS replaces the whole entity on update, so this cmdlet reads the current server first and keeps whatever the caller does not explicitly pass. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        The bind password is an exception to this API's usual replace-the-whole-entity behaviour, measured live: sending an empty <Password></Password> on update is accepted (code 200) and the previously stored password is preserved, not cleared - confirmed by reading it back afterwards (Get returns it hashed, e.g. <Password hashform="mode1">$sfos$...</Password>, and the hash was unchanged). Get-SfosActiveDirectoryServer still never exposes it in either form, since there is no legitimate use for the hash in this cmdlet's own output - Set-SfosActiveDirectoryServer relies on the firewall's own "empty means unchanged" behaviour instead of reading anything back. Passing -BindPassword replaces it as normal.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ServerAddress
        IP address or domain name of the server. If omitted, the existing value is kept.

        .PARAMETER ServerPort
        Port through which the server communicates. If omitted, the existing value is kept. Named -ServerPort, not -Port: -Port is already the fixed connection parameter and cannot be reused, and no alias 'Port' is defined either, because PowerShell rejects a parameter alias that collides with another parameter's own name on the same command - measured, it breaks the command's metadata entirely. The generated XML still uses <Port> unchanged. Because there is no alias, piping Get-* output (its Port property, named after the wire element) does not auto-bind to -ServerPort; pass it explicitly.

        .PARAMETER NetBIOSDomain
        NetBIOS domain name. If omitted, the existing value is kept.

        .PARAMETER ADSUsername
        Admin username used to access the server. If omitted, the existing value is kept.

        .PARAMETER BindPassword
        Admin password used to access the server. If omitted, the existing password is preserved (see the .DESCRIPTION) - measured live, not merely assumed.

        .PARAMETER ConnectionSecurity
        Connection security: Simple, SSL or StartTLS. If omitted, the existing value is kept.

        .PARAMETER ValidCertReq
        Whether to validate the server's certificate: Enable or Disable. If omitted, the existing value is kept.

        .PARAMETER IntegrationType
        Integration type: LooseIntegration or TightIntegration. If omitted, the existing value is kept.

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user for this server. If omitted, the existing value is kept.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the configured email address. If omitted, the existing value is kept.

        .PARAMETER DomainName
        Domain name to which the search query is added. If omitted, the existing value is kept.

        .PARAMETER SearchQueries
        One or more search queries. If omitted, the existing entries are kept.

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
        # Update the domain name only, everything else preserved except the bind password
        $bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        Set-SfosActiveDirectoryServer -ServerName "CorpAD" -DomainName "corp.example.invalid" -BindPassword $bindPw

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <ActiveDirectory> nested under <AuthenticationServer> - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ADSServer/operations/AddActiveDirectoryServer%26EditActiveDirectoryServer.html
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

        # Measured: an empty <Password> on update is accepted and preserves the existing bind
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
        # Measured: <Set operation="update"> answers at /Response/ActiveDirectory/Status too,
        # same as add - see the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ActiveDirectory' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an ActiveDirectory authentication server from the Sophos Firewall.

        .DESCRIPTION
        Removes an ActiveDirectory authentication server object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosActiveDirectoryServer -ServerName "CorpAD" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosActiveDirectoryServer -ServerName "CorpAD"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <ActiveDirectory> nested under <AuthenticationServer> - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ADSServer/operations/Delete%20Active%20Directory%20Server.html
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
        Retrieves LDAPServer authentication server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for LDAP servers configured under AuthenticationServer. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering on this nested container is unconfirmed against a live appliance, so no <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default), keyed on ServerName. System.Xml.XmlElement when -AsXml is specified. The port property is named Port, matching the API element (section 7); ServerPort is an AliasProperty on the same value, so piping into Set-SfosLDAPServer's -ServerPort parameter still binds by property name.

        .EXAMPLE
        # Retrieve all LDAP servers
        Get-SfosLDAPServer

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosLDAPServer -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <LDAPServer>, matching the cmdlet noun - see the region header.
        The stored bind password is never exposed here: the firewall does not return it on <Get>.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/LDAPServer/LDAPServer.html
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
        Creates a new LDAPServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Creates an LDAPServer authentication server object under AuthenticationServer using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas).

        .PARAMETER ServerAddress
        IP address or domain name of the LDAP server [doc].

        .PARAMETER ServerPort
        Port through which the server communicates [doc]. Sophos documents a default of 389. Wire element is <Port>; renamed to -ServerPort because -Port is already the fixed connection parameter and cannot be reused. No alias 'Port' is defined either: PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it makes the whole command's metadata fail to resolve. The generated XML still uses <Port> unchanged.

        .PARAMETER Version
        LDAP protocol version [doc]: '2' or '3'.

        .PARAMETER AnonymousLogin
        Whether to bind anonymously (no username/password sent) [doc]: Enable or Disable. Sophos documents a default of Enable.

        .PARAMETER Administrator
        Bind DN username used to authenticate when -AnonymousLogin is Disable [doc].

        .PARAMETER BindPassword
        Bind password used when -AnonymousLogin is Disable [doc]. Wire element is <Password>; renamed to avoid colliding with the connection -Password parameter.

        .PARAMETER AppendBaseDN
        Whether to append the base DN during the bind operation [doc]: Enable or Disable.

        .PARAMETER ConnectionSecurity
        Connection security used when sending the user credentials [doc]: Simple, SSL or STARTTLS.

        .PARAMETER ValidateServerCertificate
        Whether to validate the LDAP server's certificate [doc]: Enable or Disable. The Attribute/Parameter table documents 'y'/'n' for this field, but the sample configuration comment documents Enable/Disable, consistent with the equivalent field on every other server type in this region; Enable/Disable is implemented. Sophos documents a default of Enable.

        .PARAMETER ClientCertificate
        Client certificate selection used for the secured connection [doc].

        .PARAMETER BaseDN
        Base distinguished name of the directory service [doc]. The table marks this optional, and the sample configuration scopes GroupNameAttribute/ExpiryDateAttribute (but not BaseDN) to TightIntegration only - however, a live, deliberately incomplete <Set operation="add"> with AnonymousLogin=Enable and every other base field set still listed /AuthenticationServer/LDAPServer/BaseDN in <InvalidParams>. Unconditionally mandatory.

        .PARAMETER AuthenticationAttribute
        Attribute used for the user search [doc].

        .PARAMETER IntegrationType
        Integration type used when setting user group membership [doc]: LooseIntegration or TightIntegration.

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user for this server [doc]. Only relevant for TightIntegration per the sample configuration; not flagged by the live mandatory-field probe (run under LooseIntegration), so kept optional.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the configured email address [doc]. Sophos documents a default of 'mail'. Only relevant for TightIntegration per the sample configuration; not flagged by the live mandatory-field probe, so kept optional.

        .PARAMETER GroupNameAttribute
        Attribute name displayed to the user for the configured group name [doc]. The sample configuration scopes this to TightIntegration only, but a live, deliberately incomplete <Set operation="add"> with AnonymousLogin=Enable (LooseIntegration, no -IntegrationType sent at all) still listed /AuthenticationServer/LDAPServer/GroupNameAttribute in <InvalidParams>. Unconditionally mandatory, contrary to the sample comment's TightIntegration-only scoping.

        .PARAMETER ExpiryDateAttribute
        Attribute displayed to the user for the configured expiry date [doc]. Same measured correction as -GroupNameAttribute: unconditionally mandatory regardless of IntegrationType, confirmed live via <InvalidParams>.

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
        # Create an LDAP server with anonymous bind
        New-SfosLDAPServer -ServerName "CorpLDAP" -ServerAddress "ldap.example.invalid" -ServerPort 389 -Version 3 -AnonymousLogin Enable -ConnectionSecurity Simple -AuthenticationAttribute "uid" -BaseDN "dc=corp,dc=example,dc=invalid" -GroupNameAttribute "memberOf" -ExpiryDateAttribute "accountExpires"

        .NOTES
        Minimum supported PowerShell version: 5.1
        ServerType, documented in the Attribute/Parameter table but absent from the sample XML for this entity, is not implemented.
        Mandatory-ness of BaseDN, GroupNameAttribute and ExpiryDateAttribute was corrected against a live firewall - see the region header.
        Measured: -Administrator is conditionally mandatory - required whenever -AnonymousLogin is 'Disable', although the Attribute/Parameter table does not mark it mandatory. The cmdlet checks this client-side and throws before calling the API; without the check, the firewall answers code 501 with no field named specifically. -BindPassword carries no such condition - confirmed not required even together with -AnonymousLogin Disable and -Administrator set.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/LDAPServer/operations/AddLDAPServer%26EditLDAPServer.html

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

    # Measured against a live firewall: with -AnonymousLogin Disable, an add that omits
    # -Administrator answers code="501" (Configuration parameters validation failed), even
    # though the Attribute/Parameter table does not mark Administrator as mandatory. With
    # -AnonymousLogin Enable the same add succeeds without -Administrator. -BindPassword was
    # also tested and is NOT part of this condition: an add with -AnonymousLogin Disable and
    # -Administrator set, but no -BindPassword, succeeds (code 200).
    if ($AnonymousLogin -eq 'Disable' -and [string]::IsNullOrWhiteSpace($Administrator)) {
        throw "New-SfosLDAPServer: -Administrator is required for LDAPServer authentication server '$ServerName' when -AnonymousLogin is 'Disable' (measured: the firewall answers code 501 without it)."
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
    # Measured: <Set operation="add"> answers at /Response/LDAPServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LDAPServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an existing LDAPServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Updates an LDAPServer authentication server object using the Sophos Firewall XML API. SFOS replaces the whole entity on update, so this cmdlet reads the current server first and keeps whatever the caller does not explicitly pass. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        The bind password is an exception to this API's usual replace-the-whole-entity behaviour, measured live: sending an empty <Password></Password> on update is accepted (code 200) and the previously stored password is preserved, not cleared - confirmed by reading it back afterwards. Get-SfosLDAPServer still never exposes it in either form; Set-SfosLDAPServer relies on the firewall's own "empty means unchanged" behaviour instead. Passing -BindPassword replaces it as normal.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ServerAddress
        IP address or domain name of the server. If omitted, the existing value is kept.

        .PARAMETER ServerPort
        Port through which the server communicates. If omitted, the existing value is kept. Named -ServerPort, not -Port: -Port is already the fixed connection parameter and cannot be reused, and no alias 'Port' is defined either, because PowerShell rejects a parameter alias that collides with another parameter's own name on the same command - measured, it breaks the command's metadata entirely. The generated XML still uses <Port> unchanged. Because there is no alias, piping Get-* output (its Port property, named after the wire element) does not auto-bind to -ServerPort; pass it explicitly.

        .PARAMETER Version
        LDAP protocol version: '2' or '3'. If omitted, the existing value is kept.

        .PARAMETER AnonymousLogin
        Whether to bind anonymously: Enable or Disable. If omitted, the existing value is kept.

        .PARAMETER Administrator
        Bind DN username. If omitted, the existing value is kept.

        .PARAMETER BindPassword
        Bind password. If omitted, the existing password is preserved (see the .DESCRIPTION) - measured live, not merely assumed.

        .PARAMETER AppendBaseDN
        Whether to append the base DN during bind: Enable or Disable. If omitted, the existing value is kept.

        .PARAMETER ConnectionSecurity
        Connection security: Simple, SSL or STARTTLS. If omitted, the existing value is kept.

        .PARAMETER ValidateServerCertificate
        Whether to validate the server's certificate: Enable or Disable. If omitted, the existing value is kept.

        .PARAMETER ClientCertificate
        Client certificate selection. If omitted, the existing value is kept.

        .PARAMETER BaseDN
        Base distinguished name. If omitted, the existing value is kept.

        .PARAMETER AuthenticationAttribute
        Attribute used for the user search. If omitted, the existing value is kept.

        .PARAMETER IntegrationType
        Integration type: LooseIntegration or TightIntegration. If omitted, the existing value is kept.

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user. If omitted, the existing value is kept.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the email address. If omitted, the existing value is kept.

        .PARAMETER GroupNameAttribute
        Attribute name displayed to the user for the group name. If omitted, the existing value is kept.

        .PARAMETER ExpiryDateAttribute
        Attribute displayed to the user for the expiry date. If omitted, the existing value is kept.

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
        # Update the base DN only, everything else preserved except the bind password
        $bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        Set-SfosLDAPServer -ServerName "CorpLDAP" -BaseDN "dc=corp,dc=example,dc=invalid" -BindPassword $bindPw

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured: -Administrator is conditionally mandatory - required whenever the update's resulting AnonymousLogin (the passed value, or the existing one if -AnonymousLogin was not passed) is 'Disable', same as New-SfosLDAPServer. The check is against the merged target values, since read-modify-write can supply Administrator from the existing object; the cmdlet throws before calling the API if the merged result would be Disable with no Administrator. Without the check, the firewall answers code 501. -BindPassword carries no such condition - confirmed not required even together with AnonymousLogin Disable and Administrator set.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/LDAPServer/operations/AddLDAPServer%26EditLDAPServer.html
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

        # Measured against a live firewall: this condition applies to Set-* as well as New-*.
        # An update that resolves to AnonymousLogin=Disable with no Administrator (neither
        # passed nor already stored on the object) answers code="501". Checked against the
        # merged target values, not the raw parameters, because read-modify-write can supply
        # Administrator from the existing object even when -Administrator was not passed here.
        if ($targetAnonymousLogin -eq 'Disable' -and [string]::IsNullOrWhiteSpace($targetAdministrator)) {
            throw "Set-SfosLDAPServer: -Administrator is required for LDAPServer authentication server '$ServerName' when -AnonymousLogin is 'Disable' (measured: the firewall answers code 501 without it)."
        }

        # Measured: an empty <Password> on update is accepted and preserves the existing bind
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
        # Measured: <Set operation="update"> answers at /Response/LDAPServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LDAPServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an LDAPServer authentication server from the Sophos Firewall.

        .DESCRIPTION
        Removes an LDAPServer authentication server object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosLDAPServer -ServerName "CorpLDAP" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosLDAPServer -ServerName "CorpLDAP"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/LDAPServer/operations/Delete%20LDAP%20Server.html
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
        Retrieves RADIUSServer authentication server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for RADIUS servers configured under AuthenticationServer. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering on this nested container is unconfirmed against a live appliance, so no <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default), keyed on ServerName. System.Xml.XmlElement when -AsXml is specified. The port property is named Port, matching the API element (section 7); ServerPort is an AliasProperty on the same value, so piping into Set-SfosRADIUSServer's -ServerPort parameter still binds by property name. SharedSecretHash/SharedSecretHashForm carry the firewall's hashed form of the shared secret - not the plaintext - and exist so Get-* | Set-* can preserve an unchanged secret; see the .NOTES.

        .EXAMPLE
        # Retrieve all RADIUS servers
        Get-SfosRADIUSServer

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosRADIUSServer -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <RADIUSServer>, matching the cmdlet noun - see the region header.
        The shared secret IS returned by <Get>, but hashed, as <SharedSecret hashform="mode1">$sfos$...</SharedSecret> - measured against a live firewall - it is not write-only. It is exposed here as SharedSecretHash/SharedSecretHashForm, not as SharedSecret, to make clear it is not the plaintext secret; Set-SfosRADIUSServer uses these two properties to preserve an unchanged secret across an update.
        The address field is <ServerAddress> and the port field is <Port>, not ServerIP/AuthenticationPort as the Attribute/Parameter table names them - measured against a live firewall via the <InvalidParams> element of a deliberately incomplete <Set operation="add">; see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/RADIUSServer/RADIUSServer.html
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
            # Measured: unlike ActiveDirectory/LDAPServer/EDirectory's <Password>, RADIUS
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
        Creates a new RADIUSServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Creates a RADIUSServer authentication server object under AuthenticationServer using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas). The Attribute/Parameter table marks this field mandatory 'No' for RADIUS, unlike every other server type in this region; it is required here regardless, because a name-less object cannot be looked up by Get-SfosRADIUSServer -ServerNameLike or Set-/Remove-SfosRADIUSServer afterwards.

        .PARAMETER ServerAddress
        IP address of the RADIUS server. Measured against a live firewall via <InvalidParams>: the wire element is <ServerAddress>, not <ServerIP> as the Attribute/Parameter table names it. Mandatory - confirmed live.

        .PARAMETER ServerPort
        Port through which the server communicates. Measured against a live firewall via <InvalidParams>: the wire element is <Port>, not <AuthenticationPort> as the Attribute/Parameter table names it. Because the true wire name collides with the fixed connection -Port parameter, it is renamed here to -ServerPort; no alias 'Port' is defined either, because PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it makes the whole command's metadata fail to resolve (see Get-SfosRADIUSServer's AliasProperty for the pipeline-binding workaround). Mandatory - confirmed live.

        .PARAMETER Timeout
        Request timeout, in seconds. Undocumented in both the Attribute/Parameter table and the sample XML - found only by observing the <InvalidParams> of a live, deliberately incomplete <Set operation="add">, which named /AuthenticationServer/RADIUSServer/Timeout as missing. Confirmed mandatory; values 1-60 were accepted live on <Set operation="update">, every value from 61 up to 300 tried was rejected with code 501 naming Timeout as invalid - so 60 is enforced here as the measured maximum, even though no documentation states it.

        .PARAMETER AccountingPort
        Accounting port [doc]. Per the sample configuration comment, this element is only sent when accounting is to be enabled; if omitted, accounting stays disabled. Not covered by the live mandatory-field probe (which used a fixed request without accounting), so its optionality remains as documented, not independently measured.

        .PARAMETER SharedSecret
        Shared secret used to encrypt information passed to the appliance [doc]. Confirmed mandatory live: omitting it answers a generic code="500" ("Operation could not be performed on Entity") rather than the code="501" validation-failure/<InvalidParams> pattern every other missing field produces here - so a caller relying only on <InvalidParams> would not learn that the secret was the cause. Adding it turned the same request into a code="200" success.

        .PARAMETER DomainName
        Domain name of the users [doc]. The table casing is 'domainName' (lower-case initial letter); PascalCase 'DomainName' is used here for consistency with the identical field on every other server type and with the sample XML tag - a likely table transcription error. Not flagged by the live mandatory-field probe, so kept optional.

        .PARAMETER IntegrationType
        Integration type used when setting user group membership [doc]: LooseIntegration or TightIntegration. Not flagged by the live mandatory-field probe, so kept optional.

        .PARAMETER GroupNameAttribute
        Attribute name displayed to the user for the configured group name [doc]. Measured against a live firewall via <InvalidParams>: unconditionally mandatory, unlike the table's plain "Mandatory: Yes" which gave no indication whether that held regardless of other field values.

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
        # Create a RADIUS server
        $secret = ConvertTo-SecureString "s3cr3t" -AsPlainText -Force
        New-SfosRADIUSServer -ServerName "CorpRadius" -ServerAddress "203.0.113.10" -ServerPort 1812 -Timeout 60 -SharedSecret $secret -GroupNameAttribute "memberOf"

        .NOTES
        Minimum supported PowerShell version: 5.1
        ServerType, documented in the Attribute/Parameter table but absent from the sample XML for this entity, is not implemented.
        Field names and mandatory-ness were corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/RADIUSServer/operations/AddRADIUSServer%26EditRADIUSServer.html

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
    # Measured: <Set operation="add"> answers at /Response/RADIUSServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RADIUSServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an existing RADIUSServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Updates a RADIUSServer authentication server object using the Sophos Firewall XML API. SFOS replaces the whole entity on update, so this cmdlet reads the current server first and keeps whatever the caller does not explicitly pass. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        Measured: an empty <SharedSecret></SharedSecret> is rejected outright by this entity (code 501, naming SharedSecret as invalid) - unlike ActiveDirectory/LDAPServer/EDirectory's <Password>, which tolerates an empty resend and keeps the existing value. So when -SharedSecret is omitted, this cmdlet instead resends the hashed secret Get-SfosRADIUSServer returns (SharedSecretHash/SharedSecretHashForm), which the firewall accepts and treats as "unchanged" - also confirmed live. That only works when the object already has a secret; a brand-new object always needs -SharedSecret via New-SfosRADIUSServer, which already requires it.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ServerAddress
        IP address of the server. If omitted, the existing value is kept. Wire element is <ServerAddress> - measured live; see Get-SfosRADIUSServer .NOTES for the correction from the table's ServerIP.

        .PARAMETER ServerPort
        Port through which the server communicates. If omitted, the existing value is kept. Wire element is <Port> - measured live. Renamed to -ServerPort because -Port is already the fixed connection parameter and cannot be reused; no alias 'Port' is defined either, because PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it breaks the command's metadata entirely. Because there is no alias, piping Get-* output (its Port property, named after the wire element) does not auto-bind here through the parameter - it binds through the AliasProperty ServerPort that Get-SfosRADIUSServer adds to its output object; pass -ServerPort explicitly otherwise.

        .PARAMETER Timeout
        Request timeout, in seconds (1-60, measured live - see New-SfosRADIUSServer .PARAMETER Timeout). If omitted, the existing value is kept.

        .PARAMETER AccountingPort
        Accounting port. If omitted, the existing value is kept.

        .PARAMETER SharedSecret
        Shared secret. If omitted, this cmdlet resends the hashed value read back from Get-SfosRADIUSServer instead - see the .DESCRIPTION for why that is necessary for this entity specifically.

        .PARAMETER DomainName
        Domain name of the users. If omitted, the existing value is kept.

        .PARAMETER IntegrationType
        Integration type: LooseIntegration or TightIntegration. If omitted, the existing value is kept. Get-SfosRADIUSServer never returns this field even when it was set on create, so "kept" here means an empty element is resent; that was confirmed live not to disturb the server's actual integration mode (TightIntegration-only fields on a sibling ActiveDirectory object survived the same treatment unchanged).

        .PARAMETER GroupNameAttribute
        Attribute name displayed to the user for the group name. If omitted, the existing value is kept. Measured mandatory live - see New-SfosRADIUSServer .PARAMETER GroupNameAttribute.

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
        # Update the domain name only, everything else preserved except the shared secret
        $secret = ConvertTo-SecureString "s3cr3t" -AsPlainText -Force
        Set-SfosRADIUSServer -ServerName "CorpRadius" -DomainName "corp.example.invalid" -SharedSecret $secret

        .NOTES
        Minimum supported PowerShell version: 5.1
        Field names and mandatory-ness were corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/RADIUSServer/operations/AddRADIUSServer%26EditRADIUSServer.html
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

        # Measured: an empty <SharedSecret> is rejected outright for this entity (code 501),
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
        # Measured: <Set operation="update"> answers at /Response/RADIUSServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RADIUSServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a RADIUSServer authentication server from the Sophos Firewall.

        .DESCRIPTION
        Removes a RADIUSServer authentication server object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosRADIUSServer -ServerName "CorpRadius" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosRADIUSServer -ServerName "CorpRadius"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/RADIUSServer/operations/Delete%20RADIUS%20Server.html
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
        Retrieves TACACSServer authentication server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for TACACS+ servers configured under AuthenticationServer. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering on this nested container is unconfirmed against a live appliance, so no <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default), keyed on ServerName. System.Xml.XmlElement when -AsXml is specified. The port property is named Port, matching the API element (section 7); ServerPort is an AliasProperty on the same value, so piping into Set-SfosTACACSServer's -ServerPort parameter still binds by property name. SharedSecretHash/SharedSecretHashForm carry the firewall's hashed form of the shared secret - not the plaintext - and exist so Get-* | Set-* can preserve an unchanged secret; see the .NOTES.

        .EXAMPLE
        # Retrieve all TACACS+ servers
        Get-SfosTACACSServer

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosTACACSServer -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <TACACSServer>, matching the cmdlet noun - see the region header.
        The shared secret IS returned by <Get>, but hashed, as <SharedSecret hashform="mode1">$sfos$...</SharedSecret> - measured against a live firewall - it is not write-only. It is exposed here as SharedSecretHash/SharedSecretHashForm, not as SharedSecret, to make clear it is not the plaintext secret; Set-SfosTACACSServer uses these two properties to preserve an unchanged secret across an update.
        The address field is <ServerAddress>, not ServerIP as the Attribute/Parameter table names it - measured against a live firewall via <InvalidParams>; see the region header.
        The port is exposed as Port (from the sample configuration), not as AuthenticationPort as the Attribute/Parameter table names it - also confirmed live via <InvalidParams>.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/TACACSServer/TACACSServer.html
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
        Creates a new TACACSServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Creates a TACACSServer authentication server object under AuthenticationServer using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas). The Attribute/Parameter table marks this field mandatory 'No' for TACACS+, unlike every other server type in this region; it is required here regardless, because a name-less object cannot be looked up by Get-SfosTACACSServer -ServerNameLike or Set-/Remove-SfosTACACSServer afterwards.

        .PARAMETER ServerAddress
        IP address of the TACACS+ server. Measured against a live firewall via <InvalidParams>: the wire element is <ServerAddress>, not <ServerIP> as the Attribute/Parameter table names it (matching the sample configuration instead). Mandatory - confirmed live.

        .PARAMETER ServerPort
        Port through which the server communicates [doc]. The sample configuration shows a default of 49 (the standard TACACS+ port) and the wire element <Port>; the Attribute/Parameter table instead names this field AuthenticationPort with a default of 1812, which is identical to the RADIUS table row on the sibling page and does not match TACACS+'s traditional port. That row is treated as a copy/paste artifact from the RADIUS documentation and is not followed here. Wire element is <Port>; renamed to -ServerPort because -Port is already the fixed connection parameter and cannot be reused. No alias 'Port' is defined either: PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it makes the whole command's metadata fail to resolve. The generated XML still uses <Port> unchanged.

        .PARAMETER SharedSecret
        Shared secret used to encrypt information passed to the appliance [doc].

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
        # Create a TACACS+ server
        $secret = ConvertTo-SecureString "s3cr3t" -AsPlainText -Force
        New-SfosTACACSServer -ServerName "CorpTacacs" -ServerAddress "203.0.113.20" -ServerPort 49 -SharedSecret $secret

        .NOTES
        Minimum supported PowerShell version: 5.1
        ServerType, documented in the Attribute/Parameter table but absent from the sample XML for this entity, is not implemented.
        Field name was corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/TACACSServer/operations/AddTACACS+Server%26EditTACACS+Server.html

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
    # Measured: <Set operation="add"> answers at /Response/TACACSServer/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TACACSServer' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an existing TACACSServer authentication server on the Sophos Firewall.

        .DESCRIPTION
        Updates a TACACSServer authentication server object using the Sophos Firewall XML API. SFOS replaces the whole entity on update, so this cmdlet reads the current server first and keeps whatever the caller does not explicitly pass. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        Measured: an empty <SharedSecret></SharedSecret> is rejected outright by this entity (code 501, naming SharedSecret as invalid) - unlike ActiveDirectory/LDAPServer/EDirectory's <Password>, which tolerates an empty resend and keeps the existing value. So when -SharedSecret is omitted, this cmdlet instead resends the hashed secret Get-SfosTACACSServer returns (SharedSecretHash/SharedSecretHashForm), which the firewall accepts and treats as "unchanged" - also confirmed live.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ServerAddress
        IP address of the server. If omitted, the existing value is kept. Wire element is <ServerAddress> - measured live; see Get-SfosTACACSServer .NOTES for the correction from the table's ServerIP.

        .PARAMETER ServerPort
        Port through which the server communicates. If omitted, the existing value is kept. Named -ServerPort, not -Port: -Port is already the fixed connection parameter and cannot be reused, and no alias 'Port' is defined either, because PowerShell rejects a parameter alias that collides with another parameter's own name on the same command - measured, it breaks the command's metadata entirely. The generated XML still uses <Port> unchanged. Because there is no alias, piping Get-* output (its Port property, named after the wire element) does not auto-bind to -ServerPort; pass it explicitly.

        .PARAMETER SharedSecret
        Shared secret. If omitted, this cmdlet resends the hashed value read back from Get-SfosTACACSServer instead - see the .DESCRIPTION for why that is necessary for this entity specifically.

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
        # Update the IP only, the shared secret is preserved automatically
        Set-SfosTACACSServer -ServerName "CorpTacacs" -ServerAddress "203.0.113.21"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Field name was corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/TACACSServer/operations/AddTACACS+Server%26EditTACACS+Server.html
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

        # Measured: an empty <SharedSecret> is rejected outright for this entity (code 501),
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
        # Measured: <Set operation="update"> answers at /Response/TACACSServer/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TACACSServer' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a TACACSServer authentication server from the Sophos Firewall.

        .DESCRIPTION
        Removes a TACACSServer authentication server object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosTACACSServer -ServerName "CorpTacacs" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosTACACSServer -ServerName "CorpTacacs"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/TACACSServer/operations/Delete%20TACACS+%20Server.html
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
        Retrieves EDirectory authentication server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for eDirectory servers configured under AuthenticationServer. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering on this nested container is unconfirmed against a live appliance, so no <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default), keyed on ServerName. System.Xml.XmlElement when -AsXml is specified. The port property is named Port, matching the API element (section 7); ServerPort is an AliasProperty on the same value, so piping into Set-SfosEDirectoryServer's -ServerPort parameter still binds by property name.

        .EXAMPLE
        # Retrieve all eDirectory servers
        Get-SfosEDirectoryServer

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosEDirectoryServer -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The cmdlet noun is 'EDirectoryServer' for consistency with the other four authentication server cmdlets, but the wire element is <EDirectory> - without "Server" - confirmed against a live firewall response (see the region header). This is a deliberate deviation from the Sophos wire spelling, kept for naming consistency with the other four authentication server cmdlets.
        The stored bind password is never exposed here: the firewall does not return it on <Get>.
        The address field is <ServerIpDomain>, not ServerAddress as the Attribute/Parameter table names it - measured against a live firewall via <InvalidParams>; see the region header.
        The username field's wire element is <Username> - also measured live, matching the sample configuration rather than the table's EdirUsername. The cmdlet parameter and this output property still use the name EdirUsername, though, because the true wire name collides with this module's own connection -Username parameter; only the XML tag sent to and read from the firewall changed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/EDirServer/EDirServer.html
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
        Creates a new EDirectory authentication server on the Sophos Firewall.

        .DESCRIPTION
        Creates an EDirectory authentication server object under AuthenticationServer using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas).

        .PARAMETER ServerIpDomain
        IP address or domain name of the eDirectory server. Measured against a live firewall via <InvalidParams>: the wire element is <ServerIpDomain>, not <ServerAddress> as the Attribute/Parameter table names it (the sample configuration's ServerIpDomain is correct). Mandatory - confirmed live.

        .PARAMETER ServerPort
        Port through which the server communicates [doc]. Sophos documents a default of 389. Wire element is <Port>; renamed to -ServerPort because -Port is already the fixed connection parameter and cannot be reused. No alias 'Port' is defined either: PowerShell rejects a parameter alias that matches another parameter's own name on the same command - measured, it makes the whole command's metadata fail to resolve. The generated XML still uses <Port> unchanged. Mandatory - confirmed live.

        .PARAMETER EdirUsername
        Admin username used to access eDirectory. Measured against a live firewall via <InvalidParams>: the wire element is <Username>, matching the sample configuration - not <EdirUsername> as the Attribute/Parameter table names it. The parameter here keeps the name EdirUsername anyway, because the true wire name <Username> would collide with this module's own connection -Username parameter; only the generated XML tag changed to <Username>. Mandatory - confirmed live.

        .PARAMETER BindPassword
        Admin password used to access eDirectory [doc]. Wire element is <Password>; renamed to avoid colliding with the connection -Password parameter.

        .PARAMETER BaseDN
        Base distinguished name of the directory service [doc].

        .PARAMETER ConnectionSecurity
        Connection security used when sending the username and password to the server [doc]: Simple, SSL or TLS. Note this entity's sample configuration spells the third option 'TLS', not 'StartTLS' as ActiveDirectory/LDAPServer do - kept distinct per entity, per Sophos's own spelling.

        .PARAMETER ValidateServerCertificate
        Whether to validate the server's certificate [doc]: Enable or Disable. The Attribute/Parameter table documents 'y'/'n' for this field, but the sample configuration comment documents Enable/Disable, consistent with the equivalent field on ActiveDirectory; Enable/Disable is implemented. Sophos documents a default of Enable.

        .PARAMETER ClientCertificate
        Client certificate selection used for the secured connection [doc].

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user for this server [doc]. Sophos documents a default of 'fullName'. This field appears only in the Attribute/Parameter table, not in the sample XML for this entity.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the configured email address [doc]. Sophos documents a default of 'mail'. Same table-only provenance as -DisplayNameAttribute.

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
        # Create an eDirectory server
        $bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        New-SfosEDirectoryServer -ServerName "CorpEdir" -ServerIpDomain "edir.example.invalid" -ServerPort 389 -EdirUsername "svc-sfos" -BindPassword $bindPw -ConnectionSecurity Simple

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <EDirectory> (no "Server") nested under <AuthenticationServer> - see the region header.
        ServerType, documented in the Attribute/Parameter table but absent from the sample XML for this entity, is not implemented.
        Field names were corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/EDirServer/operations/AddEDirectoryServer%26EditEDirectoryServer.html

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
    # Measured: <Set operation="add"> answers at /Response/EDirectory/Status - NOT nested
    # under AuthenticationServer. See the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EDirectory' -Action 'create' -Target $ServerName
}

<#
        .SYNOPSIS
        Updates an existing EDirectory authentication server on the Sophos Firewall.

        .DESCRIPTION
        Updates an EDirectory authentication server object using the Sophos Firewall XML API. SFOS replaces the whole entity on update, so this cmdlet reads the current server first and keeps whatever the caller does not explicitly pass. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        The bind password is an exception to this API's usual replace-the-whole-entity behaviour, measured live: sending an empty <Password></Password> on update is accepted (code 200) and the previously stored password is preserved, not cleared - confirmed by reading it back afterwards. Get-SfosEDirectoryServer still never exposes it in either form; Set-SfosEDirectoryServer relies on the firewall's own "empty means unchanged" behaviour instead. Passing -BindPassword replaces it as normal.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ServerIpDomain
        IP address or domain name of the server. If omitted, the existing value is kept. Wire element is <ServerIpDomain> - measured live; see Get-SfosEDirectoryServer .NOTES for the correction from the table's ServerAddress.

        .PARAMETER ServerPort
        Port through which the server communicates. If omitted, the existing value is kept. Named -ServerPort, not -Port: -Port is already the fixed connection parameter and cannot be reused, and no alias 'Port' is defined either, because PowerShell rejects a parameter alias that collides with another parameter's own name on the same command - measured, it breaks the command's metadata entirely. The generated XML still uses <Port> unchanged. Because there is no alias, piping Get-* output (its Port property, named after the wire element) does not auto-bind to -ServerPort; pass it explicitly.

        .PARAMETER EdirUsername
        Admin username used to access eDirectory. If omitted, the existing value is kept. Wire element is <Username> - measured live; see Get-SfosEDirectoryServer .NOTES for why the parameter keeps the name EdirUsername anyway.

        .PARAMETER BindPassword
        Admin password used to access eDirectory. If omitted, the existing password is preserved (see the .DESCRIPTION) - measured live, not merely assumed.

        .PARAMETER BaseDN
        Base distinguished name. If omitted, the existing value is kept.

        .PARAMETER ConnectionSecurity
        Connection security: Simple, SSL or TLS. If omitted, the existing value is kept.

        .PARAMETER ValidateServerCertificate
        Whether to validate the server's certificate: Enable or Disable. If omitted, the existing value is kept.

        .PARAMETER ClientCertificate
        Client certificate selection. If omitted, the existing value is kept.

        .PARAMETER DisplayNameAttribute
        Attribute name displayed to the user for this server. If omitted, the existing value is kept.

        .PARAMETER EmailAddressAttribute
        Attribute name displayed to the user for the configured email address. If omitted, the existing value is kept.

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
        # Update the base DN only, everything else preserved except the bind password
        $bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
        Set-SfosEDirectoryServer -ServerName "CorpEdir" -BaseDN "o=corp" -BindPassword $bindPw

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <EDirectory> nested under <AuthenticationServer> - see the region header.
        Field names were corrected against a live firewall - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/EDirServer/operations/AddEDirectoryServer%26EditEDirectoryServer.html
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

        # Measured: an empty <Password> on update is accepted and preserves the existing bind
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
        # Measured: <Set operation="update"> answers at /Response/EDirectory/Status too - see
        # the region header.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EDirectory' -Action 'update' -Target $ServerName
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an EDirectory authentication server from the Sophos Firewall.

        .DESCRIPTION
        Removes an EDirectory authentication server object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosEDirectoryServer -ServerName "CorpEdir" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosEDirectoryServer -ServerName "CorpEdir"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Wire element is <EDirectory> nested under <AuthenticationServer> - see the region header.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/EDirServer/operations/Delete%20EDirectory%20Server.html
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
        Retrieves User objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for User objects (local firewall/administrator/user
        accounts). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
        return the raw XML nodes.

        The entity key is <Username>, not <Name> - both exist side by side on the same object.
        <Status> on a User is a data field (Active/deactivated), not an API status; it is
        returned unchanged as the Status property.

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

        .PARAMETER UsernameLike
        Optional filter on the Username field, matched as a substring anywhere in the value. Sent to the firewall as the server-side pre-filter (key "Username"), then re-applied client-side.

        .PARAMETER NameLike
        Optional filter on the display Name field, matched as a substring anywhere in the value. Always applied client-side; the firewall filters User objects only on Username server-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all users
        Get-SfosUser

        .EXAMPLE
        # Filter by username (substring match)
        Get-SfosUser -UsernameLike "jdoe"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosUser -UsernameLike "jdoe" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        Password is never exposed by this cmdlet: the firewall always returns <Password/> empty,
        so it is not part of the output object. PasswordHash is returned as an opaque string (it
        is already a hash, not the clear-text password).

        The output carries both Username (the API element name, per module convention) and a
        duplicate AccountName property with the same value. New-/Set-/Remove-SfosUser cannot
        name their identifying parameter -Username, because PowerShell rejects two parameters
        of the same name on one command and -Username is already the fixed connection
        parameter (Section 4). AccountName exists purely so "Get-SfosUser | Set-SfosUser" and
        "| Remove-SfosUser" still bind by pipeline property name.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Users/Users.html
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
    # Measured live: the firewall lowercases Username on storage regardless
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
        Creates a new User on the Sophos Firewall.

        .DESCRIPTION
        Creates a User object (local firewall/administrator/user account) using the Sophos
        Firewall XML API.

        .PARAMETER AccountName
        Unique username identifying the user (1-50 characters). Named AccountName rather than
        Username on this cmdlet only, because the connection parameter -Username (Section 4)
        already owns that name and PowerShell rejects two parameters of the same name in one
        command - the wire element sent to the firewall is still <Username>.

        .PARAMETER Name
        Display name of the user (1-50 characters).

        .PARAMETER UserType
        Administrator or User. If omitted, the firewall applies its own default (User).

        .PARAMETER ProfileName
        Administrator profile. Required by the firewall when -UserType is Administrator.
        Aliased to -Profile; the parameter is named ProfileName because $Profile is an
        automatic PowerShell variable and a parameter of that name would shadow it. The
        wire element stays <Profile>.

        .PARAMETER AccountPassword
        Clear-text password for the account. Named AccountPassword rather than Password on
        this cmdlet only, because the connection parameter -Password (Section 4) already owns
        that name - the wire element is still <Password>. Mandatory [measured]: omitting
        both Password and PasswordHash on Add User answers 510 "PasswdComplexityMisMatch"
        every time, despite the doc table marking Password optional (see module NOTES).

        .PARAMETER AccountPasswordHash
        Pre-hashed password, as an alternative to -AccountPassword. Named AccountPasswordHash
        for the same reason as -AccountPassword; the wire element is still <PasswordHash>. If
        omitted, the element is not sent.

        .PARAMETER Description
        Optional description.

        .PARAMETER EmailList
        One or more e-mail addresses for the user.

        .PARAMETER Group
        Name of the UserGroup the user is to be added to.

        .PARAMETER SurfingQuotaPolicy
        Name of the surfing quota policy. If omitted, the value is inherited from the group.

        .PARAMETER AccessTimePolicy
        Name of the access time policy. If omitted, the value is inherited from the group.

        .PARAMETER DataTransferPolicy
        Name of the data transfer policy. If omitted, the value is inherited from the group.

        .PARAMETER QoSPolicy
        Name of the QoS (bandwidth) policy. If omitted, the value is inherited from the group.

        .PARAMETER SSLVPNPolicy
        Name of the SSL VPN policy.

        .PARAMETER SSLVPNIPv4Address
        Reserved static IPv4 address for SSL VPN, from the SSL VPN global settings range.

        .PARAMETER SSLVPNIPv6Address
        Reserved static IPv6 address for SSL VPN, from the SSL VPN global settings range.

        .PARAMETER ClientlessPolicy
        Name of the clientless access policy.

        .PARAMETER L2TP
        Enable or Disable L2TP access.

        .PARAMETER PPTP
        Enable or Disable PPTP access.

        .PARAMETER CISCO
        Enable or Disable CISCO (IPsec) access.

        .PARAMETER QuarantineDigest
        Enable or Disable the daily quarantine digest e-mail.

        .PARAMETER MACBinding
        Enable or Disable binding the user to a set of MAC addresses. This module does not implement the MACAddressList (see module NOTES).

        .PARAMETER IsEncryptCert
        Enable or Disable per-user certificate encryption. Applicable only when PerUserCertificate is enabled in the SSL/TLS tunnel access settings.

        .PARAMETER SimultaneousLoginsGlobal
        Enable or Disable simultaneous logins.

        .PARAMETER LoginRestriction
        AnyNode or UserGroupNode. Mandatory [measured]: Add User fails with 500 when this
        is omitted even though it does not appear in the doc's Add User attribute table at
        all (see module NOTES). SelectedNodes and NodeRange are documented but not implemented
        - see module NOTES.

        .PARAMETER ScheduleForApplianceAccess
        Name of the schedule for appliance (WebAdmin) access. Administrators only.

        .PARAMETER LoginRestrictionForAppliance
        AnyNode. Optional despite the doc table marking it Mandatory: Yes [measured]: Add
        User succeeds without it as long as -LoginRestriction is supplied (see module NOTES).
        SelectedNodes and NodeRange are documented but not implemented - see module NOTES.

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
        # Create a standard user
        $securePw = ConvertTo-SecureString "Zz-Str0ng-Passw0rd!9" -AsPlainText -Force
        New-SfosUser -AccountName "jdoe" -Name "Jane Doe" -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group "Open Group"

        .EXAMPLE
        # Create an administrator
        New-SfosUser -AccountName "admin2" -Name "Second Admin" -UserType Administrator -ProfileName "Administrator" -AccountPassword $securePw -LoginRestriction AnyNode

        .NOTES
        Minimum supported PowerShell version: 5.1

        Measured against a lab appliance: the Add User doc table marks
        Password optional and does not list LoginRestriction as a parameter at all; both are
        required in practice. Tested combinations: Password+Group+LoginRestrictionForAppliance
        without LoginRestriction -> 500; Password+Group+LoginRestriction without
        LoginRestrictionForAppliance -> 200. UserType and Group are genuinely optional - tested
        both present and entirely absent, both succeed.

        Measured: the value of -AccountPassword itself is checked against
        an undocumented complexity/blocklist rule, independent of every other field. A
        dictionary-shaped password such as "P@ssw0rd!" is rejected outright with Code 510 -
        "Operation failed. Deleting entity referred by another entity." - a message that has
        nothing to do with the actual cause. The exact same numeric code (510) is documented
        above for the different case of an entirely missing Password/PasswordHash
        ("PasswdComplexityMisMatch"), so Code 510 is reused by the firewall for at least two
        unrelated password-validation failures with two unrelated message texts; the message,
        not the code, is what has to be read. Confirmed by holding every other field constant
        (AccountName, Name, UserType, LoginRestriction, Group, EmailList all tried both present
        and absent) and varying only the password value: "P@ssw0rd!" fails every time, a longer
        non-dictionary password such as the one in the example above succeeds every time. Do not
        use "P@ssw0rd!" or similarly common passwords in examples or tests against this cmdlet.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Users/operations/AddUser%26AddAdminUser%26UpdateAdminUser%26UpdateUser.html

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
        # (LoginRestrictionForAppliance is listed there, LoginRestriction is not). Measured:
        # Password + Group + LoginRestrictionForAppliance without
        # LoginRestriction answers 500; adding LoginRestriction alone (without
        # LoginRestrictionForAppliance) succeeds. LoginRestriction, not
        # LoginRestrictionForAppliance, is the field the firewall actually requires.
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

        # Measured live: leaving QuarantineDigest empty or omitting it
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
        Updates an existing User object on the Sophos Firewall.

        .DESCRIPTION
        Updates a User object using the Sophos Firewall XML API. You can supply the target
        username directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current user first and keeps whatever
        the caller does not explicitly pass. To clear a field, pass it explicitly with an
        empty value.

        Password and PasswordHash are the exception: the firewall never returns them from a
        Get-*, so they cannot be read back. If -Password/-PasswordHash are not supplied, the
        elements are simply left out of the request. Whether that then clears the stored
        password or leaves it untouched is unverified on this firmware - see module NOTES.

        .PARAMETER AccountName
        Username of the target object. Named AccountName rather than Username on this cmdlet
        only, because the connection parameter -Username (Section 4) already owns that name -
        see module NOTES. Binds from the pipeline by the AccountName property that Get-SfosUser
        adds alongside its canonical Username property for exactly this reason.

        .PARAMETER Name
        Display name of the user. If omitted, the existing name is kept.

        .PARAMETER UserType
        Administrator or User. If omitted, the existing value is kept.

        .PARAMETER ProfileName
        Administrator profile. If omitted, the existing value is kept. Aliased to -Profile;
        the parameter is named ProfileName because $Profile is an automatic PowerShell
        variable and a parameter of that name would shadow it. The wire element stays
        <Profile>.

        .PARAMETER AccountPassword
        New clear-text password. Named AccountPassword rather than Password on this cmdlet
        only, because the connection parameter -Password (Section 4) already owns that name -
        the wire element is still <Password>. If omitted, the element is left out of the
        request (see module NOTES).

        .PARAMETER AccountPasswordHash
        New pre-hashed password, as an alternative to -AccountPassword; the wire element is
        still <PasswordHash>. If omitted, the element is left out of the request (see module
        NOTES).

        .PARAMETER Description
        Optional description. If omitted, the existing value is kept.

        .PARAMETER EmailList
        One or more e-mail addresses. If omitted, the existing list is kept.

        .PARAMETER Group
        Name of the UserGroup. If omitted, the existing value is kept.

        .PARAMETER SurfingQuotaPolicy
        Name of the surfing quota policy. If omitted, the existing value is kept.

        .PARAMETER AccessTimePolicy
        Name of the access time policy. If omitted, the existing value is kept.

        .PARAMETER DataTransferPolicy
        Name of the data transfer policy. If omitted, the existing value is kept.

        .PARAMETER QoSPolicy
        Name of the QoS (bandwidth) policy. If omitted, the existing value is kept.

        .PARAMETER SSLVPNPolicy
        Name of the SSL VPN policy. If omitted, the existing value is kept.

        .PARAMETER SSLVPNIPv4Address
        Reserved static IPv4 address for SSL VPN. If omitted, the existing value is kept.

        .PARAMETER SSLVPNIPv6Address
        Reserved static IPv6 address for SSL VPN. If omitted, the existing value is kept.

        .PARAMETER ClientlessPolicy
        Name of the clientless access policy. If omitted, the existing value is kept.

        .PARAMETER L2TP
        Enable or Disable L2TP access. If omitted, the existing value is kept.

        .PARAMETER PPTP
        Enable or Disable PPTP access. If omitted, the existing value is kept.

        .PARAMETER CISCO
        Enable or Disable CISCO (IPsec) access. If omitted, the existing value is kept.

        .PARAMETER QuarantineDigest
        Enable or Disable the daily quarantine digest e-mail. If omitted, the existing value is kept.

        .PARAMETER MACBinding
        Enable or Disable MAC address binding. If omitted, the existing value is kept.

        .PARAMETER IsEncryptCert
        Enable or Disable per-user certificate encryption. If omitted, the existing value is kept.

        .PARAMETER SimultaneousLoginsGlobal
        Enable or Disable simultaneous logins. If omitted, the existing value is kept.

        .PARAMETER LoginRestriction
        AnyNode or UserGroupNode. If omitted, the existing value is kept.

        .PARAMETER ScheduleForApplianceAccess
        Name of the schedule for appliance access. If omitted, the existing value is kept.

        .PARAMETER LoginRestrictionForAppliance
        AnyNode. If omitted, the existing value is kept.

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
        # Update the description only, every other field is preserved
        Set-SfosUser -AccountName "jdoe" -Description "Updated via PowerShell"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosUser -UsernameLike "jdoe" | Set-SfosUser -SurfingQuotaPolicy "Unlimited Internet Access"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Users/operations/AddUser%26AddAdminUser%26UpdateAdminUser%26UpdateUser.html
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

        # Measured live: a User created without an explicit QuarantineDigest
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
        Removes a User object from the Sophos Firewall.

        .DESCRIPTION
        Removes a User object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

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

        .PARAMETER AccountName
        Username of the target object. Named AccountName rather than Username on this cmdlet
        only, because the connection parameter -Username above already owns that name - see
        module NOTES.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosUser -AccountName "jdoe" -WhatIf

        .EXAMPLE
        # Remove a user
        Remove-SfosUser -AccountName "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Users/operations/Delete%20User.html
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

        # Measured live: Delete User matches <Name> case-sensitively against
        # the firewall's stored value, which is always lowercase regardless of the case used
        # at creation (see Get-SfosUser NOTES). Sending the caller's original casing here
        # answers <Status code="200"> - a false success - and removes nothing, reproduced live
        # with a mixed-case AccountName against an object that demonstrably existed.
        $usernameEsc = ConvertTo-SfosXmlEscaped -Text $AccountName.ToLowerInvariant()

        # Measured live: the Delete User operation's own doc page states
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

        # Defensive read-back: UserGroup's Remove operation was measured to answer <Status
        # code="200"> unconditionally, even for a group that never existed (see
        # Remove-SfosUserGroup NOTES). Not independently reproduced for User with the
        # corrected lowercase <Name>, but given the case-sensitivity defect just fixed above
        # produced exactly this "200 and nothing changed" shape for the wrong reason, the same
        # guard is applied here as a precaution.
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
        Retrieves UserGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for UserGroup objects. By default the cmdlet
        returns PowerShell-friendly objects. Use -AsXml to return the raw XML <GroupDetail>
        nodes.

        Measured on the lab appliance: sending any <Filter> at all on a <Get><UserGroup>
        request answers a successful, empty response - not the affected group, not every
        group, none. This differs from every other entity in this suite, where an
        unsupported key is either ignored (returns everything) or answers a recognisable
        error. Because of this, Get-SfosUserGroup never sends a server-side filter; -NameLike
        is applied entirely client-side against the full, unfiltered list.

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

        .PARAMETER NameLike
        Optional name filter, matched as a substring anywhere in the value. Applied entirely client-side (see .DESCRIPTION).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML <GroupDetail> nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all groups
        Get-SfosUserGroup

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosUserGroup -NameLike "Guest"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        Measured live: group membership in this API is NOT stored on
        <UserGroup>/<GroupMembers> - that block is a dead write path. Setting a user's own
        <Group> field and re-reading <UserGroup> afterwards shows <GroupMembers> unchanged; the
        only entry ever returned names the account the API session itself authenticates as,
        regardless of what was written. Membership actually lives on the User object's own
        <Group> field. The UserList property here is therefore populated by fetching every User
        (one extra API call) and selecting those whose Group equals this group's Name, not by
        reading <GroupMembers>. Because a User has a single Group value, a user can be a member
        of at most one UserGroup at a time. See Add-/Remove-SfosUserGroupMember NOTES.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/Groups.html
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

    # No server-side filter is sent at all: measured behaviour shows any <Filter> on this
    # entity answers a successful but empty response, regardless of whether the value would
    # match. See .DESCRIPTION.
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
    # [measured], see .NOTES. Fetch every user once and derive each group's UserList by
    # matching User.Group against this group's Name.
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
        Creates a new UserGroup on the Sophos Firewall.

        .DESCRIPTION
        Creates a UserGroup object using the Sophos Firewall XML API.

        .PARAMETER Name
        Name of the group (1-256 characters). Sophos documents this entity's Name with a 256
        character limit, unlike the 50 character limit used for most other entities in this
        API.

        .PARAMETER GroupType
        Normal or Clienless. This is the literal spelling used by the Sophos API and appliance
        - not a typo introduced here. Mandatory despite the doc table marking it optional -
        [measured]: an empty GroupType makes creation fail validation on LoginRestriction
        instead (see module NOTES).

        .PARAMETER After
        Name of the group after which the new group is positioned in the group list.

        .PARAMETER QoSPolicy
        Name of the QoS (bandwidth) policy. Documented as mandatory for this operation.

        .PARAMETER SurfingQuotaPolicy
        Name of the surfing quota policy. Applicable to GroupType Normal. Mandatory despite
        the doc table marking it optional [measured]: creation fails with a generic 500
        without both this and -AccessTimePolicy (see module NOTES).

        .PARAMETER AccessTimePolicy
        Name of the access time policy. Applicable to GroupType Normal. Mandatory despite the
        doc table marking it optional - see -SurfingQuotaPolicy and module NOTES.

        .PARAMETER DataTransferPolicy
        Name of the data transfer policy. Applicable to GroupType Normal.

        .PARAMETER SSLVPNPolicy
        Name of the SSL VPN policy. Applicable to GroupType Normal.

        .PARAMETER ClientlessPolicy
        Name of the clientless access policy. Applicable to GroupType Normal.

        .PARAMETER QuarantineDigest
        Enable or Disable the daily quarantine digest e-mail for group members.

        .PARAMETER MACBinding
        Enable or Disable binding group members to a set of MAC addresses.

        .PARAMETER L2TP
        Enable or Disable L2TP access for group members.

        .PARAMETER PPTP
        Enable or Disable PPTP access for group members.

        .PARAMETER SophosConnectClient
        Enable or Disable access through the Sophos Connect client.

        .PARAMETER LoginRestriction
        AnyNode. SelectedNodes and NodeRange are documented but not implemented - see module NOTES. Documented as mandatory for this operation.

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
        # Create a normal group
        New-SfosUserGroup -Name "Sales" -GroupType Normal -QoSPolicy "None" -SurfingQuotaPolicy "Unlimited Internet Access" -AccessTimePolicy "Allowed all the time" -LoginRestriction AnyNode

        .NOTES
        Minimum supported PowerShell version: 5.1

        Measured against a lab appliance: the response to a <Set> on
        this entity is a bare <GroupDetail>, not wrapped in <UserGroup> - Assert-
        SfosApiReturnSuccess is called with -ObjectName 'GroupDetail' for that reason. See the
        -SurfingQuotaPolicy/-AccessTimePolicy notes above for the mandatory-field finding.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/operations/AddGroups%26EditGroups.html

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

        # Mandatory despite the doc table marking it optional: measured live -
        # a create with GroupType omitted or empty and LoginRestriction=AnyNode fails with
        # 501, InvalidParams pointing at LoginRestriction instead of GroupType - an empty
        # GroupType appears to make the firewall validate LoginRestriction against the wrong
        # (or an undefined) group-type schema. Sending GroupType explicitly avoids that.
        [Parameter(Mandatory)]
        [ValidateSet('Normal', 'Clienless')]
        [string]$GroupType,

        [string]$After,

        [Parameter(Mandatory)]
        [string]$QoSPolicy,

        # Mandatory despite the doc table marking both "No": measured live -
        # a GroupType Normal create with Name+GroupType+QoSPolicy+LoginRestriction alone fails
        # with a generic 500; adding both SurfingQuotaPolicy and AccessTimePolicy together
        # produces 200. Which of the two alone would suffice was not narrowed down further -
        # both are required here, the safer of the two possible readings.
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

    # Measured: a <Set> on UserGroup answers with a bare <GroupDetail>
    # as the direct child of <Response> - NOT wrapped in <UserGroup> the way <Get> responses
    # are. -ObjectName 'UserGroup' here would search /Response/UserGroup/Status, find
    # nothing, fall back to /Response/Status, find nothing there either, and silently report
    # success: a duplicate-name create with the wrong ObjectName returned no exception although
    # the firewall answered a real error.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing UserGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a UserGroup object using the Sophos Firewall XML API. You can supply the
        target group name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current group first and keeps whatever
        the caller does not explicitly pass. To clear a field, pass it explicitly with an
        empty value. This cmdlet only touches the group's own GroupDetail fields; it never
        sends a <GroupMembers> block, so membership set via Add-/Remove-SfosUserGroupMember is
        unaffected by a plain Set-SfosUserGroup call.

        .PARAMETER Name
        Name of the target group.

        .PARAMETER GroupType
        Normal or Clienless (the literal Sophos spelling). If omitted, the existing value is kept.

        .PARAMETER After
        Name of the group after which this group is positioned. If omitted, the existing value is kept.

        .PARAMETER QoSPolicy
        Name of the QoS (bandwidth) policy. If omitted, the existing value is kept.

        .PARAMETER SurfingQuotaPolicy
        Name of the surfing quota policy. If omitted, the existing value is kept.

        .PARAMETER AccessTimePolicy
        Name of the access time policy. If omitted, the existing value is kept.

        .PARAMETER DataTransferPolicy
        Name of the data transfer policy. If omitted, the existing value is kept.

        .PARAMETER SSLVPNPolicy
        Name of the SSL VPN policy. If omitted, the existing value is kept.

        .PARAMETER ClientlessPolicy
        Name of the clientless access policy. If omitted, the existing value is kept.

        .PARAMETER QuarantineDigest
        Enable or Disable the daily quarantine digest e-mail. If omitted, the existing value is kept.

        .PARAMETER MACBinding
        Enable or Disable MAC address binding. If omitted, the existing value is kept.

        .PARAMETER L2TP
        Enable or Disable L2TP access. If omitted, the existing value is kept.

        .PARAMETER PPTP
        Enable or Disable PPTP access. If omitted, the existing value is kept.

        .PARAMETER SophosConnectClient
        Enable or Disable access through the Sophos Connect client. If omitted, the existing value is kept.

        .PARAMETER LoginRestriction
        AnyNode. If omitted, the existing value is kept.

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
        # Update the QoS policy only, every other field is preserved
        Set-SfosUserGroup -Name "Sales" -QoSPolicy "Unlimited"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosUserGroup -NameLike "Sales" | Set-SfosUserGroup -L2TP Enable

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/operations/AddGroups%26EditGroups.html
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
        # other than Enable/Disable (measured as literal "0" on the User entity when the
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

        # Measured: a <Set> on UserGroup answers with a bare
        # <GroupDetail>, not wrapped in <UserGroup> - see New-SfosUserGroup NOTES for the
        # silent-success defect this avoids.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a UserGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a UserGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

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

        .PARAMETER Name
        Name of the target group.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails, or if the group is still present after a
        reported success (see module NOTES).

        .EXAMPLE
        # Preview removal
        Remove-SfosUserGroup -Name "Sales" -WhatIf

        .EXAMPLE
        # Remove a group
        Remove-SfosUserGroup -Name "Sales"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        Measured against a lab appliance, two findings:

        1. The Remove request must wrap <Name> inside <GroupDetail> -
           <Remove><UserGroup><GroupDetail><Name>x</Name></GroupDetail></UserGroup></Remove> -
           not the flat <Remove><UserGroup><Name>x</Name></UserGroup></Remove> shape that
           works for every other entity in this suite. The flat shape answers a blank
           Login-only response and removes nothing.
        2. Even with the correct shape, the firewall answers <Status code="200"> for a group
           that does not exist at all - identically to a real removal. A status code can
           never distinguish "removed" from "there was nothing to remove" for this entity, so
           this cmdlet reads the group back after the write and throws if it is still present,
           the same defence Remove-SfosUserGroupMember uses for its append-only-list risk.

        The successful response is <Response><UserGroup><GroupDetail><Status code="200">...
        - one level deeper than every other Set/Remove response in this module - so
        Assert-SfosApiReturnSuccess is called with the compound -ObjectName
        'UserGroup/GroupDetail', which Core's XPath-based status lookup accepts as a literal
        multi-segment path without requiring any change to Core itself.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/operations/Delete%20Groups.html
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

        # <Name> must be wrapped in <GroupDetail> [measured]; the flat
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

        # The firewall answers <Status code="200"> even when the named group never existed -
        # [measured]: identical response for a real removal and a no-op. A status code
        # can never prove the removal actually happened for this entity, so read the group
        # back and throw if it is still there rather than reporting a false success.
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
        Adds members to an existing UserGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds usernames to a UserGroup's membership using the Sophos Firewall XML API.

        Measured: the documented <GroupMembers> write path on <UserGroup>
        does not work. A <Set operation="update"> carrying
        <GroupMembers><GroupName>X</GroupName><UserName>Y</UserName></GroupMembers> answers
        <Status code="200"> but a subsequent <Get><UserGroup></Get> shows no change - the only
        <GroupMembers> entry ever returned names the account the API session itself
        authenticates as, regardless of what was written. Membership actually
        lives on the User object's own <Group> field (confirmed the other way too: setting a
        user's <Group> and reading the user back shows the change, and the group's member list
        derived from scanning users - see Get-SfosUserGroup - picks it up immediately).

        This cmdlet therefore sets each named user's <Group> to this group's name, using
        Set-SfosUser's own read-modify-write for the User entity, and reads every affected user
        back afterwards to confirm before returning - a status code alone cannot be trusted for
        this write path (see above).

        Because <Group> on a User is a single value, adding a user to this group implicitly
        removes them from whatever UserGroup they were previously a member of; this API has no
        concept of multi-group membership.

        .PARAMETER Name
        Name of the target group. Must already exist.

        .PARAMETER Members
        One or more usernames to add to the group. Each must already exist as a User object.

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
        None. Throws an exception if the group or a named user does not exist, if the update
        fails, or if a member's Group still does not match this group's name after the write.

        .EXAMPLE
        # Add users to an existing group
        Add-SfosUserGroupMember -Name "Sales" -Members "jdoe","asmith"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        Measured against a lab appliance - see .DESCRIPTION for the
        <GroupMembers> defect this replaces.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/operations/AddGroups%26EditGroups.html
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
        Removes members from an existing UserGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes usernames from a UserGroup's membership using the Sophos Firewall XML API.

        Measured: the documented <GroupMembers> write path on <UserGroup>
        does not work - see Add-SfosUserGroupMember .DESCRIPTION for the measured evidence.
        Membership actually lives on the User object's own <Group> field, so this cmdlet clears
        <Group> on each named user (only if it currently equals this group's name; a user who
        is not currently a member is left untouched, matching the idempotent behaviour every
        other member-removal cmdlet in this module has), using Set-SfosUser's own read-modify-
        write for the User entity. Every affected user is read back afterwards to confirm the
        field actually cleared - a status code alone cannot be trusted for this write path.

        .PARAMETER Name
        Name of the target group.

        .PARAMETER Members
        One or more usernames to remove from the group. Each must already exist as a User
        object; a user who exists but is not currently a member of this group is left
        untouched, not treated as an error.

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
        None. Throws an exception if a named user does not exist, if the update fails, or if a
        member's Group still matches this group's name after the write.

        .EXAMPLE
        # Remove users from an existing group
        Remove-SfosUserGroupMember -Name "Sales" -Members "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        Measured against a lab appliance - see .DESCRIPTION and
        Add-SfosUserGroupMember NOTES for the <GroupMembers> defect this replaces.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/Groups/operations/AddGroups%26EditGroups.html
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
        # Add-SfosUserGroupMember NOTES for the measured <GroupMembers> defect this replaces.
        # Read every removed member back and throw if its Group still matches this group.
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

# Set-SfosGuestUser: NOT IMPLEMENTED - measured on the lab firewall (task 3), against a guest
# user created via New-SfosGuestUser (Username guest-00001, Name ZZTestC2-guest1,
# UserValidity 24). Two variants tried, both against a live object, each verified with a
# follow-up Get-SfosGuestUser rather than trusting the status code alone:
#
# 1. <Set operation="update"><GuestUser>...</GuestUser></Set>, identified by <Username>
#    (the field Remove-SfosGuestUser uses) with the full current field set resent, answered
#    code="500" "Operation could not be performed on Entity." Identified by <Name> instead
#    answered code="501" "Configuration parameters validation failed." with
#    <InvalidParams><Params>/GuestUser/Username</Params></InvalidParams> (doubled in the
#    response). Neither changed the object - the follow-up Get showed guest-00001 unchanged.
# 2. <Set operation="edit"> (undocumented but accepted by other entities in this API) did
#    not error - it answered code="200" "Configuration applied successfully." - but the
#    follow-up Get showed guest-00001 untouched and a SECOND, brand-new object
#    (guest-00002) created with the submitted fields. UserValidity was re-interpreted
#    days->hours again (24 in, 576 out) exactly as New-SfosGuestUser does on create,
#    confirming operation="edit" routed through the add path for this entity rather than
#    performing an update. This is the class of write that answers 200 and changes nothing
#    on the object it names, except here it also has the side effect of creating an
#    unwanted duplicate.
#
# Both test objects were removed with Remove-SfosGuestUser and a follow-up Get-SfosGuestUser
# confirmed no ZZTestC2- objects remained. Conclusion: GuestUser objects cannot be updated
# through the API on this firmware (SFOS 22.0, APIVersion 2200.1). This matches the vendor
# documentation, which lists only Add, Add Multiple and Delete for GuestUser - no edit/update
# operation is documented, and none was found to work. No Set-SfosGuestUser cmdlet exists in
# this module; to change a guest user's fields, remove and recreate it with
# Remove-SfosGuestUser + New-SfosGuestUser.

<#
        .SYNOPSIS
        Retrieves GuestUser objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for GuestUser objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found - the lab firewall answered <Status>No. of records Zero.</Status> for this entity with no guest users configured.

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

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match. Sent to the firewall as the server-side filter.

        .PARAMETER EmailLike
        Optional email filter, matched as a substring anywhere in the value. Applied client-side only.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all guest users
        Get-SfosGuestUser

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosGuestUser -NameLike "visitor"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured against the lab firewall: the persisted object bears little resemblance to the 'Add' sample XML. Confirmed fields, none of which are documented anywhere: <Username> (an auto-generated login distinct from the caller-supplied <Name>, e.g. 'guest-00001'), <Email> is wrapped as <EmailList><EmailID>...</EmailID></EmailList> not a flat <Email>, <UserValidity> is returned in HOURS (an input of '1' via New-SfosGuestUser -UserValidity read back as '24'), plus <Group>, <SurfingQuotaPolicy>, <AccessTimePolicy>, <DataTransferPolicy>, <QoSPolicy>, <SSLVPNPolicy>, <CreateDate>, <ExpireDate>, <L2TP>, <PPTP>, <QuarantineDigest>, <MACBinding>, <LoginRestriction>, <ScheduleForApplianceAccess>. <ValidityStart> is not returned - it is a create-time-only directive, not a persisted attribute.
        The output object exposes both the wire property name (Username) and the renamed parameter name (AccountName, an AliasProperty on Username, the same collision as ClientlessUser.UserName) so that 'Get-SfosGuestUser | Remove-SfosGuestUser' binds by property name.
        Fields NoOfUsers and the 'genexpiryperiodtype' selector (values 1/2/3, documented Mandatory but with no confirmed wire element name in the sample XML or a live object) are not implemented.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsers/GuestUsers.html
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
        Creates a new GuestUser on the Sophos Firewall.

        .DESCRIPTION
        Creates a GuestUser object using the Sophos Firewall XML API ('Add Single OR Multiple Guest Users' operation).

        .PARAMETER Name
        Name of the guest user.

        .PARAMETER UserValidity
        Guest user validity in DAYS ('genexpiryperiod' in the vendor documentation), passed as a string. The web admin labels the same field "User validity (duration in days)".

        Beware the asymmetry: the value is written in days and read back in HOURS. Creating a guest user with 1 returns 24, with 2 returns 48 - measured against a live appliance. Feeding the output of Get-SfosGuestUser straight back into New-SfosGuestUser therefore multiplies the validity by 24 on every pass. Convert explicitly, or pass the intended number of days as a literal.

        .PARAMETER Email
        Email address of the guest user. Optional here, unlike in the web admin, which marks the field mandatory: an add without it answers 200 and the object comes back with an empty Email - measured against a live appliance. Supply it anyway where guest credentials are meant to be mailed out.

        .PARAMETER ValidityStart
        Optional. When the validity period starts: 'Immediately' or 'AfterFirstLogin'. If omitted, the firewall default applies.

        .PARAMETER NoOfUsers
        Optional. Number of auto-generated guest users to create in this call (1-100). Only meaningful when GuestUserSettings uses AutoGenerate naming; not a persisted attribute of an individual guest user, so it is not exposed on Get-SfosGuestUser.

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
        # Create a single guest user
        New-SfosGuestUser -Name "visitor1" -UserValidity "1" -Email "visitor1@example.test"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured against the lab firewall: the firewall assigns its own login username (e.g. 'guest-00001', prefixed per GuestUserSettings.UserNamePrefix) independent of -Name - see Get-SfosGuestUser. -UserValidity '1' was read back by Get-SfosGuestUser as UserValidity '24', '2' as '48' - the input is in DAYS, matching both the web admin's field label ("User validity (duration in days)") and the vendor sample, while the persisted value is in HOURS. Feeding a Get straight back into this cmdlet therefore multiplies the validity by 24 per pass.

        Three points from the vendor reference (Add Single OR Multiple Guest Users), checked against the appliance:
        - Only Add and Delete are documented for this entity. There is no update operation, which is why this module ships no Set-SfosGuestUser - see the region header for what operation="edit" does instead.
        - The table marks 'genexpiryperiodtype' mandatory and allows only '1', '2' or '3'; the sample XML omits it entirely. Measured: an add without it answers 200, and sending it as <ExpiryPeriodType> or <genexpiryperiodtype> with 1, 2 or 3 changes nothing about the value read back (1 in, 24 out in every case). It is therefore not implemented, and the unit conversion above is not selectable through it.
        - The table marks Email optional, and an add without it answers 200 with an empty Email on the way back. The web admin marks the same field mandatory. The documentation wins here because the appliance agrees with it.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsers/operations/AddSingleORMultipleGuestUsers.html

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
        Removes a GuestUser object from the Sophos Firewall.

        .DESCRIPTION
        Removes a GuestUser object using the Sophos Firewall XML API ('Delete Guest User' operation). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER AccountName
        Login username identifying the guest user (the auto-generated value shown as <Username> by Get-SfosGuestUser, e.g. 'guest-00001' - NOT the caller-supplied display -Name used at creation). Wire element is <Username>; renamed to -AccountName for the same reason as ClientlessUser's identifying parameter: -Username is already the fixed connection parameter and collides with it case-insensitively during PowerShell parameter binding. No alias 'Username' is defined either.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        Remove-SfosGuestUser -AccountName "guest-00001" -WhatIf

        .EXAMPLE
        Get-SfosGuestUser -NameLike "visitor1" | Remove-SfosGuestUser

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured against the lab firewall: the 'Delete Guest User' documentation page names the identifying field 'Username', and this is literally correct, not generic boilerplate - <Remove><GuestUser><Name>...</Name></GuestUser></Remove> answers Code 500 "Operation could not be performed on Entity", while <Remove><GuestUser><Username>...</Username></GuestUser></Remove> (the auto-generated login, not the display Name) answers Code 200 and actually deletes the object. Confirmed with a full create/remove/verify cycle.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsers/operations/Delete%20Guest%20User.html
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
        Retrieves the GuestUserSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the GuestUserSettings singleton ('General Settings' / 'Configure Guest User' operation). There is exactly one instance of this element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

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
        Get-SfosGuestUserSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        The lab firewall's live object had no <SMSGateway> element even though the documentation marks it Mandatory - it is only relevant when GuestUserSettingsName is 'CellNumber', and the live configuration uses 'AutoGenerate'. Exposed here as optional.
        The sample XML also lists <grouplist_cat> and <smsgwprofileid_cat> - these read like internal admin-console field identifiers (lower-case, '_cat' suffix), appear in no other source and are not present on the live object, so they are not implemented.

        CONFIRMED LIVE DEFECT: calling Set-SfosGuestUserSettings - even a no-op update that resends the exact values this cmdlet had just read - makes every subsequent Get-SfosGuestUserSettings answer <Status>Transaction fail</Status> (no code attribute) instead of the settings, and this cmdlet correctly throws on it rather than mis-reading it as an empty result (see Assert-SfosApiReturnSuccess). The broken state was still present after a 30+ second wait and did not self-heal; a follow-up Set with the original captured values answered 200 but did not restore the Get path either. No other entity's Get was affected in the same session (SMSGateway kept working throughout), so this is isolated to GuestUserSettings, not a session- or Core-wide issue. This looks like a firmware-side bug in the settings singleton's own transaction handling, not something a client-side retry or workaround can fix - do not call Set-SfosGuestUserSettings against a firewall you cannot immediately verify afterward through the web admin console.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersGeneralSettings/GuestUsersGeneralSettings.html
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
        Updates the GuestUserSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the GuestUserSettings singleton using the Sophos Firewall XML API ('Configure Guest User' operation). This cmdlet reads the current settings first and resends every field, overriding only what the caller explicitly passes (read-modify-write). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER AllowGuestUserSettings
        Enable/Disable secured internet access for guest users. If omitted, the existing value is kept.

        .PARAMETER SMSGateway
        Name of the SMS gateway to use when GuestUserSettingsName is 'CellNumber'. If omitted, the existing value is kept.

        .PARAMETER GuestUserSettingsName
        Method for generating the guest username: 'CellNumber' or 'AutoGenerate'. If omitted, the existing value is kept.

        .PARAMETER UserNamePrefix
        Prefix used for auto-generated usernames (max 10 characters). If omitted, the existing value is kept.

        .PARAMETER Days
        Guest user validity period in days. If omitted, the existing value is kept.

        .PARAMETER AutoPurgeOnExpiry
        Enable/Disable automatic purging of user details on expiry. The vendor documentation states only 'Enable' is allowed, but the lab firewall's own live object carries this element, so both values are accepted here. If omitted, the existing value is kept.

        .PARAMETER UserGroup
        Group to assign to guest users. If omitted, the existing value is kept.

        .PARAMETER CountryCode
        Default country code. If omitted, the existing value is kept.

        .PARAMETER CAPTCHVerification
        Enable/Disable CAPTCHA verification. Spelling matches the wire element (missing the second 'A' of CAPTCHA) - not a typo introduced here. If omitted, the existing value is kept.

        .PARAMETER PasswordLength
        Length of the auto-generated password (3-50). If omitted, the existing value is kept.

        .PARAMETER PasswordComplexity
        Complexity of the auto-generated password. If omitted, the existing value is kept.

        .PARAMETER Disclaimer
        Disclaimer text shown to guest users. Pass an empty string to clear it. If omitted, the existing value is kept.

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
        Set-SfosGuestUserSettings -Days 14 -AutoPurgeOnExpiry Enable

        .NOTES
        Minimum supported PowerShell version: 5.1
        CONFIRMED LIVE DEFECT (task 10, lab firewall): every call to this cmdlet that reached the firewall - including a pure no-op update resending the values just read back - answered <Status code="200">Configuration applied successfully.</Status> for the write itself, but permanently broke Get-SfosGuestUserSettings afterward (<Status>Transaction fail</Status>, no code, on every subsequent call, no self-healing observed after 30+ seconds). A second write with the original captured values also answered 200 without restoring the Get path. See Get-SfosGuestUserSettings .NOTES for the full reproduction. This cmdlet is kept implemented (documentation-faithful, matching the project convention for measured-but-unfixable firmware defects such as Remove-SfosFileType) but must not be treated as safe to call without the ability to verify the result through the web admin console immediately afterward.

        Follow-up on a later day, after the web admin was consulted: the stored configuration is intact. The web admin renders every field with exactly the values captured before the first write, and pressing its own Apply button reports success - yet the API's Get keeps answering 'Transaction fail'. Only the API read path is affected, not the data. None of the following restored it: rewriting the captured baseline through the API, omitting <SMSGateway>, sending a valid one, operation="update", operation="add", and no operation attribute at all. The web admin's Apply does not help either, plausibly because the registration block it would have to rewrite is greyed out while guest registration is disabled.

        The vendor reference (Configure Guest User) lists exactly the eleven elements this cmdlet sends, with matching allowed values, plus nothing this cmdlet lacks - so the request shape is not the cause. Note the reference marks SMSGateway mandatory although a live object exists without it.

        Investigation closed. The appliance was restarted and the read path stayed broken, so it is not a boot-lifetime state. Writes do land: PasswordLength was set to 11 through the API and appeared in the web admin, then set back to 8 - the stored record therefore holds exactly what was written and is still unreadable. Eleven alternative root element names were probed and every one answered 529 "Input request module is Invalid", while GuestUserSettings answers the code-less "Transaction fail" - the request reaches its handler and the handler fails internally. Element names are case-insensitive here; GuestUsersGeneralSettings, the folder name used by the documentation, is not a valid element in either direction.

        What this means for callers: on an appliance in this state the settings can only be changed through the web admin, because this cmdlet reads before it writes and that read throws. No bypass switch was added on purpose - a write that cannot read the current object first cannot preserve the fields it does not know, which is the exact damage read-modify-write exists to prevent. It is a firmware defect worth reporting to Sophos, and the useful part of that report is that writing still works while reading does not.

        ConfirmImpact High: a write can irreversibly break this entity's own
        read path (measured, reboot does not restore it); automation must pass -Confirm:$false.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersGeneralSettings/operations/ConfigureGuestUser.html
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
    [CmdletBinding(SupportsShouldProcess)]
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

# Not exported. Measured on the lab firewall (task 10): the response body for ClientlessUser
# operations can carry the root entity element's 'transactionid' attribute TWICE
# (<ClientlessUser transactionid="" transactionid="">...</ClientlessUser>), which makes
# System.Xml.XmlDocument reject the whole response ("'transactionid' is a duplicate
# attribute name") before Assert-SfosApiReturnSuccess ever sees the real status. Reproduced
# on New-SfosClientlessUser with both a rejected (Code 501 + InvalidParams) and an accepted
# (two Code 200 blocks) request, so it is a response-formatting defect independent of
# whether the write itself succeeds. Collapsing the duplicate attribute only fixes parsing;
# it does not change which status codes count as success - Assert-SfosApiReturnSuccess still
# throws on a genuine embedded failure status, now with the real Sophos message instead of an
# XML parser exception.
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
        Retrieves ClientlessUser objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ClientlessUser objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found - the lab firewall answered <Status>No. of records Zero.</Status> for this entity with no clientless users configured.

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

        .PARAMETER NameLike
        Optional display-name filter. Sent to the firewall as the server-side filter ('like' is a substring match).

        .PARAMETER AccountNameLike
        Optional login-username filter, matched as a substring anywhere in the value. Applied client-side only.

        .PARAMETER IPAddressLike
        Optional IP address filter, matched as a substring anywhere in the value. Applied client-side only.

        .PARAMETER ClientLessGroupLike
        Optional group filter, matched as a substring anywhere in the value. Applied client-side only.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        Get-SfosClientlessUser

        .EXAMPLE
        Get-SfosClientlessUser -AccountNameLike "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The output object exposes both the wire property name (UserName) and the renamed parameter name (AccountName, an AliasProperty on UserName) so that 'Get-SfosClientlessUser | Set-SfosClientlessUser' binds by property name.
        WebFilter, AppFilter and QOS appear in the 'Update Client Less Users' attribute table but have no corresponding element in either sample XML and no live object exists to confirm them - not implemented.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ClientlessUsers/ClientlessUsers.html
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
        Creates a new ClientlessUser on the Sophos Firewall.

        .DESCRIPTION
        Creates a ClientlessUser object using the Sophos Firewall XML API ('Add Clientless Users' operation). Clientless users bypass client login and access the internet directly.

        .PARAMETER AccountName
        Login username of the clientless user. Wire element is <UserName>; renamed to -AccountName because -Username is already the fixed connection parameter and 'UserName' collides with it case-insensitively during PowerShell parameter binding. No alias 'Username' is defined either - see the fragment header comment on Get-SfosGuestUser.

        .PARAMETER Name
        Display name of the user.

        .PARAMETER ClientLessGroup
        Group in which the user is added.

        .PARAMETER Email
        Email address of the user.

        .PARAMETER IPAddress
        Optional IPv4/IPv6 address for the clientless user.

        .PARAMETER Description
        Optional free-text description.

        .PARAMETER QuarantineDigest
        Optional. Spam/quarantine digest option: 'ApplyGroupSettings', 'Enable' or 'Disable'.

        .PARAMETER Status
        Optional. 'Active' or 'Inactive'.

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
        New-SfosClientlessUser -AccountName "jdoe" -Name "John Doe" -ClientLessGroup "Clientless Group" -Email "jdoe@example.test" -IPAddress "203.0.113.10"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ClientlessUsers/operations/AddClientlessUsers.html

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
        Updates an existing ClientlessUser object on the Sophos Firewall.

        .DESCRIPTION
        Updates a ClientlessUser object using the Sophos Firewall XML API ('Update Client Less Users' operation). This cmdlet reads the current object first and keeps whatever the caller does not explicitly pass (read-modify-write). Single parameter set so pipeline input from Get-SfosClientlessUser binds correctly.

        .PARAMETER AccountName
        Login username identifying the clientless user. Same rename rationale as New-SfosClientlessUser.

        .PARAMETER Name
        Optional display name. If omitted, the existing value is kept.

        .PARAMETER ClientLessGroup
        Optional group. If omitted, the existing value is kept.

        .PARAMETER Email
        Optional email address. If omitted, the existing value is kept.

        .PARAMETER IPAddress
        Optional IP address. If omitted, the existing value is kept.

        .PARAMETER Description
        Optional description. If omitted, the existing value is kept.

        .PARAMETER QuarantineDigest
        Optional spam/quarantine digest option. If omitted, the existing value is kept.

        .PARAMETER QoSPolicy
        Optional QoS policy, only accepted on update per the vendor sample XML ('only for Edit'). If omitted, the existing value is kept.

        .PARAMETER Status
        Optional 'Active'/'Inactive'. If omitted, the existing value is kept.

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
        Set-SfosClientlessUser -AccountName "jdoe" -Status Inactive

        .EXAMPLE
        Get-SfosClientlessUser -AccountNameLike "jdoe" | Set-SfosClientlessUser -Description "Contractor access"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ClientlessUsers/operations/UpdateClientlessUsers.html
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
        Removes a ClientlessUser object from the Sophos Firewall.

        .DESCRIPTION
        Removes a ClientlessUser object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        UNCONFIRMED: the Sophos documentation lists only 'Add Clientless User Range', 'Add Clientless Users' and 'Update Client Less Users' as operations for this entity - no delete operation is documented. This cmdlet sends the generic <Remove> envelope that works for every other entity in this API family and is implemented so it can be checked against a live firewall in task 10. If the firewall rejects it (or answers success while leaving the object in place), this cmdlet must be removed rather than worked around.

        .PARAMETER AccountName
        Login username identifying the clientless user. Same rename rationale as New-SfosClientlessUser.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        Remove-SfosClientlessUser -AccountName "jdoe" -WhatIf

        .EXAMPLE
        Remove-SfosClientlessUser -AccountName "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against a live firewall - no delete operation is documented for this entity. The append-only/no-op class of defect seen elsewhere in this API is possible here too: verify before relying on removal, and remove this cmdlet if the firewall rejects the removal or silently leaves the object in place.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ClientlessUsers/ClientlessUsers.html
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
        Adds a range of ClientlessUser objects on the Sophos Firewall.

        .DESCRIPTION
        Creates multiple ClientlessUser objects for an IP address range in a single call, using the Sophos Firewall XML API ('Add Clientless User Range' operation). This is a pure add operation - the live response for this entity carries no content node to read back, so there is no matching Get- cmdlet; use Get-SfosClientlessUser to see the resulting objects.

        .PARAMETER FromIPAddress
        Starting IP address of the range.

        .PARAMETER ToIPAddress
        Ending IP address of the range.

        .PARAMETER ClientLessGroup
        Optional group to assign to the generated users.

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
        New-SfosClientlessUserRange -FromIPAddress "203.0.113.10" -ToIPAddress "203.0.113.20" -ClientLessGroup "Clientless Group"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The wire entity is <ClientlessUserAddRange>, distinct from <ClientlessUser> used by the other cmdlets in this region - confirmed by the sample XML, no live object exists for this operation-only element.
        All three fields are documented Mandatory="No", which is unusual for a range operation - implemented as documented rather than second-guessed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/ClientlessUsers/operations/AddClientlessUserRange.html
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
        Retrieves SMSGateway objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SMSGateway objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

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

        .PARAMETER NameLike
        Optional name filter. Sent to the firewall as the server-side filter ('like' is a substring match).

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        Get-SfosSMSGateway

        .EXAMPLE
        Get-SfosSMSGateway -NameLike "Turkcell"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured on the live firewall: <RequestParamterList> and <ResponseParamterList> each wrap exactly one <RequestParamter>/<ResponseParamter> element that itself holds N sibling <ParameterName> elements followed by N sibling <ParameterValue> elements, matched positionally by index - not N repeated <RequestParamter> elements each with one name/value pair. This cmdlet exposes them as parallel arrays (RequestParameterName/RequestParameterValue, ResponseParameterName/ResponseParameterValue) rather than reconstructing a merged object, matching what Get-* actually returns.
        The wrapper element names carry the firmware's own misspelling 'Paramter' (RequestParamterList, RequestParamter, ResponseParamterList, ResponseParamter) - reproduced verbatim; ParameterName/ParameterValue are spelled correctly.
        <MobileNo> appears in the sample XML but is a parameter of the 'SMS Gateway Test Connection' operation, not a stored field of the entity - absent from the live object and not implemented.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersSMSGateway/GuestUsersSMSGateway.html
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
        Creates a new SMSGateway on the Sophos Firewall.

        .DESCRIPTION
        Creates an SMSGateway profile using the Sophos Firewall XML API ('Add SMS Gateway Profile' operation).

        .PARAMETER Name
        Name of the SMS gateway (1-100 characters, no commas).

        .PARAMETER URL
        URL for sending the SMS request. Must start with ftp/http/https, or be an IPv4 address.

        .PARAMETER HTTPMethod
        Optional HTTP method: 'Get' or 'Post'.

        .PARAMETER UseCountryCodeWithCellNumber
        Optional. Enable/Disable prefixing the cell number with the country code.

        .PARAMETER CellNumberPreFix
        Optional prefix to use with the cell number.

        .PARAMETER RequestParameterName
        Optional array of request parameter names, matched positionally with -RequestParameterValue.

        .PARAMETER RequestParameterValue
        Optional array of request parameter values, matched positionally with -RequestParameterName. Must be the same length.

        .PARAMETER ResponseFormat
        Optional response format string (max 255 characters).

        .PARAMETER ResponseParameterName
        Optional array of response parameter names, matched positionally with -ResponseParameterValue.
        Unlike the request parameters, these names must be
        NUMERIC placeholder indexes ('0', '1', ...) matching {0}/{1} in -ResponseFormat - a
        free-text name is rejected with 400. The three factory templates all follow this shape.

        .PARAMETER ResponseParameterValue
        Optional array of response parameter values, matched positionally with -ResponseParameterName. Must be the same length.

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
        New-SfosSMSGateway -Name "ExampleGateway" -URL "https://sms.example.test/send" -HTTPMethod Post -RequestParameterName @('to','msg') -RequestParameterValue @('{mobileno}','{msg}')

        .NOTES
        Minimum supported PowerShell version: 5.1
        See Get-SfosSMSGateway for the measured, undocumented shape of the parameter list wrappers and the firmware misspelling 'Paramter'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersSMSGateway/operations/AddSMSGatewayProfile%26SMSGatewayTestConnection%26EditSMSGatewayProfile.html

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
        Updates an existing SMSGateway object on the Sophos Firewall.

        .DESCRIPTION
        Updates an SMSGateway profile using the Sophos Firewall XML API ('Edit SMS Gateway Profile' operation). This cmdlet reads the current object first and keeps whatever the caller does not explicitly pass (read-modify-write).

        .PARAMETER Name
        Name of the target SMS gateway.

        .PARAMETER URL
        Optional. If omitted, the existing value is kept.

        .PARAMETER HTTPMethod
        Optional. If omitted, the existing value is kept.

        .PARAMETER UseCountryCodeWithCellNumber
        Optional. If omitted, the existing value is kept.

        .PARAMETER CellNumberPreFix
        Optional. If omitted, the existing value is kept.

        .PARAMETER RequestParameterName
        Optional array of request parameter names, matched positionally with -RequestParameterValue. If neither -RequestParameterName nor -RequestParameterValue is passed, the existing list is kept.

        .PARAMETER RequestParameterValue
        Optional array of request parameter values, matched positionally with -RequestParameterName. Must be the same length.

        .PARAMETER ResponseFormat
        Optional. If omitted, the existing value is kept.

        .PARAMETER ResponseParameterName
        Optional array of response parameter names, matched positionally with -ResponseParameterValue.
        Unlike the request parameters, these names must be
        NUMERIC placeholder indexes ('0', '1', ...) matching {0}/{1} in -ResponseFormat - a
        free-text name is rejected with 400. The three factory templates all follow this shape. If neither -ResponseParameterName nor -ResponseParameterValue is passed, the existing list is kept.

        .PARAMETER ResponseParameterValue
        Optional array of response parameter values, matched positionally with -ResponseParameterName. Must be the same length.

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
        Set-SfosSMSGateway -Name "ExampleGateway" -CellNumberPreFix "+1"

        .EXAMPLE
        Get-SfosSMSGateway -NameLike "ExampleGateway" | Set-SfosSMSGateway -HTTPMethod Get

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersSMSGateway/operations/AddSMSGatewayProfile%26SMSGatewayTestConnection%26EditSMSGatewayProfile.html
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
        Removes an SMSGateway object from the Sophos Firewall.

        .DESCRIPTION
        Removes an SMSGateway object using the Sophos Firewall XML API ('Delete SMS Gateway Profile' operation). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Name
        Name of the target SMS gateway.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        Remove-SfosSMSGateway -Name "ExampleGateway" -WhatIf

        .EXAMPLE
        Remove-SfosSMSGateway -Name "ExampleGateway"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/GuestUsersSMSGateway/operations/Delete%20SMS%20Gateway%20Profile.html
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
        Retrieves the OTPSettings singleton from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the OTPSettings singleton, which holds the
        global One-Time-Password configuration. There is exactly one instance of this element
        per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to
        return the raw XML node.

        The 12 wire elements returned by the firewall are all lower-camelCase (otp, allUsers,
        tokenAutoCreation, ...). The PowerShell properties on the returned object are
        PascalCase; see the module documentation for the full name mapping.

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
        # Retrieve the current OTP settings
        Get-SfosOTPSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>) and XML escaping for user input.

        The Attribute/Parameter Information table on the operations page documents two
        further fields, waf and hotspot, that do not appear in the table's own sample XML
        block. Measured live: a Get of OTPSettings returns exactly the 12 elements listed
        above - no waf, no hotspot element, present or empty - on this firmware. Same
        precedent as FileType/-Template in the Web module: a field the Get never returns
        cannot be read back, so Set-SfosOTPSettings does not expose it either, rather than
        implementing a parameter that read-modify-write could never actually preserve.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPSettings/operations/ConfigureOTP.html
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
        Updates the OTPSettings singleton on the Sophos Firewall.

        .DESCRIPTION
        Updates the global One-Time-Password configuration using the Sophos Firewall XML API.
        SFOS replaces the whole entity on update - every element the request omits is cleared
        on the firewall - so this cmdlet reads the current settings first and resends all 12
        fields plus the explicit user list, overriding only what the caller explicitly passes.

        .PARAMETER Otp
        Switches OTP on ('1') or off ('0') globally. If omitted, the value on the firewall is kept.

        .PARAMETER AllUsers
        Require all users to provide One Time Passwords ('1'), or only users/groups for which OTP was explicitly enabled ('0'). If omitted, the value on the firewall is kept.

        .PARAMETER Members
        Explicit list of usernames that must use OTP when -AllUsers is '0'. Maps to the <otpUsers><user>...</user></otpUsers> wire list. If omitted, the existing list is kept. Prefer Add-SfosOTPSettingsMember/Remove-SfosOTPSettingsMember for incremental changes - this parameter replaces the whole list.

        .PARAMETER TokenAutoCreation
        Automatically generate a user's OTP token when the user is created ('1') or not ('0'). If omitted, the value on the firewall is kept.

        .PARAMETER OtpUserPortal
        Require OTP for the User Portal ('1' or '0'). If omitted, the value on the firewall is kept.

        .PARAMETER OtpVPNPortal
        Require OTP for the VPN Portal ('1' or '0'). If omitted, the value on the firewall is kept.

        .PARAMETER OtpSSLVPN
        Require OTP for SSL VPN sign-in ('1' or '0'). If omitted, the value on the firewall is kept.

        .PARAMETER OtpWebAdmin
        Require OTP for WebAdmin sign-in ('1' or '0'). WARNING: WebAdmin is the same login this
        API session authenticates through. Setting this to '1' without a working OTP token
        configured for the account in use can lock the account out of both WebAdmin and the API.
        This module was never used to write this field against a live firewall - verify on a
        console or out-of-band access path before changing it. If omitted, the value on the
        firewall is kept.

        .PARAMETER OtpIPsec
        Require OTP for IPsec remote access ('1' or '0'). If omitted, the value on the firewall is kept.

        .PARAMETER Algorithm
        Hash algorithm used to generate OTPs: 'SHA1', 'SHA256' or 'SHA512'. If omitted, the value on the firewall is kept.

        .PARAMETER DefaultTimeStep
        Length, in seconds, of the interval during which an OTP is valid (10-300). If omitted, the value on the firewall is kept.

        .PARAMETER MaxTimeStepsInterval
        Number of time steps to search backward/forward for a matching OTP, to compensate for clock drift (0-10). If omitted, the value on the firewall is kept.

        .PARAMETER MaxInitialTimeStepDiff
        Number of time steps to search backward/forward for the very first use of a token, to compensate for missing clock synchronisation (0-600). If omitted, the value on the firewall is kept.

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
        # Change only the default time step, every other field is preserved
        Set-SfosOTPSettings -DefaultTimeStep 60

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified against a live firewall: a no-op round trip (read, write back unchanged,
        read again) produced character-identical raw XML, and a change/revert cycle on
        MaxInitialTimeStepDiff (10 -> 11 -> 10) left all 11 other fields untouched. otp,
        otpWebAdmin, otpUserPortal, otpVPNPortal, otpSSLVPN, otpIPsec and allUsers were never
        used as a change target in that verification - only ever resent unchanged as part of
        read-modify-write - because otpWebAdmin governs the WebAdmin login this API session
        itself authenticates through.

        The operations page documents two further fields, waf and hotspot, that this cmdlet
        does not send. Measured live: Get-SfosOTPSettings never returns either element on
        this firmware, so there is no value to preserve and nothing to merge in a
        read-modify-write. Sending them regardless would be guessing at a value the firewall
        never discloses. See Get-SfosOTPSettings for the same finding and the FileType/
        -Template precedent it is measured against.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPSettings/operations/ConfigureOTP.html
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
        Adds usernames to the OTPSettings explicit OTP user list.

        .DESCRIPTION
        Adds one or more usernames to the <otpUsers> list of the OTPSettings singleton, which
        governs which users must use OTP when -AllUsers is '0'. SFOS replaces the whole entity
        on update, so this cmdlet reads the current settings first and resends every field,
        merging the new usernames into the existing list instead of overwriting it.

        .PARAMETER Members
        One or more usernames to add to the explicit OTP user list. Duplicates are silently reduced to a single entry. Measured on a live firewall: a username that does not exist on the firewall is silently dropped by SFOS - the call answers 200 and the list is left without that entry. This cmdlet does not validate the username against the User entity first, so verify with Get-SfosOTPSettings after adding.

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
        # Add two users to the explicit OTP user list
        Add-SfosOTPSettingsMember -Members "jdoe","asmith"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The underlying <otpUsers> wire behaviour - including the silent-drop of a non-existent
        username documented on -Members above - was measured live against a raw request. This
        cmdlet's own read-modify-write wrapper around that behaviour was not separately
        exercised against a live firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPSettings/operations/ConfigureOTP.html

        .LINK
        Get-SfosOTPSettings

        .LINK
        Set-SfosOTPSettings
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
        Removes usernames from the OTPSettings explicit OTP user list.

        .DESCRIPTION
        Removes one or more usernames from the <otpUsers> list of the OTPSettings singleton.
        SFOS replaces the whole entity on update, so this cmdlet reads the current settings
        first and resends every field, writing back the member list with the given usernames
        removed instead of an operation="remove" (which does not exist for <Set>).

        Measured on a live firewall: <otpUsers> is append-only on a normal update. Omitting the
        wrapper, sending <otpUsers/>, and sending <otpUsers></otpUsers> all answer 200 and leave
        the list unchanged - a shorter, non-empty list is silently ignored. The one way found to
        actually clear entries is a single empty <user/> child, <otpUsers><user/></otpUsers>,
        which empties the whole list (not just the targeted entries) and also answers 200. As a
        result, this cmdlet can reliably remove usernames only when the removal empties the list
        completely; removing one username out of several currently cannot be done through this
        API and this cmdlet detects that after writing and throws rather than reporting a silent
        success - the same behavior as Remove-SfosFirewallRuleGroupMember.

        .PARAMETER Members
        One or more usernames to remove from the explicit OTP user list.

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
        # Remove a user from the explicit OTP user list
        Remove-SfosOTPSettingsMember -Members "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        The underlying <otpUsers> append-only behaviour described above was measured live
        against a raw request (see Set-SfosOTPSettings for the OTPSettings verification
        summary). This cmdlet's own read-modify-write wrapper, including the post-write guard
        below, was not separately exercised against a live firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPSettings/operations/ConfigureOTP.html

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

    # <otpUsers> is append-only on a normal update (measured live): a shorter, non-empty list
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
        throw "Removing member(s) '$($stillPresent -join ', ')' from OTPSettings answered success but the firewall left them in place. otpUsers only accepts a full clear (empty the whole list) on this firmware, not a partial removal - see this cmdlet's help for the measured behaviour."
    }
}

#endregion

#region OTPTokens

<#
        .SYNOPSIS
        Retrieves OTPTokens objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for OTPTokens objects. By default the cmdlet
        returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Field list confirmed against a live OTPTokens object created for verification. The
        documentation's <timeStep> field does not exist on the wire; the real fields are
        <useCustomTokenTimeStep> and <timeStepOffset> (see -UseCustomTokenTimeStep below).

        .PARAMETER TokenIdLike
        Optional filter on the token id, matched as a substring. Sent to the firewall as the
        server-side filter (unverified - see .NOTES) and re-applied client-side.

        .PARAMETER UserLike
        Optional filter on the associated username, matched as a substring. Always applied client-side; the firewall's filter support for this field is unverified.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all OTP tokens
        Get-SfosOTPTokens

        .EXAMPLE
        # Filter by associated user (substring match, client-side)
        Get-SfosOTPTokens -UserLike "jdoe"

        .NOTES
        Minimum supported PowerShell version: 5.1
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
        PSUseSingularNouns is suppressed on purpose: <OTPTokens> is the entity's own element
        name and there is no singular child element. Renaming it would break the mapping to
        the API.

        The returned object has no -Secret/-SecretHash property. Measured live: the firewall
        does return a <secret hashform="mode1"> element - an opaque hash, not the plaintext
        that was written - and it was character-identical before and after an unrelated update
        (see Set-SfosOTPTokens .NOTES). This cmdlet still does not surface it as a property, to
        avoid ever handling anything that reads like a secret value even in hashed form; a
        caller who needs to confirm a token's secret was not silently cleared can use -AsXml.
        Exposing it as a first-class property would be a reasonable follow-up but was out of
        scope here.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPTokens/operations/AddOTPToken%26UpdateOTPToken.html
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
        Creates a new OTPTokens object on the Sophos Firewall.

        .DESCRIPTION
        Creates an OTP token using the Sophos Firewall XML API. -User and -Secret are mandatory:
        every successful create observed on a live firewall carried a <user> and a valid
        <secret>, and every attempt with an invalid secret was rejected outright, so a token
        cannot be functionally created without both.

        .PARAMETER TokenId
        Token identifier (1-32 characters). If omitted, behaviour is undocumented - most likely the firewall assigns one, but this was not verified against a live firewall.

        .PARAMETER User
        Username the token is associated with. Mandatory - see .DESCRIPTION. Maps to the wire element <user>. The documented attribute table names this field 'userid' (datatype INTEGER) instead, but that table row's own description is malformed (empty "confines to:" label, unlike every other row), while the sample XML consistently uses <user>. Measured live: both <user> and <userid> were accepted without complaint by the firewall in every test - the only field the firewall ever objected to was secret - so the two forms could not be told apart this way. <user> was kept because it is the form the sample XML uses consistently and it is what Get-SfosOTPTokens reads back from a live object.

        .PARAMETER Secret
        OTP shared secret, as a SecureString. Mandatory - see .DESCRIPTION. Measured live: the vendor documentation's length constraint (32-120 characters) is necessary but not sufficient - the firewall also requires the value to be hexadecimal digits (0-9, a-f/A-F). A 16-character Base32 value and a 20-character hex value were both rejected with 501 naming only "/OTPTokens/secret", with no explanation; 32/40/64-character hex values were all accepted. Neither the attribute table nor the sample XML documents the hex requirement - this is unmeasured for any encoding not tried.

        .PARAMETER Algorithm
        Hash algorithm used to generate OTPs for this token: 'SHA1', 'SHA256' or 'SHA512'.

        .PARAMETER UseCustomTokenTimeStep
        Whether this token uses a custom time step instead of the OTPSettings default. Only 'Off' has been observed on a live token; the wire element is <useCustomTokenTimeStep>, not the documented-but-nonexistent <timeStep>. No ValidateSet is applied because the 'On' counterpart was never observed.

        .PARAMETER TimeStepOffset
        OTP time step offset.

        .PARAMETER TimeOffset
        Time offset used to adjust clock skew.

        .PARAMETER ExtraCodes
        One-time random codes usable if the secret is temporarily unavailable (max 69 characters).

        .PARAMETER Active
        Whether the token is enabled ('1') or disabled ('0').

        .PARAMETER AutoCreated
        Whether this token is flagged as auto-created ('1') or not ('0'). Documented as an accepted parameter on this operation; it looks like status the firewall would set itself, but nothing confirms that, so it is exposed as documented rather than guessed away.

        .PARAMETER LastLogin
        Timestamp of the last successful OTP login. Documented as an accepted parameter on this operation; setting it at creation time is unusual, but nothing confirms it is rejected, so it is exposed as documented rather than guessed away.

        .PARAMETER Comment
        Free-text comment for the token.

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
        # Create a token for a user with a hexadecimal secret
        $secret = ConvertTo-SecureString "0123456789abcdef0123456789abcdef" -AsPlainText -Force
        New-SfosOTPTokens -User "jdoe" -Secret $secret -Algorithm SHA1

        .NOTES
        Minimum supported PowerShell version: 5.1
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
        PSUseSingularNouns is suppressed on purpose: <OTPTokens> is the entity's own element
        name and there is no singular child element. Renaming it would break the mapping to
        the API.

        Verified against a live firewall: creating a token with a valid user and a hexadecimal
        secret succeeded and the object was found afterwards with Get-SfosOTPTokens. The
        firewall's error response for an invalid -Secret only names the offending field
        (/OTPTokens/secret), never the reason - the hex-digit and minimum-length requirement
        documented on -Secret above was determined by testing multiple encodings and lengths
        against a live firewall, not from any documentation.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPTokens/operations/AddOTPToken%26UpdateOTPToken.html
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
    # Measured live: the vendor documentation's 32-120 character length constraint is
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
        Updates an existing OTPTokens object on the Sophos Firewall.

        .DESCRIPTION
        Updates an OTP token using the Sophos Firewall XML API. You can supply the target
        token id directly or via the pipeline. SFOS replaces the whole entity on update - any
        element not sent in the request is cleared on the firewall - so this cmdlet reads the
        current token first and keeps whatever the caller does not explicitly pass.

        .PARAMETER TokenId
        Token identifier of the object to update.

        .PARAMETER User
        Username the token is associated with. If omitted, the existing value is kept.

        .PARAMETER Algorithm
        Hash algorithm used to generate OTPs for this token: 'SHA1', 'SHA256' or 'SHA512'. If omitted, the existing value is kept.

        .PARAMETER UseCustomTokenTimeStep
        Whether this token uses a custom time step instead of the OTPSettings default. Maps to the wire element <useCustomTokenTimeStep>, not the documented-but-nonexistent <timeStep> - see Get-SfosOTPTokens. If omitted, the existing value is kept.

        .PARAMETER TimeStepOffset
        OTP time step offset. If omitted, the existing value is kept.

        .PARAMETER TimeOffset
        Time offset used to adjust clock skew. If omitted, the existing value is kept.

        .PARAMETER ExtraCodes
        One-time random codes usable if the secret is temporarily unavailable (max 69 characters). If omitted, the existing value is kept.

        .PARAMETER Active
        Whether the token is enabled ('1') or disabled ('0'). If omitted, the existing value is kept.

        .PARAMETER AutoCreated
        Whether this token is flagged as auto-created ('1') or not ('0'). If omitted, the existing value is kept.

        .PARAMETER LastLogin
        Timestamp of the last successful OTP login. If omitted, the existing value is kept.

        .PARAMETER Comment
        Free-text comment for the token. If omitted, the existing value is kept.

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
        # Disable a token, every other field is preserved
        Set-SfosOTPTokens -TokenId "ABC123" -Active 0

        .EXAMPLE
        # Update using pipeline input
        Get-SfosOTPTokens -TokenIdLike "ABC" | Set-SfosOTPTokens -Comment "Reissued"

        .NOTES
        Minimum supported PowerShell version: 5.1
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
        PSUseSingularNouns is suppressed on purpose: <OTPTokens> is the entity's own element
        name and there is no singular child element. Renaming it would break the mapping to
        the API.

        This cmdlet deliberately has no -Secret parameter, unlike New-SfosOTPTokens. Verified
        against a live firewall: an update sent without <secret> left the token's secret
        unchanged - the value returned by the firewall (as an opaque hash, hashform="mode1")
        was character-identical before and after the update. -Secret was still left off, since
        Get-SfosOTPTokens does not expose the hashed value either (see that cmdlet's .NOTES on
        why secret is treated as write-only) - so even though this update did not clear it,
        there is no way to preserve a caller-supplied plaintext value across a read-modify-write
        here. To change a token's secret, recreate it with New-SfosOTPTokens.

        TokenId identification and the read-modify-write for the other fields were verified
        against a live firewall. Get-SfosOTPTokens | Set-SfosOTPTokens previously failed because
        this cmdlet demanded a -TimeStep the firewall never returns - see .PARAMETER
        UseCustomTokenTimeStep for the corrected field. That fix itself is pending
        re-verification against the live firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPTokens/operations/AddOTPToken%26UpdateOTPToken.html
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
        Removes an OTPTokens object from the Sophos Firewall.

        .DESCRIPTION
        Removes an OTP token identified by its token id, using the Sophos Firewall XML API.

        .PARAMETER TokenId
        Token identifier of the object to remove.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Remove a token by id
        Remove-SfosOTPTokens -TokenId "ABC123"

        .EXAMPLE
        # Remove via pipeline
        Get-SfosOTPTokens -TokenIdLike "ABC" | Remove-SfosOTPTokens

        .NOTES
        Minimum supported PowerShell version: 5.1
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
        PSUseSingularNouns is suppressed on purpose: <OTPTokens> is the entity's own element
        name and there is no singular child element. Renaming it would break the mapping to
        the API.

        This cmdlet passes the raw firewall answer through without a not-found check of
        its own, the same caveat that applies to every other Remove-Sfos* cmdlet.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/OTPTokens/operations/Delete%20OTP%20Token.html
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
        Retrieves the FirewallAuthentication GlobalSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the GlobalSettings singleton nested under
        FirewallAuthentication. There is exactly one instance of this element per firewall.
        By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the
        raw XML node.

        The Sophos API has no dedicated Get operation for GlobalSettings alone: only the
        FirewallAuthentication entity as a whole can be fetched (measured - a Get of a bare
        'GlobalSettings' element answers 'code="529" Input request module is Invalid'). This
        cmdlet therefore requests the full FirewallAuthentication entity and returns only the
        GlobalSettings sub-node.

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
        # Retrieve the current session/login limits
        Get-SfosFirewallAuthenticationGlobalSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: SimultaneousLogins and MaximumSessionTimeoutMinutes both read literally
        as the string 'Unlimited' when no limit is configured, not a numeric sentinel.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureGlobal.html
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

    # Measured live (malformed Filter and malformed sub-child sent under <Get>
    # <FirewallAuthentication><GlobalSettings>...): SFOS never returned a Status node at all
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
        Updates the FirewallAuthentication GlobalSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the GlobalSettings singleton nested under FirewallAuthentication. This cmdlet
        reads the current settings first and resends every field, overriding only what the
        caller explicitly passes (read-modify-write - SFOS replaces the whole sub-block on
        update). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER SimultaneousLogins
        Maximum number of simultaneous logins per user (1-99), or the literal string
        'Unlimited'. If omitted, the value currently on the firewall is kept.

        .PARAMETER MaximumSessionTimeoutMinutes
        Maximum session duration in minutes (3-1440) after which the user is logged out, or
        the literal string 'Unlimited'. If omitted, the value currently on the firewall is kept.

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
        # Cap sessions at 30 minutes
        Set-SfosFirewallAuthenticationGlobalSettings -MaximumSessionTimeoutMinutes 30

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write: this cmdlet was implemented and
        checked structurally only, in line with the task instruction to not perform write
        operations against firewall authentication settings. The nesting of the Set body
        under <FirewallAuthentication> is inferred from the documented sample XML, which uses
        the same nesting for the Get/Configure operation of every block in this entity.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureGlobal.html
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

    # Measured live: forcing a 501 (SimultaneousLogins out of range) put the Status at
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
        Retrieves the FirewallAuthentication AuthenticationMethods from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the AuthenticationMethods singleton nested
        under FirewallAuthentication. This block controls which authentication server(s) and
        default group are used when an administrator or user logs in to the firewall. By
        default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw
        XML node.

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
        # Retrieve the current login method configuration
        Get-SfosFirewallAuthenticationMethods

        .NOTES
        Minimum supported PowerShell version: 5.1
        This block determines how administrators and users authenticate to the firewall.
        Misconfiguring it can lock every account out. See Set-SfosFirewallAuthenticationMethods.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureFirewall.html
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
    # measured ObjectName for every Get-* in this fragment.
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
        Updates the FirewallAuthentication AuthenticationMethods on the Sophos Firewall.

        .DESCRIPTION
        Updates the AuthenticationMethods singleton nested under FirewallAuthentication. This
        cmdlet reads the current settings first and resends every field, overriding only what
        the caller explicitly passes (read-modify-write). This cmdlet supports ShouldProcess;
        use -WhatIf to preview the change.

        WARNING: this block controls which authentication server(s) users and administrators
        log in against. Removing every server, or pointing DefaultGroup at a group that does
        not exist, can lock every account out of the firewall, including the API user this
        module authenticates as. This cmdlet was implemented and verified structurally only -
        it was never executed against the lab firewall.

        .PARAMETER DefaultGroup
        Default group assigned to users authenticated through this configuration. If omitted, the value currently on the firewall is kept.

        .PARAMETER AuthenticationServer
        One or more authentication server names to use for login, in priority order. If
        omitted, the servers currently on the firewall are kept. Use Add-/Remove-SfosFirewallAuthenticationMethodsMember to change the list incrementally instead of replacing it outright.

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
        # Change the default group only, the server list is preserved
        Set-SfosFirewallAuthenticationMethods -DefaultGroup "Open Group"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write - deliberately not exercised because
        a mistake here can lock out every account. The nesting of the Set body under
        <FirewallAuthentication> is inferred from the documented sample XML.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureFirewall.html
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

    # Measured live via a diagnostic-only invalid DefaultGroup value (validation failed
    # before anything was written): Status landed at /Response/AuthenticationMethods/Status -
    # top level, matching every other Set-* in this fragment, not nested under
    # FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the FirewallAuthentication AuthenticationMethods server list.

        .DESCRIPTION
        Adds one or more authentication servers to the AuthenticationServerList of the
        AuthenticationMethods singleton, preserving the existing servers and DefaultGroup
        (SFOS replaces the whole sub-block on update, so the current list is read back and
        resent together with the new entries).

        WARNING: this block controls which authentication server(s) users and administrators
        log in against. This cmdlet was implemented and verified structurally only - it was
        never executed against the lab firewall.

        .PARAMETER Members
        One or more authentication server names to add.

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
        # Add a RADIUS server alongside the existing servers
        Add-SfosFirewallAuthenticationMethodsMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write - deliberately not exercised because
        a mistake here can lock out every account.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureFirewall.html
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
    # /Response/AuthenticationMethods/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the FirewallAuthentication AuthenticationMethods server list.

        .DESCRIPTION
        Removes one or more authentication servers from the AuthenticationServerList of the
        AuthenticationMethods singleton, preserving DefaultGroup and every remaining server
        (SFOS replaces the whole sub-block on update, so the remaining entries are read back
        and resent).

        WARNING: this block controls which authentication server(s) users and administrators
        log in against. Removing every server can lock every account out of the firewall,
        including the API user this module authenticates as. This cmdlet was implemented and
        verified structurally only - it was never executed against the lab firewall.

        .PARAMETER Members
        One or more authentication server names to remove.

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
        # Remove a decommissioned RADIUS server
        Remove-SfosFirewallAuthenticationMethodsMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write - deliberately not exercised because
        a mistake here can lock out every account.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureFirewall.html
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
    # /Response/AuthenticationMethods/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AuthenticationMethods' -Action 'remove members'
}

#endregion

#region FirewallAuthenticationNTLMSettings

<#
        .SYNOPSIS
        Retrieves the FirewallAuthentication NTLMSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the NTLMSettings singleton nested under
        FirewallAuthentication. There is exactly one instance of this element per firewall.
        By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the
        raw XML node.

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
        # Retrieve the current NTLM settings
        Get-SfosFirewallAuthenticationNTLMSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        The element names NTLMInActivtyTime and NTLMChallegeRedirect are spelled exactly as
        the API returns them (missing 'i' in 'Activty', missing 'n' in 'Challege') - the
        Sophos spelling wins over the expected English spelling.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureNTLM.html
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
    # measured ObjectName for every Get-* in this fragment.
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
        Updates the FirewallAuthentication NTLMSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the NTLMSettings singleton nested under FirewallAuthentication. This cmdlet
        reads the current settings first and resends every field, overriding only what the
        caller explicitly passes (read-modify-write). This cmdlet supports ShouldProcess; use
        -WhatIf to preview the change.

        .PARAMETER NTLMInActivtyTime
        Inactivity time in minutes (6-1440) after which the NTLM user is logged out and must
        re-authenticate. If omitted, the value currently on the firewall is kept.

        .PARAMETER NTLMDataTransferThreshold
        Minimum data in bytes to be transferred within NTLMInActivtyTime for the session to
        count as active. If omitted, the value currently on the firewall is kept.

        .PARAMETER NTLMChallegeRedirect
        Enable or disable the NTLM challenge redirect. If omitted, the value currently on the
        firewall is kept.

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
        # Disable the NTLM challenge redirect
        Set-SfosFirewallAuthenticationNTLMSettings -NTLMChallegeRedirect Disable

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write, in line with the task instruction
        to not perform write operations against firewall authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureNTLM.html
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

    # Measured live (out-of-range NTLMInActivtyTime forced a 501): Status landed at
    # /Response/NTLMSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NTLMSettings' -Action 'update'
}

#endregion

#region FirewallAuthenticationCTASSettings

<#
        .SYNOPSIS
        Retrieves the FirewallAuthentication CTASSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the CTASSettings singleton nested under
        FirewallAuthentication. There is exactly one instance of this element per firewall.
        By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the
        raw XML node.

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
        # Retrieve the current CTAS (Client Transparent Authentication Suite) settings
        Get-SfosFirewallAuthenticationCTASSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the lab firewall's CTASSettings block only contains CTASUserInactivity
        (value 'Disable'); CTASInActivtyTime and CTASDataTransferThreshold, both documented
        with defaults of 3 and 100, were absent from the response. This cmdlet still reads and
        writes them, since they are attested in the documentation and belong to the same
        block - most likely they are only returned once CTASUserInactivity is 'Enable'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureCTAS.html
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
    # measured ObjectName for every Get-* in this fragment.
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
        Updates the FirewallAuthentication CTASSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the CTASSettings singleton nested under FirewallAuthentication. This cmdlet
        reads the current settings first and resends every field, overriding only what the
        caller explicitly passes (read-modify-write). This cmdlet supports ShouldProcess; use
        -WhatIf to preview the change.

        .PARAMETER CTASUserInactivity
        Enable or disable the CTAS user inactivity timeout. If omitted, the value currently on
        the firewall is kept.

        .PARAMETER CTASInActivtyTime
        Inactivity time in minutes (3-1440, default 3) after which the CTAS user is logged out
        and must re-authenticate. If omitted, the value currently on the firewall is kept
        (empty string if the field was never returned by Get-SfosFirewallAuthenticationCTASSettings).

        .PARAMETER CTASDataTransferThreshold
        Minimum data in bytes (default 100) to be transferred within CTASInActivtyTime for the
        session to count as active. If omitted, the value currently on the firewall is kept
        (empty string if the field was never returned by Get-SfosFirewallAuthenticationCTASSettings).

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
        # Enable CTAS user inactivity logout after 10 minutes
        Set-SfosFirewallAuthenticationCTASSettings -CTASUserInactivity Enable -CTASInActivtyTime 10

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write, in line with the task instruction
        to not perform write operations against firewall authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureCTAS.html
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

    # Measured live (out-of-range CTASInActivtyTime forced a 501): Status landed at
    # /Response/CTASSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CTASSettings' -Action 'update'
}

#endregion

#region FirewallAuthenticationiOSWebClientSettings

<#
        .SYNOPSIS
        Retrieves the FirewallAuthentication iOSWebClientSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the iOSWebClientSettings singleton nested
        under FirewallAuthentication. There is exactly one instance of this element per
        firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to
        return the raw XML node.

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
        # Retrieve the current iOS web client settings
        Get-SfosFirewallAuthenticationiOSWebClientSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        The element name iOSWebClientInActivtyTime is spelled exactly as the API returns it
        (missing 'i' in 'Activty') - the Sophos spelling wins over the expected English
        spelling. The function name keeps the lowercase 'i' of 'iOS' for the same reason.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureIOSWebClient.html
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
    # measured ObjectName for every Get-* in this fragment.
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
        Updates the FirewallAuthentication iOSWebClientSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the iOSWebClientSettings singleton nested under FirewallAuthentication. This
        cmdlet reads the current settings first and resends every field, overriding only what
        the caller explicitly passes (read-modify-write). This cmdlet supports ShouldProcess;
        use -WhatIf to preview the change.

        .PARAMETER iOSWebClientInActivtyTime
        Inactivity time in minutes (6-1440) after which the iOS web client user is logged out
        and must re-authenticate. If omitted, the value currently on the firewall is kept.

        .PARAMETER iOSWebClientDataTransferThreshold
        Minimum data in bytes (1-4294967295) to be transferred within iOSWebClientInActivtyTime
        for the session to count as active. If omitted, the value currently on the firewall is
        kept.

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
        # Raise the inactivity timeout to 20 minutes
        Set-SfosFirewallAuthenticationiOSWebClientSettings -iOSWebClientInActivtyTime 20

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write, in line with the task instruction
        to not perform write operations against firewall authentication settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/ConfigureIOSWebClient.html
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

    # Measured live (out-of-range iOSWebClientInActivtyTime forced a 501): Status landed at
    # /Response/iOSWebClientSettings/Status - top level, not nested under FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'iOSWebClientSettings' -Action 'update'
}

#endregion

#region SSORadiusAccount

<#
        .SYNOPSIS
        Retrieves the FirewallAuthentication SSORadiusAccount configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the SSORadiusAccount block nested under
        FirewallAuthentication, which configures RADIUS accounting-based single sign-on. By
        default the cmdlet returns PowerShell-friendly objects, one per documented <Radius>
        entry. Use -AsXml to return the raw XML nodes.

        UNCONFIRMED: this block was absent from every live FirewallAuthentication response
        captured for this module, most likely because nothing is configured on the lab
        firewall. Field names and nesting come from the vendor documentation only and have
        not been checked against a populated live object.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified. An empty
        array when SSORadiusAccount is not configured.

        .EXAMPLE
        # Retrieve the current SSO-via-RADIUS-accounting configuration, if any
        Get-SfosSSORadiusAccount

        .NOTES
        Minimum supported PowerShell version: 5.1
        UNCONFIRMED - implemented documentation-faithful only, see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/SSOUsingRADIUSAccountingRequest.html
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
    # measured ObjectName for every Get-* in this fragment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallAuthentication' -Action 'get'

    $containerNode = $XmlResponse.SelectSingleNode('/Response/FirewallAuthentication/SSORadiusAccount')
    if (-not $containerNode) {
        # Not present when unconfigured (measured) - treated the same as an empty result,
        # not as an error.
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
        Creates or replaces the FirewallAuthentication SSORadiusAccount configuration on the Sophos Firewall.

        .DESCRIPTION
        Writes a single RADIUS accounting client entry (one <Radius> block, with one or more
        ClientIP addresses sharing one SharedSecret) under the SSORadiusAccount block of
        FirewallAuthentication. This cmdlet supports ShouldProcess; use -WhatIf to preview the
        change.

        The documented sample XML shows SSORadiusAccount as a repeatable list of <Radius>
        blocks (a ':' placeholder follows the first block in the sample). This cmdlet
        implements only a single block, because no live example was available to confirm the
        multi-block shape and no member-management cmdlet was requested for this entity. Both
        parameters are therefore mandatory and no read-modify-write merge is performed - a call
        replaces the whole configuration with exactly the one entry supplied.

        UNCONFIRMED: this cmdlet was never executed against a live firewall - the block was
        absent from every live response captured for this module, and write operations
        against it were not exercised.

        .PARAMETER ClientIP
        One or more RADIUS client IP addresses that this shared secret applies to.

        .PARAMETER SharedSecret
        Shared secret for the RADIUS accounting client(s), as a SecureString.

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
        # Configure a single RADIUS accounting client
        Set-SfosSSORadiusAccount -ClientIP "203.0.113.10" -SharedSecret (Read-Host -AsSecureString)

        .NOTES
        Minimum supported PowerShell version: 5.1
        UNCONFIRMED - implemented documentation-faithful only, never executed against a live
        firewall, see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/FirewallAuthenticationMethods/operations/SSOUsingRADIUSAccountingRequest.html
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

    # Measured live (diagnostic-only invalid ClientIP forced a 501 without writing anything -
    # <InvalidParams> even named the field, confirming the Radius/ClientIP nesting is correct):
    # Status landed at /Response/SSORadiusAccount/Status - top level, not nested under
    # FirewallAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSORadiusAccount' -Action 'update'
}

#endregion

#region AdminAuthentication

<#
        .SYNOPSIS
        Retrieves the AdminAuthentication configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the AdminAuthentication entity, which
        determines against which server(s) an administrator authenticates when logging in to
        the WebAdmin / API. There is exactly one instance of this entity per firewall. By
        default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw
        XML node.

        SECURITY NOTE: this entity governs the login path used by this module's own API
        session. Get-SfosAdminAuthentication is read-only and safe; see
        Set-SfosAdminAuthentication and the member cmdlets for the write-side restriction.

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
        # Retrieve the current admin authentication configuration
        Get-SfosAdminAuthentication

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the entity has exactly two children, AuthenticationServerList (wrapper
        of one or more AuthenticationServer elements) and AuthenticationMethods (a single
        string; only the value 'Custom' has been observed on the lab firewall). Get is lenient
        - an unrecognised sub-child under <Get><AdminAuthentication> is silently ignored and
        the full entity is still returned - and a successful Get carries no <Status> node at
        all, only <AuthenticationServerList> and <AuthenticationMethods> under
        /Response/AdminAuthentication. 'AdminAuthentication' is therefore the correct
        -ObjectName: Assert-SfosApiReturnSuccess finds no status node in the success case and
        falls through as success, which was confirmed against the live firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/AuthAdmin/AuthAdmin.html
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

    # Measured live: a successful Get carries no Status node at all under
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
        Updates the AdminAuthentication configuration on the Sophos Firewall.

        .DESCRIPTION
        Updates the AdminAuthentication entity, which determines against which server(s) an
        administrator authenticates when logging in to the WebAdmin / API. This cmdlet reads
        the current configuration first and resends every field, overriding only what the
        caller explicitly passes (read-modify-write - SFOS replaces the whole entity on
        update). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        SECURITY NOTE: this entity governs the login path used by this module's own API
        session, including its own connection parameters. This cmdlet was implemented and
        checked structurally only (generated XML inspected, never sent) - it was deliberately
        never executed against the lab firewall, in line with the task's security boundary. A
        wrong AuthenticationMethods value or an emptied AuthenticationServerList can lock every
        administrator, including this module's API user, out of the firewall.

        .PARAMETER AuthenticationMethods
        Admin authentication method. Only the value 'Custom' has been observed live; no
        ValidateSet is applied because the full set of allowed values could not be confirmed
        (the operation's documentation page returned HTTP 404, and probing this field against
        the live entity was excluded by the task's security boundary). If omitted, the value
        currently on the firewall is kept.

        .PARAMETER AuthenticationServer
        One or more authentication server names to use for admin login, in priority order. If
        omitted, the servers currently on the firewall are kept. Use
        Add-/Remove-SfosAdminAuthenticationMember to change the list incrementally instead of
        replacing it outright.

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
        # Change the default group only, the server list is preserved (structurally verified only, see .NOTES)
        Set-SfosAdminAuthentication -AuthenticationMethods "Custom"

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT verified against the live firewall as a write, by deliberate policy: this entity
        controls the login path of the API user this module authenticates as. Verified only
        structurally (parameter validation, generated XML). The -ObjectName used below
        ('AdminAuthentication') is inferred by analogy with the identically shaped
        VPNAuthentication and SSLVPNAuthentication entities in this module, where the same
        Set operation="update" was measured to place its Status node at
        /Response/<Entity>/Status - not from a direct measurement on AdminAuthentication
        itself, since that measurement would have required a write against this entity.

        ConfirmImpact is High: this governs the API session's own login path; a wrong
        value can lock the appliance's administrators out. Automation must pass -Confirm:$false.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/AuthAdmin/operations/ConfigureAdministratorAuthenticationServer.html
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

    # Not measured directly (write excluded by the task's security boundary) - inferred by
    # analogy with Set-SfosVPNAuthentication / Set-SfosSSLVPNAuthentication in this fragment,
    # both measured to place Status at /Response/<Entity>/Status for operation="update".
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the AdminAuthentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the AuthenticationServerList of the
        AdminAuthentication entity, preserving the existing servers and AuthenticationMethods
        (SFOS replaces the whole entity on update, so the current list is read back and resent
        together with the new entries).

        SECURITY NOTE: this entity governs the login path used by this module's own API
        session. This cmdlet was implemented and checked structurally only - it was
        deliberately never executed against the lab firewall.

        .PARAMETER Members
        One or more authentication server names to add.

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
        # Add a RADIUS server alongside the existing admin authentication servers (structurally verified only, see .NOTES)
        Add-SfosAdminAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT verified against the live firewall as a write, by deliberate policy - this entity
        controls the login path of the API user this module authenticates as.

        ConfirmImpact is High: this governs the API session's own login path; automation
        must pass -Confirm:$false.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/AuthAdmin/operations/ConfigureAdministratorAuthenticationServer.html
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

    # Not measured directly - see Set-SfosAdminAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the AdminAuthentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the AuthenticationServerList of the
        AdminAuthentication entity, preserving AuthenticationMethods and every remaining server
        (SFOS replaces the whole entity on update, so the remaining entries are read back and
        resent).

        SECURITY NOTE: this entity governs the login path used by this module's own API
        session. Removing every server can lock every administrator out of the firewall,
        including the API user this module authenticates as. This cmdlet was implemented and
        checked structurally only - it was deliberately never executed against the lab
        firewall.

        .PARAMETER Members
        One or more authentication server names to remove.

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
        # Remove a decommissioned RADIUS server (structurally verified only, see .NOTES)
        Remove-SfosAdminAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT verified against the live firewall as a write, by deliberate policy - this entity
        controls the login path of the API user this module authenticates as.

        ConfirmImpact is High: removing the last server can lock every
        administrator out, including this module's own API user; automation must pass
        -Confirm:$false.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/AuthAdmin/operations/ConfigureAdministratorAuthenticationServer.html
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

    # Not measured directly - see Set-SfosAdminAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminAuthentication' -Action 'remove members'
}

#endregion

#region VPNAuthentication

<#
        .SYNOPSIS
        Retrieves the VPNAuthentication configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the VPNAuthentication entity, which determines
        against which server(s) a VPN user authenticates. There is exactly one instance of
        this entity per firewall. By default the cmdlet returns a PowerShell-friendly object.
        Use -AsXml to return the raw XML node.

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
        # Retrieve the current VPN authentication configuration
        Get-SfosVPNAuthentication

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the entity has exactly two children, VPNAuthenticationMethods (a single
        string; only 'Custom' has been observed) and VPNAuthenticationServerList (wrapper of
        one or more AuthenticationServer elements - the member element itself is NOT prefixed
        'VPN'). Get is lenient - an unrecognised sub-child under <Get><VPNAuthentication> is
        silently ignored and the full entity is still returned - and a successful Get carries
        no <Status> node at all. 'VPNAuthentication' is the correct -ObjectName.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/VPNAuthenticationMethods.html
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

    # Measured live: a successful Get carries no Status node at all under
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
        Updates the VPNAuthentication configuration on the Sophos Firewall.

        .DESCRIPTION
        Updates the VPNAuthentication entity, which determines against which server(s) a VPN
        user authenticates. This cmdlet reads the current configuration first and resends
        every field, overriding only what the caller explicitly passes (read-modify-write -
        SFOS replaces the whole entity on update). This cmdlet supports ShouldProcess; use
        -WhatIf to preview the change.

        .PARAMETER VPNAuthenticationMethods
        VPN authentication method. Only the value 'Custom' has been observed live; a live
        probe with 'Local' was rejected with code 501 ('Configuration parameters validation
        failed'), so the full set of allowed values remains uncharacterised (the operation's
        documentation page returned HTTP 404). No ValidateSet is applied for this reason. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER AuthenticationServer
        One or more authentication server names to use for VPN login, in priority order. If
        omitted, the servers currently on the firewall are kept. Use
        Add-/Remove-SfosVPNAuthenticationMember to change the list incrementally instead of
        replacing it outright.

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
        # Re-apply the current VPN authentication method (no-op round trip)
        Set-SfosVPNAuthentication -VPNAuthenticationMethods "Custom"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip (VPNAuthenticationMethods 'Custom', AuthenticationServer
        'Local' - the values already on the firewall) answered code="200" at
        /Response/VPNAuthentication/Status. A forced invalid VPNAuthenticationMethods value
        answered code="501" at the same path, confirming the -ObjectName below.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/VPNAuthenticationMethods.html
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

    # Measured live (see .NOTES): Status lands at /Response/VPNAuthentication/Status for
    # both the success and the 501 case.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the VPNAuthentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the VPNAuthenticationServerList of the
        VPNAuthentication entity, preserving the existing servers and VPNAuthenticationMethods
        (SFOS replaces the whole entity on update, so the current list is read back and resent
        together with the new entries).

        .PARAMETER Members
        One or more authentication server names to add.

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
        # Add a RADIUS server alongside the existing VPN authentication servers
        Add-SfosVPNAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live, success path: after creating a throwaway LDAPServer authentication
        server object (ZZTestF-LDAP), adding it answered code="200" at
        /Response/VPNAuthentication/Status and a subsequent Get showed both 'Local' and
        'ZZTestF-LDAP' in the list (Count=2). The test object was removed from the list and
        deleted again afterwards; see Remove-SfosVPNAuthenticationMember.
        Verified live, other cases: adding a duplicate of the already-present server 'Local'
        answered code="200" and the firewall deduplicates the list itself (a subsequent Get
        still showed exactly one 'Local' entry) - the same behaviour this cmdlet already
        produces client-side via Select-Object -Unique. Adding an unknown server name
        ('ZZTestF-NoServer', which does not correspond to any configured server object) was
        rejected with code="501" and left the list unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/VPNAuthenticationMethods.html
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
    # /Response/VPNAuthentication/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the VPNAuthentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the VPNAuthenticationServerList of the
        VPNAuthentication entity, preserving VPNAuthenticationMethods and every remaining
        server (SFOS replaces the whole entity on update, so the remaining entries are read
        back and resent).

        .PARAMETER Members
        One or more authentication server names to remove.

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
        # Remove a decommissioned RADIUS server
        Remove-SfosVPNAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live, success path: with a throwaway LDAPServer authentication server object
        (ZZTestF-LDAP) added to the list alongside 'Local' (see
        Add-SfosVPNAuthenticationMember), removing it answered code="200" at
        /Response/VPNAuthentication/Status and a subsequent Get showed only 'Local' left
        (Count=1); the raw XML matched the pre-test baseline exactly. ZZTestF-LDAP was then
        deleted via Remove-SfosLDAPServer and confirmed gone via Get-SfosLDAPServer.
        Verified live, error path: removing the sole remaining entry ('Local', with no other
        server present) answered code="500" 'Operation could not be performed on Entity' at
        the same path, and a subsequent Get confirmed the list was left unchanged - the
        firewall refuses to empty this list, and this cmdlet correctly surfaces that refusal
        as a thrown error rather than reporting success.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/VPNAuthenticationMethods.html
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
    # /Response/VPNAuthentication/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNAuthentication' -Action 'remove members'
}

#endregion

#region SSLVPNAuthentication

<#
        .SYNOPSIS
        Retrieves the SSLVPNAuthentication configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the SSLVPNAuthentication entity, which
        determines against which server(s) an SSL VPN user authenticates. There is exactly one
        instance of this entity per firewall. By default the cmdlet returns a
        PowerShell-friendly object. Use -AsXml to return the raw XML node.

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
        # Retrieve the current SSL VPN authentication configuration
        Get-SfosSSLVPNAuthentication

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the entity has exactly two children, SSLVPNAuthenticationMethods (a
        single string; only 'Custom' has been observed) and SSLVPNAuthenticationServerList
        (wrapper of one or more AuthenticationServer elements - the member element itself is
        NOT prefixed 'SSLVPN'). Get is lenient - an unrecognised sub-child under
        <Get><SSLVPNAuthentication> is silently ignored and the full entity is still returned
        - and a successful Get carries no <Status> node at all. 'SSLVPNAuthentication' is the
        correct -ObjectName.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/VPNAuthenticationMethods.html
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

    # Measured live: a successful Get carries no Status node at all under
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
        Updates the SSLVPNAuthentication configuration on the Sophos Firewall.

        .DESCRIPTION
        Updates the SSLVPNAuthentication entity, which determines against which server(s) an
        SSL VPN user authenticates. This cmdlet reads the current configuration first and
        resends every field, overriding only what the caller explicitly passes
        (read-modify-write - SFOS replaces the whole entity on update). This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER SSLVPNAuthenticationMethods
        SSL VPN authentication method. Only the value 'Custom' has been observed live; the
        full set of allowed values could not be confirmed (the operation's documentation page
        returned HTTP 404) and was not probed against this entity to limit the number of
        writes made against the lab firewall - see Set-SfosVPNAuthentication for the
        equivalent probe on the sibling entity, which rejected 'Local'. No ValidateSet is
        applied for this reason. If omitted, the value currently on the firewall is kept.

        .PARAMETER AuthenticationServer
        One or more authentication server names to use for SSL VPN login, in priority order.
        If omitted, the servers currently on the firewall are kept. Use
        Add-/Remove-SfosSSLVPNAuthenticationMember to change the list incrementally instead of
        replacing it outright.

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
        # Re-apply the current SSL VPN authentication method (no-op round trip)
        Set-SfosSSLVPNAuthentication -SSLVPNAuthenticationMethods "Custom"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip (SSLVPNAuthenticationMethods 'Custom',
        AuthenticationServer 'Local' - the values already on the firewall) answered
        code="200" at /Response/SSLVPNAuthentication/Status. A forced invalid
        SSLVPNAuthenticationMethods value answered code="501" at the same path, confirming the
        -ObjectName below.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/ConfigureSSLVPNAuthentication.html
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

    # Measured live (see .NOTES): Status lands at /Response/SSLVPNAuthentication/Status for
    # both the success and the 501 case.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds authentication servers to the SSLVPNAuthentication server list.

        .DESCRIPTION
        Adds one or more authentication servers to the SSLVPNAuthenticationServerList of the
        SSLVPNAuthentication entity, preserving the existing servers and
        SSLVPNAuthenticationMethods (SFOS replaces the whole entity on update, so the current
        list is read back and resent together with the new entries).

        .PARAMETER Members
        One or more authentication server names to add.

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
        # Add a RADIUS server alongside the existing SSL VPN authentication servers
        Add-SfosSSLVPNAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live, success path: after creating a throwaway LDAPServer authentication
        server object (ZZTestF-LDAP), adding it answered code="200" at
        /Response/SSLVPNAuthentication/Status and a subsequent Get showed both 'Local' and
        'ZZTestF-LDAP' in the list (Count=2). The test object was removed from the list and
        deleted again afterwards; see Remove-SfosSSLVPNAuthenticationMember.
        Verified live, other cases: adding a duplicate of the already-present server 'Local'
        answered code="200" and the firewall deduplicates the list itself (a subsequent Get
        still showed exactly one 'Local' entry) - the same behaviour this cmdlet already
        produces client-side via Select-Object -Unique. Adding an unknown server name
        ('ZZTestF-NoServer', which does not correspond to any configured server object) was
        rejected with code="501" and left the list unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/ConfigureSSLVPNAuthentication.html
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
    # /Response/SSLVPNAuthentication/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes authentication servers from the SSLVPNAuthentication server list.

        .DESCRIPTION
        Removes one or more authentication servers from the SSLVPNAuthenticationServerList of
        the SSLVPNAuthentication entity, preserving SSLVPNAuthenticationMethods and every
        remaining server (SFOS replaces the whole entity on update, so the remaining entries
        are read back and resent).

        .PARAMETER Members
        One or more authentication server names to remove.

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
        # Remove a decommissioned RADIUS server
        Remove-SfosSSLVPNAuthenticationMember -Members "RADIUS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live, success path: with a throwaway LDAPServer authentication server object
        (ZZTestF-LDAP) added to the list alongside 'Local' (see
        Add-SfosSSLVPNAuthenticationMember), removing it answered code="200" at
        /Response/SSLVPNAuthentication/Status and a subsequent Get showed only 'Local' left
        (Count=1); the raw XML matched the pre-test baseline exactly. ZZTestF-LDAP was then
        deleted via Remove-SfosLDAPServer and confirmed gone via Get-SfosLDAPServer.
        Verified live, error path: removing the sole remaining entry ('Local', with no other
        server present) answered code="500" 'Operation could not be performed on Entity' at
        the same path, and a subsequent Get confirmed the list was left unchanged - the
        firewall refuses to empty this list, and this cmdlet correctly surfaces that refusal
        as a thrown error rather than reporting success.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/VPNAuthenticationMethods/operations/ConfigureSSLVPNAuthentication.html
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
    # /Response/SSLVPNAuthentication/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNAuthentication' -Action 'remove members'
}

#endregion

#region WebAuthenticationSettings

<#
        .SYNOPSIS
        Retrieves the WebAuthentication WebAuthenticationSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the WebAuthenticationSettings singleton
        nested under WebAuthentication. There is exactly one instance of this element per
        firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to
        return the raw XML node.

        The Sophos API has no dedicated Get operation for WebAuthenticationSettings alone:
        only the WebAuthentication entity as a whole can be fetched, the same pattern as
        FirewallAuthentication in the firewall-authentication group of this module. This
        cmdlet therefore requests the full WebAuthentication entity and returns only the
        WebAuthenticationSettings sub-node.

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
        # Retrieve the current web authentication (captive portal login flow) settings
        Get-SfosWebAuthenticationSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: a Get of <WebAuthentication> with an unrecognised sub-element under it
        is accepted and silently ignored - the API answers the real WebAuthenticationSettings
        content with no Status node at all, the same lenient behaviour measured for
        FirewallAuthentication in the firewall-authentication group.

        The Attribute/Parameter Information table and the sample XML on the operations page
        both list three further fields: CustomURL, BytesRequired and MinutesRequired. Measured
        live: a Get of WebAuthenticationSettings returns exactly the 8 elements listed above -
        none of the three, present or empty - on this firmware. Same precedent as FileType/
        -Template in the Web module: a field the Get never returns cannot be read back, so
        Set-SfosWebAuthenticationSettings does not expose it either, rather than implementing
        a parameter that read-modify-write could never actually preserve.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/WebAuthenticationMethods/operations/WebAuthenticationSettings.html
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

    # Measured live (malformed sub-element sent under <Get><WebAuthentication>...): SFOS
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
        Updates the WebAuthentication WebAuthenticationSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the WebAuthenticationSettings singleton nested under WebAuthentication. This
        cmdlet reads the current settings first and resends every field, overriding only what
        the caller explicitly passes (read-modify-write - SFOS replaces the whole sub-block on
        update). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        SAFETY NOTE: WebAuthenticationSettings governs the end-user captive portal login flow,
        not the WebAdmin/API management access this module authenticates through. UseHTTPS
        toggles HTTPS for the captive portal service, unrelated to the management HTTPS port.
        None of these fields were excluded from live write verification on that basis.

        .PARAMETER DisplayCaptivePortalLink
        Show a link to the captive portal on the disconnected/block pages. If omitted, the
        value currently on the firewall is kept.

        .PARAMETER UseHTTPS
        Serve the captive portal login page over HTTPS instead of HTTP. If omitted, the value
        currently on the firewall is kept.

        .PARAMETER LogOutUserSetting
        Controls when a captive-portal-authenticated user is logged out (measured live value:
        'Portal closed'; the full set of accepted values is not documented and therefore not
        enforced client-side). If omitted, the value currently on the firewall is kept.

        .PARAMETER DisplayUserPortalLink
        Show a link to the User Portal on the captive portal login page. If omitted, the value
        currently on the firewall is kept.

        .PARAMETER DisplayWebpageAfterLogin
        Show a webpage to the user immediately after a successful captive portal login. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER UseKerberosForADSSO
        Use Kerberos for Active Directory single sign-on during web authentication. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER OpenWebpageInNewWindow
        Open the post-login webpage (see DisplayWebpageAfterLogin) in a new browser window. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER WebpageToDisplay
        Which webpage to show after login (measured live value: 'User requested URL'; the full
        set of accepted values is not documented and therefore not enforced client-side). If
        omitted, the value currently on the firewall is kept.

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
        # Stop opening the post-login webpage in a separate window
        Set-SfosWebAuthenticationSettings -OpenWebpageInNewWindow Disable

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip (read, write back unchanged, read again) matched the
        pre-image field for field, and a single-field toggle (DisplayUserPortalLink) was
        applied, confirmed via Get-SfosWebAuthenticationSettings, and reverted, again confirmed
        via Get-SfosWebAuthenticationSettings.

        Measured live: -OpenWebpageInNewWindow Disable is rejected by the firewall with
        code="501" and an empty <InvalidParams/> - no field is named - while every other
        Enable/Disable field on this same entity (verified: DisplayUserPortalLink) is accepted
        without issue. The cause is unconfirmed; a dependency on DisplayWebpageAfterLogin was
        suspected but never checked against the appliance, so it is not asserted here.

        The operations page documents three further fields, CustomURL, BytesRequired and
        MinutesRequired, that this cmdlet does not send. Measured live:
        Get-SfosWebAuthenticationSettings never returns any of the three on this firmware, so
        there is no value to preserve and nothing to merge in a read-modify-write. Sending
        them regardless would be guessing at a value the firewall never discloses. See
        Get-SfosWebAuthenticationSettings for the same finding and the FileType/-Template
        precedent it is measured against.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/WebAuthenticationMethods/operations/WebAuthenticationSettings.html
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

    # Measured live (forcing a 501 via an invalid UseHTTPS value): Status landed at
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
        Retrieves the WebAuthentication CaptivePortalAppearance from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the CaptivePortalAppearance singleton nested
        under WebAuthentication, which controls the branding (logo, colours, field labels) of
        the captive portal login page. By default the cmdlet returns a PowerShell-friendly
        object. Use -AsXml to return the raw XML node.

        Like WebAuthenticationSettings, this block has no dedicated Get operation of its own:
        it is read out of the full WebAuthentication entity.

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
        # Retrieve the current captive portal branding
        Get-SfosCaptivePortalAppearance

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: LogoImage and LogoLink are empty (self-closing) elements when no custom
        logo is configured - they read back as an empty string, not $null.

        The entity is a discriminated union on UseCustomLayout, confirmed live by toggling it:
        with UseCustomLayout=Disable the wire carries a <DefaultLayout> block and no
        <CustomLayout> element at all; with UseCustomLayout=Enable the wire carries
        <CustomLayout> (UserDefinedTemplate, SystemGeneratedHtml) and no <DefaultLayout>
        element, so every DefaultLayout-only property below reads back empty while in that
        mode. This cmdlet always returns both sets of properties; whichever branch is not the
        active one is empty, not $null. SsoButtonLabel is not in the sample XML on the
        operations page but is documented in that page's own Attribute/Parameter Information
        table (default "Single sign-on") and is confirmed live inside <DefaultLayout> - a
        table/sample disagreement, not an undocumented field.
        SystemGeneratedHtml is read-only in every test run against this firmware: setting
        UserDefinedTemplate to real HTML content left SystemGeneratedHtml empty rather than
        populating it, and the operations page's own Attribute/Parameter Information table
        omits it entirely (sample XML only). Set-SfosCaptivePortalAppearance therefore exposes
        no parameter to write it.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/WebAuthenticationMethods/operations/CaptivePortalAppearance.html
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

    # See Get-SfosWebAuthenticationSettings: 'WebAuthentication' is the measured ObjectName
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
        Updates the WebAuthentication CaptivePortalAppearance on the Sophos Firewall.

        .DESCRIPTION
        Updates the CaptivePortalAppearance singleton nested under WebAuthentication. This
        cmdlet reads the current settings first and resends every field, overriding only what
        the caller explicitly passes (read-modify-write - SFOS replaces the whole sub-block on
        update, including the nested DefaultLayout element). This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        Every value interpolated into the request runs through ConvertTo-SfosXmlEscaped,
        which matters in particular for LoginPageHeaderHTML and LoginPageFooterHTML - both are
        free-form HTML fields that reliably contain '<', '>' and '&'.

        .PARAMETER UseCustomLayout
        Use a custom captive portal layout instead of the built-in default. If omitted, the
        value currently on the firewall is kept.

        .PARAMETER Logo
        Logo source for the captive portal page (measured live value: 'Default'). If omitted,
        the value currently on the firewall is kept.

        .PARAMETER LogoImage
        Uploaded logo image reference, empty when no custom logo is set. If omitted, the value
        currently on the firewall is kept.

        .PARAMETER LogoLink
        Target URL when the logo is clicked, empty when unset. If omitted, the value currently
        on the firewall is kept.

        .PARAMETER LoginPageHeaderHTML
        Custom HTML injected above the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER UserPrompt
        Prompt text shown above the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER UsernameFieldLabel
        Label of the username field. If omitted, the value currently on the firewall is kept.

        .PARAMETER PasswordFieldLabel
        Label of the password field. If omitted, the value currently on the firewall is kept.

        .PARAMETER LoginButtonLabel
        Label of the login button. If omitted, the value currently on the firewall is kept.

        .PARAMETER LogoutButtonLabel
        Label of the logout button. If omitted, the value currently on the firewall is kept.

        .PARAMETER UserPortalLinkLabel
        Label of the link to the User Portal. If omitted, the value currently on the firewall
        is kept.

        .PARAMETER RegistrationLinkLabel
        Label of the guest registration link. If omitted, the value currently on the firewall
        is kept.

        .PARAMETER SsoButtonLabel
        Label of the single sign-on button. If omitted, the value currently on the firewall is
        kept.

        .PARAMETER LoginPageFooterHTML
        Custom HTML injected below the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER BackgroundColor
        Page background colour, as a 6-digit hex string without '#'. If omitted, the value
        currently on the firewall is kept.

        .PARAMETER UserPromptFontColor
        Font colour of the prompt text, as a 6-digit hex string without '#'. If omitted, the
        value currently on the firewall is kept.

        .PARAMETER PageTitleBackgroundColor
        Background colour of the page title bar, as a 6-digit hex string without '#'. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER HeaderFooterFontColor
        Font colour of the header/footer text, as a 6-digit hex string without '#'. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER UserPortalLinkFontColor
        Font colour of the User Portal link, as a 6-digit hex string without '#'. If omitted,
        the value currently on the firewall is kept.

        .PARAMETER UserDefinedTemplate
        Raw HTML template used for the captive portal login page when UseCustomLayout is
        'Enable'. Measured live: the firewall only stores this value while UseCustomLayout is
        'Enable' at the time of the update - sending it together with UseCustomLayout
        'Disable' is accepted (200) but silently discarded, confirmed by re-enabling
        UseCustomLayout afterwards and finding the template empty again. If omitted, the value
        currently on the firewall is kept.

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
        # Change only the sign-in prompt text, every other field is preserved
        Set-SfosCaptivePortalAppearance -UserPrompt "Please sign in"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip matched the pre-image field for field, and a
        single-field change (UserPrompt) was applied, confirmed, and reverted. See the task
        report for the exact responses.

        This cmdlet always sends both the <DefaultLayout> and <CustomLayout> blocks, whichever
        of UseCustomLayout's two branches is currently active or not - confirmed live to be
        accepted (200) and harmless: sending <CustomLayout> while UseCustomLayout stays
        'Disable' does not create a visible CustomLayout block and does not disturb
        DefaultLayout, and sending <DefaultLayout> while UseCustomLayout stays 'Enable' does
        not restore a visible DefaultLayout block. Sending only the active branch was not
        tried, since the entity does not expose which branch was active before this cmdlet
        read it back - both are simply included every time.

        SystemGeneratedHtml has no corresponding parameter here - see
        Get-SfosCaptivePortalAppearance for why.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/WebAuthenticationMethods/operations/CaptivePortalAppearance.html
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

    # Measured live (forcing a 501 via an invalid UseCustomLayout value): Status landed at
    # /Response/CaptivePortalAppearance/Status - top level, not nested under WebAuthentication.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CaptivePortalAppearance' -Action 'update'
}

#endregion

#region DefaultCaptivePortal

<#
        .SYNOPSIS
        Retrieves the DefaultCaptivePortal configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the DefaultCaptivePortal entity, which holds
        all of the wording and templates the built-in captive portal uses (labels, status
        messages and the raw login page template). DefaultCaptivePortal is its own root
        element, unlike WebAuthenticationSettings/CaptivePortalAppearance which are nested
        under WebAuthentication. By default the cmdlet returns a PowerShell-friendly object.
        Use -AsXml to return the raw XML node.

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
        # Retrieve the current captive portal wording and login page template
        Get-SfosDefaultCaptivePortal

        .NOTES
        Minimum supported PowerShell version: 5.1
        All 17 fields returned by the firewall (UserPrompt, UsernameFieldLabel,
        PasswordFieldLabel, LoginButtonLabel, LogoutButtonLabel, UserPortalLinkLabel,
        RegistrationLinkLabel, CredentialLoginButtonLabel, UserDefinedTemplate,
        LoginPageHeaderHTML, LoginPageFooterHTML, DoNotClosePage, WillBeSignedOut,
        SsoSignedOut, SigningIn, EnterUsername, EnterPassword) are present in the live
        response, so Set-* can preserve every one of them via read-modify-write.

        The sample XML on the operations page also shows an 18th field, EnterValidUsername,
        sitting between EnterUsername and EnterPassword (it is absent from the page's own
        Attribute/Parameter Information table - the two disagree on which fields exist).
        A Get of DefaultCaptivePortal does not return an
        EnterValidUsername element at all on this firmware. Same precedent as FileType/
        -Template in the Web module: a field the Get never returns cannot be read back, so
        Set-SfosDefaultCaptivePortal does not expose it either, rather than implementing a
        parameter that read-modify-write could never actually preserve.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/DefaultCaptivePortal/DefaultCaptivePortal.html
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
    # genuinely wrong entity name answers a flat code="529" at /Response/<Name>/Status
    # (measured via <Get><ZZBogusEntityZZ></ZZBogusEntityZZ></Get> during status-path probing
    # for this fragment). 'DefaultCaptivePortal' is therefore the correct ObjectName.
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
        Updates the DefaultCaptivePortal configuration on the Sophos Firewall.

        .DESCRIPTION
        Updates the DefaultCaptivePortal entity. This cmdlet reads the current configuration
        first and resends every one of the 17 fields, overriding only what the caller
        explicitly passes (read-modify-write). This cmdlet supports ShouldProcess; use -WhatIf
        to preview the change.

        UserDefinedTemplate, LoginPageHeaderHTML and LoginPageFooterHTML are free-form HTML
        and, like every other value here, pass through ConvertTo-SfosXmlEscaped without
        exception - HTML reliably contains '<', '>' and '&'.

        Sending a Set with only an unrecognised element under
        DefaultCaptivePortal (no real field at all) answered code="200" and left every one of
        the 17 real fields on the firewall unchanged - unlike the settings singletons
        elsewhere in this module family, where an update clears every omitted field. This
        cmdlet still performs full read-modify-write regardless, since whole-entity replace
        applies without exception elsewhere - the single data point above is not treated as
        proof that every field is safe to omit.

        .PARAMETER UserPrompt
        Prompt text shown above the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER UsernameFieldLabel
        Label of the username field. If omitted, the value currently on the firewall is kept.

        .PARAMETER PasswordFieldLabel
        Label of the password field. If omitted, the value currently on the firewall is kept.

        .PARAMETER LoginButtonLabel
        Label of the login button. If omitted, the value currently on the firewall is kept.

        .PARAMETER LogoutButtonLabel
        Label of the logout button. If omitted, the value currently on the firewall is kept.

        .PARAMETER UserPortalLinkLabel
        Label of the link to the User Portal. If omitted, the value currently on the firewall
        is kept.

        .PARAMETER RegistrationLinkLabel
        Label of the guest registration link. If omitted, the value currently on the firewall
        is kept.

        .PARAMETER CredentialLoginButtonLabel
        Label of the credential login button. If omitted, the value currently on the firewall
        is kept.

        .PARAMETER UserDefinedTemplate
        Raw HTML template of the captive portal login page. If omitted, the value currently on
        the firewall is kept.

        .PARAMETER LoginPageHeaderHTML
        Custom HTML injected above the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER LoginPageFooterHTML
        Custom HTML injected below the login form. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER DoNotClosePage
        Wording of the "do not close this page" notice. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER WillBeSignedOut
        Wording warning the user they will be signed out if they close the page. If omitted,
        the value currently on the firewall is kept.

        .PARAMETER SsoSignedOut
        Wording of the single sign-on sign-out instructions. If omitted, the value currently
        on the firewall is kept.

        .PARAMETER SigningIn
        Wording shown while the sign-in is in progress. If omitted, the value currently on the
        firewall is kept.

        .PARAMETER EnterUsername
        Validation message shown when the username field is left empty. If omitted, the value
        currently on the firewall is kept.

        .PARAMETER EnterPassword
        Validation message shown when the password field is left empty. If omitted, the value
        currently on the firewall is kept.

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
        # Change only the sign-in prompt text, every other field is preserved
        Set-SfosDefaultCaptivePortal -UserPrompt "Please sign in to continue"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip matched the pre-image field for field, and a
        single-field change (UserPrompt) was applied, confirmed, and reverted. See the task
        report for the exact responses.

        The sample XML on the operations page documents an 18th field, EnterValidUsername,
        that this cmdlet does not send. Get-SfosDefaultCaptivePortal never
        returns an EnterValidUsername element on this firmware, so there is no value to
        preserve and nothing to merge in a read-modify-write. Sending it regardless would be
        guessing at a value the firewall never discloses. See Get-SfosDefaultCaptivePortal for
        the same behavior and the FileType/-Template precedent it follows.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/DefaultCaptivePortal/operations/UpdateDefaultSettingsOfCaptivePortal.html
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

    # Measured live (a Set carrying only an unrecognised element, no valid operation
    # attribute misuse): Status landed at /Response/DefaultCaptivePortal/Status - top level,
    # matching the entity's own top-level nesting.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultCaptivePortal' -Action 'update'
}

#endregion

#region DirectWebProxyAuthentication

<#
        .SYNOPSIS
        Retrieves the DirectWebProxyAuthentication configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the DirectWebProxyAuthentication entity, which
        controls per-connection authentication for the direct (non-transparent) web proxy and
        the list of multi-user hosts/servers (e.g. terminal servers) exempted from per-user
        session caching. DirectWebProxyAuthentication is its own root element. By default the
        cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

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
        # Retrieve the current direct web proxy authentication configuration
        Get-SfosDirectWebProxyAuthentication

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the lab firewall's MultiUserHosts list is unconfigured and the whole
        <MultiUserHosts> wrapper is absent from the response - the same "container missing
        when empty" shape measured for SSORadiusAccount in the firewall-authentication group
        of this module. MultiUserHostList reads as @() in that case, not $null.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/PerConnectionAuth/PerConnectionAuth.html
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
        Updates the DirectWebProxyAuthentication configuration on the Sophos Firewall.

        .DESCRIPTION
        Updates the DirectWebProxyAuthentication entity. This cmdlet reads the current
        configuration first and resends both fields, overriding only what the caller
        explicitly passes (read-modify-write - SFOS replaces the whole entity on update, so
        the existing MultiUserHosts list is preserved unless -MultiUserHost is supplied). This
        cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        Use Add-/Remove-SfosDirectWebProxyAuthenticationMember to change the host list
        incrementally instead of replacing it outright.

        .PARAMETER PerConnectionAuth
        Require authentication for every connection through the direct web proxy, rather than
        caching authentication per session. If omitted, the value currently on the firewall is
        kept.

        .PARAMETER MultiUserHost
        One or more host object names to treat as multi-user hosts/servers (their traffic is
        excluded from per-user session caching). If omitted, the hosts currently on the
        firewall are kept.

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
        # Require per-connection authentication on the direct web proxy
        Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Enable

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: a no-op round trip - reading PerConnectionAuth (Disable on the lab
        firewall) and writing it back unchanged - matched the pre-image field for field and
        answered code="200".

        Measured live: -PerConnectionAuth Enable is rejected by the firewall with code="501"
        and an empty <InvalidParams/> - no field is named - regardless of whether the
        MultiUserHosts block is included in the same request or omitted. The read path and
        the no-op write of Disable both work; only writing Enable fails. The cause is unknown;
        most likely an unmet prerequisite on the appliance, but this is not confirmed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/PerConnectionAuth/operations/UpdateAuthenticationSettingsForDirectWebProxy.html
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

    # Measured live (forcing a 501 via an invalid PerConnectionAuth value): Status landed at
    # /Response/DirectWebProxyAuthentication/Status - top level, matching the entity's own
    # top-level nesting.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'update'
}

<#
        .SYNOPSIS
        Adds hosts to the DirectWebProxyAuthentication MultiUserHosts list.

        .DESCRIPTION
        Adds one or more host object names to the MultiUserHosts/Host list of
        DirectWebProxyAuthentication, preserving the existing hosts and PerConnectionAuth
        setting (SFOS replaces the whole entity on update, so the current list is read back
        and resent together with the new entries).

        .PARAMETER Members
        One or more host object names to add to the multi-user hosts list.

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
        # Add a terminal server to the multi-user hosts list
        Add-SfosDirectWebProxyAuthenticationMember -Members "TS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live against a ZZTestG-prefixed IPHost object: added, confirmed present via
        Get-SfosDirectWebProxyAuthentication, then removed again via
        Remove-SfosDirectWebProxyAuthenticationMember.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/PerConnectionAuth/operations/UpdateAuthenticationSettingsForDirectWebProxy.html
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
    # /Response/DirectWebProxyAuthentication/Status, measured there.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DirectWebProxyAuthentication' -Action 'add members'
}

<#
        .SYNOPSIS
        Removes hosts from the DirectWebProxyAuthentication MultiUserHosts list.

        .DESCRIPTION
        Removes one or more host object names from the MultiUserHosts/Host list of
        DirectWebProxyAuthentication, preserving PerConnectionAuth and every remaining host
        (SFOS replaces the whole entity on update, so the remaining entries are read back and
        resent). After writing, this cmdlet reads the list back and throws if a member that
        was supposed to be removed is still present, because several list fields in this API
        are append-only on update and silently ignore a shorter list.

        .PARAMETER Members
        One or more host object names to remove from the multi-user hosts list.

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
        None. Throws an exception if the update fails, or if a member that should have been
        removed is still present on the firewall afterwards.

        .EXAMPLE
        # Remove a decommissioned terminal server
        Remove-SfosDirectWebProxyAuthenticationMember -Members "TS-Server1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live against a ZZTestG-prefixed IPHost object.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/PerConnectionAuth/operations/UpdateAuthenticationSettingsForDirectWebProxy.html
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
    # /Response/DirectWebProxyAuthentication/Status, measured there.
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
# Wire element is <AzureADSSO>, matching the cmdlet noun. Status path measured live for
# every operation (Get/Set add/Set update/Remove) at the SAME top-level path:
#   /Response/AzureADSSO/Status
# - never nested under any wrapper - so every Assert-SfosApiReturnSuccess call below uses
# -ObjectName 'AzureADSSO'. Measured by: (a) a normal Get on an empty result answers
# <AzureADSSO><Status>No. of records Zero.</Status></AzureADSSO>; (b) a <Set operation="add">
# missing the mandatory ApplicationID answers 501 with <InvalidParams><Params>
# /AzureADSSO/ApplicationID</Params></InvalidParams> at that same path; (c) a duplicate
# ServerName+ApplicationID add answers 503 at that path; (d) <Remove> answers 200 at that
# path, including - measured, not merely assumed - when the ServerName does not exist,
# which is documented as a known limitation below.
#
# Three-source conflict, resolved by live measurement: the Attribute/
# Parameter table on the Sophos 22.0 doc page names the RoleMapping profile field
# 'profileidentifier'; the sample XML on the same page calls it 'profileid'. A live
# <Set operation="add"> using 'profileid' was accepted and echoed back verbatim by <Get> as
# 'profileid' - the sample wins, the table is wrong. identifiertype/identifiervalue matched
# in both sources and are unchanged.
#
# RoleMapping is documented as a list (<RoleMapping> wrapping one-or-more
# <IdentifierTypeAndProfile>), but only a single entry survives on this firmware: a live add
# with two <IdentifierTypeAndProfile> blocks inside one <RoleMapping> answered 200, and the
# following <Get> echoed back only the first entry - the second was silently dropped. This
# cmdlet set therefore exposes RoleMapping as three scalar parameters
# (-RoleMappingIdentifierType/-RoleMappingIdentifierValue/-RoleMappingProfileID), not an
# array, matching what the firewall actually keeps.
#
# RoleMapping itself is only returned by <Get> when UserType is 'Administrator' - measured:
# an object created with UserType 'User' and a RoleMapping block in the request never shows
# RoleMapping in the following <Get>, while the identical request with UserType
# 'Administrator' echoes it back in full. Get-SfosAzureADSSO therefore returns empty strings
# for the three RoleMapping properties whenever the stored object has no RoleMapping (either
# because UserType is 'User', or the field was never set) - this is not a bug in the cmdlet,
# it mirrors what the firewall itself does not return.
#
# ClientSecret is returned by <Get>, but only in hashed form:
# <ClientSecret hashform="mode1">$sfos$7$0$...</ClientSecret>, freshly salted on every read
# (measured: the same plaintext secret produces a different hash string on every <Get>, so
# hash equality cannot be used to detect "unchanged"). Get-SfosAzureADSSO exposes this as
# ClientSecretHash/ClientSecretHashForm, not as ClientSecret, to make clear neither is the
# plaintext - the same pattern already used for RADIUSServer/TACACSServer SharedSecret in
# Group A. Resending the hash text together with its hashform attribute on <Set
# operation="update"> is accepted by the firewall (code 200, measured); Set-SfosAzureADSSO
# uses exactly that to preserve an unchanged secret when -ClientSecret is not passed.
#
# DisplayName/EmailAddress: the Attribute/Parameter table claims only 'upn'/'name'
# (DisplayName) and only 'email' (EmailAddress) are accepted, calling them out as fixed
# keywords rather than free text. A live add with DisplayName 'bogus' was accepted anyway
# (code 200) - the firewall does not enforce this constraint server-side. ValidateSet is
# kept here regardless, because the two keywords are the only values that have any
# documented meaning to the firewall; sending anything else is accepted but does nothing
# useful. This deviation from doc-vs-measured is recorded here, not silently
# corrected away.

<#
        .SYNOPSIS
        Retrieves Microsoft Entra ID (Azure AD) SSO server objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for AzureADSSO objects. By default the cmdlet
        returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Server-side filtering is unconfirmed against a live appliance for this entity, so no
        <Filter> is sent with the request. -ServerNameLike is applied client-side only, as a
        substring match.

        .PARAMETER ServerNameLike
        Optional name filter, applied client-side as a substring match.

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
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.
        ClientSecretHash/ClientSecretHashForm carry the firewall's hashed form of the client
        secret, not the plaintext - see the region header. RoleMappingIdentifierType/
        RoleMappingIdentifierValue/RoleMappingProfileID are empty strings when the stored
        object has no RoleMapping (see the region header for when the firewall omits it).

        .EXAMPLE
        # Retrieve all Azure AD SSO servers
        Get-SfosAzureADSSO

        .EXAMPLE
        # Filter by name (substring match, applied client-side)
        Get-SfosAzureADSSO -ServerNameLike "Corp"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/IDPSSOServer/IDPSSOServer.html
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
        Creates a new Microsoft Entra ID (Azure AD) SSO server on the Sophos Firewall.

        .DESCRIPTION
        Creates an AzureADSSO object using the Sophos Firewall XML API.

        .PARAMETER ServerName
        Name identifying the server (1-50 characters, no commas) [doc].

        .PARAMETER ApplicationID
        Application (client) ID from Microsoft Entra ID > App registrations (max 50 characters) [doc].

        .PARAMETER TenantID
        Directory (tenant) ID from Microsoft Entra ID > App registrations (max 50 characters) [doc].

        .PARAMETER ClientSecret
        The client secret used by the firewall to authenticate with the Microsoft Entra ID application [doc].

        .PARAMETER RedirectURI
        FQDN or IP address of this firewall, as registered in Microsoft Entra ID (max 200 characters) [doc].

        .PARAMETER DisplayName
        Attribute the firewall uses to retrieve the user's display name [doc]: 'upn' or 'name'. Not enforced server-side (measured - see the region header), kept here because these are the only two documented values with meaning to the firewall.

        .PARAMETER EmailAddress
        Attribute the firewall uses to retrieve the user's email address [doc]: only 'email' is documented. Not enforced server-side (measured - see the region header).

        .PARAMETER FallbackUserGroup
        User group assigned if the firewall finds no matching local group [doc].

        .PARAMETER UserType
        Type of user this server authenticates [doc]: 'User' or 'Administrator'. RoleMapping is only meaningful - and only echoed back by Get-SfosAzureADSSO - when this is 'Administrator' (measured, see the region header).

        .PARAMETER RoleMappingIdentifierType
        For UserType 'Administrator': whether the mapping matches on Entra ID app roles or groups [doc]: 'roles' or 'groups'. Must be supplied together with -RoleMappingIdentifierValue and -RoleMappingProfileID - the firewall keeps only one IdentifierTypeAndProfile entry regardless (measured, see the region header), so this cmdlet does not accept more than one.

        .PARAMETER RoleMappingIdentifierValue
        The role or group value configured in Microsoft Entra ID to match on [doc]. Required together with -RoleMappingIdentifierType and -RoleMappingProfileID.

        .PARAMETER RoleMappingProfileID
        The administrator profile assigned when the mapping matches [doc]. Required together with -RoleMappingIdentifierType and -RoleMappingIdentifierValue.

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
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a user-facing SSO server (no role mapping)
        $secret = ConvertTo-SecureString "MySecret" -AsPlainText -Force
        New-SfosAzureADSSO -ServerName "CorpEntra" -ApplicationID "fa7fc787-011e-4398-812f-3152d8843320" -TenantID "10657f8b-d541-41a5-8e25-a8d7cbb9d4dd" -ClientSecret $secret -RedirectURI "fw.example.invalid" -DisplayName upn -EmailAddress email -FallbackUserGroup "Open Group" -UserType User

        .EXAMPLE
        # Create an administrator SSO server with a role mapping
        $secret = ConvertTo-SecureString "MySecret" -AsPlainText -Force
        New-SfosAzureADSSO -ServerName "CorpEntraAdmin" -ApplicationID "fa7fc787-011e-4398-812f-3152d8843320" -TenantID "10657f8b-d541-41a5-8e25-a8d7cbb9d4dd" -ClientSecret $secret -RedirectURI "fw.example.invalid" -DisplayName upn -EmailAddress email -FallbackUserGroup "Open Group" -UserType Administrator -RoleMappingIdentifierType roles -RoleMappingIdentifierValue "role.admin" -RoleMappingProfileID "Administrator"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/IDPSSOServer/operations/AddMicrosoftEntraID(AzureAD)SSOServer%26EditMicrosoftEntraID(AzureAD)SSOServer.html

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
        Updates an existing Microsoft Entra ID (Azure AD) SSO server on the Sophos Firewall.

        .DESCRIPTION
        Updates an AzureADSSO object using the Sophos Firewall XML API. SFOS replaces the
        whole entity on update, so this cmdlet reads the current object first and keeps
        whatever the caller does not explicitly pass - including the nested RoleMapping
        sub-structure, which is otherwise cleared silently on any update that does not
        resend it. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        When -ClientSecret is omitted, the previously stored secret is preserved by resending
        its hashed form together with its hashform attribute - accepted by the firewall as
        "unchanged" (measured, see the region header). Passing -ClientSecret replaces it.

        .PARAMETER ServerName
        Name of the target server.

        .PARAMETER ApplicationID
        Application (client) ID. If omitted, the existing value is kept.

        .PARAMETER TenantID
        Directory (tenant) ID. If omitted, the existing value is kept.

        .PARAMETER ClientSecret
        New client secret. If omitted, the existing secret is preserved (see the .DESCRIPTION).

        .PARAMETER RedirectURI
        FQDN or IP address of this firewall. If omitted, the existing value is kept.

        .PARAMETER DisplayName
        'upn' or 'name'. If omitted, the existing value is kept.

        .PARAMETER EmailAddress
        Only 'email' is documented. If omitted, the existing value is kept.

        .PARAMETER FallbackUserGroup
        Fallback user group. If omitted, the existing value is kept.

        .PARAMETER UserType
        'User' or 'Administrator'. If omitted, the existing value is kept.

        .PARAMETER RoleMappingIdentifierType
        'roles' or 'groups'. Must be supplied together with -RoleMappingIdentifierValue and -RoleMappingProfileID. If none of the three are supplied, the existing RoleMapping (if any) is preserved unchanged.

        .PARAMETER RoleMappingIdentifierValue
        Role or group value to match on. Required together with -RoleMappingIdentifierType and -RoleMappingProfileID.

        .PARAMETER RoleMappingProfileID
        Administrator profile assigned on match. Required together with -RoleMappingIdentifierType and -RoleMappingIdentifierValue.

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
        # Change only the redirect URI; ClientSecret and RoleMapping are preserved
        Set-SfosAzureADSSO -ServerName "CorpEntraAdmin" -RedirectURI "fw2.example.invalid"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Confirmed: a full round trip (read, write back unchanged, read again), a single-field
        update with a two-entry RoleMapping present beforehand (preserved afterwards), and the
        -ClientSecret-omitted hash-resend path all work as documented.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/IDPSSOServer/operations/AddMicrosoftEntraID(AzureAD)SSOServer%26EditMicrosoftEntraID(AzureAD)SSOServer.html
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
            # attribute - measured to be accepted as "unchanged" (see the region header).
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
        Removes a Microsoft Entra ID (Azure AD) SSO server from the Sophos Firewall.

        .DESCRIPTION
        Removes an AzureADSSO object using the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ServerName
        Name of the target server.

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
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosAzureADSSO -ServerName "CorpEntra" -WhatIf

        .EXAMPLE
        # Remove a server
        Remove-SfosAzureADSSO -ServerName "CorpEntra"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Known limitation: removing a ServerName that does not exist answers
        code 200 "Configuration applied successfully" - the same misleading behaviour common
        to Remove-Sfos* cmdlets generally, but here without even the raw-528
        passthrough other entities show. This cmdlet does not pre-check existence (consistent
        with every other Remove-Sfos* in this module); the caller cannot distinguish "removed"
        from "never existed" from the response alone.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/IDPSSOServer/operations/Delete%20Microsoft%20Entra%20ID%20(Azure%20AD)%20SSO%20Server.html
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
# <AuthCTA> (Cyberoam-era naming: "Client Transparent Authentication" / the CISHCyberoam doc
# folder this page lives under). Both names are recorded here so the deviation is not
# mistaken for an error.
#
# Status path is operation-dependent, exactly the trap called out for this module:
#   <Get><AuthCTA/></Get>            success -> no <Status> node at all (lenient Get,
#                                     same pattern as FirewallAuthentication in Group E)
#   <Set operation="update">          -> /Response/EnableDisable/Status - NOT nested under
#                                     AuthCTA, and NOT named 'AuthCTA' either
# Measured by forcing an error on Set (ACTION 'Maybe'): the 500 landed at
# /Response/EnableDisable/Status. A genuine state-changing update (Disable -> Enable) landed
# a 200 at the same path. Get-SfosSTAS therefore asserts with -ObjectName 'AuthCTA' (matches
# the lenient-Get pattern, tolerates zero Status nodes); Set-SfosSTAS asserts with
# -ObjectName 'EnableDisable'.
#
# Live baseline for this firewall was <AuthCTA><EnableDisable><ACTION>Disable</ACTION>
# </EnableDisable></AuthCTA> - no Settings, Collector or VpnZone sub-blocks at all. Enabling
# STAS (ACTION=Enable) caused a Settings sub-block to appear on the next Get, populated with
# firewall defaults (IdentityProbeTimeout 120, RestrictClientTraffic Yes, UserInactivity
# Disable) that were never sent in the request - the same "only shown once active" pattern
# already measured for CTASSettings in Group E. Reverting to Disable made the Settings block
# disappear again from Get, restoring the exact original baseline (confirmed by raw XML
# comparison).
#
# Collector/Settings/VpnZone are NOT implemented on Set-SfosSTAS, and this is a deliberate
# scope decision, not an oversight: a live <Set> combining an unchanged ACTION with a changed
# Settings/IdentityProbeTimeout answered with TWO INDEPENDENT Status nodes in one response -
# /Response/EnableDisable/Status (502 "already exists", because ACTION did not change) AND
# /Response/Settings/Status (200) - and the following Get, with STAS still Disabled, showed
# no Settings block at all, so whether the 200 for Settings actually persisted anything could
# not be confirmed. Assert-SfosApiReturnSuccess checks exactly one -ObjectName per call;
# extending Set-SfosSTAS to Collector/Settings/VpnZone would need per-sub-block status
# handling that has not been designed or verified, so it is left out rather than shipped
# half-checked. Get-SfosSTAS still exposes whatever Settings/Collector/VpnZone fields ARE
# present on a given Get, so nothing observable is hidden.
#
# The 502 above is itself documented, not merely observed: the STAS operation page's own
# Status Message Information table lists 502 = "STAS is already in that state" - so
# Assert-SfosApiReturnSuccess correctly throws on a same-value resend, and a caller (or a
# round-trip test) must not treat that as a defect.

<#
        .SYNOPSIS
        Retrieves the STAS (Single Agent Transparent Authentication Suite) configuration from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the AuthCTA singleton - shown in the webadmin
        and the Sophos API documentation as "STAS". There is exactly one instance of this
        element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use
        -AsXml to return the raw XML node.

        Settings/Collector/VpnZone sub-blocks are only populated by the firewall once STAS is
        enabled (see the region header); their properties are empty strings otherwise.

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
        # Retrieve the current STAS state
        Get-SfosSTAS

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/CISHCyberoam/CISHCyberoam.html
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
        Enables or disables STAS (Single Agent Transparent Authentication Suite) on the Sophos Firewall.

        .DESCRIPTION
        Updates the ACTION field of the AuthCTA/EnableDisable singleton using the Sophos
        Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the
        change.

        Only the enable/disable state is implemented - see the region header for why
        Collector/Settings/VpnZone are deliberately out of scope for this cmdlet.

        Sending the same ACTION value the firewall already has is rejected with code 502
        "already in that state" (documented by Sophos, measured live) - this is not a defect
        in the cmdlet, and -WhatIf will not reveal it since it does not call the firewall.

        .PARAMETER ACTION
        Enable or disable STAS.

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
        # Enable STAS
        Set-SfosSTAS -ACTION Enable

        .NOTES
        Minimum supported PowerShell version: 5.1
        Toggling Enable then Disable returns the firewall to its exact original state.
        Setting a state the firewall is already in answers 502.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/CISHCyberoam/operations/UpdateSTAS.html
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
    # Measured: the Status for this Set lands at /Response/EnableDisable/Status - see the
    # region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EnableDisable' -Action 'update'
}

#endregion STAS

#region LiveUser
#
# Connect-/Disconnect-SfosLiveUser log an END USER in or out at the firewall's own
# transparent-authentication tracking (the "Live Users" list under Current Activities in the
# webadmin) - they have NOTHING to do with Connect-SfosFirewall/Disconnect-SfosFirewall,
# which manage the API session this whole module authenticates with. That distinction is
# repeated in both functions' help on purpose.
#
# The operations are documented under APIUserLogin/APIUserLogout, not under a 'LiveUser' term:
#   https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogin/operations/APIUserLogin.html
#   https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogout/operations/APIUserLogout.html
# Both pages give a distinct root element - <LiveUserLogin> / <LiveUserLogout> - that is NOT
# wrapped in <Set>, plus an <Admin> block carrying a second, in-payload set of credentials
# alongside the session's own <Login> block. Sending the wrong root element, wrapping it in
# <Set>, or omitting <Admin> answers HTTP 200 with no <Status> node of any kind - the firewall
# never recognises the request as either operation.
#
# A create/read/delete/read round trip confirms the documented shape below end to end:
# LiveUserLogin registers a record a follow-up <Get><LiveUser/></Get> shows, and
# LiveUserLogout removes it (back to "No. of records Zero."). Two deliberately provoked
# failures (a wrong <Admin><Password>, a request missing the mandatory <IPAddress>) both come
# back as HTTP 200 with a documented failure status code (500, 501).
# The status node in every case sits at /Response/LiveUserLogin/Status and
# /Response/LiveUserLogout/Status respectively - a <Status code="..."> child of the operation's
# own root element, not of a generic 'LiveUser' object name - so -ObjectName below is set to
# the operation name, not the entity name. See each function's .NOTES.
#
# DeviceType: the Attribute/Parameter table on the APIUserLogin page states "Only 'iOS',
# 'Android' are allowed", but the page's own sample XML comment lists four options -
# "iOS/Android/iPhone/iPad". <DeviceType>iPhone</DeviceType> is accepted with
# status 200, contradicting the table. The ValidateSet below follows the sample and the live
# measurement, not the narrower table wording.

<#
        .SYNOPSIS
        Retrieves LiveUser objects (currently logged-in end users) from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for LiveUser objects - the "Live Users" list under
        Current Activities in the webadmin, the same tracking Connect-/Disconnect-SfosLiveUser
        write to. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
        return the raw XML nodes.

        .PARAMETER UserNameLike
        Optional username filter, matched as a substring anywhere in the value. Applied
        client-side only - server-side filtering for this entity has not been verified, so no
        <Filter> is sent (an unverified key risks a silent full-table scan
        rather than a real filter).

        .PARAMETER HostIPLike
        Optional client IP address filter, matched as a substring anywhere in the value.
        Applied client-side only, for the same reason as -UserNameLike.

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
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all currently logged-in live users
        Get-SfosLiveUser

        .EXAMPLE
        # Filter by client IP (substring match)
        Get-SfosLiveUser -HostIPLike "10.99.99."

        .EXAMPLE
        # Log a live user back out again
        Get-SfosLiveUser -UserNameLike "jdoe" | Disconnect-SfosLiveUser

        .NOTES
        Minimum supported PowerShell version: 5.1
        The vendor reference for this area (APIUserLogin) documents only the Login and Logout
        operations - there is no published Get page for LiveUser. The read path exists anyway:
        <Get><LiveUser></LiveUser></Get>
        answers with one <LiveUser> element per active session directly under /Response,
        carrying <UserID>, <UserName>, <LiveUserID>, <ClientType>, <HostIP>, <IPFamily>, <MAC>,
        <StartTime>, <Upload>, <Download>, <DataTransferRate> and <InternetUsageTime>. An empty
        result answers <LiveUser transactionid=""><Status>No. of records Zero.</Status></LiveUser>
        with no <UserID> - the documented empty-result wording - and
        is returned as an empty array rather than thrown. The status path is
        /Response/LiveUser/Status, so -ObjectName below is 'LiveUser', same as the entity name -
        unlike Connect-/Disconnect-SfosLiveUser, whose status sits under the operation's own
        root element (LiveUserLogin/LiveUserLogout), this Get uses the entity name directly.
        The output exposes the wire property names (UserName, HostIP) plus two AliasProperty
        members, LiveUserName and IPAddress, added purely so 'Get-SfosLiveUser |
        Disconnect-SfosLiveUser' binds by property name without extra parameters. The alias
        could not be declared the usual way, as a parameter [Alias(...)] on Connect-/Disconnect-
        SfosLiveUser themselves: [Alias('UserName')] on their -LiveUserName parameter collides
        case-insensitively with their own -Username connection parameter and breaks the whole
        cmdlet - Get-Help and every invocation throw "parameter 'Username' cannot be specified
        because it conflicts with the parameter alias of the same name" - the same failure
        mode already seen for -ServerPort. Adding the alias on this cmdlet's output instead avoids the collision
        entirely.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogin/APIUserLogin.html
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
        Logs an end user in at the Sophos Firewall's live/transparent-authentication user tracking.

        .DESCRIPTION
        Registers a user session in the firewall's "Live Users" tracking (Current Activities
        in the webadmin), using the Sophos Firewall XML API 'API User Login' operation. This
        is UNRELATED to Connect-SfosFirewall, which establishes the API session this whole
        module authenticates with - this cmdlet logs in an end user of the firewall's network
        services, not this PowerShell session. This cmdlet supports ShouldProcess; use -WhatIf
        to preview the call.

        The documented wire shape carries a second, in-payload set of admin credentials in an
        <Admin> block, alongside the API session's own <Login> block. By default this cmdlet
        reuses the same resolved session credentials for both, so the ordinary call needs no
        extra parameters; -AdminUsername/-AdminPassword let the payload-level credentials be a
        different account.

        .PARAMETER LiveUserName
        Guest/end-user username to log in. Wire element is <UserName>; named -LiveUserName
        here because -Username is already the fixed connection parameter and cannot be reused -
        a parameter alias colliding with another parameter's own name breaks the whole
        command's metadata resolution (as seen with -ServerPort elsewhere in this module), so
        this is a rename, not an alias.

        .PARAMETER IPAddress
        IP address of the client the user is being logged in from. Mandatory per the API
        documentation.

        .PARAMETER MacAddress
        Optional MAC address of the client device. Wire element is <MacAddress>.

        .PARAMETER GroupName
        Optional group to associate the session with. Wire element is <GroupName>.

        .PARAMETER DeviceType
        Optional device type. Wire element is <DeviceType>. The documentation's own sources
        disagree on the allowed values - the Attribute/Parameter table restricts this to 'iOS'
        and 'Android', but the sample XML on the same page lists 'iPhone' and 'iPad' as well.
        Measured live against the lab firewall: 'iPhone' is accepted with status 200. The
        ValidateSet here follows the sample and the live measurement.

        .PARAMETER AdminUsername
        Username for the in-payload <Admin> block. Defaults to the resolved session username
        (Username/-Firewall context) if not supplied - the ordinary call does not need this.

        .PARAMETER AdminPassword
        Password for the in-payload <Admin> block, as a SecureString. Defaults to the resolved
        session password if not supplied.

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
        None. Throws an exception if the underlying API call fails or if the firewall reports
        a non-success status for the LiveUserLogin operation.

        .EXAMPLE
        Connect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55"

        .EXAMPLE
        # Preview the call
        Connect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        The documented <LiveUserLogin> shape with an <Admin> block works: a
        create/read/delete/read round trip succeeds end to end, and the status for this
        operation lands at /Response/LiveUserLogin/Status[@code], not under a generic
        'LiveUser' object name.

        A login CREATES A PERSISTENT User record (Group 'Open Group') for the given name if
        none exists. Disconnect-SfosLiveUser ends only the live session and never removes
        that record - clean up with Remove-SfosUser if the account is not wanted.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogin/operations/APIUserLogin.html
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
        Logs an end user out of the Sophos Firewall's live/transparent-authentication user tracking.

        .DESCRIPTION
        Removes a user session from the firewall's "Live Users" tracking (Current Activities
        in the webadmin), using the Sophos Firewall XML API 'API User Logout' operation. This
        is UNRELATED to Disconnect-SfosFirewall, which ends the API session this whole module
        authenticates with - this cmdlet logs out an end user of the firewall's network
        services, not this PowerShell session. This cmdlet supports ShouldProcess; use -WhatIf
        to preview the call.

        The documented wire shape carries a second, in-payload set of admin credentials in an
        <Admin> block, alongside the API session's own <Login> block. By default this cmdlet
        reuses the same resolved session credentials for both, so the ordinary call needs no
        extra parameters; -AdminUsername/-AdminPassword let the payload-level credentials be a
        different account. This cmdlet deliberately never targets a session whose owner cannot
        be confirmed - see the task's safety instruction; never call it against a live user
        session you cannot positively identify as your own test session.

        .PARAMETER LiveUserName
        Username to log out. Wire element is <UserName>; named -LiveUserName here for the
        same reason as Connect-SfosLiveUser - -Username is already the fixed connection
        parameter and cannot be reused or aliased.

        .PARAMETER IPAddress
        IP address of the client the user was logged in from. Mandatory per the API
        documentation.

        .PARAMETER AdminUsername
        Username for the in-payload <Admin> block. Defaults to the resolved session username
        if not supplied - the ordinary call does not need this.

        .PARAMETER AdminPassword
        Password for the in-payload <Admin> block, as a SecureString. Defaults to the resolved
        session password if not supplied.

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
        None. Throws an exception if the underlying API call fails or if the firewall reports
        a non-success status for the LiveUserLogout operation.

        .EXAMPLE
        Disconnect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55"

        .EXAMPLE
        # Preview the call
        Disconnect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        The documented <LiveUserLogout> shape with an <Admin> block works: a
        create/read/delete/read round trip succeeds end to end, and the status for this
        operation lands at /Response/LiveUserLogout/Status[@code], not under a generic
        'LiveUser' object name.
        Never call this against a session you cannot positively identify as your own test
        session; on a shared firewall it may target the wrong user.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Authentication/APIUserLogout/operations/APIUserLogout.html
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
        # Measured live: the status for this operation is a <Status code="..."> child of the
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

