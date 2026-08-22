#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }

<#
.SYNOPSIS
    Manages Sophos Central cloud management and registration on a Sophos Firewall.

.DESCRIPTION
    Functions for the SYSTEM > Sophos Central area of the Sophos Firewall XML API (SFOS
    22.0): the cloud central management switches - centralized reporting, management from
    Sophos Central, and configuration backup - that sit under EnableCloudCentralManagement.

    Registering a firewall with a Sophos Central tenant is deliberately not part of this
    module. The API offers exactly one way to do it, and that way sends the account name and
    password of a Sophos Central administrator in the request body. A tenant secured with a
    passkey, or with any other passwordless sign-in, cannot supply those, and the one-time
    password the web admin console accepts instead has no API equivalent. Register the
    firewall through the web admin console, then use this module for the switches.

    Total Functions: 2 - see README.md for the full cmdlet table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosCentralManagement

    Connects to the firewall and reads the current cloud central management settings.

.EXAMPLE
    Set-SfosCentralManagement -UseCentralReporting Disable -Confirm:$false
    Get-SfosCentralManagement

    Switches Sophos Central reporting off, leaving management, backup and join method
    untouched, then confirms the new state.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>


#region CentralManagement

<#
.SYNOPSIS
    Retrieves the Sophos Central cloud management settings from a Sophos Firewall.

.DESCRIPTION
    Returns the four switches that control how this firewall works with Sophos Central:
    whether configuration backups are sent to Sophos Central, how the firewall joined
    Sophos Central, whether centralized reporting is on, and whether the firewall is managed
    from Sophos Central. There is exactly one instance of this object per firewall, held
    under the wire element EnableCloudCentralManagement - despite the name, it is a settings
    object, not a command. The cmdlet only reads; nothing on the firewall is changed. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

    This cmdlet does not reveal whether the firewall is actually registered with a Sophos
    Central tenant. Registration and these four switches are
    independent according to Sophos: turning a switch off does not end the registration, and
    a switch can read Enable without a registration ever having been confirmed. Check the
    Sophos Central status in the web admin console (menu Sophos Central) for the actual
    registration state.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Sophos Central settings. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. One object with the properties FWBackup,
    JoinMethod, UseCentralReporting and CMStatus. UseCentralReporting and CMStatus normally
    read Enable or Disable, but can also read the undocumented value WaitingForApproval while
    a service that was just switched on is waiting for a super admin to confirm it in the
    Sophos Central console. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosCentralManagement

    Returns the current Sophos Central management settings of the firewall of the current
    connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosCentralManagement
#>
function Get-SfosCentralManagement {
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

    $inner = '<Get><EnableCloudCentralManagement></EnableCloudCentralManagement></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving CentralManagement: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EnableCloudCentralManagement' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/EnableCloudCentralManagement')
    if (-not $node) {
        throw 'CentralManagement could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        FWBackup            = [string]$node.FWBackup
        JoinMethod          = [string]$node.JoinMethod
        UseCentralReporting = [string]$node.UseCentralReporting
        CMStatus            = [string]$node.CMStatus
    }
}

<#
.SYNOPSIS
    Updates the Sophos Central cloud management settings on a Sophos Firewall.

.DESCRIPTION
    Updates the four EnableCloudCentralManagement switches. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change Sophos Central settings. The cmdlet reads the current
    settings first and resends every field, overriding only what you explicitly pass, so
    fields you do not pass keep their current value.

    FWBackup depends on CMStatus, matching the web admin console, where the configuration
    backup checkbox sits nested under the "Manage from Sophos Central" checkbox. This
    cmdlet refuses to set FWBackup to BackupEnable while CMStatus (whether passed explicitly
    or read back from the firewall) resolves to Disable, and throws instead of sending a
    combination the firewall's own web admin console cannot produce.

    Switching UseCentralReporting or CMStatus off takes effect immediately. Switching either
    back on is accepted by the firewall and reported as a success, but has no effect until a
    super admin confirms the service in the Sophos Central console with Accept services -
    turning a service back on is not something this cmdlet, or the API behind it, can
    complete on its own. After every update the cmdlet reads the settings back: a field that
    still shows its previous value throws, naming the field and the Sophos Central console
    step it is waiting on; a field that shows the undocumented value WaitingForApproval
    produces a warning instead, because that outcome means the request was accepted and is
    pending, not that it failed silently.

    This cmdlet changes only EnableCloudCentralManagement. It does not register or
    unregister the firewall with Sophos Central, and switching CMStatus to Disable does not
    end an existing registration.

.PARAMETER FWBackup
    Optional. Whether configuration backups are sent to Sophos Central: BackupEnable or
    BackupDisable. Corresponds to "Send configuration backup to Sophos Central" in the web
    admin console. Requires CMStatus to resolve to Enable - see the description. If omitted,
    the current value is kept.

.PARAMETER JoinMethod
    Optional. How the firewall joined Sophos Central: Manual or ZeroTouch. This switch has
    no equivalent in the web admin console; it reflects how the join happened rather than
    being a setting an administrator toggles directly. If omitted, the current value is
    kept.

.PARAMETER UseCentralReporting
    Optional. Whether centralized reporting in Sophos Central is on: Enable or Disable.
    Corresponds to "Use Sophos Central reporting" in the web admin console. Switching this to
    Enable is accepted by the firewall but not completed by this cmdlet alone - see the
    description. If omitted, the current value is kept.

.PARAMETER CMStatus
    Optional. Whether the firewall is managed from Sophos Central: Enable or Disable.
    Corresponds to "Use Sophos Central management" in the web admin console. Switching this
    to Enable is accepted by the firewall but not completed by this cmdlet alone - see the
    description. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change Sophos
    Central settings. If omitted, the value from the current connection is used.

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
    None. The cmdlet writes no output. It throws if the firewall rejects the update, and
    also if the firewall reports success but a requested change to UseCentralReporting or
    CMStatus was not applied - see the description.

.EXAMPLE
    Set-SfosCentralManagement -CMStatus Disable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosCentralManagement -UseCentralReporting Disable -Confirm:$false

    Switches only centralized reporting off, leaving management, backup and join method
    untouched, without asking for confirmation. Use this form only in scripts where the
    value has already been reviewed.

.EXAMPLE
    Set-SfosCentralManagement -FWBackup BackupEnable -CMStatus Disable -Confirm:$false

    Throws before sending anything to the firewall, because FWBackup cannot be BackupEnable
    while CMStatus is Disable.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosCentralManagement
#>
function Set-SfosCentralManagement {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('BackupEnable', 'BackupDisable')]
        [string]$FWBackup,

        [ValidateSet('Manual', 'ZeroTouch')]
        [string]$JoinMethod,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseCentralReporting,

        [ValidateSet('Enable', 'Disable')]
        [string]$CMStatus,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    # Cheap short-circuit: if the caller passed both FWBackup and CMStatus explicitly, the
    # conflict is already fully known and is reported before the firewall is contacted at
    # all - not just before anything is written.
    if ($bp.ContainsKey('FWBackup') -and $bp.ContainsKey('CMStatus') -and
        $FWBackup -eq 'BackupEnable' -and $CMStatus -eq 'Disable') {
        throw "Cannot update CentralManagement: FWBackup cannot be 'BackupEnable' together with CMStatus 'Disable' - configuration backup to Sophos Central depends on Sophos Central management being on, matching the web admin console. Set CMStatus to 'Enable' as well, or leave FWBackup at 'BackupDisable'."
    }

    $existing = Get-SfosCentralManagement -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetFWBackup = if ($bp.ContainsKey('FWBackup')) { $FWBackup } else { $existing.FWBackup }
    $targetJoinMethod = if ($bp.ContainsKey('JoinMethod')) { $JoinMethod } else { $existing.JoinMethod }
    $targetUseCentralReporting = if ($bp.ContainsKey('UseCentralReporting')) { $UseCentralReporting } else { $existing.UseCentralReporting }
    $targetCMStatus = if ($bp.ContainsKey('CMStatus')) { $CMStatus } else { $existing.CMStatus }

    if ($targetFWBackup -eq 'BackupEnable' -and $targetCMStatus -eq 'Disable') {
        throw "Cannot update CentralManagement: FWBackup cannot be 'BackupEnable' while CMStatus resolves to 'Disable' (the current value on the firewall, since it was not passed) - configuration backup to Sophos Central depends on Sophos Central management being on, matching the web admin console. Set CMStatus to 'Enable' as well, or leave FWBackup at 'BackupDisable'."
    }

    if (-not $PSCmdlet.ShouldProcess("CentralManagement on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <EnableCloudCentralManagement>
    <FWBackup>$(ConvertTo-SfosXmlEscaped -Text $targetFWBackup)</FWBackup>
    <JoinMethod>$(ConvertTo-SfosXmlEscaped -Text $targetJoinMethod)</JoinMethod>
    <UseCentralReporting>$(ConvertTo-SfosXmlEscaped -Text $targetUseCentralReporting)</UseCentralReporting>
    <CMStatus>$(ConvertTo-SfosXmlEscaped -Text $targetCMStatus)</CMStatus>
  </EnableCloudCentralManagement>
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
        throw "Error updating CentralManagement: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EnableCloudCentralManagement' -Action 'update'

    # The firewall answers 200 for a write it does not apply. Turning a Sophos Central
    # service off works; turning one back on is accepted, reported successful and silently
    # ignored, because a service has to be accepted in the Sophos Central console before it
    # runs. A cmdlet whose name promises the change therefore reads the object back and
    # throws instead of leaving the caller with a success that never happened.
    $applied = Get-SfosCentralManagement -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $mismatch = @(
        @{ Field = 'FWBackup'; Wanted = $targetFWBackup; Actual = [string]$applied.FWBackup }
        @{ Field = 'JoinMethod'; Wanted = $targetJoinMethod; Actual = [string]$applied.JoinMethod }
        @{ Field = 'UseCentralReporting'; Wanted = $targetUseCentralReporting; Actual = [string]$applied.UseCentralReporting }
        @{ Field = 'CMStatus'; Wanted = $targetCMStatus; Actual = [string]$applied.CMStatus }
    ) | Where-Object { $_.Wanted -ne $_.Actual }

    # A service switched on lands on the undocumented value 'WaitingForApproval' first: the
    # request was accepted and now waits for a super admin to click 'Accept services' in the
    # Sophos Central console. That is a pending request, not a failed write, so it warns.
    # Anything else that did not take effect is the silent-no-op case and throws.
    $pending = @($mismatch | Where-Object { $_.Actual -eq 'WaitingForApproval' })
    $failed = @($mismatch | Where-Object { $_.Actual -ne 'WaitingForApproval' })

    foreach ($field in $pending) {
        Write-Warning "$($field.Field) was requested as '$($field.Wanted)' and now reads 'WaitingForApproval'. The service starts once a super admin confirms it in the Sophos Central console with 'Accept services'."
    }

    if ($failed) {
        $detail = ($failed | ForEach-Object { "$($_.Field): requested '$($_.Wanted)', firewall reports '$($_.Actual)'" }) -join '; '
        throw "The firewall reported success for the CentralManagement update but did not apply it - $detail. Switching a Sophos Central service on cannot be completed through the API alone; confirm it in the Sophos Central console instead."
    }
}

#endregion
