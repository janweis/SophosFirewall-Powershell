#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Diagnostics module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all four exported functions
    with their connection parameters (order and type); Get-SfosSupportAccess parsing both
    the enabled state (ConfigOption + GrantAccessFor) and the disabled state (no duration
    element on the wire, GrantAccessFor comes back as an empty string, not null);
    Set-SfosSupportAccess always sending ConfigOption and sending GrantAccessFor only while
    the resolved state is Enable; the wire spelling GrantAccessFor (one 'r', not the
    documentation's GrantAccessForr); a Set that cannot resolve ConfigOption (existing value
    on the firewall is neither Enable nor Disable) throwing instead of sending;
    -WhatIf suppressing the write call while still allowing the read-first existence check;
    and a 501 validation failure surfacing as an exception naming the code.

    Get-SfosLog and Get-SfosLogCategory talk to the web console, not the XML API, through
    SophosFirewall.Core's Connect-SfosWebAdmin/Invoke-SfosWebAdminRequest, so Invoke-WebRequest
    is mocked in SophosFirewall.Core's scope instead of Invoke-SfosApi. Coverage:
    Get-SfosLogCategory parsing Name/Label/Condition out of the mode 5002 filter catalog;
    Get-SfosLog sending only limit/offset (offset always 0) to mode 5001 (never module or
    filter, which break the call on the appliance); -MaxRecords counting records after
    -Category/-Since are applied, widening a single request's limit fourfold (up to five
    attempts, capped at 50000) when the first request does not yield enough matches; no
    further request once the appliance returns fewer records than asked for, with a warning
    naming the shortfall; the five-attempt ceiling itself being reached and warning rather than
    retrying forever; -All requesting limit 50000 in one call and warning that the result may
    be truncated when the appliance answers with exactly that many; -All rejected together with
    -MaxRecords or with -Follow; -Category evaluating the mode 5002 condition client-side for
    AND, OR, NOT and the implicit AND between two adjacent terms; -Since comparing absolute
    instants, both for a value with an explicit zone (Kind Utc/Local, used as the instant it
    names) and for a plain Unspecified-kind value (read on the appliance's own clock, via the
    tz_offset the matching record carries) - so the appliance's time zone decides the outcome
    and not the machine running the test; a record without tz_offset falling back to offset
    zero; Datetime/DatetimeOffset being added to the default output and withheld under -AsJson;
    an empty result coming back as an empty array; a response containing 'loginstylesheet'
    failing with an error that names the session, not the HTML; and a failed console login
    (status -1) throwing with the account and the firewall named.

    Get-SfosLog -Follow: Start-Sleep is mocked in this module's scope, alongside
    Invoke-WebRequest mocked in SophosFirewall.Core's scope, so no test actually waits and
    the infinite polling loop is left by
    having the Start-Sleep mock throw after a fixed number of calls, which the test then
    expects while asserting on everything written to the pipeline before that point. Coverage:
    the current backlog is streamed first, then only newly arrived records; a record with a
    later timestamp is streamed while an unchanged backlog on the next poll streams nothing;
    the same exact raw record repeated once more on the same second streams exactly once more,
    neither zero nor two times - the main defect this mode exists to avoid; streamed output is
    chronological; -PollIntervalSeconds reaches Start-Sleep unchanged; a poll whose response
    contains 'loginstylesheet' once triggers exactly one reconnect and the same pass is
    repeated rather than lost; a poll whose standard 200-record window does not reach back to
    the last record shown widens the same single call fourfold, up to three attempts, before
    warning instead of retrying forever; and -Category keeps filtering client-side in both the
    backlog and every later poll.

    Get-SfosLog's built-in field filters (-LogType, -LogComponent, -LogSubtype, -Status, -User,
    -SourceIP, -DestinationIP, -DestinationPort, -MessageLike) match on the raw record JSON
    text before it is decoded. Coverage: an exact filter matching both wire-text spacings the
    appliance is known to use (with and without a space after the colon); -MessageLike matching
    a substring anywhere in the message field; several values on one field filter OR-combined
    while different field filters AND-combine; a dotted value such as an IP address not
    matching unrelated text of the same length, proving [regex]::Escape is applied; field
    filters widening the request together with -MaxRecords exactly like -Category; the fallback
    to decoding and comparing on the parsed object - with a Verbose message naming the field -
    when the raw-text match cannot cope with an unexpected wire form; and, directly against
    Get-SfosLogViewerRecordPage, that only the records passing the pre-filter are ever handed to
    ConvertFrom-Json, not every record the appliance returned.

    Get-SfosLog tolerates the raw syslog stream carrying entries the appliance itself leaves
    empty: a null or empty/whitespace-only entry is dropped before decoding, and an entry that
    is not valid JSON is skipped with a Verbose message rather than aborting the whole page -
    both proven by returning exactly the valid records on either side, without error.
    -MessageLike is [string[]], matching the other eight field filters: several values
    OR-combine on the message field, and -MessageLike still AND-combines with a different field
    filter such as -SourceIP.

    Every built-in field filter has an Exclude* counterpart (-ExcludeStatus, -ExcludeUser, ...):
    it removes exactly the matching records, removes all of them when given several OR-combined
    values, AND-combines with an include filter on a different field, and - the defining rule of
    negation here - never drops a record that does not carry the excluded field at all, checked
    directly against both Test-SfosLogViewerRawFieldMatch (the pre-filter) and
    Test-SfosLogViewerDecodedFieldMatch (the decode fallback). -AnyIP and -AnyPort match either
    side of a connection (src_ip/dst_ip, src_port/dst_port) and nothing else; -SourcePort -
    previously missing while -DestinationPort already existed - matches only the source side; and
    -AnyIP still AND-combines with a single-sided filter such as -DestinationPort.

    -Protocol is an exact-match field filter like the others above - including that it never
    translates between the name and number forms the appliance logs a protocol under. -Text has
    no fixed wire field: it matches when the search text is found in the VALUE of any field the
    record carries. Coverage: a match found in two different fields; ORing two values; ANDing
    with a field filter; -ExcludeText keeping a record where the text is in no field at all; and
    - the one test this filter exists for - a search term that occurs only inside a field NAME
    (such as 'port' inside dst_port) returning no records rather than every record, both on the
    live path and the same result read back through Import-SfosLog from an exported file.

    Get-SfosLog's default table/list views (SophosFirewall.Diagnostics.Format.ps1xml): the
    manifest names the format file and it is well-formed XML the module loads without error; the
    firewall table view lists exactly its nine specified columns in the specified order, checked
    against the format file itself, not the screen - that view is unchanged and kept at the
    operator's request, not migrated to the console's own (wider) Firewall layout; every other
    category's table and list views exist with the console-derived column count for that
    category, table and list agreeing; no table header in any view is wider than its own column;
    no view references packetcapturefilter (the console's Live PCAP action button, not a data
    field); a record's TypeNames carries the view matching -Category, or - without -Category - a
    single-valued -LogType normalised against the category keys, or the Sfos.Log fallback
    otherwise (including -Category all and an unmatched -LogType); -List prepends the .List
    variant of the same view; -AsJson sets no type name at all; and a record missing one of a
    view's columns (out_interface) formats without error.

    Invoke-SfosCliCommand reaches the device console, a third access path implemented in
    SophosFirewall.Core as Connect-SfosCliConsole, Send-SfosCliInput, Receive-SfosCliOutput and
    Disconnect-SfosCliConsole; those four are mocked at their call site inside this module, the
    same way Invoke-SfosApi is mocked above. Coverage: the menu navigation (sending '4' then
    Enter) runs once before the command; -SkipMenu omits it; the command's own echo and the
    trailing prompt line are stripped from the returned output; a session opened by the cmdlet
    itself is closed even when a command fails, and the failure still propagates; a session
    supplied through -CliSession is reused and left open; and -WhatIf still runs the menu
    navigation but never sends the command itself, closing its own session regardless.

    Export-SfosLog captures a Get-SfosLog read to a file; Import-SfosLog reads it back without
    contacting any firewall. Coverage: a round trip through Export/Import returns the same
    objects, field by field, that Get-SfosLog itself returns for the same raw records; an
    include filter, an exclude filter and a both-sided filter each give the same result applied
    through Import-SfosLog against a file as applied live through Get-SfosLog; refusing to
    overwrite an existing file without -Force and overwriting it with -Force; -WhatIf writing no
    file; -PassThru returning the written file; Import-SfosLog warning and naming the filters a
    file was captured with, and not warning for an unfiltered capture; and a missing, unrelated
    or unparsable file each throwing an error that names the path.

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/Context,
    never at the script's top level, following the pattern already used across this project's
    test suites.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6,
    once loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its type
    data collides with the one PS 5.1 already loaded at startup. Work around it by restricting
    $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Diagnostics.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# The device console transport (Connect-SfosCliConsole, Send-SfosCliInput, Receive-
# SfosCliOutput, Disconnect-SfosCliConsole) is being added to SophosFirewall.Core separately.
# Until that lands, this suite defines them here with the agreed signature so Invoke-
# SfosCliCommand's tests below can mock them with working parameter binding. Once Core exports
# the real functions, Get-Command finds them first and this block is skipped.
if (-not (Get-Command Connect-SfosCliConsole -ErrorAction SilentlyContinue)) {
    Write-Warning 'SophosFirewall.Core does not export the device console transport (Connect-SfosCliConsole/Send-SfosCliInput/Receive-SfosCliOutput/Disconnect-SfosCliConsole) yet - defining stand-in functions with the agreed signature for this test run.'

    function Connect-SfosCliConsole {
        param(
            [string]$Firewall,
            [int]$Port,
            [string]$Username,
            [SecureString]$Password,
            [switch]$SkipCertificateCheck,
            [object]$Session
        )
    }

    function Send-SfosCliInput {
        [CmdletBinding(DefaultParameterSetName = 'Text')]
        param(
            [Parameter(Mandatory)]
            [object]$CliSession,

            [Parameter(Mandatory, ParameterSetName = 'Text')]
            [string]$Text,

            [Parameter(Mandatory, ParameterSetName = 'Key')]
            [string]$Key
        )
    }

    function Receive-SfosCliOutput {
        param(
            [Parameter(Mandatory)]
            [object]$CliSession,

            [int]$TimeoutSeconds,

            [string]$Until
        )
    }

    function Disconnect-SfosCliConsole {
        param(
            [Parameter(Mandatory)]
            [object]$CliSession
        )
    }
}

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.Diagnostics module should load' {
        Get-Module SophosFirewall.Diagnostics | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 8 functions' {
        (Get-Module SophosFirewall.Diagnostics).ExportedFunctions.Count | Should -Be 8
    }

    It 'Manifest FunctionsToExport should list exactly 8 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 8
        @($manifest.ExportedFunctions.Keys | Sort-Object) | Should -Be @('Enter-SfosCliConsole', 'Export-SfosLog', 'Get-SfosLog', 'Get-SfosLogCategory', 'Get-SfosSupportAccess', 'Import-SfosLog', 'Invoke-SfosCliCommand', 'Set-SfosSupportAccess')
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosSupportAccess' }
    @{ Function = 'Set-SfosSupportAccess' }
    @{ Function = 'Get-SfosLog' }
    @{ Function = 'Get-SfosLogCategory' }
    @{ Function = 'Export-SfosLog' }
    @{ Function = 'Invoke-SfosCliCommand' }
    @{ Function = 'Enter-SfosCliConsole' }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with the six connection parameters, no identifying parameter' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.Diagnostics -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
        $cmd.Parameters.Keys | Should -Not -Contain 'Name'
        $cmd.Parameters.Keys | Should -Not -Contain 'NameLike'
    }

    It 'Exports <Function> with the connection parameters in the fixed order and types' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.Diagnostics

        $expectedTypes = [ordered]@{
            Firewall             = [string]
            Port                 = [int]
            Username             = [string]
            Password             = [securestring]
            SkipCertificateCheck = [switch]
            Session              = [object]
        }

        $connKeys = @($cmd.Parameters.Keys | Where-Object { $expectedTypes.Contains($_) })
        $connKeys | Should -Be @($expectedTypes.Keys)

        foreach ($name in $expectedTypes.Keys) {
            $cmd.Parameters[$name].ParameterType | Should -Be $expectedTypes[$name]
        }
    }

    It 'Set-SfosSupportAccess supports ShouldProcess' {
        $cmd = Get-Command Set-SfosSupportAccess -Module SophosFirewall.Diagnostics
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }

    It 'Invoke-SfosCliCommand supports ShouldProcess' {
        $cmd = Get-Command Invoke-SfosCliCommand -Module SophosFirewall.Diagnostics
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }

    It 'Export-SfosLog supports ShouldProcess' {
        $cmd = Get-Command Export-SfosLog -Module SophosFirewall.Diagnostics
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }

    It 'Import-SfosLog has no connection parameters - it never contacts a firewall' {
        $cmd = Get-Command Import-SfosLog -Module SophosFirewall.Diagnostics
        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Not -Contain $connParam
        }
        $cmd.Parameters.Keys | Should -Contain 'Path'
        $cmd.Parameters.Keys | Should -Contain 'SourceIP'
        $cmd.Parameters.Keys | Should -Not -Contain 'Category'
        $cmd.Parameters.Keys | Should -Not -Contain 'Since'
        $cmd.Parameters.Keys | Should -Not -Contain 'MaxRecords'
        $cmd.Parameters.Keys | Should -Not -Contain 'All'
    }
}

Describe 'Get-SfosSupportAccess' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'returns ConfigOption and GrantAccessFor while access is switched on' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Enable</ConfigOption><GrantAccessFor>1 week</GrantAccessFor></SupportAccess></Response>' }
        }

        $result = Get-SfosSupportAccess @conn

        $result.ConfigOption | Should -Be 'Enable'
        $result.GrantAccessFor | Should -Be '1 week'
    }

    It 'returns an empty GrantAccessFor - not null - while access is switched off, because the firewall omits the duration element' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Disable</ConfigOption></SupportAccess></Response>' }
        }

        $result = Get-SfosSupportAccess @conn

        $result.ConfigOption | Should -Be 'Disable'
        $result.GrantAccessFor | Should -BeOfType [string]
        $result.GrantAccessFor | Should -Be ''
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="501">Configuration parameters validation failed.</Status></SupportAccess></Response>' }
        }

        { Get-SfosSupportAccess @conn } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosSupportAccess - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        # Existing state used for calls where the resolved ConfigOption is not itself under
        # test, so the value returned by the read-first Get is irrelevant to the assertion.
        $script:DisabledArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Disable</ConfigOption></SupportAccess></Response>'
        $script:EnabledArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Enable</ConfigOption><GrantAccessFor>1 week</GrantAccessFor></SupportAccess></Response>'
        $script:UnresolvedArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption></ConfigOption></SupportAccess></Response>'
    }

    It 'sends ConfigOption and GrantAccessFor - wire name with exactly one r - while switching on' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:DisabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="200">Configuration applied successfully.</Status></SupportAccess></Response>' }
            }
        }

        Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SupportAccess>' -and
            $InnerXml -match '<ConfigOption>Enable</ConfigOption>' -and
            $InnerXml -match '<GrantAccessFor>1 day</GrantAccessFor>' -and
            $InnerXml -notmatch 'GrantAccessForr'
        }
    }

    It 'sends ConfigOption but never GrantAccessFor while switching off' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:EnabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="200">Configuration applied successfully.</Status></SupportAccess></Response>' }
            }
        }

        Set-SfosSupportAccess -ConfigOption Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ConfigOption>Disable</ConfigOption>' -and
            $InnerXml -notmatch '<GrantAccessFor>'
        }
    }

    It 'a Set without -ConfigOption against a firewall value that is neither Enable nor Disable throws instead of sending' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = $script:UnresolvedArchive }
        }

        { Set-SfosSupportAccess -GrantAccessFor '1 day' @conn -Confirm:$false } | Should -Throw '*resolved*'

        # Only the read-first existence check ran; no update was ever attempted.
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:DisabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="501">Configuration parameters validation failed.</Status></SupportAccess></Response>' }
            }
        }

        { Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check read but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = $script:DisabledArchive }
        }

        Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

# ------------------------------------------------------------------------------------------
# Get-SfosLog / Get-SfosLogCategory talk to the web console (Controller?mode=5001/5002), not
# the XML API - see this module's own findings file. The console transport itself (Connect-SfosWebAdmin,
# Invoke-SfosWebAdminRequest) lives in SophosFirewall.Core, so Invoke-WebRequest is mocked in
# Core's scope instead of Invoke-SfosApi. Every mock below distinguishes the four calls a
# console session makes (root GET, mode=151 login POST, index.jsp GET for the CSRF token, and
# the mode=5001/5002 data POST) by $Uri/$Body, since none of the tests below care about the
# session cookie or CSRF token themselves.

Describe 'Get-SfosLogCategory' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        # Single-quoted token text concatenated in, not interpolated - '$rFt0k3n' inside a
        # double-quoted string would otherwise be read as a (nonexistent) variable reference.
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'returns Name, Label and Condition parsed from the mode 5002 filter catalog' {
        $script:CatalogJson = @{
            filter = @{
                module = @{
                    val = @{
                        all      = @{ label = 'All' }
                        firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                    }
                }
            }
        } | ConvertTo-Json -Depth 8 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson }
            }
            if ($Uri -like '*/webconsole/webpages/index.jsp') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml }
            }
            if ($Body -like 'mode=5002*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLogCategory @conn

        $all = $result | Where-Object Name -eq 'all'
        $all.Label | Should -Be 'All'
        $all.Condition | Should -BeNullOrEmpty

        $firewall = $result | Where-Object Name -eq 'firewall'
        $firewall.Label | Should -Be 'Firewall'
        $firewall.Condition | Should -Be '( "log_type=Firewall" )'
    }

    It 'throws naming the account and the firewall when the console login answers status -1' {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = '{"status":-1}' }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $thrown = $null
        try { Get-SfosLogCategory @conn } catch { $thrown = $_ }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -BeLike "*$($conn.Username)*"
        $thrown.Exception.Message | Should -BeLike "*$($conn.Firewall)*"
    }
}

Describe 'Get-SfosLog' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'sends only limit and offset to mode 5001 - never module or filter, which break the call on the appliance' {
        $recordsJson = @((@{ log_type = 'Firewall' } | ConvertTo-Json -Compress))
        $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $recordsJson } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson }
            }
            if ($Uri -like '*/webconsole/webpages/index.jsp') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml }
            }
            if ($Body -like 'mode=5001*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        Get-SfosLog @conn | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            if ($Body -notlike 'mode=5001*') { return $false }
            $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
            $props = @($bodyObj.PSObject.Properties.Name | Sort-Object)
            ($props -join ',') -eq 'limit,offset'
        }
    }

    It 'widens the request with a larger limit until -MaxRecords filtered records are found, when a filter thins the raw records' {
        # Every 10th raw record matches the 'firewall' category; -MaxRecords 100 therefore
        # cannot be satisfied by the first (limit 100) request and needs a wider one.
        $script:CatalogJson = @{
            filter = @{ module = @{ val = @{
                            firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                        } } }
        } | ConvertTo-Json -Depth 8 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                $limit = [int]$bodyObj.limit
                $records = @(1..$limit | ForEach-Object {
                        $type = if ($_ % 10 -eq 0) { 'Firewall' } else { 'IPS' }
                        @{ id = $_; log_type = $type } | ConvertTo-Json -Compress
                    })
                $page = @{ status = 200; limit = $limit; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
                return [PSCustomObject]@{ StatusCode = 200; Content = $page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Category firewall -MaxRecords 100 @conn -AsJson

        @($result).Count | Should -Be 100
        @($result | Where-Object { $_.log_type -ne 'Firewall' }) | Should -BeNullOrEmpty

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 100
        }
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 400
        }
    }

    It 'does not ask again when the appliance returns fewer records than requested, and warns that fewer were found' {
        $records = @(1..5 | ForEach-Object { @{ id = $_ } | ConvertTo-Json -Compress })
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson }
            }
            if ($Uri -like '*/webconsole/webpages/index.jsp') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml }
            }
            if ($Body -like 'mode=5001*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $warnings = $null
        $result = Get-SfosLog @conn -AsJson -WarningVariable warnings -WarningAction SilentlyContinue

        @($result).Count | Should -Be 5
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*'
        }
        $warnings | Should -Not -BeNullOrEmpty
        "$warnings" | Should -BeLike '*5*'
    }

    It 'stops after five attempts widening the limit and warns instead of retrying forever, when a filter never matches' {
        $script:CatalogJson = @{
            filter = @{ module = @{ val = @{
                            firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                        } } }
        } | ConvertTo-Json -Depth 8 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                $limit = [int]$bodyObj.limit
                # Every record is IPS - the 'firewall' condition never matches, so the request
                # never gets enough hits and this appliance never runs out either (always
                # returns exactly the requested limit).
                $records = @(1..$limit | ForEach-Object { @{ id = $_; log_type = 'IPS' } | ConvertTo-Json -Compress })
                $page = @{ status = 200; limit = $limit; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
                return [PSCustomObject]@{ StatusCode = 200; Content = $page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $warnings = $null
        $result = Get-SfosLog -Category firewall -MaxRecords 100 @conn -AsJson -WarningVariable warnings -WarningAction SilentlyContinue

        @($result).Count | Should -Be 0
        $warnings | Should -Not -BeNullOrEmpty

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 5 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*'
        }
    }

    It 'stops paging and returns an empty array, not null, when the appliance answers with no records' {
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = @() } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson }
            }
            if ($Uri -like '*/webconsole/webpages/index.jsp') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml }
            }
            if ($Body -like 'mode=5001*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog @conn

        @($result).Count | Should -Be 0
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*'
        }
    }

    Context '-All' {

        It 'requests limit 50000 in a single call' {
            $records = @(1..10 | ForEach-Object { @{ id = $_ } | ConvertTo-Json -Compress })
            $script:Page = @{ status = 200; limit = 50000; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -All @conn -AsJson

            @($result).Count | Should -Be 10
            Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
                $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 50000
            }
        }

        It 'warns that the result may be truncated when the appliance answers with exactly 50000 records' {
            $records = @(1..50000 | ForEach-Object { @{ id = $_ } | ConvertTo-Json -Compress })
            $script:Page = @{ status = 200; limit = 50000; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $warnings = $null
            $result = Get-SfosLog -All @conn -AsJson -WarningVariable warnings -WarningAction SilentlyContinue

            @($result).Count | Should -Be 50000
            $warnings | Should -Not -BeNullOrEmpty
            "$warnings" | Should -BeLike '*truncat*'
        }

        It 'throws when combined with -MaxRecords' {
            $thrown = $null
            try { Get-SfosLog -All -MaxRecords 50 @conn } catch { $thrown = $_ }

            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*All*'
            $thrown.Exception.Message | Should -BeLike '*MaxRecords*'
        }

        It 'throws when combined with -Follow' {
            $thrown = $null
            try { Get-SfosLog -All -Follow @conn } catch { $thrown = $_ }

            $thrown | Should -Not -BeNullOrEmpty
            $thrown.Exception.Message | Should -BeLike '*All*'
            $thrown.Exception.Message | Should -BeLike '*Follow*'
        }
    }

    Context '-Category evaluates the mode 5002 condition client-side' {

        It 'AND: keeps only records where every operand holds' {
            $records = @(
                (@{ log_type = 'Firewall'; log_subtype = 'Admin' } | ConvertTo-Json -Compress),
                (@{ log_type = 'Firewall'; log_subtype = 'System' } | ConvertTo-Json -Compress)
            )
            $script:Page = @{ status = 200; limit = 200; offset = 2; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
            $script:CatalogJson = @{
                filter = @{ module = @{ val = @{
                            firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" AND "log_subtype=Admin" )' }
                        } } }
            } | ConvertTo-Json -Depth 8 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category firewall @conn -AsJson

            @($result).Count | Should -Be 1
            $result[0].log_subtype | Should -Be 'Admin'
        }

        It 'OR: keeps a record when either operand holds' {
            $records = @(
                (@{ log_type = 'Firewall' } | ConvertTo-Json -Compress),
                (@{ log_type = 'IPS' } | ConvertTo-Json -Compress),
                (@{ log_type = 'Web' } | ConvertTo-Json -Compress)
            )
            $script:Page = @{ status = 200; limit = 200; offset = 3; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
            $script:CatalogJson = @{
                filter = @{ module = @{ val = @{
                            vpn = @{ label = 'VPN'; condition = '( "log_type=Firewall" OR "log_type=IPS" )' }
                        } } }
            } | ConvertTo-Json -Depth 8 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category vpn @conn -AsJson

            @($result).Count | Should -Be 2
            @($result.log_type | Sort-Object) | Should -Be @('Firewall', 'IPS')
        }

        It 'NOT: excludes the negated operand' {
            $records = @(
                (@{ log_type = 'IPS' } | ConvertTo-Json -Compress),
                (@{ log_type = 'Firewall' } | ConvertTo-Json -Compress)
            )
            $script:Page = @{ status = 200; limit = 200; offset = 2; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
            $script:CatalogJson = @{
                filter = @{ module = @{ val = @{
                            ips = @{ label = 'IPS'; condition = 'NOT ( "log_type=IPS" )' }
                        } } }
            } | ConvertTo-Json -Depth 8 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category ips @conn -AsJson

            @($result).Count | Should -Be 1
            $result[0].log_type | Should -Be 'Firewall'
        }

        It 'implicit AND: two terms with no operator between them both have to hold' {
            $records = @(
                (@{ log_subtype = 'System'; log_type = 'Firewall' } | ConvertTo-Json -Compress),
                (@{ log_subtype = 'System'; log_type = 'VPN' } | ConvertTo-Json -Compress),
                (@{ log_subtype = 'Admin'; log_type = 'Firewall' } | ConvertTo-Json -Compress)
            )
            $script:Page = @{ status = 200; limit = 200; offset = 3; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
            $script:CatalogJson = @{
                filter = @{ module = @{ val = @{
                            system = @{ label = 'System'; condition = '"log_subtype=System" "log_type=Firewall"' }
                        } } }
            } | ConvertTo-Json -Depth 8 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category system @conn -AsJson

            @($result).Count | Should -Be 1
            $result[0].log_subtype | Should -Be 'System'
            $result[0].log_type | Should -Be 'Firewall'
        }
    }

    Context '-Since with an explicit zone (Kind Utc/Local, or a DateTimeOffset) is used as the absolute instant it names' {

        BeforeEach {
            # 2026-08-20 17:21:52 UTC. Kind is explicitly Utc, so this is never reinterpreted
            # onto the appliance's own clock - unlike an Unspecified-kind value (see the next
            # Context), an explicit zone already names one unambiguous instant.
            $script:Since = [datetime]::new(2026, 8, 20, 17, 21, 52, [DateTimeKind]::Utc)
        }

        It 'includes a record one second inside the cutoff, at appliance-local time with tz_offset +0200' {
            $records = @((@{ id = 'inside'; datetime = '2026-08-20 19:21:53'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Since $script:Since @conn -AsJson

            @($result).Count | Should -Be 1
            $result[0].id | Should -Be 'inside'
        }

        It 'excludes a record one second outside the cutoff, at appliance-local time with tz_offset +0200' {
            $records = @((@{ id = 'outside'; datetime = '2026-08-20 19:21:51'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Since $script:Since @conn -AsJson

            @($result).Count | Should -Be 0
        }
    }

    Context '-Since without a zone (Kind Unspecified) is read on the appliance''s own clock' {

        It 'includes a record whose appliance-local time is one second inside a naive cutoff, offset taken from the record''s own tz_offset' {
            # No Kind specified - the shape a caller gets by copying a timestamp out of the log
            # viewer or writing '2026-08-20 19:21:52' by hand. Read as the appliance's own wall
            # clock, using the +0200 the matching record carries - not the machine's local zone.
            $since = [datetime]::new(2026, 8, 20, 19, 21, 52)
            $records = @((@{ id = 'inside'; datetime = '2026-08-20 19:21:53'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Since $since @conn -AsJson

            @($result).Count | Should -Be 1
            $result[0].id | Should -Be 'inside'
        }

        It 'excludes a record whose appliance-local time is one second outside a naive cutoff, offset taken from the record''s own tz_offset' {
            $since = [datetime]::new(2026, 8, 20, 19, 21, 52)
            $records = @((@{ id = 'outside'; datetime = '2026-08-20 19:21:51'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Since $since @conn -AsJson

            @($result).Count | Should -Be 0
        }
    }

    It 'exposes Datetime ([datetime]) and DatetimeOffset ([datetimeoffset]), derived from the record''s own tz_offset' {
        $records = @((@{ id = 'r1'; datetime = '2026-08-20 19:21:53'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
        $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog @conn

        @($result).Count | Should -Be 1
        $result[0].Datetime | Should -BeOfType [datetime]
        $result[0].Datetime | Should -Be ([datetime]'2026-08-20 19:21:53')
        $result[0].DatetimeOffset | Should -BeOfType [datetimeoffset]
        $result[0].DatetimeOffset.Offset | Should -Be ([timespan]::new(2, 0, 0))
    }

    It 'falls back to offset zero for a record without tz_offset' {
        $records = @((@{ id = 'r1'; datetime = '2026-08-20 19:21:53' } | ConvertTo-Json -Compress))
        $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog @conn

        @($result).Count | Should -Be 1
        $result[0].DatetimeOffset.Offset | Should -Be ([timespan]::Zero)
    }

    It 'ConvertTo-SfosLogInstant still returns the record''s instant, not $null, once the record has already been formatted' {
        # Regression coverage for the Get-SfosLog -Follow defect: Format-SfosLogViewerRecord
        # renames a record's 'datetime' string to 'Datetime' (a [datetime]) in place, and a
        # naive re-parse of that value against the fixed 'yyyy-MM-dd HH:mm:ss' string format
        # then fails and returns $null. The record used here is not hand-built - it is a real
        # Datetime/DatetimeOffset pair obtained through the public Get-SfosLog call, so the
        # types are exactly what Format-SfosLogViewerRecord actually produces.
        $records = @((@{ id = 'r1'; datetime = '2026-08-20 19:21:53'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
        $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $formatted = Get-SfosLog @conn
        $formatted.Datetime | Should -BeOfType [datetime]
        $formatted.DatetimeOffset | Should -BeOfType [datetimeoffset]

        $instant = InModuleScope SophosFirewall.Diagnostics -Parameters @{ Record = $formatted } {
            param($Record)
            ConvertTo-SfosLogInstant -Record $Record
        }

        $instant | Should -Not -BeNullOrEmpty
        $instant | Should -Be $formatted.DatetimeOffset
    }

    It '-AsJson does not add Datetime or DatetimeOffset - the record keeps its own string ''datetime'' field, unparsed' {
        $records = @((@{ id = 'r1'; datetime = '2026-08-20 19:21:53'; tz_offset = '+0200' } | ConvertTo-Json -Compress))
        $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog @conn -AsJson

        @($result).Count | Should -Be 1
        # Property names are case-insensitive, so -Contains 'Datetime' would also match the
        # original lowercase 'datetime' field and prove nothing; check the type and the exact
        # property set instead.
        $result[0].datetime | Should -BeOfType [string]
        $result[0].PSObject.Properties.Match('DatetimeOffset').Count | Should -Be 0
        @($result[0].PSObject.Properties.Name | Sort-Object) | Should -Be @('datetime', 'id', 'tz_offset')
    }

    It 'throws pointing at the missing session instead of returning the login page as data' {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson }
            }
            if ($Uri -like '*/webconsole/webpages/index.jsp') {
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml }
            }
            if ($Body -like 'mode=5001*') {
                return [PSCustomObject]@{ StatusCode = 200; Content = '<html><head><link rel="stylesheet" href="loginstylesheet.css"></head></html>' }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $thrown = $null
        try { Get-SfosLog @conn } catch { $thrown = $_ }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -BeLike '*session*'
        $thrown.Exception.Message | Should -Not -BeLike '*<html*'
    }
}

# ------------------------------------------------------------------------------------------
# Get-SfosLog -Follow never returns on its own, so every test here stops the loop by having
# the Start-Sleep mock throw after a fixed number of calls, wraps the call in try/catch, and
# asserts on whatever was already written to the pipeline before that exception - collected
# with ForEach-Object so streaming, not just the final result, is what gets checked. Start-Sleep
# is mocked in this module's scope exactly like Invoke-WebRequest.

Describe 'Get-SfosLog -Follow' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    BeforeEach {
        $script:SleepCalls = 0
    }

    It 'streams the current backlog first, then only records that arrived afterwards' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 1; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        $poll = @(
            (@{ id = 'r2'; datetime = '2026-08-20 10:00:05' } | ConvertTo-Json -Compress),
            (@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress)
        )
        $script:PollPage = @{ status = 200; limit = 200; offset = 2; syslog = $poll } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        $thrown = $null
        try {
            Get-SfosLog @conn -Follow -PollIntervalSeconds 5 -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch { $thrown = $_ }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -BeLike '*stop-follow-loop*'

        @($results).Count | Should -Be 2
        $results[0].id | Should -Be 'r1'
        $results[1].id | Should -Be 'r2'
    }

    It 'anchors on the backlog before formatting mutates the record, so a poll carrying only older records stays empty' {
        # Regression test for a live-only defect: the anchor used to be computed AFTER the
        # backlog's foreach output loop. Format-SfosLogViewerRecord renames a record's
        # 'datetime' string property to 'Datetime' (a [datetime]) in place, so with that
        # ordering ConvertTo-SfosLogInstant read the anchor off already-mutated records. On the
        # live appliance this produced a $null anchor, and a $null anchor makes every record in
        # the next poll look new - 205 old records were replayed after a backlog of 3. This
        # test is intentionally run without -AsJson, because -AsJson is exactly the path that
        # skips the mutation and would not have caught the defect.
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        # syslog arrives newest first, offset increasing further into the past - the same
        # order every other test in this file uses, and the order the real appliance answers.
        $backlog = @(
            (@{ id = 'r3'; datetime = '2026-08-20 15:30:00' } | ConvertTo-Json -Compress),
            (@{ id = 'r2'; datetime = '2026-08-20 15:18:00' } | ConvertTo-Json -Compress),
            (@{ id = 'r1'; datetime = '2026-08-20 15:06:00' } | ConvertTo-Json -Compress)
        )
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 3; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        # Every record in this poll page is older than r3 (2026-08-20 15:30:00), the backlog's
        # newest and therefore the anchor. With a correctly computed anchor none of these count
        # as new; with the defect's $null anchor, all of them would have been replayed.
        $pollOlder = @(
            (@{ id = 'old2'; datetime = '2026-08-20 14:54:00' } | ConvertTo-Json -Compress),
            (@{ id = 'old1'; datetime = '2026-08-20 14:42:00' } | ConvertTo-Json -Compress)
        )
        $script:PollPage = @{ status = 200; limit = 200; offset = 2; syslog = $pollOlder } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog @conn -Follow | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results).Count | Should -Be 3
        @($results.id) | Should -Be @('r1', 'r2', 'r3')
    }

    It 'streams nothing on a poll where the backlog is unchanged' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:UnchangedPage = @{ status = 200; limit = 200; offset = 1; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:UnchangedPage } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog @conn -Follow -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results).Count | Should -Be 1
        $results[0].id | Should -Be 'r1'
    }

    It 'streams exactly one more copy of a raw record repeated once more on the same second - not zero, not two' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $raw1 = (@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress)
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 1; syslog = @($raw1) } | ConvertTo-Json -Depth 5 -Compress
        $script:PollPage = @{ status = 200; limit = 200; offset = 2; syslog = @($raw1, $raw1) } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog @conn -Follow -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results).Count | Should -Be 2
        $results[0].id | Should -Be 'r1'
        $results[1].id | Should -Be 'r1'
    }

    It 'streams records in chronological order, oldest first' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 1; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        # Server order is newest first - r4, r3, r2 - the reverse of the chronological order
        # the test expects on the pipeline.
        $poll = @(
            (@{ id = 'r4'; datetime = '2026-08-20 10:00:30' } | ConvertTo-Json -Compress),
            (@{ id = 'r3'; datetime = '2026-08-20 10:00:20' } | ConvertTo-Json -Compress),
            (@{ id = 'r2'; datetime = '2026-08-20 10:00:10' } | ConvertTo-Json -Compress)
        )
        $script:PollPage = @{ status = 200; limit = 200; offset = 3; syslog = $poll } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog @conn -Follow -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results.id) | Should -Be @('r1', 'r2', 'r3', 'r4')
    }

    It 'passes -PollIntervalSeconds through to Start-Sleep unchanged' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith { throw 'stop-follow-loop' }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 1; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        try { Get-SfosLog @conn -Follow -PollIntervalSeconds 7 -AsJson | Out-Null } catch {}

        Should -Invoke -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $Seconds -eq 7
        }
    }

    It 'reconnects once and repeats the pass when a poll finds the session discarded' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 1; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        $poll = @((@{ id = 'r2'; datetime = '2026-08-20 10:00:05' } | ConvertTo-Json -Compress))
        $script:PollPage = @{ status = 200; limit = 200; offset = 1; syslog = $poll } | ConvertTo-Json -Depth 5 -Compress
        $script:LoginPageHtml = '<html><head><link rel="stylesheet" href="loginstylesheet.css"></head></html>'

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                if ($script:Mode5001Calls -eq 2) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginPageHtml } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog @conn -Follow -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results).Count | Should -Be 2
        $results[1].id | Should -Be 'r2'

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 2 -Exactly -ParameterFilter {
            $Body -like 'mode=151*'
        }
    }

    It 'widens the polling window with a larger limit when the standard window does not bridge the gap, and warns after three attempts' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $backlog = @((@{ id = 'r1'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress))
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 0; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) {
                    return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage }
                }
                # Every record - at every widened limit - shares one timestamp a second after the
                # backlog's r1, so the oldest record the call returns always still looks newer
                # than the last one shown, and the poll never finds its own reason to stop
                # widening: the retry ceiling is the only thing that ends it.
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                $limit = [int]$bodyObj.limit
                $records = @(1..$limit | ForEach-Object { @{ id = "n$_"; datetime = '2026-08-20 10:00:01' } | ConvertTo-Json -Compress })
                $page = @{ status = 200; limit = $limit; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
                return [PSCustomObject]@{ StatusCode = 200; Content = $page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $warnings = $null
        try {
            Get-SfosLog @conn -Follow -AsJson -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        }
        catch {}

        $warnings | Should -Not -BeNullOrEmpty
        "$warnings" | Should -BeLike '*three*'

        # 1 backlog call + 3 poll attempts (limit 200, then 800, then 3200)
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 4 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*'
        }
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 3200
        }
    }

    It '-Category keeps filtering client-side in the backlog and in every later poll' {
        Mock -CommandName Start-Sleep -ModuleName SophosFirewall.Diagnostics -MockWith {
            $script:SleepCalls++
            if ($script:SleepCalls -gt 1) { throw 'stop-follow-loop' }
        }

        $script:CatalogJson = @{
            filter = @{ module = @{ val = @{
                            firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                        } } }
        } | ConvertTo-Json -Depth 8 -Compress

        $backlog = @(
            (@{ id = 'match1'; log_type = 'Firewall'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress),
            (@{ id = 'nomatch1'; log_type = 'IPS'; datetime = '2026-08-20 10:00:00' } | ConvertTo-Json -Compress)
        )
        $script:BacklogPage = @{ status = 200; limit = 200; offset = 2; syslog = $backlog } | ConvertTo-Json -Depth 5 -Compress

        $poll = @(
            (@{ id = 'nomatch2'; log_type = 'IPS'; datetime = '2026-08-20 10:00:05' } | ConvertTo-Json -Compress),
            (@{ id = 'match2'; log_type = 'Firewall'; datetime = '2026-08-20 10:00:05' } | ConvertTo-Json -Compress)
        )
        $script:PollPage = @{ status = 200; limit = 200; offset = 2; syslog = $poll } | ConvertTo-Json -Depth 5 -Compress

        $script:Mode5001Calls = 0
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
            if ($Body -like 'mode=5001*') {
                $script:Mode5001Calls++
                if ($script:Mode5001Calls -eq 1) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:BacklogPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:PollPage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $results = [System.Collections.Generic.List[object]]::new()
        try {
            Get-SfosLog -Category firewall @conn -Follow -AsJson | ForEach-Object { $results.Add($_) }
        }
        catch {}

        @($results.id) | Should -Be @('match1', 'match2')
    }
}

# ------------------------------------------------------------------------------------------
# The built-in field filters (-LogType, -LogComponent, -LogSubtype, -Status, -User, -SourceIP,
# -DestinationIP, -DestinationPort, -MessageLike) match on the raw record JSON text, before
# ConvertFrom-Json runs - see this module's own findings file for the measured cost this avoids.

Describe 'Get-SfosLog field filters' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'LogType filters to an exact match, matching both wire-text spacings the appliance is known to use' {
        $records = @(
            (@{ id = 1; log_type = 'Firewall' } | ConvertTo-Json -Compress),  # no space after the colon
            '{"id": 2, "log_type": "Firewall"}',                             # space after the colon
            (@{ id = 3; log_type = 'IPS' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -LogType Firewall @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'MessageLike matches a substring anywhere in the message field, on the raw record text' {
        $records = @(
            (@{ id = 1; message = 'connection timeout on port 443' } | ConvertTo-Json -Compress),
            '{"id": 2, "message": "authentication timeout for user admin"}',
            (@{ id = 3; message = 'clean shutdown' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -MessageLike 'timeout' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'ORs several values on one field filter and ANDs different field filters, never accumulating into an OR' {
        $records = @(
            (@{ id = 1; log_type = 'Firewall'; status = 'Deny' } | ConvertTo-Json -Compress),  # LogType OR hit, Status hit -> kept
            (@{ id = 2; log_type = 'IPS'; status = 'Deny' } | ConvertTo-Json -Compress),  # LogType OR hit, Status hit -> kept
            (@{ id = 3; log_type = 'Firewall'; status = 'Allow' } | ConvertTo-Json -Compress),  # LogType hit, Status miss -> dropped
            (@{ id = 4; log_type = 'WAF'; status = 'Deny' } | ConvertTo-Json -Compress)   # LogType miss -> dropped
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -LogType Firewall, IPS -Status Deny @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'escapes special regex characters in the filter value, so a dotted IP address does not match unrelated text of the same length' {
        $records = @(
            (@{ id = 1; src_ip = '192.0.2.10' } | ConvertTo-Json -Compress),    # the exact value - should match
            (@{ id = 2; src_ip = 'X92X0X2X10' } | ConvertTo-Json -Compress)     # same length, dots replaced - must NOT match
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -SourceIP '192.0.2.10' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }

    It 'falls back to decoding and comparing on the parsed object, with a Verbose message, when the raw-text pre-filter cannot match an unexpected wire form' {
        # dst_port sent as an unquoted JSON number: the raw-text pre-filter expects a quoted
        # string value and cannot match this, even though the "dst_port" key is present.
        $records = @('{"id":1,"dst_port":8080}', '{"id":2,"dst_port":9090}')
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $allOutput = Get-SfosLog -DestinationPort '8080' @conn -AsJson -Verbose -WarningAction SilentlyContinue 4>&1
        $verboseMessages = @($allOutput | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $result = @($allOutput | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] })

        @($result.id) | Should -Be @(1)
        ($verboseMessages -join ' ') | Should -BeLike '*pre-filter*'
        ($verboseMessages -join ' ') | Should -BeLike '*dst_port*'
    }

    It 'widens the request together with -MaxRecords, exactly like -Category, when a field filter thins the raw records' {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                $limit = [int]$bodyObj.limit
                # Every 10th raw record matches - MaxRecords 100 cannot be satisfied by the
                # first (limit 100) request and needs a wider one, same as the -Category test.
                $records = @(1..$limit | ForEach-Object {
                        $type = if ($_ % 10 -eq 0) { 'Firewall' } else { 'IPS' }
                        @{ id = $_; log_type = $type } | ConvertTo-Json -Compress
                    })
                $page = @{ status = 200; limit = $limit; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress
                return [PSCustomObject]@{ StatusCode = 200; Content = $page }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -LogType Firewall -MaxRecords 100 @conn -AsJson

        @($result).Count | Should -Be 100
        @($result | Where-Object { $_.log_type -ne 'Firewall' }) | Should -BeNullOrEmpty

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 100
        }
        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'mode=5001*' -and ([uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json).limit -eq 400
        }
    }

    It 'decodes only the records that pass the raw-text pre-filter, not every fetched record' {
        InModuleScope SophosFirewall.Diagnostics {
            $records = @(1..40 | ForEach-Object {
                    $type = if ($_ % 4 -eq 0) { 'Firewall' } else { 'IPS' }
                    @{ id = $_; log_type = $type } | ConvertTo-Json -Compress
                })

            Mock -CommandName Invoke-SfosWebAdminRequest -MockWith {
                [PSCustomObject]@{ syslog = $records }
            }

            $script:ConvertFromJsonCalls = 0
            Mock -CommandName ConvertFrom-Json -MockWith {
                $script:ConvertFromJsonCalls++
                $Input | Microsoft.PowerShell.Utility\ConvertFrom-Json
            }

            $fieldFilter = Get-SfosLogViewerFieldFilter -BoundParameters @{ LogType = @('Firewall') }
            $page = Get-SfosLogViewerRecordPage -LogViewerConsole ([PSCustomObject]@{}) -Take 200 -FieldFilter $fieldFilter

            # 10 of the 40 raw records match (every 4th) - only those 10 are decoded, not all 40.
            $page.Pairs.Count | Should -Be 10
            $page.FetchedCount | Should -Be 40
            $script:ConvertFromJsonCalls | Should -Be 10
        }
    }

    Context 'Default table/list views (Format.ps1xml)' {

        BeforeAll {
            $conn = @{
                Firewall = '192.0.2.1'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }

            $script:LoginOkJson = '{"status":200}'
            $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"

            $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
            $script:FormatXmlPath = Join-Path $modulesDir 'SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.Format.ps1xml'
            $script:DiagManifestPath = Join-Path $modulesDir 'SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.psd1'

            $script:CatalogJson = @{
                filter = @{ module = @{ val = @{
                                firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                            } } }
            } | ConvertTo-Json -Depth 8 -Compress
        }

        It 'manifest lists the format file, and the file is well-formed XML that Import-Module loads without error' {
            $manifest = Import-PowerShellDataFile $script:DiagManifestPath
            $manifest.FormatsToProcess | Should -Contain 'SophosFirewall.Diagnostics.Format.ps1xml'

            Test-Path $script:FormatXmlPath | Should -BeTrue
            { [xml](Get-Content -Path $script:FormatXmlPath -Raw) } | Should -Not -Throw

            # The module under test is already imported (top of this file) - if the format file
            # failed to load, that Import-Module would already have thrown.
            Get-Module SophosFirewall.Diagnostics | Should -Not -BeNullOrEmpty
        }

        It 'the firewall table view lists exactly the nine specified columns, in order - checked against the format file, not the screen' {
            [xml]$formatXml = Get-Content -Path $script:FormatXmlPath -Raw
            $view = $formatXml.Configuration.ViewDefinitions.View | Where-Object { $_.Name -eq 'Sfos.Log.Firewall' }
            $view | Should -Not -BeNullOrEmpty

            # The columns are the properties, not the headers: a header is only a caption and may
            # be shortened so it fits, which is what the width check below guards.
            $columns = @($view.TableControl.TableRowEntries.TableRowEntry.TableColumnItems.TableColumnItem.PropertyName)
            $columns | Should -Be @('Datetime', 'log_component', 'log_subtype', 'in_interface', 'src_ip', 'src_port', 'out_interface', 'dst_ip', 'dst_port')
        }

        It 'no table header in any view is wider than its own column, so the header row cannot wrap' {
            [xml]$formatXml = Get-Content -Path $script:FormatXmlPath -Raw
            $views = @($formatXml.Configuration.ViewDefinitions.View | Where-Object { $_.TableControl })
            $views.Count | Should -BeGreaterThan 0

            foreach ($view in $views) {
                $headers = @($view.TableControl.TableHeaders.TableColumnHeader)
                foreach ($header in $headers) {
                    $width = [int]$header.Width
                    if ($width -le 0) { continue }
                    ([string]$header.Label).Length | Should -BeLessOrEqual $width -Because "in $($view.Name), the header '$($header.Label)' has to fit into its $width-character column"
                }
            }
        }

        It 'no view - table or list - references packetcapturefilter, the console''s Live PCAP action button, not a data field' {
            [xml]$formatXml = Get-Content -Path $script:FormatXmlPath -Raw
            $tableProps = @($formatXml.Configuration.ViewDefinitions.View.TableControl.TableRowEntries.TableRowEntry.TableColumnItems.TableColumnItem.PropertyName)
            $listProps = @($formatXml.Configuration.ViewDefinitions.View.ListControl.ListEntries.ListEntry.ListItems.ListItem.PropertyName)

            $tableProps | Should -Not -Contain 'packetcapturefilter'
            $listProps | Should -Not -Contain 'packetcapturefilter'
        }

        $script:CategoryColumnCountCases = @(
            @{ ViewName = 'Sfos.Log.Webfilter'; ExpectedCount = 12 }
            @{ ViewName = 'Sfos.Log.Admin'; ExpectedCount = 7 }
            @{ ViewName = 'Sfos.Log.Ips'; ExpectedCount = 13 }
            @{ ViewName = 'Sfos.Log.Vpn'; ExpectedCount = 7 }
            @{ ViewName = 'Sfos.Log.System'; ExpectedCount = 6 }
            @{ ViewName = 'Sfos.Log.Authentication'; ExpectedCount = 9 }
            @{ ViewName = 'Sfos.Log.Malware'; ExpectedCount = 9 }
            @{ ViewName = 'Sfos.Log.Atp'; ExpectedCount = 12 }
            @{ ViewName = 'Sfos.Log.Sandbox'; ExpectedCount = 9 }
            @{ ViewName = 'Sfos.Log.Heartbeat'; ExpectedCount = 5 }
            @{ ViewName = 'Sfos.Log.Ssltls'; ExpectedCount = 14 }
            @{ ViewName = 'Sfos.Log.Waf'; ExpectedCount = 11 }
            @{ ViewName = 'Sfos.Log.Email'; ExpectedCount = 11 }
            @{ ViewName = 'Sfos.Log.Sdwan'; ExpectedCount = 8 }
            @{ ViewName = 'Sfos.Log.Applicationfilter'; ExpectedCount = 9 }
            @{ ViewName = 'Sfos.Log.Webcontentpolicy'; ExpectedCount = 10 }
        )

        It '<ViewName> table view exists with its console-derived column count' -TestCases $script:CategoryColumnCountCases {
            param($ViewName, $ExpectedCount)

            [xml]$formatXml = Get-Content -Path $script:FormatXmlPath -Raw
            $view = $formatXml.Configuration.ViewDefinitions.View | Where-Object { $_.Name -eq $ViewName }
            $view | Should -Not -BeNullOrEmpty -Because "$ViewName should have a table view"

            $columns = @($view.TableControl.TableRowEntries.TableRowEntry.TableColumnItems.TableColumnItem.PropertyName)
            $columns.Count | Should -Be $ExpectedCount

            $listView = $formatXml.Configuration.ViewDefinitions.View | Where-Object { $_.Name -eq "$ViewName.List" }
            $listView | Should -Not -BeNullOrEmpty -Because "$ViewName.List should have a list view"
            $listColumns = @($listView.ListControl.ListEntries.ListEntry.ListItems.ListItem.PropertyName)
            $listColumns.Count | Should -Be $ExpectedCount
        }

        It 'a record from -Category firewall carries Sfos.Log.Firewall first in TypeNames, and Sfos.Log.Firewall.List with -List' {
            $records = @((@{ id = 'r1'; log_type = 'Firewall'; src_ip = '192.0.2.10' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category firewall @conn
            @($result).Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log.Firewall'

            $listResult = Get-SfosLog -Category firewall -List @conn
            @($listResult).Count | Should -Be 1
            $listResult[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log.Firewall.List'
        }

        It 'a single-valued -LogType Firewall selects the same view as -Category firewall, without -Category being bound' {
            $records = @((@{ id = 'r1'; log_type = 'Firewall' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -LogType Firewall @conn
            @($result).Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log.Firewall'
        }

        It 'falls back to Sfos.Log when neither -Category nor a single-valued -LogType was bound' {
            $records = @((@{ id = 'r1'; log_type = 'Event' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog @conn
            @($result).Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log'
        }

        It 'falls back to Sfos.Log for -Category all, and for a -LogType value matching no category' {
            $records = @((@{ id = 'r1'; log_type = 'Nonsense' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $resultAll = Get-SfosLog -Category all @conn
            @($resultAll).Count | Should -Be 1
            $resultAll[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log'

            $resultUnmatched = Get-SfosLog -LogType 'Nonsense' @conn
            @($resultUnmatched).Count | Should -Be 1
            $resultUnmatched[0].PSObject.TypeNames[0] | Should -Be 'Sfos.Log'
        }

        It '-AsJson sets no type name - the record keeps the default PSCustomObject type' {
            $records = @((@{ id = 'r1'; log_type = 'Firewall' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category firewall @conn -AsJson
            @($result).Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'System.Management.Automation.PSCustomObject'
        }

        It 'a record missing out_interface does not throw when formatted' {
            $records = @((@{ id = 'r1'; log_type = 'Firewall'; src_ip = '192.0.2.10'; dst_ip = '192.0.2.20' } | ConvertTo-Json -Compress))
            $script:Page = @{ status = 200; limit = 200; offset = 1; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }

            $result = Get-SfosLog -Category firewall @conn
            { $result | Out-String } | Should -Not -Throw
            $result[0].PSObject.Properties.Match('out_interface').Count | Should -Be 0
        }
    }
}

# ------------------------------------------------------------------------------------------
# -Protocol matches the wire field protocol exactly, like every other single-field filter; it
# does not translate between the name and number forms the appliance uses inconsistently. -Text
# is different from every other filter: it has no fixed wire field at all, and matches when the
# search text appears in the VALUE of any field the record carries - never in a field name. The
# critical case is a search term that only ever occurs as a field name (e.g. 'port' inside
# "dst_port"): that must return nothing, not every record.

Describe 'Get-SfosLog -Protocol and -Text' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'Protocol filters to an exact match on the raw record text' {
        $records = @(
            (@{ id = 1; protocol = 'TCP' } | ConvertTo-Json -Compress),
            (@{ id = 2; protocol = 'UDP' } | ConvertTo-Json -Compress),
            (@{ id = 3; protocol = 'TCP' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Protocol 'TCP' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 3)
    }

    It 'Protocol does not translate between a name and a number - matches only the exact wire value' {
        $records = @(
            (@{ id = 1; protocol = 'ICMP' } | ConvertTo-Json -Compress),
            (@{ id = 2; protocol = '1' } | ConvertTo-Json -Compress)  # same protocol, logged as a number on this record
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Protocol 'ICMP' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }

    It 'ExcludeProtocol removes exactly the matching records and keeps the rest' {
        $records = @(
            (@{ id = 1; protocol = 'TCP' } | ConvertTo-Json -Compress),
            (@{ id = 2; protocol = 'UDP' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -ExcludeProtocol 'TCP' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(2)
    }

    It 'Text matches a value found in different fields, not one fixed wire field' {
        $records = @(
            (@{ id = 1; src_ip = '192.0.2.10'; message = 'nothing relevant' } | ConvertTo-Json -Compress),  # match in src_ip
            (@{ id = 2; src_ip = '198.51.100.1'; message = 'seen from 192.0.2.10 earlier' } | ConvertTo-Json -Compress),  # match in message
            (@{ id = 3; src_ip = '198.51.100.2'; message = 'unrelated' } | ConvertTo-Json -Compress)  # no match anywhere
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Text '192.0.2.10' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'Text with a word that only occurs as a field name returns no records - the critical case this filter exists to get right' {
        $records = @(
            (@{ id = 1; dst_port = '443'; hb_status = 'No Heartbeat' } | ConvertTo-Json -Compress),
            (@{ id = 2; dst_port = '8080'; hb_status = 'No Heartbeat' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        # 'port' occurs only inside the field NAME "dst_port" on both records, never inside a
        # field VALUE - a naive whole-record-text search would match both records here.
        $result = Get-SfosLog -Text 'port' @conn -AsJson -WarningAction SilentlyContinue

        @($result) | Should -BeNullOrEmpty
    }

    It 'ORs two -Text values: a record matching either one is kept' {
        $records = @(
            (@{ id = 1; message = 'alpha' } | ConvertTo-Json -Compress),
            (@{ id = 2; message = 'beta' } | ConvertTo-Json -Compress),
            (@{ id = 3; message = 'gamma' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Text 'alpha', 'beta' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'ANDs -Text with a field filter (-Status)' {
        $records = @(
            (@{ id = 1; status = 'Deny'; message = 'alpha' } | ConvertTo-Json -Compress),   # Text hit, Status hit - kept
            (@{ id = 2; status = 'Allow'; message = 'alpha' } | ConvertTo-Json -Compress),  # Text hit, Status miss - dropped
            (@{ id = 3; status = 'Deny'; message = 'other' } | ConvertTo-Json -Compress)    # Text miss - dropped
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Text 'alpha' -Status 'Deny' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }

    It 'ExcludeText removes only the matching records and keeps everything else, including a record where the text appears nowhere' {
        $records = @(
            (@{ id = 1; src_ip = '192.0.2.10'; message = 'first' } | ConvertTo-Json -Compress),   # match in src_ip - dropped
            (@{ id = 2; src_ip = '198.51.100.1'; message = 'saw 192.0.2.10 earlier' } | ConvertTo-Json -Compress),  # match in message - dropped
            (@{ id = 3; src_ip = '198.51.100.2'; message = 'clean' } | ConvertTo-Json -Compress)   # no match anywhere - kept
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -ExcludeText '192.0.2.10' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(3)
    }

    It 'an ExcludeText filter never drops a record - decoded fallback, matched the same way as the raw pre-filter' {
        InModuleScope SophosFirewall.Diagnostics {
            $filter = Get-SfosLogViewerFieldFilter -BoundParameters @{ ExcludeText = @('foo') }

            $withMatch = [PSCustomObject]@{ id = 2; message = 'a foo here' }
            $withoutMatch = [PSCustomObject]@{ id = 3; message = 'nothing relevant' }

            Test-SfosLogViewerDecodedFieldMatch -Record $withMatch -FieldFilter $filter | Should -BeFalse
            Test-SfosLogViewerDecodedFieldMatch -Record $withoutMatch -FieldFilter $filter | Should -BeTrue
        }
    }
}

# ------------------------------------------------------------------------------------------
# Measured against a live appliance: the syslog array mode 5001 returns occasionally carries
# an entry that is $null or an empty/whitespace-only string, or one that is not valid JSON.
# Get-SfosLog has to skip those quietly rather than surface a PowerShell binding error for
# every one of them while the rest of the page is perfectly usable.

Describe 'Get-SfosLog tolerates empty and malformed raw records' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'drops null and empty entries in the raw stream and returns only the valid records, without erroring' {
        $records = @(
            (@{ id = 1; message = 'first' } | ConvertTo-Json -Compress),
            '',
            $null,
            (@{ id = 2; message = 'second' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $script:Result = $null
        { $script:Result = Get-SfosLog @conn -AsJson -WarningAction SilentlyContinue } | Should -Not -Throw

        @($script:Result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'skips a record that is not valid JSON and still returns the records around it' {
        $records = @(
            (@{ id = 1; message = 'ok before' } | ConvertTo-Json -Compress),
            '{not valid json',
            (@{ id = 2; message = 'ok after' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $allOutput = Get-SfosLog @conn -AsJson -Verbose -WarningAction SilentlyContinue 4>&1
        $verboseMessages = @($allOutput | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $result = @($allOutput | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] })

        @($result.id | Sort-Object) | Should -Be @(1, 2)
        ($verboseMessages -join ' ') | Should -BeLike '*skip*'
    }
}

# ------------------------------------------------------------------------------------------
# -MessageLike is [string[]], like the other eight built-in field filters, so several values
# are OR-combined on the same field while different field filters still AND together.

Describe 'Get-SfosLog -MessageLike accepts multiple values' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'Get-SfosLog declares MessageLike as string[]' {
        $cmd = Get-Command Get-SfosLog -Module SophosFirewall.Diagnostics
        $cmd.Parameters['MessageLike'].ParameterType | Should -Be ([string[]])
    }

    It 'ORs two -MessageLike values: a record matching either one is kept' {
        $records = @(
            (@{ id = 1; message = 'connection timeout on port 443' } | ConvertTo-Json -Compress),
            (@{ id = 2; message = 'authentication failure for user admin' } | ConvertTo-Json -Compress),
            (@{ id = 3; message = 'clean shutdown' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -MessageLike 'timeout', 'failure' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It 'ANDs -MessageLike with -SourceIP: only a record matching both is kept' {
        $records = @(
            (@{ id = 1; message = 'connection timeout'; src_ip = '192.0.2.10' } | ConvertTo-Json -Compress),  # both match -> kept
            (@{ id = 2; message = 'connection timeout'; src_ip = '192.0.2.99' } | ConvertTo-Json -Compress),  # message only -> dropped
            (@{ id = 3; message = 'clean shutdown'; src_ip = '192.0.2.10' } | ConvertTo-Json -Compress)       # src_ip only -> dropped
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -MessageLike 'timeout' -SourceIP '192.0.2.10' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }
}

# ------------------------------------------------------------------------------------------
# Regression coverage for a defect where -MessageLike (and every other built-in field filter)
# could report "found only 0" for a record known to be on the appliance. Root cause: the
# -MaxRecords widening loop fetches a fresh, independent top-N window on every attempt -
# offset-based paging is unreliable past roughly 750 records (see this module's own findings
# file) - and used to replace $pairs outright with whatever the latest attempt found. A record
# genuinely matched on a narrower attempt is not guaranteed to reappear in a wider attempt's
# window (new records arriving between the two calls push it further back), so a match already
# found used to be discarded the moment a later, wider attempt did not repeat it. Reproduced
# below with exactly the shape measured against a live appliance: 600 fetched records, exactly
# one carrying "message", which forces the loop to widen because FetchedCount equals the
# requested limit.
Describe 'Get-SfosLog widening retry loop does not lose a match already found on a narrower attempt' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"

        function New-SparseLogPage {
            param(
                [int]$Count,
                [int]$MatchIndex,
                [string]$MatchMessage,
                [string]$MatchStatus = 'Allow',
                [string]$IdPrefix = 'r'
            )
            $records = New-Object System.Collections.Generic.List[string]
            for ($i = 1; $i -le $Count; $i++) {
                if ($i -eq $MatchIndex -and $MatchMessage) {
                    $records.Add((@{ id = "$IdPrefix-$i"; log_type = 'Firewall'; status = $MatchStatus; message = $MatchMessage } | ConvertTo-Json -Compress))
                }
                else {
                    $records.Add((@{ id = "$IdPrefix-$i"; log_type = 'Firewall'; status = 'Allow' } | ConvertTo-Json -Compress))
                }
            }
            return @{ status = 200; limit = $Count; offset = 0; syslog = $records.ToArray() } | ConvertTo-Json -Depth 5 -Compress
        }

    }

    It 'keeps the -MessageLike match found on the first (600-record) attempt once the widened (2400-record) attempt does not repeat it' {
        # First attempt: 600 records, fetched count equals the requested limit, so the loop
        # widens even though the match was already found. Second attempt: fewer records than
        # requested (so the loop stops there), none carrying "message" - as measured, the
        # single matching record did not reappear once the request widened.
        $narrowPage = New-SparseLogPage -Count 600 -MatchIndex 300 -MatchMessage 'Could not associate packet to any connection.'
        $widePage = New-SparseLogPage -Count 700 -MatchIndex -1 -MatchMessage $null

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                if ([int]$bodyObj.limit -eq 600) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:NarrowPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:WidePage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }
        $script:NarrowPage = $narrowPage
        $script:WidePage = $widePage

        $result = Get-SfosLog -MaxRecords 600 -MessageLike 'Could' @conn -AsJson -WarningAction SilentlyContinue -WarningVariable warnings

        @($result).Count | Should -Be 1
        $result[0].message | Should -BeLike '*Could not associate*'
        ($warnings -join ' ') | Should -BeLike '*found only 1 of the requested 600*'
    }

    It 'ORs two -MessageLike values found on different widening attempts, keeping both' {
        # The first value's match sits in the narrow (600) attempt; the second value's match
        # only shows up once the loop widens to the next attempt. Both must survive.
        $narrowPage = New-SparseLogPage -Count 600 -MatchIndex 300 -MatchMessage 'Could not associate packet to any connection.' -IdPrefix 'n'
        $widePage = New-SparseLogPage -Count 700 -MatchIndex 50 -MatchMessage 'connection timeout on port 443' -IdPrefix 'w'

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                if ([int]$bodyObj.limit -eq 600) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:NarrowPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:WidePage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }
        $script:NarrowPage = $narrowPage
        $script:WidePage = $widePage

        $result = Get-SfosLog -MaxRecords 600 -MessageLike 'Could', 'timeout' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @('n-300', 'w-50')
    }

    It 'combines -MessageLike with an exact field filter (AND) across the widening loop without losing the match' {
        $narrowPage = New-SparseLogPage -Count 600 -MatchIndex 300 -MatchMessage 'Could not associate packet to any connection.' -MatchStatus 'Deny'
        $widePage = New-SparseLogPage -Count 700 -MatchIndex -1 -MatchMessage $null

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                if ([int]$bodyObj.limit -eq 600) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:NarrowPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:WidePage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }
        $script:NarrowPage = $narrowPage
        $script:WidePage = $widePage

        $result = Get-SfosLog -MaxRecords 600 -MessageLike 'Could' -Status Deny @conn -AsJson -WarningAction SilentlyContinue

        @($result).Count | Should -Be 1
        $result[0].status | Should -Be 'Deny'
    }

    It 'returns an empty result, not the full set, when the search term matches nothing across the widening loop' {
        $narrowPage = New-SparseLogPage -Count 600 -MatchIndex 300 -MatchMessage 'Could not associate packet to any connection.'
        $widePage = New-SparseLogPage -Count 700 -MatchIndex -1 -MatchMessage $null

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') {
                $bodyObj = [uri]::UnescapeDataString(($Body -replace '^mode=5001&json=', '')) | ConvertFrom-Json
                if ([int]$bodyObj.limit -eq 600) { return [PSCustomObject]@{ StatusCode = 200; Content = $script:NarrowPage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = $script:WidePage }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }
        $script:NarrowPage = $narrowPage
        $script:WidePage = $widePage

        $result = Get-SfosLog -MaxRecords 600 -MessageLike 'nonexistent-search-term' @conn -AsJson -WarningAction SilentlyContinue -WarningVariable warnings

        @($result).Count | Should -Be 0
        ($warnings -join ' ') | Should -BeLike '*found only 0 of the requested 600*'
    }
}

# ------------------------------------------------------------------------------------------
# Exclude* filters invert the same field match (Test-SfosLogViewerRawFieldMatch and
# Test-SfosLogViewerDecodedFieldMatch, both driven by the Negate flag Get-SfosLogViewerFieldFilter
# sets on an Exclude* entry): a record is dropped only when the field actually carries one of
# the excluded values, never because the field is missing.

Describe 'Get-SfosLog built-in field filters: negation (Exclude*)' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It 'ExcludeStatus removes exactly the matching records and keeps the rest' {
        $records = @(
            (@{ id = 1; status = 'Deny' } | ConvertTo-Json -Compress),
            (@{ id = 2; status = 'Allow' } | ConvertTo-Json -Compress),
            (@{ id = 3; status = 'Deny' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -ExcludeStatus 'Deny' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(2)
    }

    It 'ExcludeStatus with two values removes both' {
        $records = @(
            (@{ id = 1; status = 'Deny' } | ConvertTo-Json -Compress),
            (@{ id = 2; status = 'Allow' } | ConvertTo-Json -Compress),
            (@{ id = 3; status = 'Reject' } | ConvertTo-Json -Compress)
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -ExcludeStatus 'Deny', 'Reject' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(2)
    }

    It 'combines an include filter and an Exclude* filter as AND' {
        $records = @(
            (@{ id = 1; status = 'Deny'; user = 'alice' } | ConvertTo-Json -Compress),  # kept: Deny, not bob
            (@{ id = 2; status = 'Deny'; user = 'bob' } | ConvertTo-Json -Compress),    # dropped: excluded user
            (@{ id = 3; status = 'Allow'; user = 'alice' } | ConvertTo-Json -Compress)  # dropped: not Deny
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -Status Deny -ExcludeUser bob @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }

    It 'an Exclude* filter never drops a record that does not carry the field at all - raw pre-filter' {
        InModuleScope SophosFirewall.Diagnostics {
            $filter = Get-SfosLogViewerFieldFilter -BoundParameters @{ ExcludeMessageLike = @('foo') }

            $withoutField = '{"id":1}'
            $withMatch = '{"id":2,"message":"a foo here"}'
            $withoutMatch = '{"id":3,"message":"nothing relevant"}'

            Test-SfosLogViewerRawFieldMatch -Raw $withoutField -FieldFilter $filter | Should -BeTrue
            Test-SfosLogViewerRawFieldMatch -Raw $withMatch -FieldFilter $filter | Should -BeFalse
            Test-SfosLogViewerRawFieldMatch -Raw $withoutMatch -FieldFilter $filter | Should -BeTrue
        }
    }

    It 'an Exclude* filter never drops a record that does not carry the field at all - decoded fallback' {
        InModuleScope SophosFirewall.Diagnostics {
            $filter = Get-SfosLogViewerFieldFilter -BoundParameters @{ ExcludeMessageLike = @('foo') }

            $withoutField = [PSCustomObject]@{ id = 1 }
            $withMatch = [PSCustomObject]@{ id = 2; message = 'a foo here' }
            $withoutMatch = [PSCustomObject]@{ id = 3; message = 'nothing relevant' }

            Test-SfosLogViewerDecodedFieldMatch -Record $withoutField -FieldFilter $filter | Should -BeTrue
            Test-SfosLogViewerDecodedFieldMatch -Record $withMatch -FieldFilter $filter | Should -BeFalse
            Test-SfosLogViewerDecodedFieldMatch -Record $withoutMatch -FieldFilter $filter | Should -BeTrue
        }
    }
}

# ------------------------------------------------------------------------------------------
# -AnyIP and -AnyPort (named -AnyPort, not -Port, because the connection parameter of the same
# name already occupies -Port - see this module's own findings file) match either side of a
# connection: src_ip/dst_ip and src_port/dst_port. -SourcePort fills in -DestinationPort's
# previously missing counterpart.

Describe 'Get-SfosLog -AnyIP and -AnyPort match either side of a connection' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"
    }

    It '-AnyIP matches an address on either the source or the destination side, and nothing else' {
        $records = @(
            (@{ id = 1; src_ip = '192.0.2.10'; dst_ip = '198.51.100.1' } | ConvertTo-Json -Compress),  # source side
            (@{ id = 2; src_ip = '198.51.100.1'; dst_ip = '192.0.2.10' } | ConvertTo-Json -Compress),  # destination side
            (@{ id = 3; src_ip = '198.51.100.1'; dst_ip = '198.51.100.2' } | ConvertTo-Json -Compress) # neither side
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -AnyIP '192.0.2.10' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It '-AnyPort matches a port on either the source or the destination side, and nothing else' {
        $records = @(
            (@{ id = 1; src_port = '8080'; dst_port = '443' } | ConvertTo-Json -Compress),   # source side
            (@{ id = 2; src_port = '443'; dst_port = '8080' } | ConvertTo-Json -Compress),   # destination side
            (@{ id = 3; src_port = '80'; dst_port = '22' } | ConvertTo-Json -Compress)       # neither side
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -AnyPort '8080' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id | Sort-Object) | Should -Be @(1, 2)
    }

    It '-SourcePort matches only the source side' {
        $records = @(
            (@{ id = 1; src_port = '8080'; dst_port = '443' } | ConvertTo-Json -Compress),   # source side - kept
            (@{ id = 2; src_port = '443'; dst_port = '8080' } | ConvertTo-Json -Compress)    # destination side - dropped
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -SourcePort '8080' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }

    It '-AnyIP combined with -DestinationPort acts as AND' {
        $records = @(
            (@{ id = 1; src_ip = '192.0.2.10'; dst_ip = '198.51.100.1'; dst_port = '443' } | ConvertTo-Json -Compress),  # host hit, port hit - kept
            (@{ id = 2; src_ip = '192.0.2.10'; dst_ip = '198.51.100.1'; dst_port = '8080' } | ConvertTo-Json -Compress), # host hit, port miss - dropped
            (@{ id = 3; src_ip = '198.51.100.2'; dst_ip = '198.51.100.1'; dst_port = '443' } | ConvertTo-Json -Compress) # host miss - dropped
        )
        $script:Page = @{ status = 200; limit = 200; offset = 0; syslog = $records } | ConvertTo-Json -Depth 5 -Compress

        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
            if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
            if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:Page } }
            return [PSCustomObject]@{ StatusCode = 200; Content = '' }
        }

        $result = Get-SfosLog -AnyIP '192.0.2.10' -DestinationPort '443' @conn -AsJson -WarningAction SilentlyContinue

        @($result.id) | Should -Be @(1)
    }
}

# ------------------------------------------------------------------------------------------
# Invoke-SfosCliCommand reaches the device console, a third access path implemented in
# SophosFirewall.Core as Connect-SfosCliConsole/Send-SfosCliInput/Receive-SfosCliOutput/
# Disconnect-SfosCliConsole (see this module's own findings file). Those four are mocked here at
# their call site inside SophosFirewall.Diagnostics - the same pattern already used above for
# Invoke-SfosApi, a Core-defined function called from this module's own functions.

Describe 'Invoke-SfosCliCommand' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'admin'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'navigates to the device console menu, sends the command, and returns the cleaned output' {
        Mock -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ BaseUri = 'https://192.0.2.1:4444'; Banner = 'MAIN MENU' }
        }
        Mock -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -MockWith { }
        Mock -CommandName Receive-SfosCliOutput -ModuleName SophosFirewall.Diagnostics -MockWith {
            param($CliSession, $TimeoutSeconds, $Until)
            if ($Until -eq 'console>\s*$') {
                "show version`r`nSFOS 22.0.0`r`nconsole> "
            }
        }
        Mock -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }

        $result = Invoke-SfosCliCommand -Command 'show version' @conn -Confirm:$false

        $result | Should -Be 'SFOS 22.0.0'

        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $Text -eq '4'
        }
        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $Text -eq 'show version'
        }
        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 2 -Exactly -ParameterFilter {
            $Key -eq 'Enter'
        }
        Should -Invoke -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
    }

    It 'skips the menu navigation with -SkipMenu' {
        Mock -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ BaseUri = 'https://192.0.2.1:4444'; Banner = 'console> ' }
        }
        Mock -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -MockWith { }
        Mock -CommandName Receive-SfosCliOutput -ModuleName SophosFirewall.Diagnostics -MockWith {
            "show version`r`nSFOS 22.0.0`r`nconsole> "
        }
        Mock -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }

        Invoke-SfosCliCommand -Command 'show version' -SkipMenu @conn -Confirm:$false | Out-Null

        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $Text -eq '4'
        }
    }

    It 'closes its own session when a command fails, and rethrows' {
        Mock -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ BaseUri = 'https://192.0.2.1:4444'; Banner = 'MAIN MENU' }
        }
        Mock -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -MockWith {
            param($CliSession, $Text, $Key)
            if ($PSBoundParameters.ContainsKey('Text') -and $Text -ne '4') {
                throw 'device console rejected the command'
            }
        }
        Mock -CommandName Receive-SfosCliOutput -ModuleName SophosFirewall.Diagnostics -MockWith { 'console> ' }
        Mock -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }

        { Invoke-SfosCliCommand -Command 'show version' @conn -Confirm:$false } | Should -Throw '*device console rejected the command*'

        Should -Invoke -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
    }

    It 'reuses a supplied -CliSession and does not close it' {
        Mock -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }
        Mock -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -MockWith { }
        Mock -CommandName Receive-SfosCliOutput -ModuleName SophosFirewall.Diagnostics -MockWith {
            "show version`r`nSFOS 22.0.0`r`nconsole> "
        }
        Mock -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }

        $existingSession = [PSCustomObject]@{ BaseUri = 'https://192.0.2.1:4444'; Banner = 'MAIN MENU' }

        $result = Invoke-SfosCliCommand -Command 'show version' -CliSession $existingSession -SkipMenu -Confirm:$false

        $result | Should -Be 'SFOS 22.0.0'
        Should -Invoke -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly
        Should -Invoke -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly
    }

    It '-WhatIf still navigates the menu but never sends the command, and still closes its own session' {
        Mock -CommandName Connect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ BaseUri = 'https://192.0.2.1:4444'; Banner = 'MAIN MENU' }
        }
        Mock -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -MockWith { }
        Mock -CommandName Receive-SfosCliOutput -ModuleName SophosFirewall.Diagnostics -MockWith { 'console> ' }
        Mock -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -MockWith { }

        Invoke-SfosCliCommand -Command 'reboot' @conn -WhatIf

        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $Text -eq '4'
        }
        Should -Invoke -CommandName Send-SfosCliInput -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $Text -eq 'reboot'
        }
        Should -Invoke -CommandName Disconnect-SfosCliConsole -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
    }
}

# ------------------------------------------------------------------------------------------
# Export-SfosLog / Import-SfosLog: capture a Get-SfosLog read to a file once, then filter it
# repeatedly with Import-SfosLog, without contacting the appliance again. Export-SfosLog still
# talks to the web console (Invoke-WebRequest mocked in SophosFirewall.Core's scope, exactly
# like the Get-SfosLog tests above); Import-SfosLog never does.

Describe 'Export-SfosLog / Import-SfosLog' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:LoginOkJson = '{"status":200}'
        $script:CsrfHtml = '<html><script>Cyberoam.c' + '$rFt0k3n' + " = 'tok123';</script></html>"

        # Five raw records, JSON-encoded exactly the way the console sends them - deliberately
        # spanning several fields (source/destination address, user, status, message) so include,
        # exclude and both-sided field filters each have something to prove.
        $script:SampleRecords = @(
            (@{ id = 1; log_type = 'Firewall'; src_ip = '192.0.2.10'; dst_ip = '192.0.2.20'; user = 'admin'; status = 'Allow'; protocol = 'TCP'; message = 'alpha'; datetime = '2026-08-20 10:00:00'; tz_offset = '+0200' } | ConvertTo-Json -Compress),
            (@{ id = 2; log_type = 'Firewall'; src_ip = '192.0.2.11'; dst_ip = '192.0.2.10'; user = 'svc-backup'; status = 'Deny'; protocol = 'TCP'; message = 'beta'; datetime = '2026-08-20 10:01:00'; tz_offset = '+0200' } | ConvertTo-Json -Compress),
            (@{ id = 3; log_type = 'IPS'; src_ip = '192.0.2.12'; dst_ip = '192.0.2.13'; user = 'admin'; status = 'Allow'; protocol = 'UDP'; message = 'gamma'; datetime = '2026-08-20 10:02:00'; tz_offset = '+0200' } | ConvertTo-Json -Compress),
            (@{ id = 4; log_type = 'Firewall'; src_ip = '192.0.2.13'; dst_ip = '192.0.2.10'; user = 'jdoe'; status = 'Deny'; protocol = 'TCP'; message = 'delta'; datetime = '2026-08-20 10:03:00'; tz_offset = '+0200' } | ConvertTo-Json -Compress),
            (@{ id = 5; log_type = 'Firewall'; src_ip = '192.0.2.14'; dst_ip = '192.0.2.15'; user = 'admin'; status = 'Allow'; protocol = 'TCP'; message = 'epsilon'; datetime = '2026-08-20 10:04:00'; tz_offset = '+0200' } | ConvertTo-Json -Compress)
        )
        $script:SamplePage = @{ status = 200; limit = 200; offset = 0; syslog = $script:SampleRecords } | ConvertTo-Json -Depth 5 -Compress

        $script:FirewallCatalogJson = @{
            filter = @{ module = @{ val = @{
                            firewall = @{ label = 'Firewall'; condition = '( "log_type=Firewall" )' }
                        } } }
        } | ConvertTo-Json -Depth 8 -Compress

        # Defined in BeforeAll, not at the Describe body's top level: a function declared there
        # runs during Pester's discovery phase and is not reliably visible to It blocks in the
        # later run phase.
        function New-SampleConsoleMock {
            Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
                if ($Body -like 'mode=151*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:LoginOkJson } }
                if ($Uri -like '*/webconsole/webpages/index.jsp') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:CsrfHtml } }
                if ($Body -like 'mode=5002*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:FirewallCatalogJson } }
                if ($Body -like 'mode=5001*') { return [PSCustomObject]@{ StatusCode = 200; Content = $script:SamplePage } }
                return [PSCustomObject]@{ StatusCode = 200; Content = '' }
            }
        }
    }

    It 'writes a file that Import-SfosLog reads back into the same objects Get-SfosLog returns for the same raw records' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'roundtrip.sfoslog'

        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -MaxRecords 10 @conn -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path | Sort-Object id)

        $imported.Count | Should -Be $live.Count
        $imported.Count | Should -Be 5

        for ($i = 0; $i -lt $live.Count; $i++) {
            $imported[$i].id | Should -Be $live[$i].id
            $imported[$i].log_type | Should -Be $live[$i].log_type
            $imported[$i].src_ip | Should -Be $live[$i].src_ip
            $imported[$i].dst_ip | Should -Be $live[$i].dst_ip
            $imported[$i].user | Should -Be $live[$i].user
            $imported[$i].status | Should -Be $live[$i].status
            $imported[$i].message | Should -Be $live[$i].message
            $imported[$i].Datetime | Should -Be $live[$i].Datetime
            $imported[$i].PSObject.TypeNames[0] | Should -Be $live[$i].PSObject.TypeNames[0]
        }
    }

    It 'an include filter (-SourceIP) gives the same result on the file path as on the live path' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'include.sfoslog'
        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -SourceIP '192.0.2.10' -MaxRecords 10 @conn -AsJson -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path -SourceIP '192.0.2.10' -AsJson | Sort-Object id)

        $imported.Count | Should -Be 1
        @($imported.id) | Should -Be @($live.id)
    }

    It 'an exclude filter (-ExcludeUser) gives the same result on the file path as on the live path' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'exclude.sfoslog'
        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -ExcludeUser 'svc-backup' -MaxRecords 10 @conn -AsJson -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path -ExcludeUser 'svc-backup' -AsJson | Sort-Object id)

        $imported.Count | Should -Be 4
        @($imported.id) | Should -Be @($live.id)
    }

    It 'a both-sided filter (-AnyIP) gives the same result on the file path as on the live path' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'host.sfoslog'
        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -AnyIP '192.0.2.10' -MaxRecords 10 @conn -AsJson -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path -AnyIP '192.0.2.10' -AsJson | Sort-Object id)

        # id 1 (src_ip 192.0.2.10) and id 2/4 (dst_ip 192.0.2.10) all match either side.
        $imported.Count | Should -Be 3
        @($imported.id) | Should -Be @($live.id)
    }

    It '-Protocol gives the same result on the file path as on the live path' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'protocol.sfoslog'
        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -Protocol 'UDP' -MaxRecords 10 @conn -AsJson -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path -Protocol 'UDP' -AsJson | Sort-Object id)

        $imported.Count | Should -Be 1
        @($imported.id) | Should -Be @($live.id)
    }

    It '-Text gives the same result on the file path as on the live path' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'text.sfoslog'
        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $live = @(Get-SfosLog -Text '192.0.2.10' -MaxRecords 10 @conn -AsJson -WarningAction SilentlyContinue | Sort-Object id)
        $imported = @(Import-SfosLog -Path $path -Text '192.0.2.10' -AsJson | Sort-Object id)

        # id 1 (src_ip), id 2/4 (dst_ip) - matched wherever the value appears, not one fixed field.
        $imported.Count | Should -Be 3
        @($imported.id) | Should -Be @($live.id)
    }

    It 'throws without -Force when the target file already exists' {
        $path = Join-Path $TestDrive 'existing.sfoslog'
        Set-Content -Path $path -Value 'placeholder'

        { Export-SfosLog -Path $path -MaxRecords 5 @conn -Confirm:$false } | Should -Throw "*$path*"

        (Get-Content -Path $path -Raw).TrimEnd() | Should -Be 'placeholder'
    }

    It 'overwrites the target file with -Force' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'existing2.sfoslog'
        Set-Content -Path $path -Value 'placeholder'

        Export-SfosLog -Path $path -MaxRecords 5 -Force @conn -Confirm:$false -WarningAction SilentlyContinue

        (Get-Content -Path $path -Raw).TrimEnd() | Should -Not -Be 'placeholder'
        (Get-Content -Path $path -Raw | ConvertFrom-Json).RecordCount | Should -Be 5
    }

    It '-WhatIf writes no file' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'whatif.sfoslog'

        Export-SfosLog -Path $path -MaxRecords 5 @conn -WhatIf -WarningAction SilentlyContinue

        Test-Path -Path $path | Should -BeFalse
    }

    It '-PassThru returns the written file as a FileInfo' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'passthru.sfoslog'

        $result = Export-SfosLog -Path $path -MaxRecords 5 -PassThru @conn -Confirm:$false -WarningAction SilentlyContinue

        $result | Should -BeOfType [System.IO.FileInfo]
        $result.FullName | Should -Be (Get-Item -Path $path).FullName
    }

    It 'Import-SfosLog warns and names the filters recorded at capture time' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'recorded-filters.sfoslog'

        Export-SfosLog -Path $path -Category firewall -SourceIP '192.0.2.10' -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $warnings = $null
        Import-SfosLog -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        $warnings | Should -Not -BeNullOrEmpty
        # The category is scope, not a field filter. Naming it here would make the warning fire
        # on every capture, and one that always fires is one nobody reads.
        "$warnings" | Should -Not -BeLike '*Category=*'
        "$warnings" | Should -BeLike '*src_ip*'
        "$warnings" | Should -BeLike '*192.0.2.10*'
    }

    It 'Import-SfosLog does not warn about a capture that only chose a category' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'category-only.sfoslog'

        Export-SfosLog -Path $path -Category firewall -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $warnings = $null
        Import-SfosLog -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        $warnings | Should -BeNullOrEmpty
    }
    It 'Import-SfosLog does not warn about a capture with no filters applied' {
        New-SampleConsoleMock
        $path = Join-Path $TestDrive 'no-filters.sfoslog'

        Export-SfosLog -Path $path -MaxRecords 10 @conn -Confirm:$false -WarningAction SilentlyContinue

        $warnings = $null
        Import-SfosLog -Path $path -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        $warnings | Should -BeNullOrEmpty
    }

    It 'throws an error naming the path for a file that does not exist' {
        $path = Join-Path $TestDrive 'missing.sfoslog'

        { Import-SfosLog -Path $path } | Should -Throw "*$path*"
    }

    It 'throws an error naming the path for a file that is not a Sophos Firewall log export' {
        $path = Join-Path $TestDrive 'unrelated.json'
        Set-Content -Path $path -Value '{"foo":"bar"}'

        { Import-SfosLog -Path $path } | Should -Throw "*$path*"
    }

    It 'throws an error naming the path for a file that is not valid JSON at all' {
        $path = Join-Path $TestDrive 'notjson.txt'
        Set-Content -Path $path -Value 'this is not json {{{'

        { Import-SfosLog -Path $path } | Should -Throw "*$path*"
    }
}

