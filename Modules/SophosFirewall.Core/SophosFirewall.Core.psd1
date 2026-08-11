@{
    RootModule           = 'SophosFirewall.Core.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = 'cf0350d0-30af-4cd9-ae9e-8eb43356718d'
    Author               = 'Jan Weis'
    Description          = 'Core helper functions for Sophos Firewall API modules. Provides session management, API communication, XML escaping, and response validation.'
    
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    
    FunctionsToExport    = @(
        'Connect-SfosFirewall',
        'Disconnect-SfosFirewall',
        'Invoke-SfosApi',
        'Get-SfosApiStatus',
        'Assert-SfosApiReturnSuccess',
        'Resolve-SfosParameters',
        'ConvertTo-SfosXmlEscaped'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'XGS', 'SFOS', 'API', 'Core', 'Helper')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Core/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Core'
            ReleaseNotes = @'
Version 1.1.0 (2026-08-11)
Correctness fixes measured against a live SFOS 22.0 appliance. The exported
surface is unchanged, so no caller has to be adapted, but the behaviour of
existing calls changes for the better. Upgrading is strongly recommended:
1.0.0 can report success for operations that never happened.

- A failed login is no longer read as success. SFOS answers a bad login with
  HTTP 200 and a lowercase <status> under <Login>, which matches neither
  status path - so every write reported success while the firewall did
  nothing. Checked now before the response is parsed.
- The request body is URL-encoded. Sent unencoded, any "&" - including every
  "&amp;" produced by XML escaping - made the firewall answer 529 Invalid XML
  request.
- Web requests use -UseBasicParsing. Without it every call failed under
  Windows PowerShell 5.1 on hosts without the Internet Explorer engine.
- Status evaluation follows the documented table: 200 and 216 are success,
  201/203/211-215 succeed with a warning, 204-210 and 500-599 fail. There is
  no code 202. The undocumented 217 and 222 warn; the rest of the 217-499 gap
  still fails, because failing open is worse than a false alarm.
- A response with no recognisable status is an error, not success. Only the
  exact wording "No. of records Zero." counts as an empty result - a code-less
  "Transaction fail" used to pass as "nothing found".
- One status object per <Status> node instead of a collapsed string, and the
  node is located by XPath rather than by property access.
- SecureString conversion uses PtrToStringBSTR, which does not truncate.
- The process-wide certificate callback used under PS 5.1 is restored in a
  finally block and guarded by a lock, so parallel runspaces cannot leave
  validation permanently disabled.
- New -ApiVersion parameter on Invoke-SfosApi for callers that need a specific
  schema; omitted, the appliance uses its active firmware version.

Version 1.0.0 (2025-12-31)
- Initial release
'@
        }
    }
}

