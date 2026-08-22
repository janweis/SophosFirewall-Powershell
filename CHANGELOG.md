# Changelog

This file lists the changes shipped in each release of the Sophos Firewall
PowerShell module suite. All modules in the suite are versioned and released
together: every module carries the same `ModuleVersion`, and each domain
module pins the matching minimum version of `SophosFirewall.Core` in its
`RequiredModules`. A release therefore covers the whole suite even in
versions where only a subset of modules changed.

Each module also publishes its own `ReleaseNotes` in its manifest, shown on
its package page in the PowerShell Gallery. This file gives the same
information in one place, with more detail than the per-module notes allow.

## 1.4.0

### SophosFirewall.Core

Adds two further ways to reach the appliance alongside the documented XML
API:

- The web admin console (`Connect-SfosWebAdmin`, `Invoke-SfosWebAdminRequest`)
  for screens that the XML API does not expose. Both are undocumented and
  firmware-dependent.
- The appliance device console (`Connect-SfosCliConsole`, `Send-SfosCliInput`,
  `Receive-SfosCliOutput`, `Disconnect-SfosCliConsole`). Only the `admin` and
  `support` accounts may open it, it asks for the account password again on
  connect, and an open session has to be closed explicitly.

New `-AcceptLoginDisclaimer` switch on the connect cmdlets. Where the
appliance has a login disclaimer configured, a connection attempt without
this switch now reports the disclaimer text instead of failing with an
unrelated error. The switch is the only way to accept it; no cmdlet accepts
a disclaimer on the caller's behalf.

### SophosFirewall.Diagnostics

Log retrieval becomes an analysis tool:

- `Get-SfosLog` and `Get-SfosLogCategory` read the web admin console's log
  viewer, which the XML API does not offer.
- 28 field filters are available. Each accepts multiple values combined with
  OR, different filters combine with AND, and each has a matching
  `-Exclude...` counterpart. `-AnyIP` and `-AnyPort` match either the source
  or the destination side; `-SourceIP`/`-DestinationIP` and
  `-SourcePort`/`-DestinationPort` match one side only. New in this release:
  `-Protocol` and `-Text`. `-Text` searches every field value at once and
  deliberately never the field names.
- `Export-SfosLog` and `Import-SfosLog` capture a set of log entries to a
  file, so it can be filtered repeatedly offline without querying the
  appliance again. The captured file records when and from what it was
  taken, and whether a filter was already applied during capture.
- `Invoke-SfosCliCommand` and `Enter-SfosCliConsole` reach the appliance
  device console. `Invoke-SfosCliCommand` asks for confirmation before
  running a command, because the console itself executes commands without
  asking.
- Fixed: a filtered query could lose matching entries when a request came
  back short of the requested count and was retried with a broader query.
  This affected every filter and was most visible with the text search.
  Empty and unreadable entries returned by the appliance are now discarded
  instead of surfacing as binding errors.

### SophosFirewall.Administration

Adds `Restart-SfosFirewall` and `Stop-SfosFirewall`, reaching the appliance
through the web admin console because the XML API offers no restart or
shutdown operation. New `-AcceptLoginDisclaimer` switch, matching
`SophosFirewall.Core`: where the appliance has a login disclaimer
configured, these cmdlets now report the disclaimer text and require the
switch to proceed, instead of failing with an unrelated error.

### All other modules

`SophosFirewall.ActiveThreatResponse`, `SophosFirewall.Applications`,
`SophosFirewall.Authentication`, `SophosFirewall.Certificates`,
`SophosFirewall.Email`, `SophosFirewall.Firewall`,
`SophosFirewall.HostsAndServices`, `SophosFirewall.IntrusionPrevention`,
`SophosFirewall.Network`, `SophosFirewall.Profiles`,
`SophosFirewall.Routing`, `SophosFirewall.SophosCentral`,
`SophosFirewall.SystemServices`, `SophosFirewall.VPN`, `SophosFirewall.Web`,
`SophosFirewall.WebServer` and `SophosFirewall.ZeroDayProtection` have no
functional change in 1.4.0. Their version number is aligned with the rest of
the suite, and each now requires `SophosFirewall.Core` 1.4.0.

## Earlier releases

The notes below are the release notes each module carried before 1.4.0,
kept here so that history is not lost when a manifest's `ReleaseNotes` field
is replaced.

### SophosFirewall.ActiveThreatResponse

Documentation revised for production use: rewritten cmdlet help, module
description and README.

### SophosFirewall.Administration

Added `Restart-SfosFirewall` and `Stop-SfosFirewall`, through the web admin
console - not part of the XML API. Required `SophosFirewall.Core` 1.4.0.

### SophosFirewall.Applications

Documentation revised for production use: rewritten cmdlet help, module
description and README.

### SophosFirewall.Authentication

Documentation revised for production use: rewritten cmdlet help, module
description and README. `Set-SfosGuestUserSettings` now asks for
confirmation before it writes.

### SophosFirewall.Certificates

First release. Adds certificates and certificate authorities, including
upload of PKCS#12 and PEM material and export of stored files, plus read
access to certificate revocation lists.

### SophosFirewall.Core

Added `Connect-SfosWebAdmin` and `Invoke-SfosWebAdminRequest`, moved here
from `SophosFirewall.Diagnostics` so a second module can reach the web admin
interface the same way. This is the web admin console, not the appliance
device console. Undocumented and firmware-bound - see their own help before
using them.

### SophosFirewall.Diagnostics

Web admin console access (login, CSRF, the controller POST) moved to
`SophosFirewall.Core` as `Connect-SfosWebAdmin`/`Invoke-SfosWebAdminRequest`,
so a second module can reach the web admin console the same way. Behaviour
of `Get-SfosLog`/`Get-SfosLogCategory` was unchanged at that point. Required
`SophosFirewall.Core` 1.4.0.

### SophosFirewall.Email

First release. Covers the email area in both of its shapes: SMTP policies,
MTA address groups, exception policies and data control lists for MTA mode,
anti-spam rules and SMTP malware scanning policies for legacy mode, plus the
objects both share - mail configuration, malware protection, POP/IMAP
scanning policies, trusted domains and SPX. Relay, smarthost, blocked
senders, DKIM and the quarantine digest are read-only.

### SophosFirewall.Firewall

Documentation revised for production use: rewritten cmdlet help, module
description and README.

### SophosFirewall.HostsAndServices

The seven `Import-Sfos*` cmdlets gained `-WhatIf`/`-Confirm` support and
skip the individual `New-Sfos*` calls they would have made. Required
`SophosFirewall.Core` 1.3.2 or later.

### SophosFirewall.IntrusionPrevention

`Import-SfosTrustedMACs` gained `-WhatIf`/`-Confirm` support and skips the
individual `New-SfosTrustedMAC` calls it would have made. Required
`SophosFirewall.Core` 1.3.2 or later.

### SophosFirewall.Network

Documentation revised for production use: rewritten cmdlet help, module
description and README.

### SophosFirewall.Profiles

First release. Adds schedules, access time policies, data transfer
policies, decryption profiles and administrator role profiles.

### SophosFirewall.Routing

Documentation revised for production use: rewritten cmdlet help, module
description and README.

### SophosFirewall.SophosCentral

First release. Adds read and update access to the Sophos Central cloud
management switches (`EnableCloudCentralManagement`), including a read-back
check for the case where the firewall reports success without applying the
change.

### SophosFirewall.SystemServices

Documentation revised for production use: rewritten cmdlet help, module
description and README. `Initialize-SfosHAConfiguration` now asks for
confirmation before it writes.

### SophosFirewall.VPN

`-ServerConfigurationFile` on `New-/Set-SfosSiteToSiteClient` gained upload
of a local `.apc`/`.epc` file via the Core multipart transport, replacing
the earlier content-string parameter that never worked against the
firewall.

### SophosFirewall.Web

`Set-SfosWebFilterSettings` gained `-TopImageFile` and `-BottomImageFile`,
uploading the block/warn page images through the multipart transport added
to `SophosFirewall.Core`. Both fields are write-only; `Get-SfosWebFilterSettings`
still does not return them.

### SophosFirewall.WebServer

1.3.2: Added `New-SfosWebServerAuthenticationTemplate` and
`Set-SfosWebServerAuthenticationTemplate`, uploading the template (and asset
files) via the multipart transport added to `SophosFirewall.Core` 1.3.2.
Removing a template is still not possible through the API.

1.3.1: First release. Adds web servers, protection policies, authentication
policies and templates, and slow HTTP protection settings.

### SophosFirewall.ZeroDayProtection

First release. Adds read and update access to the zero-day protection
settings singleton: analysis datacenter location and excluded file types.
