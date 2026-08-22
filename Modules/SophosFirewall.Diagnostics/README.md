# SophosFirewall.Diagnostics

`SophosFirewall.Diagnostics` manages the MONITOR & ANALYZE > Diagnostics area of a Sophos
Firewall: remote support access, and read-only access to the log records shown by the web
admin console's log viewer. It is for administrators who need to open a temporary channel for
Sophos support to reach the appliance, or who need to read log records without a syslog
receiver in place.

## Log viewer access is not the XML API

`Get-SfosLog` and `Get-SfosLogCategory` do not use the Sophos Firewall XML API - there is no
equivalent read in it. They log into the web admin console itself (the same login an
administrator uses, via `SophosFirewall.Core`'s `Connect-SfosWebAdmin`/`Invoke-SfosWebAdminRequest`)
and read the same records the web admin console's own Log Viewer page shows. This access path
is not part of the documented API and can change with a firmware update. The account used
still needs permission to view the log viewer in the web admin console.

## Device console access is not the XML API either

`Invoke-SfosCliCommand` and `Enter-SfosCliConsole` reach a third access path, alongside the XML
API and the web admin console: the appliance's device console, the menu-driven, keystroke-based
interface an administrator would otherwise reach from a physical or serial console. Only the
`admin` and `support` accounts can open it, and the console asks for that account's password
again as a separate step, even though the caller already authenticated to reach it. The device
console runs every command immediately, without a confirmation prompt of its own, and its main
menu carries an entry that shuts down or restarts the appliance - review a command before
sending it.

## Security note

Switching support access on lets Sophos support connect to the firewall's web admin console
and shell over TCP port 22, **without needing the administrator's own credentials**, for as
long as the chosen duration runs. It stays open until it is switched off again or the
duration expires; inactive sessions are closed after 15 minutes by the firewall itself, but
the channel itself is not. Treat `Set-SfosSupportAccess -ConfigOption Enable` the same way you
would treat handing out a temporary account: open it only for as long as it is actually
needed, and switch it off explicitly afterwards rather than relying on the duration to run
out unattended.

## Requirements

- `SophosFirewall.Core` 1.4.0 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Diagnostics -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosSupportAccess

Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' -Confirm:$false
Get-SfosSupportAccess

Set-SfosSupportAccess -ConfigOption Disable -Confirm:$false

Get-SfosLogCategory
Get-SfosLog -Category firewall -MaxRecords 50
Get-SfosLog -SourceIP '192.0.2.10' -Status 'Deny' -MaxRecords 50

Get-SfosLog -Category firewall -MaxRecords 10          # default table, this module's own column set
Get-SfosLog -Category firewall -MaxRecords 10 -List    # same columns, one field per line
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSupportAccess` | Reads the current support access state and, while it is on, its remaining duration. |
| `Set-SfosSupportAccess` | Switches support access on or off and sets its duration. |
| `Get-SfosLog` | Reads log records from the web admin console's log viewer, with a category pre-filter, built-in field filters matched on the raw record text before decoding, a client-side `-Since` cutoff, and a `-Follow` mode that streams newly arriving records. |
| `Get-SfosLogCategory` | Lists the log viewer's own categories and the condition each one matches. |
| `Invoke-SfosCliCommand` | Runs one or more commands on the appliance's device console and returns the output of each. |
| `Enter-SfosCliConsole` | Opens an interactive keyboard session on the appliance's device console. |

## Log type or category - they are not the same thing

`-LogType` matches one field of the record, exactly as the appliance wrote it: `Firewall`,
`Event`, `Content Filtering`, `Anti-Virus`, `IDP`, `ATP`, `SD-WAN`, `Sandbox`, `HeartBeat`,
`SSL`, `WAF`, `Anti-Spam`.

`-Category` is the web admin console's own grouping, and a category is a condition over *several*
fields. The appliance supplies those conditions itself, and `Get-SfosLogCategory` prints them:

| Category | Condition the appliance declares |
|---|---|
| `admin` | `log_type=Event` AND `log_subtype=Admin` |
| `system` | `log_type=Event` AND `log_subtype=System` NOT (IPSec OR SSL VPN OR L2TP ...) |
| `vpn` | `log_type=Event` AND `log_component` in (IPSec, SSL VPN, L2TP, PPTP, RED) |
| `webfilter` | `log_type=Content Filtering` AND `log_component` in (HTTP, HTTPS) |

So the two do not line up one to one, in both directions:

- **One log type, several categories.** `admin`, `system`, `authentication` and `vpn` are all
  `log_type=Event`. `-LogType Event` returns all four at once.
- **One category, several log types.** `applicationfilter` matches both `Content Filtering`
  and `Firewall` records.

| You want | Use |
|---|---|
| a raw type you already know | `-LogType` - filters before decoding, markedly faster |
| exactly the slice the web admin console shows | `-Category` - reproduces its condition |
| one part of a shared log type | `-LogType Event -LogSubtype Admin` - both are pre-filters, so only the survivors get decoded |

They combine: every filter parameter is AND-ed with the others, several values of one
parameter are OR-ed.

One caveat: `-LogType Firewall` and `-Category firewall` can return identical sets, when every
firewall component present happens to be one the category condition includes. That is a
property of the traffic on a given appliance, not a guarantee - a firewall record with a
component outside the category's list shows up under `-LogType Firewall` and not under
`-Category firewall`.

## Behaviour worth knowing

**`ConfigOption` is always sent by `Set-SfosSupportAccess`, even when you do not pass it.**
The firewall accepts a write that omits it, answers success, and leaves the setting neither
Enable nor Disable. `Set-SfosSupportAccess` reads the current value first and resends it, and
throws instead of writing if that value cannot be resolved to Enable or Disable.

**The wire element is `GrantAccessFor`, one `r`.** The vendor's own attribute table spells it
`GrantAccessForr`, two `r`s; the firewall accepts a request using that spelling, answers `200`,
and silently resets the duration to its own default of one week instead of applying the value
sent. This module always uses the one-`r` spelling.

**The duration is only ever reported while support access is on.** `Get-SfosSupportAccess`
returns an empty string for `GrantAccessFor` while access is off, because the firewall itself
has nothing to report. Switching from off to on without passing `-GrantAccessFor` therefore
does not restore a previous duration - the firewall applies its own default of one week.

**The access ID shown in the web admin console is not available through the API.** Once
support access is switched on, the appliance generates an access ID that Sophos support uses
to connect; neither `Get-SfosSupportAccess` nor any other operation in this area exposes it.

**`Get-SfosLog` fetches, then filters - and `-MaxRecords` counts what comes out, not what goes
in.** `-Category` and `-Since` are both applied client-side - the console ignores the category
condition on its own read call. Depth is reached with a single request carrying a large
`limit`, never by paging with `offset`: `offset`-based paging becomes unreliable after a few
hundred records and silently repeats an earlier page instead of erroring or returning nothing.
So `Get-SfosLog` asks for `-MaxRecords` records first; if `-Category`/`-Since` leave too few and
the appliance still had at least that many to give, it asks again with four times the limit, up
to five attempts and a ceiling of 50000 - the appliance's own ceiling for a single request (see
"Limits" below). If the appliance runs out, or the attempt/limit ceiling is reached, before
enough matching records were found, the cmdlet warns with the number it actually found rather
than silently returning fewer than asked for. Every call opens its own web admin console
session; no CSRF token or cookie is reused across calls - except under `-Follow`, where the
session is opened once and kept for every poll.

**`-All` reads everything the appliance's log retention holds, in one request.** It requests
`limit 50000`; if the appliance answers with exactly that many, the log may hold more and the
cmdlet warns that the result can be truncated. `-Category`/`-Since` still apply, but there is no
`-MaxRecords` widening loop - one call is the whole point. `-All` cannot be combined with
`-MaxRecords` or with `-Follow`.

**The built-in field filters (`-LogType`, `-LogComponent`, `-LogSubtype`, `-Status`, `-User`,
`-SourceIP`, `-DestinationIP`, `-DestinationPort`, `-MessageLike`) match on the raw record text,
before it is decoded - markedly faster than filtering afterwards with `Where-Object`, because
decoding is the expensive part of processing a record and the pre-filter skips it for every
record that cannot match.** The gain grows with a sharper filter and shrinks toward nothing on
one that matches almost everything. Several values on one parameter are OR-combined; different
parameters, `-Category` included, are AND-combined. They only do exact or substring matching on
one field each; a range comparison (a port range, arithmetic across fields) is still a job for
`Where-Object` after the cmdlet. The match tolerates both spacings the appliance is known to use
around the JSON colon and falls back to decoding and comparing on the parsed object - with a
`-Verbose` message saying so - if a filtered field's own key is present in the fetched records
but the raw-text match still found nothing, so the built-in filters cannot silently return too
little if the appliance's JSON formatting ever changes.

**`Get-SfosLog`'s default output is a table sized to the record's own log category, not a
generic dump.** Sixteen of the seventeen category views reproduce the column order and labels
of the web admin console's own Log Viewer screen; `Firewall` is the one exception and keeps
this module's own nine-column choice. The view used is picked deterministically: `-Category` wins when given; otherwise a single-valued `-LogType` is
matched against the category keys (case- and separator-insensitive: `'SSL/TLS'` matches the
`ssltls` category); anything else, including `-Category all`, falls back to a generic table
(`Datetime`, `log_type`, `log_component`, `log_subtype`, `status`, `message`). `-List` shows the
same fields one per line instead of a table. Neither view removes anything from the object
itself - every field the record actually carries is still there, so
`Select-Object -Property *` or `Format-Table -Property *` shows it regardless of which default
view was picked. `-AsJson` bypasses both views and returns the record exactly as decoded.

**Wide categories wrap in a narrow console window.** `Firewall` (nine columns) and `SSL/TLS
inspection` (fourteen columns) are the widest views; in a narrow window the table wraps or
truncates. Use `-List` or `Select-Object` there instead - that is a property of the console's
own column layout, not a defect in this module.

**`-Follow` is `tail -f` for the log viewer, and it polls because there is no push channel.**
It shows the current backlog first (bounded by `-MaxRecords` exactly as without `-Follow`), then
streams only what arrives afterwards, oldest first, at the interval set by
`-PollIntervalSeconds` (default 30, matching the web admin console's own polling interval). A record
is recognised as new by comparing timestamps, with a raw-text comparison for records sharing the
exact same one-second timestamp as the last one shown, so genuine repeats on the wire are still
shown once each rather than zero or twice. Each poll asks for the standard window (200 records)
first; if the oldest record it gets back still looks newer than the last one already shown, the
gap was not bridged and the same poll asks again with four times the limit, up to three attempts
before it gives up and warns - lower `-PollIntervalSeconds` if that happens often, so each poll
has fewer new records to catch up on.

## Limits

- Paging with `offset` in 200-record steps becomes unreliable after a few hundred records;
  beyond that point the appliance answers the same page again and again, with no error and no
  empty result to signal it. This module therefore never pages with `offset` - every request
  sends `offset:0` and reaches depth through a larger `limit` instead.
- A single request's `limit` reaches much further than the 200-record page size documented as
  the default. 50000 is the appliance's own ceiling for a single request; asking for more does
  not return more. `Get-SfosLog -All` uses `limit 50000`.
- The appliance signals "nothing more to give" only by returning fewer records than the
  `limit` requested. Returning exactly the requested count means there may be more.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
