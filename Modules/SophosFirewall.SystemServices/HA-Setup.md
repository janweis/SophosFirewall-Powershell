# Building an HA cluster with the SystemServices cmdlets

A step-by-step, reproducible recipe for forming a High Availability cluster between two
Sophos XGS/SFOS 22.0 appliances using only the cmdlets in this module. Every step below
was reverse-engineered and applied against two live lab firewalls; the one thing the lab
could **not** demonstrate is the cluster actually forming, because the two appliances ran
mismatched firmware — see [Prerequisites](#prerequisites).

The cmdlets involved:

| Cmdlet | Role |
|---|---|
| `Set-SfosHAConfiguration` | Puts an appliance into a primary or auxiliary role (Quick or interactive) |
| `Get-SfosHAConfiguration` | Reads the current HA state |
| `Reset-SfosHAConfiguration` | Clears a configured-but-not-yet-formed HA setup back to unconfigured |
| `Disable-SfosHAConfiguration` | Turns off a running HA cluster |

---

## Prerequisites

These are hard requirements. The API accepts a configuration that violates the last two
without complaint, and the cluster then silently never forms.

1. **Two appliances of the same model.**
2. **Identical firmware on both.** This is the single most common reason a cluster does
   not form. The API will apply the HA config on each node and answer success; the peers
   simply never pair. Verify the firmware version on both before starting.
3. **A dedicated HA-link interface on each appliance.** In interactive mode this link must
   be a **DMZ, LAG, VLAN, or unbound** interface — a bound physical port (one that already
   carries a zone) is rejected with `501`. **QuickHA additionally accepts an unbound
   physical port**, which is the easiest link to arrange in a small lab (see
   [step 1](#step-1-free-the-ha-link-port-if-it-is-a-physical-port)).
4. **The same admin credentials** reachable on both appliances' API port (4444 by default).

Connect to both appliances up front and keep the two sessions side by side:

```powershell
$fw1 = Connect-SfosFirewall -Firewall "fw1.example.test" -Credential $cred -Name fw1 -SkipCertificateCheck
$fw2 = Connect-SfosFirewall -Firewall "fw2.example.test" -Credential $cred -Name fw2 -NoDefault -SkipCertificateCheck
```

Every cmdlet below takes `-Session fw1` / `-Session fw2` so you never have to reconnect.

---

## Recommended path: QuickHA

QuickHA is the shortest route to a cluster: you supply only the role, a node name, the
HA-link interface and a passphrase; the firewall auto-assigns the HA-link IP addresses and
the monitored ports. Configure the **auxiliary** appliance first, then the **primary**.

### Step 1 — Free the HA-link port if it is a physical port

QuickHA accepts an unbound physical interface, but the port must have **no zone bound** to
it. Detaching it is a `Set-SfosZone`/interface operation in the Network module — unbind the
port you intend to use for the HA link on **both** appliances before configuring HA.

> A dedicated DMZ/LAG/VLAN interface avoids this step entirely and is the production
> recommendation. Only reach for an unbound physical port in a lab where you have a spare.

### Step 2 — Configure the auxiliary appliance

```powershell
$pass = Read-Host -AsSecureString "HA passphrase (must contain a special character)"

Set-SfosHAConfiguration -Session fw2 `
    -Quick `
    -Device Auxilliary `
    -NodeName "FW2-Aux" `
    -DedicatedLink "PortB" `
    -Passphrase $pass
```

`-Device` takes exactly one of `Active_Active`, `Active_Passive`, `Auxilliary` — those are
the literal wire values (`Auxilliary` is Sophos' spelling, kept deliberately). The
auxiliary node is always `Auxilliary`.

### Step 3 — Configure the primary appliance

Use the **same passphrase and the same `-DedicatedLink` interface name** as the auxiliary,
and pick the active role you want the cluster to run in:

```powershell
Set-SfosHAConfiguration -Session fw1 `
    -Quick `
    -Device Active_Passive `
    -NodeName "FW1-Primary" `
    -DedicatedLink "PortB" `
    -Passphrase $pass
```

### Step 4 — Wait, then verify

The web admin quotes roughly **4 minutes** for the cluster to build. After that:

```powershell
Get-SfosHAConfiguration -Session fw1
Get-SfosHAConfiguration -Session fw2
```

A formed cluster reports the configured mode and both node roles. If it still shows
unconfigured after several minutes, the overwhelmingly likely cause is a **firmware
mismatch** — confirm both appliances are on the same build.

---

## Alternative: interactive HA

Interactive mode exposes the fields the web admin's advanced dialog does: a cluster ID, the
peer's HA-link IP, monitored ports and a peer-administration address. Use it when you need
that control; otherwise QuickHA is simpler.

The **auxiliary** node still goes first and is minimal — it only needs its role, node name,
link and passphrase (interactive auxiliary uses a nested request shape internally, which
the cmdlet handles for you):

```powershell
Set-SfosHAConfiguration -Session fw2 `
    -Device Auxilliary `
    -NodeName "FW2-Aux" `
    -DedicatedLink "PortB" `
    -Passphrase $pass
```

The **primary** node carries the full configuration:

```powershell
Set-SfosHAConfiguration -Session fw1 `
    -HAConfigurationMode Active_Passive `
    -Device Active_Passive `
    -NodeName "FW1-Primary" `
    -ClusterID 1 `
    -DedicatedLink "PortB" `
    -DedicatedLinkIPAddress "169.254.1.2" `
    -Passphrase $pass `
    -MonitorPort "PortA","PortC" `
    -PeerAdministrationInterface "PortA" `
    -PeerAdministrationIPv4 "10.0.0.253" `
    -FallbackPrimaryDevice Primary `
    -KeepAliveInterval 250 `
    -KeepAliveAttempts 16
```

Key points, all measured against the firmware:

- **`-DedicatedLinkIPAddress` is the _peer's_ HA-link IPv4**, not this appliance's.
- `-ClusterID` is `0–63`; both nodes must share the same value.
- `-KeepAliveInterval` is `250–500` ms, `-KeepAliveAttempts` is `16–24`.
- `-MonitorPort` and the `-PeerAdministration*` fields are optional; the peer-administration
  address is what keeps the auxiliary reachable for management after the cluster forms.

Then wait and verify exactly as in [step 4](#step-4-wait-then-verify).

---

## Undoing an HA configuration

Two distinct operations, deliberately split into two cmdlets so each does one thing:

**Before the cluster has formed** (you configured a role and want to back out, or you made
a mistake) — reset the node to unconfigured:

```powershell
Reset-SfosHAConfiguration -Session fw1
Reset-SfosHAConfiguration -Session fw2
```

**A running cluster** — disable HA:

```powershell
Disable-SfosHAConfiguration -Session fw1
```

Both support `-WhatIf`/`-Confirm`. `Reset` sends the documented `<HA_Interactive_Reset/>`
toggle (verified live) and is the correct tool for the "I configured it but it never
paired" case that a firmware mismatch produces.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `501` naming `DedicatedLink` | The HA-link port is a bound physical interface | Unbind it, or use a DMZ/LAG/VLAN interface; QuickHA accepts an unbound physical port |
| `501` naming `Passphrase`/`DedicatedLink` on an auxiliary | — | The cmdlet already emits the required nested shape for `-Device Auxilliary`; make sure you passed `Auxilliary`, not `Primary`/`Auxiliary` |
| Config applies (success) but the cluster never forms | Firmware mismatch between the two appliances | Bring both to the same firmware build, then reset both and reconfigure |
| Passphrase rejected | No special character | HA passphrases must contain a special character |
| Node stuck in a half-configured state | — | `Reset-SfosHAConfiguration` on that node |
