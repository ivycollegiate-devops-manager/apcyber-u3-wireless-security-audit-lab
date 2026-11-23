# Wireless Security Audit Checklist

**Reference for U3 L5 Lab: Wireless Security Audit**

Use this checklist while reviewing your `audit_results.csv` output. For each finding, classify severity and justify.

---

## Encryption Weaknesses

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **WEP-001** | Any `encryption == "WEP"` | **Critical** — WEP is cryptographically broken. Trivial to crack. |
| **WPA1-001** | Any `encryption == "WPA-Personal"` or `WPA-Enterprise` (TKIP only) | **High** — TKIP deprecated since 2012. Vulnerable to Beck-Tews attack. |
| **OPEN-001** | `encryption == "Open"` AND `client_count > 0` | **High** if corporate/OT; **Accepted Risk** if labeled "Guest" |
| **WEAK-001** | `encryption == "WPA2-Personal"` on network with >10 clients (PSK sharing risk) | **Medium** — PSK vulnerable to offline dictionary attack if handshake captured |

---

## Rogue AP / Evil Twin Detection

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **ROGUE-001** | Same SSID, different BSSID, different vendor OUI | **Critical** — Active evil twin. Attacker mimicking legitimate AP. |
| **ROGUE-002** | SSID with typo vs known corporate SSID (e.g., "TSMC-C0rp", "TSMC-Guestt") | **Critical** — Typosquatting for credential harvest. |
| **ROGUE-003** | Unknown vendor OUI on corporate SSID | **High** — Unauthorized hardware. Could be rogue AP or misconfigured vendor device. |

---

## Hidden SSID / Obscurity

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **HIDDEN-001** | `is_hidden == True` AND `client_count > 0` | **Medium** — Hidden SSIDs are discoverable (probe requests). Not a real control. |
| **HIDDEN-002** | Hidden SSID on OT/ICS network (check `notes`) | **High** — Obscurity on critical infrastructure is negligence. |

---

## Channel / Interference

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **CHANNEL-001** | >3 APs on same channel with signal > -70 dBm (co-located) | **Medium** — Performance + security (easier to jam/confuse clients). |
| **CHANNEL-002** | Overlapping channels (1, 6, 11 overlap in 2.4GHz) on adjacent APs | **Low** — Manageable with proper channel planning. |

---

## IT/OT Segregation (Taiwan Context)

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **OT-001** | Network with `notes` containing "OT", "ICS", "SCADA", "Building Mgmt", "Sensor" on same encryption as corporate Wi-Fi | **Critical** — IT/OT convergence failure. Lateral movement path to 3nm fab tools. |
| **OT-002** | OT network using WPA2-Personal instead of WPA3-Enterprise/802.1X | **High** — PSK on OT network = shared secret across critical infra. |

---

## Vendor / Hardware Anomalies

| Check | What to Look For | Severity Guidance |
|-------|------------------|-------------------|
| **VENDOR-001** | Vendor OUI not in approved list (see below) on corporate/OT network | **High** — Unauthorized device. Could be rogue AP, shadow IT, or compromised vendor equipment. |
| **VENDOR-002** | Same vendor OUI across multiple SSIDs with different encryption | **Medium** — Misconfiguration or multi-homed device bridging networks. |

---

## Approved Vendor OUIs for TSMC Fab 18 (Reference)

| OUI | Vendor | Networks seen on this OUI in the dataset |
|-----|--------|------------------------------------------|
| `00:11:22` | Cisco Meraki | TSMC-Corp |
| `33:44:55` | Aruba/HPE | TSMC-OT, TSMC-Building |
| `66:77:88` | Ubiquiti | TSMC-Guest, TSMC-Sensor |
| `99:AA:BB` | Ruckus | TSMC-IoT, TSMC-OT-Backup |
| `CC:DD:EE` | Fortinet | TSMC-Mgmt, TSMC-OT |

**Any other OUI on a TSMC-* SSID is suspicious.** The engine checks the OUI only; it does not check which SSID is allowed on which approved OUI. Use the `notes` column to judge whether a specific network is expected.

---

## Severity Classification Rubric

| Severity | Definition | Response Time |
|----------|------------|---------------|
| **Critical** | Active exploitation likely; credential theft, lateral movement to OT, or data exfiltration in progress | Immediate (hours) |
| **High** | Significant vulnerability with clear exploit path; no active exploitation observed | 24-48 hours |
| **Medium** | Vulnerability exists but requires chaining or specific conditions; or accepted risk with compensating controls | 1-2 weeks |
| **Low** | Minor misconfiguration; defense-in-depth improvement | Next maintenance window |
| **Accepted Risk** | By design (e.g., open guest Wi-Fi) with documented compensating controls | Documented, reviewed quarterly |

---

## Remediation Template (for top 3 findings)

For each of your top 3 findings, write:

```
Finding: [Check ID] — [SSID] ([BSSID])
Severity: [Critical/High/Medium/Low]
Why: [1-2 sentences linking finding to business/technical impact]
Remediation: [Specific action: "Rotate PSK to WPA3-Enterprise with 802.1X", "Deploy WIPS to detect evil twin on channel 36", "Segment OT VLAN with firewall rule blocking IT→OT except approved paths"]
Owner: [Network team / OT team / Security team]
Timeline: [Immediate / 48h / 2 weeks / Next window]
```

---

## False Positive Identification

A **false positive** is a finding that the script flagged but is **not actually a risk** in context.

Example:
> **False Positive:** `ROGUE-001` on BSSID `AA:BB:CC:DD:EE:FF`, SSID `TSMC-Guest`
> **Why:** This is the legitimate guest network failover AP (vendor `66:77:88` Ubiquiti) — same SSID, different BSSID is expected for high-availability guest Wi-Fi. The script doesn't know this is an authorized HA pair.

**You must identify at least one false positive from your own output and explain why.**