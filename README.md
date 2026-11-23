# Wireless Security Audit Lab

**AP Cybersecurity — Unit 3, Lesson 5**

You are a security analyst contracted to audit the wireless infrastructure of **Taiwan Semiconductor Manufacturing Company (TSMC) Fab 18**, a 3nm process facility in Tainan. The dataset holds 27 wireless networks: corporate Wi-Fi, guest networks, IoT sensors, building management, and isolated OT networks.

**You do not write the audit engine.** `wireless_audit.py` is provided. You run it, then you do the hard part: decide which findings are real threats, which are noise, and write remediation for the top three.

---

## WHAT YOU ARE CREATING

Two files, both at the **top level of your fork** (not inside a folder):

```text
apcyber-u3-wireless-audit/
├── wireless_networks.csv   ← ships with the repo. Do not edit.
├── wireless_audit.py       ← ships with the repo. Read it. Do not edit.
├── audit_checklist.md      ← ships with the repo. Read it. Do not edit.
├── audit_results.csv       ← created by the script. THIS IS THE FILE YOU HAND IN.
└── EXECUTIVE_SUMMARY.md    ← you create this. One paragraph.
```

| File | Who writes it | What it must contain | How you self-check |
|------|---------------|----------------------|------------------|
| `audit_results.csv` | the script creates it, you fill it in | 14 columns; no blank `analyst_notes` | `python3 -c "import pandas as pd; df=pd.read_csv('audit_results.csv'); print(len(df.columns), (df['analyst_notes'].fillna('').astype(str).str.strip()=='').sum())"` |
| `EXECUTIVE_SUMMARY.md` | you | total findings, severity counts, the one fix you would fund first, one named false positive | open the file and read it back |

The one command that creates the file you hand in:

```bash
python3 wireless_audit.py
```

**Done when, in your own fork:**

- ☐  `audit_results.csv` sits at the repo root and has 14 columns
- ☐  every finding row has `analyst_notes` with a severity word and a one-sentence reason
- ☐  at least 3 rows name a specific remediation (`remediation`, `fix`, `rotate`, `deploy`, `segment`, `block`, `patch`, `upgrade`)
- ☐  at least one row names a false positive by BSSID and SSID and says why it is not a risk
- ☐  `EXECUTIVE_SUMMARY.md` answers all four questions
- ☐  `git remote -v` shows your own username, not a classmate's
- ☐  the commit is pushed and you have the push confirmation line

---

## PART 0 — SET UP

### Step 1 — Fork this repository

Click **Fork** at the top right of the repo page, then **Create fork**. Leave every option at its default.

- **What this does:** copies the lab into your own GitHub account. The teacher's copy is the *upstream*; `github.com/<your-username>/apcyber-u3-wireless-security-audit-lab` is *yours*.
- **Why this is necessary:** you cannot write to the teacher's repository. Pushing to *your* fork is how you hand the work in.

### Step 2 — Open your fork in VS Code

Use the class server:

- **Class server:** go to `https://vscode.ivycollegiate.org`, log in with your school account, and clone **your fork** into a folder with a plain name.

On GitHub, open your fork — the copy of this lab under your own username:

1. Click the green **<> Code** button.
2. Under **HTTPS**, click the copy button (or select the URL).
3. In the VS Code server terminal, run:

```bash
cd ~
git clone <paste the HTTPS URL you copied> apcyber-u3-wireless-audit
cd apcyber-u3-wireless-audit
```

Replace `<paste the HTTPS URL you copied>` with the URL you copied. Keep the `apcyber-u3-wireless-audit` folder name at the end.

Run `whoami` if you need your username at the GitHub credential prompt. When GitHub asks for credentials, use your username and a **Personal Access Token**, not your GitHub password.

Check that the clone worked before going on:

```bash
ls -d ~/apcyber-u3-wireless-audit && cd ~/apcyber-u3-wireless-audit && pwd && ls wireless_audit.py
```

You must see the folder path and `wireless_audit.py`. If `ls` says "No such file or directory", the clone never created the folder — repeat the clone step with the URL copied from the Code button. If Git says the destination folder already exists, do not delete it blindly; open it, run `git status`, and ask the teacher.

- **What this does:** downloads your fork to the machine you are working on and moves your terminal inside it.
- **Why the short folder name:** every command below uses `cd ~/apcyber-u3-wireless-audit`. Do not leave the directory name implied.

If you already cloned it in an earlier lesson, do **not** clone it twice. Get into the copy you have and pull anything new:

```bash
cd ~/apcyber-u3-wireless-audit
git pull
```

- **What this does:** fetches newer files from your fork. `git pull` first, always — it is the habit that stops you editing a stale copy.

### Step 3 — Prove the copy is yours, and that you are in it

```bash
cd ~/apcyber-u3-wireless-audit
pwd
ls
git remote -v
```

- `pwd` must end in `/apcyber-u3-wireless-audit`. If it does not, the later `python3 wireless_audit.py` fails with "`wireless_networks.csv` not found" — you are in the wrong folder.
- `ls` must list `wireless_audit.py`, `wireless_networks.csv`, `audit_checklist.md`, and this README.
- `git remote -v` must show **your** username in the URL. If it shows a classmate's, you cloned the wrong fork: remove that folder and re-run Step 2 with your own URL.

### Step 4 — Check the Python environment

```bash
python3 --version
python3 -c "import pandas; print(pandas.__version__)"
```

Expect Python 3.11 and a pandas version number. A `ModuleNotFoundError` means you are not in the lab environment — use the class server, not your laptop's default Python.

---

## PART 1 — READ THE CHECKLIST BEFORE RUNNING ANYTHING

Open `audit_checklist.md` in the editor:

```bash
cd ~/apcyber-u3-wireless-audit
code audit_checklist.md
```

No editor pane? Use `nano audit_checklist.md`. The checklist defines each check, the severity rubric, the approved vendor OUIs, and the remediation template. Read it before you look at the output — otherwise every finding looks equally bad.

These three files ship with the repo and are **read-only for you**:

- `wireless_networks.csv` — the 27-network dataset
- `wireless_audit.py` — the detection engine
- `audit_checklist.md` — the rubric

Do not edit any of them, and do not "fix" the engine if a check reports a problem.

---

## PART 2 — RUN THE ENGINE (this creates the file you hand in)

Run it in the **terminal panel**, not a notebook:

```bash
cd ~/apcyber-u3-wireless-audit
python3 wireless_audit.py
```

- **What this does:** loads `wireless_networks.csv`, runs the checks, prints a summary, and writes `audit_results.csv` into the repo root.
- **Why the terminal:** you need to see the printout, and you need the file to land on disk.

You should see a `Loaded 27 networks` line, a findings count, severity counts, and `Results written to audit_results.csv`. If a check ever fails, the engine stops with an error and writes no results — tell the teacher rather than editing the script.

Confirm the file exists:

```bash
ls -l audit_results.csv
python3 -c "import pandas as pd; print(pd.read_csv('audit_results.csv').shape)"
```

The shape is `(your number of findings, 14)`.

**Do not re-run `python3 wireless_audit.py` after you start filling in `analyst_notes`.** It rewrites `audit_results.csv` with an empty notes column and destroys your work. If you must re-run, copy your annotated file aside first:

```bash
cp audit_results.csv audit_results_my_notes.csv
```

---

## PART 3 — TRIAGE (the actual assignment)

Open the output:

```bash
code audit_results.csv
```

The engine flags far more than you should act on. Your job is to decide which hits matter. Use `notes` and `vendor_oui` as your context clues.

For **every row**, replace the empty `analyst_notes` cell with text in this shape:

```text
High — <one sentence tying this finding to that row's notes / vendor_oui / client_count>. Remediation: <specific action>. Owner: <team>. Timeline: <48h / 2 weeks / next window>.
```

Requirements the teacher checks, so get the literal words in:

| Requirement | Put this in `analyst_notes` |
|-------------|------------------------------|
| severity on every row | one of `Critical`, `High`, `Medium`, `Low`, `Accepted Risk` |
| justification | a sentence tied to that row's `notes`, `vendor_oui`, or `client_count` |
| remediation on at least 3 rows | one of `remediation`, `fix`, `rotate`, `deploy`, `segment`, `block`, `patch`, `upgrade` |
| false positive on at least 1 row | the words `false positive`, plus the BSSID and SSID, plus why it is not a risk |

For the top three findings, use the full remediation template from `audit_checklist.md`: Finding, Severity, Why, Remediation, Owner, Timeline. Write it into that row's `analyst_notes` cell.

You do not have to agree with `default_severity`. It is the engine's guess. Downgrade an accepted risk to `Accepted Risk` and say why; upgrade a finding when the context warrants it.

Save the file (Ctrl+S / Cmd+S) before you leave this part. The teacher reads the file on GitHub, not your editor buffer.

---

## PART 4 — EXECUTIVE SUMMARY

Create the file at the repo root:

```bash
cd ~/apcyber-u3-wireless-audit
touch EXECUTIVE_SUMMARY.md
code EXECUTIVE_SUMMARY.md
```

Create and write the file first; do not put `python3` in the same block as `code`. Write one paragraph that answers all four questions:

1. How many findings did your run report?
2. How many are Critical / High / Medium / Low / Accepted Risk in **your** triage?
3. If you had budget to fix only **one** thing, which finding first — and why?
4. Which specific finding is a false positive? Name its BSSID and SSID and give one sentence why.

Put the false positive in the `analyst_notes` cell of that row **as well**, not only in the summary, so the teacher sees it next to the finding.

Save.

---

## PART 5 — SAVE, COMMIT, PUSH — THIS IS THE TURN-IN

Filling in files changes them only on your computer. Three separate commands move them to your submitted fork. Run them one at a time from the repo root:

```bash
cd ~/apcyber-u3-wireless-audit
git add audit_results.csv EXECUTIVE_SUMMARY.md
```

- **What this does:** stages both files — tells git you want their saved contents in the next snapshot.
- **Why:** git does not record edits automatically. Without `git add`, nothing below sees them.

```bash
git commit -m "Complete U3 L5 wireless security audit"
```

- **What this does:** records a permanent snapshot of the staged files in your local history.
- **Why:** a commit is the unit of recorded work. It is still only on your machine.

```bash
git push origin main
```

- **What this does:** uploads the commit to `origin` (your fork) on branch `main`.
- **Why:** **this is the delivery.** Until you push, GitHub has the old empty CSV and the teacher sees nothing.

**Verify it worked — do not skip this:**

1. Refresh your fork at `https://github.com/<your-username>/apcyber-u3-wireless-security-audit-lab`. Open `audit_results.csv` on GitHub — your notes must be there. Open `EXECUTIVE_SUMMARY.md` too.
2. Check the file's last-commit line on GitHub: it must say `Complete U3 L5 wireless security audit`. If the old empty CSV is still showing, you pushed the wrong commit — go back and re-push.
3. Copy the push confirmation line from the terminal. That line plus your total finding count is your turn-in evidence.

---

## THE DATA SCHEMA

```csv
bssid,ssid,encryption,channel,signal_dbm,vendor_oui,is_hidden,client_count,notes
00:11:22:33:44:55,TSMC-Corp,WPA3-Enterprise,36,-45,00:11:22,False,12,Corporate Wi-Fi 802.1X-RADIUS
```

| Field | Description |
|-------|-------------|
| `bssid` | MAC address of the AP |
| `ssid` | Network name (empty if hidden) |
| `encryption` | `Open`, `WEP`, `WPA-Personal`, `WPA-Enterprise`, `WPA2-Personal`, `WPA2-Enterprise`, `WPA3-Personal`, `WPA3-Enterprise` |
| `channel` | Wi-Fi channel (1-165) |
| `signal_dbm` | Signal strength in dBm (negative, closer to 0 = stronger) |
| `vendor_oui` | First 3 octets of BSSID — manufacturer ID |
| `is_hidden` | `True`/`False` — hidden SSID |
| `client_count` | Number of associated clients observed |
| `notes` | Free-form context (e.g., "OT network", "Guest Wi-Fi", "Building mgmt") |

## WHAT THE ENGINE CHECKS

| Check ID | Detection | Why It Matters |
|----------|-----------|----------------|
| **WEP-001** | Any network using WEP encryption | WEP is broken; trivial to crack in minutes |
| **WPA1-001** | Any network using WPA (TKIP) — not WPA2/WPA3 | TKIP has known vulnerabilities; deprecated |
| **OPEN-001** | Open networks with clients | Anyone can join and sniff traffic |
| **HIDDEN-001** | Hidden SSIDs with clients | Security through obscurity; still discoverable |
| **HIDDEN-002** | Hidden SSID on an OT/ICS network | Obscurity on critical infrastructure is negligence |
| **ROGUE-001** | Same SSID, different BSSID and vendor OUI — evil twin candidate | Attacker mimicking a legitimate AP |
| **ROGUE-002** | SSID with a typo of a corporate SSID (e.g., `TSMC-C0rp`) | Typosquatting for credential harvest |
| **ROGUE-003** | Unknown vendor OUI on a corporate SSID | Unauthorized hardware |
| **CHANNEL-001** | More than 3 APs on the same strong channel | Performance and jamming/confusion risk |
| **CHANNEL-002** | Overlapping 2.4 GHz channels (1, 6, 11) | Manageable with proper channel planning |
| **WEAK-001** | WPA2-Personal with more than 10 clients | PSK vulnerable to offline dictionary attack |
| **OT-001** | OT/ICS network without WPA3 | IT/OT convergence failure — lateral movement path |
| **OT-002** | OT network using WPA2-Personal | Shared secret across critical infrastructure |
| **VENDOR-001** | Unapproved vendor OUI on a corporate/OT network | Rogue AP, shadow IT, or compromised vendor gear |
| **VENDOR-002** | Same vendor across multiple SSIDs with different encryption | Misconfiguration or a device bridging networks |

Not every check fires on this dataset. A check with no rows is not a finding you have to invent.

## THE REAL SKILL IS TRIAGE

**Every check will fire on something.** Your job is not to report every hit. Your job is to decide which hits are actionable threats and which are accepted risk.

- Open guest Wi-Fi with clients — likely **Accepted Risk**: it is designed for visitors.
- A management network on weak encryption — likely **High**: a clear path to critical systems.
- An evil twin mimicking a corporate SSID — likely **Critical**: active credential harvesting.

**Context is everything.** The `notes` and `vendor_oui` columns are your primary clues. Use them. The severity words above are examples, not answers — judge each row on its own evidence.

## HOW YOUR WORK IS REVIEWED

There is no automated grader on this repo. The teacher reads what you pushed:

- `audit_results.csv` has all 14 columns and `analyst_notes` on every row
- a severity for each finding, with a justification tied to that row's evidence
- remediation for the top three findings (specific action, owner, timeline)
- at least one false positive named by BSSID and SSID, with a reason
- `EXECUTIVE_SUMMARY.md` answers all four questions

Nothing checks this automatically, so the self-check in PART 5 is the only confirmation you get before the teacher marks it. Do not skip it.

---

## FILES

| File | What It Is |
|------|------------|
| `wireless_networks.csv` | The synthetic dataset. Do not edit it. |
| `wireless_audit.py` | The audit engine. Read it. Do not edit it. |
| `audit_checklist.md` | The checklist of what to look for. Read before running. |
| `audit_results.csv` | **Your output.** Created when you run the script. You edit this. |
| `EXECUTIVE_SUMMARY.md` | **Your output.** One paragraph answering the four questions in PART 4. |
