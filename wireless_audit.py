#!/usr/bin/env python3
"""
Wireless Security Audit Engine
AP Cybersecurity Unit 3, Lesson 5

DO NOT EDIT THIS SCRIPT. Run it as-is.
The audit logic is the assignment; your analysis of the output is the grade.
"""

import pandas as pd
import sys
from datetime import datetime

# ---- CONFIG ----
INPUT_CSV = "wireless_networks.csv"
OUTPUT_CSV = "audit_results.csv"
APPROVED_OUIS = {
    "00:11:22": "Cisco Meraki",
    "33:44:55": "Aruba/HPE",
    "66:77:88": "Ubiquiti",
    "99:AA:BB": "Ruckus",
    "CC:DD:EE": "Fortinet",
}
CORPORATE_SSID_PREFIX = "TSMC-"
OT_KEYWORDS = ["OT", "SCADA", "ICS", "Building", "Sensor", "Mgmt", "Lithography", "Etch", "Metrology", "Water", "Chemical", "HVAC", "Access"]
GUEST_KEYWORDS = ["Guest", "Contractor", "Dev", "Archive"]

# ---- THRESHOLDS ----
CO_CHANNEL_THRESHOLD = 3          # >3 APs on same channel = interference
SIGNAL_THRESHOLD_DBM = -70        # Stronger than this = co-located
WEP_WPA1_CRITICAL = True          # Always flag WEP/WPA1 as critical


def load_data():
    """Load the wireless networks dataset."""
    try:
        df = pd.read_csv(INPUT_CSV)
        # CSVs edited by hand can carry numeric-looking text or "True"/"False"
        # strings. Normalise once here so every check sees the same dtypes.
        for column in ("channel", "signal_dbm", "client_count"):
            df[column] = pd.to_numeric(df[column], errors="coerce")
        df["is_hidden"] = df["is_hidden"].astype(str).str.strip().str.lower().eq("true")
        print(f"[+] Loaded {len(df)} networks from {INPUT_CSV}")
        return df
    except FileNotFoundError:
        print(f"[!] Error: {INPUT_CSV} not found. Make sure you're in the repo root.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading CSV: {e}")
        sys.exit(1)


def check_wep(df):
    """WEP-001: Any network using WEP encryption."""
    return df[df["encryption"] == "WEP"].copy()


def check_wpa1(df):
    """WPA1-001: Any network using WPA (TKIP) — not WPA2/WPA3."""
    return df[df["encryption"].str.contains("^WPA-Personal$|^WPA-Enterprise$", na=False)].copy()


def check_open(df):
    """OPEN-001: Open networks with clients."""
    return df[(df["encryption"] == "Open") & (df["client_count"] > 0)].copy()


def check_hidden(df):
    """HIDDEN-001: Hidden SSIDs with clients."""
    return df[(df["is_hidden"] == True) & (df["client_count"] > 0)].copy()


def check_hidden_ot(df):
    """HIDDEN-002: Hidden SSID on OT/ICS network."""
    ot_mask = df["notes"].str.contains("|".join(OT_KEYWORDS), case=False, na=False)
    return df[(df["is_hidden"] == True) & ot_mask].copy()


def check_rogue_same_ssid_diff_bssid(df):
    """ROGUE-001: Same SSID, different BSSID, different vendor OUI."""
    # Group by SSID, find those with multiple BSSIDs and multiple OUIs
    s = df.groupby("ssid").agg(
        bssid_count=("bssid", "nunique"),
        oui_count=("vendor_oui", "nunique"),
        ouis=("vendor_oui", lambda x: list(x.unique())),
        bssids=("bssid", lambda x: list(x.unique()))
    ).reset_index()
    suspicious = s[(s["bssid_count"] > 1) & (s["oui_count"] > 1) & (s["ssid"] != "")]
    findings = []
    for _, row in suspicious.iterrows():
        for bssid in row["bssids"]:
            net = df[df["bssid"] == bssid].iloc[0]
            findings.append(net)
    return pd.DataFrame(findings) if findings else pd.DataFrame(columns=df.columns)


def check_rogue_typosquat(df):
    """ROGUE-002: SSID mimicking a known corporate SSID with a typo."""
    ssids = df["ssid"].fillna("").astype(str)
    corporate = ssids.str.startswith(CORPORATE_SSID_PREFIX)
    # "Known" means the SSID is actually seen on an approved AP. Using every
    # TSMC-* string as the reference set would include the typo itself and make
    # this check impossible to fire.
    managed = df[corporate & df["vendor_oui"].isin(APPROVED_OUIS)]
    corporate_ssids = managed["ssid"].dropna().astype(str).unique()

    findings = []
    for _, net in df.iterrows():
        raw_ssid = net["ssid"]
        if pd.isna(raw_ssid):
            continue  # hidden SSID
        ssid = str(raw_ssid)
        if not ssid.startswith(CORPORATE_SSID_PREFIX) or ssid in corporate_ssids:
            continue
        for corp_ssid in corporate_ssids:
            if levenshtein(ssid, corp_ssid) <= 2:
                findings.append(net)
                break
    return pd.DataFrame(findings) if findings else pd.DataFrame(columns=df.columns)


def levenshtein(s1, s2):
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_rogue_unknown_vendor(df):
    """ROGUE-003: Unknown vendor OUI on corporate SSID."""
    corp_mask = df["ssid"].str.startswith(CORPORATE_SSID_PREFIX, na=False)
    approved_mask = df["vendor_oui"].isin(APPROVED_OUIS)
    return df[corp_mask & ~approved_mask].copy()


def check_cochannel(df):
    """CHANNEL-001: Co-channel interference (>3 APs same channel, strong signal)."""
    strong = df[df["signal_dbm"] > SIGNAL_THRESHOLD_DBM]
    channel_counts = strong.groupby("channel").size().reset_index(name="ap_count")
    busy_channels = channel_counts[channel_counts["ap_count"] > CO_CHANNEL_THRESHOLD]["channel"].tolist()
    return df[df["channel"].isin(busy_channels) & (df["signal_dbm"] > SIGNAL_THRESHOLD_DBM)].copy()


def check_channel_overlap(df):
    """CHANNEL-002: Overlapping 2.4GHz channels (1,6,11) on adjacent APs."""
    # Simplified: flag if multiple APs on 1, 6, or 11 with strong signal
    overlap_channels = [1, 6, 11]
    strong = df[(df["channel"].isin(overlap_channels)) & (df["signal_dbm"] > SIGNAL_THRESHOLD_DBM)]
    channel_counts = strong.groupby("channel").size().reset_index(name="ap_count")
    busy = channel_counts[channel_counts["ap_count"] > 1]["channel"].tolist()
    return df[df["channel"].isin(busy) & (df["signal_dbm"] > SIGNAL_THRESHOLD_DBM)].copy()


def check_weak_psk(df):
    """WEAK-001: WPA2-Personal with many clients (PSK sharing risk)."""
    return df[(df["encryption"] == "WPA2-Personal") & (df["client_count"] > 10)].copy()


def check_ot_segregation(df):
    """OT-001: OT/ICS network on same encryption as corporate (IT/OT convergence)."""
    ot_mask = df["notes"].str.contains("|".join(OT_KEYWORDS), case=False, na=False)
    ot_networks = df[ot_mask].copy()
    findings = []
    for _, net in ot_networks.iterrows():
        # Check if encryption is weaker than WPA3-Enterprise
        if net["encryption"] not in ["WPA3-Enterprise", "WPA3-Personal"]:
            findings.append(net)
    return pd.DataFrame(findings) if findings else pd.DataFrame(columns=df.columns)


def check_ot_psk(df):
    """OT-002: OT network using WPA2-Personal (PSK on critical infra)."""
    ot_mask = df["notes"].str.contains("|".join(OT_KEYWORDS), case=False, na=False)
    return df[ot_mask & (df["encryption"] == "WPA2-Personal")].copy()


def check_vendor_anomaly(df):
    """VENDOR-001: Unknown vendor OUI on corporate/OT network."""
    corp_ot_mask = (
        df["ssid"].str.startswith(CORPORATE_SSID_PREFIX, na=False) |
        df["notes"].str.contains("|".join(OT_KEYWORDS), case=False, na=False)
    )
    approved_mask = df["vendor_oui"].isin(APPROVED_OUIS)
    return df[corp_ot_mask & ~approved_mask].copy()


def check_vendor_bridging(df):
    """VENDOR-002: Same vendor OUI across multiple SSIDs with different encryption."""
    oui_groups = df.groupby("vendor_oui").agg(
        ssid_count=("ssid", "nunique"),
        encryption_count=("encryption", "nunique"),
        ssids=("ssid", lambda x: list(x.unique())),
        encryptions=("encryption", lambda x: list(x.unique()))
    ).reset_index()
    suspicious = oui_groups[(oui_groups["ssid_count"] > 1) & (oui_groups["encryption_count"] > 1)]
    findings = []
    for _, row in suspicious.iterrows():
        for ssid in row["ssids"]:
            nets = df[(df["vendor_oui"] == row["vendor_oui"]) & (df["ssid"] == ssid)]
            for _, net in nets.iterrows():
                findings.append(net)
    return pd.DataFrame(findings) if findings else pd.DataFrame(columns=df.columns)


def run_all_checks(df):
    """Run all audit checks and return a findings DataFrame."""
    checks = [
        ("WEP-001", "WEP Encryption", check_wep, "Critical"),
        ("WPA1-001", "WPA1/TKIP Encryption", check_wpa1, "High"),
        ("OPEN-001", "Open Network with Clients", check_open, "High"),
        ("HIDDEN-001", "Hidden SSID with Clients", check_hidden, "Medium"),
        ("HIDDEN-002", "Hidden SSID on OT Network", check_hidden_ot, "High"),
        ("ROGUE-001", "Evil Twin Candidate (Same SSID, Diff OUI)", check_rogue_same_ssid_diff_bssid, "Critical"),
        ("ROGUE-002", "Typosquatting Evil Twin", check_rogue_typosquat, "Critical"),
        ("ROGUE-003", "Unknown Vendor on Corporate SSID", check_rogue_unknown_vendor, "High"),
        ("CHANNEL-001", "Co-Channel Interference", check_cochannel, "Medium"),
        ("CHANNEL-002", "Channel Overlap (2.4GHz)", check_channel_overlap, "Low"),
        ("WEAK-001", "WPA2-Personal with Many Clients", check_weak_psk, "Medium"),
        ("OT-001", "IT/OT Convergence (Weak Encryption on OT)", check_ot_segregation, "Critical"),
        ("OT-002", "OT Network Using WPA2-Personal", check_ot_psk, "High"),
        ("VENDOR-001", "Unauthorized Vendor on Corp/OT Network", check_vendor_anomaly, "High"),
        ("VENDOR-002", "Vendor Bridging Multiple SSIDs/Encryption", check_vendor_bridging, "Medium"),
    ]

    all_findings = []
    for check_id, name, check_func, default_severity in checks:
        try:
            results = check_func(df)
            if len(results) > 0:
                for _, net in results.iterrows():
                    all_findings.append({
                        "check_id": check_id,
                        "check_name": name,
                        "bssid": net["bssid"],
                        "ssid": net["ssid"],
                        "encryption": net["encryption"],
                        "channel": net["channel"],
                        "signal_dbm": net["signal_dbm"],
                        "vendor_oui": net["vendor_oui"],
                        "vendor_name": APPROVED_OUIS.get(net["vendor_oui"], "UNKNOWN"),
                        "is_hidden": net["is_hidden"],
                        "client_count": net["client_count"],
                        "notes": net["notes"],
                        "default_severity": default_severity,
                        "analyst_notes": "",  # Student fills this in
                    })
        except Exception as e:
            print(f"[!] Check {check_id} failed: {e}")
            # A swallowed failure silently omits a check from the graded CSV.
            # Stop instead of handing students an incomplete audit.
            raise

    return pd.DataFrame(all_findings)


def main():
    print("=" * 60)
    print("WIRELESS SECURITY AUDIT — TSMC Fab 18")
    print(f"Scan time: {datetime.now().isoformat()}")
    print("=" * 60)

    df = load_data()

    print("\n[+] Running audit checks...")
    findings = run_all_checks(df)

    if len(findings) == 0:
        print("[+] No findings. Clean environment.")
        # Still write empty results with headers
        findings = pd.DataFrame(columns=[
            "check_id", "check_name", "bssid", "ssid", "encryption", "channel",
            "signal_dbm", "vendor_oui", "vendor_name", "is_hidden", "client_count",
            "notes", "default_severity", "analyst_notes"
        ])
    else:
        print(f"[+] Found {len(findings)} total findings across all checks")
        # Summary by severity
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = len(findings[findings["default_severity"] == sev])
            if count > 0:
                print(f"    {sev}: {count}")

    # Write results
    findings.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[+] Results written to {OUTPUT_CSV}")
    print("[+] Next steps:")
    print("    1. Open audit_results.csv")
    print("    2. Fill in 'analyst_notes' for each finding: severity classification + justification")
    print("    3. Add remediation proposals for top 3 findings")
    print("    4. Identify at least one false positive")
    print("    5. Commit and push")


if __name__ == "__main__":
    main()