#!/usr/bin/env python3
"""
oci_audit_to_csv.py

Parse EVERY *.json* file in <input_folder>, flatten Oracle Cloud audit events,
write two CSVs:
   <output_prefix>_full.csv      – all discovered columns
   <output_prefix>_forensic.csv  – only the 19 most valuable forensic columns

Usage
-----
python oci_audit_to_csv.py <input_folder> <output_prefix> [--threads N]

If <output_prefix> is omitted it defaults to "audit_logs".
"""

import csv
import json
import os
import sys
from glob import glob
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# 19 CRITICAL FORENSIC FIELDS (edit to taste)
# ---------------------------------------------------------------------------
FORENSIC_FIELDS = [
    "event-time",
    "event-type",
    "event-id",
    "data.event-name",
    "data.compartment-id",
    "data.compartment-name",
    "data.identity.auth-type",
    "data.identity.principal-id",
    "data.identity.principal-name",
    "data.identity.ip-address",
    "data.identity.user-agent",
    "data.request.action",
    "data.request.path",
    "data.response.status",
    "data.response.message",
    "data.resource-id",
    "data.resource-name",
    "data.event-grouping-id",
    "data.request.headers.X-Forwarded-For",
]

# ---------------------------------------------------------------------------
def flatten(d, parent_key="", sep="."):
    """Recursively flattens a dict → {'a.b.c': val, ...}."""
    out = {}
    for k, v in d.items():
        key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            out.update(flatten(v, key, sep))
        elif isinstance(v, list):
            out[key] = ",".join(map(str, v))
        else:
            out[key] = v
    return out


def each_entry(file_path):
    """
    Yields flattened dictionaries for every event in one JSON file.
    Continues gracefully on JSON errors.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            j = json.load(f)
    except Exception as exc:
        print(f"[WARN] Could not parse {os.path.basename(file_path)} – {exc}")
        return

    if isinstance(j, dict) and "data" in j:
        events = j["data"] if isinstance(j["data"], list) else [j["data"]]
    elif isinstance(j, list):
        events = j
    else:
        events = [j]

    for ev in events:
        yield flatten(ev)


def collect_headers(files, threads):
    """First fast pass – discover *all* column names."""
    headers = set()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(list, each_entry(fp)) for fp in files]
        for fut in as_completed(futures):
            for row in fut.result():
                headers.update(row.keys())
    return sorted(headers)


def stream_to_csv(files, all_cols, forensic_cols, out_full, out_forensic):
    """Second pass – write full & forensic CSVs row‑by‑row."""
    with open(out_full, "w", newline="", encoding="utf-8") as f_full, \
         open(out_forensic, "w", newline="", encoding="utf-8") as f_fore:

        w_full = csv.DictWriter(f_full, fieldnames=all_cols, extrasaction="ignore")
        w_for  = csv.DictWriter(f_fore, fieldnames=forensic_cols, extrasaction="ignore")
        w_full.writeheader()
        w_for.writeheader()

        for fp in files:          # sequential is simple & safe for streaming
            for row in each_entry(fp):
                w_full.writerow({c: row.get(c, "") for c in all_cols})
                w_for.writerow({c: row.get(c, "") for c in forensic_cols})


def main():
    # ----------------- CLI parsing -----------------
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    folder = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "audit_logs"
    threads = 4                   # default
    if "--threads" in sys.argv:
        try:
            threads = int(sys.argv[sys.argv.index("--threads") + 1])
        except (ValueError, IndexError):
            print("Invalid --threads value, using default 4.")

    files = glob(os.path.join(folder, "*.json"))
    if not files:
        print("No .json files found in the specified folder.")
        sys.exit(1)

    print(f"▶ Pass 1/2: Scanning {len(files)} file(s) with {threads} threads …")
    all_columns = collect_headers(files, threads)
    print(f"   Discovered {len(all_columns)} distinct columns.")

    out_full = f"{prefix}_full.csv"
    out_forensic = f"{prefix}_forensic.csv"
    print(f"▶ Pass 2/2: Writing\n   • {out_full}\n   • {out_forensic}")

    # keep only forensic fields that really occur (preserves order)
    forensic_cols_present = [c for c in FORENSIC_FIELDS if c in all_columns]

    stream_to_csv(files, all_columns, forensic_cols_present, out_full, out_forensic)

    print("✓ Finished!")


if __name__ == "__main__":
    main()
