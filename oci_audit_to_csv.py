#!/usr/bin/env python3
"""
oci_audit_to_csv.py

End‑to‑end extractor for Oracle Cloud (OCI) audit‑log JSON files:

1. Pass 1 (parallel): discover every field across all events
2. Pass 2 (streaming): write
     • <prefix>_full.csv      – every column ever seen
     • <prefix>_forensic.csv  – only the 19+ OCI‑doc–recommended forensic fields

Usage:
    python oci_audit_to_csv.py <input_folder> [output_prefix] [--threads N]

If output_prefix is omitted it defaults to "audit_logs".
"""

import os
import sys
import json
import csv
from glob import glob
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# 23 CRITICAL FORENSIC FIELDS (including envelope, identity delegation,
# additional-details, and state-change fields recommended by OCI docs)
# ---------------------------------------------------------------------------
FORENSIC_FIELDS = [
    # Envelope-level metadata
    "cloud-events-version",
    "content-type",
    "event-type",
    "event-type-version",
    "source",
    "event-id",
    "event-time",

    # Core event details
    "data.event-name",
    "data.compartment-id",
    "data.compartment-name",
    "data.event-grouping-id",

    # Identity context (including delegation fields)
    "data.identity.auth-type",
    "data.identity.principal-id",
    "data.identity.principal-name",
    "data.identity.caller-id",
    "data.identity.caller-name",
    "data.identity.console-session-id",
    "data.identity.tenant-id",
    "data.identity.ip-address",
    "data.identity.user-agent",

    # Request details
    "data.request.action",
    "data.request.path",
    "data.request.headers.X-Forwarded-For",

    # Response outcome
    "data.response.status",
    "data.response.message",

    # Resource context
    "data.resource-id",
    "data.resource-name",

    # Extra context
    "data.additional-details",               # full JSON string
    "data.state-change.previous.*",          # flattened subkeys
    "data.state-change.current.*",
]

# ---------------------------------------------------------------------------
def flatten(obj, parent_key="", sep="."):
    """
    Recursively flatten a nested dict into dot‑notation keys.
    Special case: at data.additional-details, stringify entire dict.
    Lists become comma‑joined strings.
    """
    out = {}
    for k, v in obj.items():
        key = f"{parent_key}{sep}{k}" if parent_key else k

        # Special handling: stringify full additional-details payload
        if parent_key == "data" and k == "additional-details":
            out[key] = json.dumps(v) if v is not None else ""
            continue

        if isinstance(v, dict):
            out.update(flatten(v, key, sep))
        elif isinstance(v, list):
            out[key] = ",".join(map(str, v))
        else:
            out[key] = v if v is not None else ""
    return out


def each_event(file_path):
    """
    Yield flattened dicts for every event in one JSON file.
    Skips on parse error, with a warning.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            j = json.load(f)
    except Exception as exc:
        print(f"[WARN] {os.path.basename(file_path)} parse error: {exc}", file=sys.stderr)
        return

    # OCI audit logs wrap events under "data"
    if isinstance(j, dict) and "data" in j:
        events = j["data"] if isinstance(j["data"], list) else [j["data"]]
    elif isinstance(j, list):
        events = j
    else:
        events = [j]

    for ev in events:
        yield flatten(ev)


def discover_all_columns(files, workers):
    """Pass 1: parallel scan to collect every distinct column name."""
    cols = set()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(list, each_event(fp)) for fp in files]
        for fut in as_completed(futures):
            for row in fut.result():
                cols.update(row.keys())
    return sorted(cols)


def write_csvs(files, all_cols, forensic_cols, out_full, out_forensic):
    """Pass 2: stream rows into two CSVs (full and forensic)."""
    with open(out_full, "w", newline="", encoding="utf-8") as f1, \
         open(out_forensic, "w", newline="", encoding="utf-8") as f2:

        writer_full = csv.DictWriter(f1, fieldnames=all_cols, extrasaction="ignore")
        writer_frc = csv.DictWriter(f2, fieldnames=forensic_cols, extrasaction="ignore")
        writer_full.writeheader()
        writer_frc.writeheader()

        for fp in files:
            for row in each_event(fp):
                writer_full.writerow({c: row.get(c, "") for c in all_cols})
                writer_frc.writerow({c: row.get(c, "") for c in forensic_cols})


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    folder = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "audit_logs"
    threads = 4
    if "--threads" in sys.argv:
        try:
            threads = int(sys.argv[sys.argv.index("--threads") + 1])
        except Exception:
            pass

    json_files = glob(os.path.join(folder, "*.json"))
    if not json_files:
        print(f"No JSON files found in {folder}", file=sys.stderr)
        sys.exit(1)

    print(f"Pass 1/2: discovering columns across {len(json_files)} files (threads={threads}) …")
    all_columns = discover_all_columns(json_files, threads)
    print(f" → Found {len(all_columns)} distinct columns.")

    # Only keep forensic fields that actually appear, preserving order
    for_cols_present = []
    for key in FORENSIC_FIELDS:
        if key.endswith(".*"):
            # wildcard: include any column starting with prefix before ".*"
            prefix_key = key[:-2]
            for col in all_columns:
                if col.startswith(prefix_key):
                    for_cols_present.append(col)
        elif key in all_columns:
            for_cols_present.append(key)

    out_full = f"{prefix}_full.csv"
    out_frc  = f"{prefix}_forensic.csv"
    print(f"Pass 2/2: writing \n  • {out_full}\n  • {out_frc}")
    write_csvs(json_files, all_columns, for_cols_present, out_full, out_frc)

    print("Done.")


if __name__ == "__main__":
    main()
