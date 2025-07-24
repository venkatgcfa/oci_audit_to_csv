# OCI Audit Log Extractor

`oci_audit_to_csv.py` is a lightweight, **two‑pass** command‑line tool that converts raw Oracle Cloud (OCI) audit‑log `*.json` files into analysis‑ready CSVs.

- **Pass 1** discovers every field across all events in parallel.
- **Pass 2** streams every event to disk twice:
  - a **wide** CSV containing *all* discovered columns; and
  - a **slim** CSV with the **19 most useful forensic fields**.

Both passes are memory‑efficient and tolerate broken / partial JSON files.

---

## ✨ Features

| Feature                       | Benefit                                                         |
| ----------------------------- | --------------------------------------------------------------- |
| 🔍 **Deep‑flattening JSON**   | Nested dictionaries become `dot.separated` columns.             |
| ⚡ **Parallel header scan**    | Fast discovery of every column, even across thousands of files. |
| 💾 **Streaming writes**       | Processes millions of events without exhausting RAM.            |
| 🛡  **Robust error handling** | Bad files logged as warnings, never crash your run.             |
| 🔑 **19‑field forensic view** | One file ready for SIEM / IR with the columns that matter most. |
| 🔧 **Easy customisation**     | Edit `FORENSIC_FIELDS` or pass `--threads` to tune performance. |

---

## 🚀 Quick Start

```bash
# 1 – Clone / copy the script
$ git clone https://github.com/venkatgcfa/oci_audit_to_csv.git
$ cd oci‑audit‑extractor

# 2 – Run against a folder of JSON logs
$ python oci_audit_to_csv.py /path/to/IAMauditLogs  audit_logs  --threads 8
```

**Outputs**

```
audit_logs_full.csv      # every column discovered
audit_logs_forensic.csv  # only the 19 key forensic columns
```

---

## 🖥️ Requirements

- Python ≥ 3.8 (standard library only; **no external dependencies**)
- A directory containing Oracle Cloud audit‑log `*.json` files (one or many).

---

## 📂 Command‑Line Usage

```bash
python oci_audit_to_csv.py <input_folder> [output_prefix] [--threads N]
```

| Positional / Flag | Default      | Description                                   |
| ----------------- | ------------ | --------------------------------------------- |
| `input_folder`    | –            | Folder containing `*.json` audit logs.        |
| `output_prefix`   | `audit_logs` | Prefix for generated CSVs.                    |
| `--threads N`     | `4`          | Threads used in header‑scan pass (I/O bound). |

---

## 🔑 Forensic Fields (Default 19)

```
event-time, event-type, event-id, data.event-name,
data.compartment-id, data.compartment-name,
data.identity.auth-type, data.identity.principal-id,
data.identity.principal-name, data.identity.ip-address,
data.identity.user-agent, data.request.action,
data.request.path, data.response.status,
data.response.message, data.resource-id,
data.resource-name, data.event-grouping-id,
data.request.headers.X-Forwarded-For
```

> **Need more / fewer fields?** Edit the `FORENSIC_FIELDS` list near the top of the script and rerun – that’s it.

---

## ⚙️ Performance Tuning

| Scenario                     | Suggestion                                                       |
| ---------------------------- | ---------------------------------------------------------------- |
| NVMe / SSD, many small files | Increase `--threads` to 8–12 for faster header pass.             |
| Very large single files      | Thread count matters less (one file ⇒ one thread).               |
| Low‑memory host              | Leave `--threads` at 4 and process sequentially to minimise RAM. |
| Need *only* forensic CSV     | Comment out the `writer_full` section to skip wide file.         |

---

## 🧐 Troubleshooting

| Symptom                      | Cause / Fix                                                               |
| ---------------------------- | ------------------------------------------------------------------------- |
| `No .json files found`       | Wrong folder path – ensure it ends **inside** the log directory.          |
| `[WARN] Could not parse ...` | File is truncated or not JSON. The script skips it; investigate manually. |
| "Killed" / OOM               | On tiny RAM machines, lower `--threads` or move to larger host.           |

---

## 🧑‍💻 Contributing

1. Fork → create feature branch (`git checkout -b feat/my‑idea`)
2. Commit changes (`git commit -am 'Add awesome feature'`)
3. Push branch (`git push origin feat/my‑idea`) & open a PR.

All contributions – docs, tests, features – are welcome 🎉.

---

## 📜 License

[MIT](LICENSE) © 2025 Venkat M

Feel free to use, modify, and distribute under the terms of the MIT license.

---

## 🤝 Acknowledgements

- Built with ❤️ for teams analysing Oracle Cloud security events.
- Inspired by countless late‑night dive‑into‑logs sessions.

