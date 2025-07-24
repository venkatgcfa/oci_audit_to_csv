# OCI Audit Log Extractor

`oci_audit_to_csv.py` is a high‑performance, memory‑efficient tool for converting raw Oracle Cloud (OCI) audit‑log JSON files (https://docs.oracle.com/en-us/iaas/Content/Audit/Reference/logeventreference.htm#Contents_of_an_Audit_Log_Event) into two CSV outputs:

1. **Full CSV** (`<prefix>_full.csv`) – every field discovered in all events
2. **Forensic CSV** (`<prefix>_forensic.csv`) – only the critical fields recommended for security investigations

---

## 📖 Key Features

* **Complete Schema Coverage** – discovers and flattens **all** JSON fields across your logs in a first parallel pass.
* **Forensic‑Ready Fields** – extracts the OCI‑documented envelope, identity (including delegation), request/response, state‑change, and additional‑details fields.
* **Two‑Pass Pipeline** –

  1. **Header Discovery** (multithreaded) to collect every column
  2. **Streaming Write** to two CSVs to keep memory usage low
* **Wildcard Forensics** – automatically expands nested state‑change fields (`data.state-change.previous.*`, `data.state-change.current.*`).
* **Configurable Parallelism** – speed up parsing with `--threads N`.
* **Robust Error Handling** – skips malformed JSON files with warnings, without stopping the pipeline.

---

## 🚀 Installation

```bash
# clone the repo
git clone https://github.com/venkatgcfa/oci_audit_to_csv.git
cd oci-audit-extractor

# (optional) set up a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# install dependencies (if you add any beyond stdlib)
pip install --upgrade pip
pip install pandas
```

---

## 🎯 Usage

```bash
python oci_audit_to_csv.py <input_folder> [output_prefix] [--threads N]
```

* `<input_folder>`: path to directory containing `*.json` audit files
* `output_prefix`: prefix for generated CSVs (defaults to `audit_logs`)
* `--threads N`: number of worker threads for header discovery (default `4`)

**Examples**

```bash
# simple run, writes audit_logs_full.csv & audit_logs_forensic.csv
python oci_audit_to_csv.py ./IAMauditLogs

# custom prefix and 8 threads
python oci_audit_to_csv.py ./IAMauditLogs my_audit --threads 8
```

---

## 📋 Forensic Fields Extracted

The forensic CSV includes these key fields (per OCI Audit Event Reference):

```
cloud-events-version
content-type
event-type
event-type-version
source
event-id
event-time

data.event-name
data.compartment-id
data.compartment-name
data.event-grouping-id

data.identity.auth-type
data.identity.principal-id
data.identity.principal-name
data.identity.caller-id
data.identity.caller-name
data.identity.console-session-id
data.identity.tenant-id
data.identity.ip-address
data.identity.user-agent

data.request.action
data.request.path
data.request.headers.X-Forwarded-For

data.response.status
data.response.message

data.resource-id
data.resource-name

data.additional-details
[data.state-change.previous.*]
[data.state-change.current.*]
```

Fields in square brackets indicate dynamic expansion of nested keys.

---

## 🔧 Customization

* **Adjust forensic fields** by editing the `FORENSIC_FIELDS` list in `oci_audit_to_csv.py`.
* **Add sample logs** under `samples/` for testing or demos.
* Integrate into CI by running smoke tests on `samples/` via GitHub Actions.

---

## 📄 License

This project is licensed under the MIT License.
© 2025 Venkat M
