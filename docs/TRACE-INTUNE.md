# Trace VM + IntuneWin Packaging (Cloud Trace v1)

This document covers the **runtime tracing** system that dynamically analyzes Windows installers by running them inside a disposable VMware VM.

It includes:
- Creating the trace VMX (`pkgprobe-trace init-vm`)
- Running a trace (`pkgprobe-trace run`) and producing a **verified trace manifest**
- Packaging into **`.intunewin`** (`pkgprobe-trace pack-intunewin`)
- Optional in-repo FastAPI (`pkgprobe_trace/trace_api.py`) and production **API** endpoints in `api.pkgprobe.io/backend` (API-key gated + TTL caching)

---

## 0) Components

### Worker / CLI (in the `pkgprobe` repo)
- `pkgprobe_trace` Python modules (VM lifecycle, ProcMon capture, diffing, manifest creation, Intune packaging)
- Console script: `pkgprobe-trace`

### Backend API (separate service)
- `api.pkgprobe.io/backend` exposes trace+pack endpoints
- The backend **shells out** to `pkgprobe-trace` and returns:
  - the `.intunewin` artifact, or
  - the verified manifest + reasons (why it can’t be packaged)

---

## 1) Required setup: Windows trace VM (guest)

You will run a Windows Server Core VM configured for headless automation.
The trace workflow depends on a few **exact guest paths**.

### 1.1 Guest directories (must exist)
In the guest, ensure the following folders exist:

- `C:\trace\tools\` (ProcMon lives here)
- `C:\trace\logs\` (ProcMon PML/CSV export lands here)

### 1.2 ProcMon install path (required by default)
Place ProcMon here:
- `C:\trace\tools\procmon.exe`

If your ProcMon is elsewhere, you can override with `pkgprobe-trace run --procmon-path <path>`.

### 1.3 Guest automation credentials (VMware Tools)
`pkgprobe-trace run` uses `vmrun runProgramInGuest` which requires:
- VMware Tools installed in the guest
- A working Windows username/password for the VMware Tools guest operations

---

## 2) Required setup: VMware VM (host)

This system uses **VMware Workstation Pro 16** and controls VMs with `vmrun`.

### 2.1 Host prerequisites
On the VMware host, ensure:
- `vmrun` is available in PATH (or configure it in code later)
- VMware Workstation Pro 16 installed
- Your trace VM has a reusable baseline snapshot

### 2.2 Baseline snapshot requirement (critical)
Before you trace any installer:
- create a snapshot named (example) `TRACE_BASE`
- the trace worker will:
  - `revertToSnapshot <snapshot>`
  - start the VM
  - **wait for VMware Tools** via `vmrun checkToolsState` (polls until Tools report **running**, default timeout 120s; optional extra `--boot-wait` seconds after that)
  - run the installer + ProcMon
  - revert snapshot again for cleanup (unless `--pause-after` — see §4.3)

If the snapshot doesn’t exist, tracing fails.

---

## 3) Create a trace VMX in a sensible location

`vmrun` can control an existing VM, but it cannot reliably create a complete VM from scratch (disk + OS install + tools + snapshots).
So this step generates a **VMX template** and (optionally) creates the VMDK with `vmware-vdiskmanager.exe` if available.

### 3.1 Generate a VMX template (recommended default path)
Run:

```powershell
pkgprobe-trace init-vm
```

This prints the absolute path to the generated VMX, for example under:
- `%LOCALAPPDATA%\pkgprobe\trace-vms\TraceVM\TraceVM.vmx` (typical)

### 3.2 Generate into an explicit folder
```powershell
pkgprobe-trace init-vm --dir "C:\VMs\TraceVM"
```

### 3.3 (Optional) Create `disk.vmdk` using `vmware-vdiskmanager.exe`
If `vmware-vdiskmanager.exe` is installed and discoverable:

```powershell
pkgprobe-trace init-vm --create-disk --disk-size-gb 60
```

If it isn’t found in PATH, provide it:

```powershell
pkgprobe-trace init-vm --create-disk --vdiskmanager "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"
```

### 3.4 What the VMX template contains
The generated VMX sets defaults intended for automation:
- guest OS: `windows9srv-64` (override with `--guest-os`)
- NAT networking using `vmxnet3`
- NAT adapter (`ethernet0.connectionType = "nat"`)
- SCSI controller: `lsisas1068`
- tools sync time enabled: `tools.syncTime = "TRUE"`
- VMX optionally references `disk.vmdk` if you did not disable it

You still must:
1. Attach/install the OS in VMware Workstation
2. Install VMware Tools in the guest
3. Create the baseline snapshot (`TRACE_BASE`)

---

## 4) Run a trace locally (produces InstallPlan + trace contract + draft manifest)

### 4.1 Run command
```powershell
pkgprobe-trace run "C:\path\to\installer.exe" `
  --vmx "C:\VMs\TraceVM\TraceVM.vmx" `
  --snapshot TRACE_BASE `
  --guest-user Administrator `
  --guest-pass "YourPasswordHere" `
  --output "C:\traces\job-001" `
  --silent-args /S `
  --emit-manifest
```

Notes:
- `--silent-args` is a list (default is `["/S"]`)
- Use `--emit-manifest` to write:
  - `trace_contract.json` — portable **install plan + diff** for **api.pkgprobe.io** verification
  - `verified_manifest.json` — **draft** preview (`draft: true`, `verification_authority: local_draft`); not authoritative for packaging
- **Artifact flow:** After stopping ProcMon, the worker copies **PML to the host first**. Then either:
  - **Default:** export `trace.csv` **inside the guest**, then copy CSV to `--output`, or
  - **`--host-procmon`:** run `procmon.exe` **on the host** to convert the copied PML → CSV (same `/OpenLog` / `/SaveAs` style as guest export). If host export fails, the worker falls back to guest export.
- The CLI prints the **InstallPlan JSON** to stdout (this is what the backend parses)

### 4.2 Guest path overrides (only if needed)
If your guest tooling differs:
- `--procmon-path` (default `C:\trace\tools\procmon.exe`)
- `--guest-installer-path` (default `C:\trace\installer.exe`)
- `--guest-pml` / `--guest-csv`

### 4.3 Reliability, diff quality, and debugging (CLI flags)

| Flag | Default | Purpose |
|------|---------|--------|
| `--guest-tools-timeout` | `120` | Max seconds to poll `checkToolsState` until Tools are **running** |
| `--boot-wait` | `0` | Extra seconds to sleep **after** Tools are ready (rarely needed) |
| `--vmrun-retries` | `2` | Extra attempts when a **checked** vmrun operation fails (e.g. copy flakiness) |
| `--host-procmon` | *(empty)* | Host path to `procmon.exe`: PML→CSV on host after PML copy |
| `--baseline-csv` | *(empty)* | Host path to a **baseline** ProcMon CSV (e.g. idle VM, no install); paths in the baseline diff are **subtracted** from the install trace |
| `--pause-after` | off | **skip** the cleanup `revertToSnapshot` so the VM stays up for inspection |

### 4.4 How the diff is built (noise, PID tree, baseline)

- **Noise filters** (`pkgprobe_trace/trace_noise.py`): drop rows from known non-installer processes (ProcMon, VMware Tools daemons, Defender, etc.) and from paths such as `Program Files\VMware\`, `C:\trace\`, drivers, guest `Guest\AppData`, etc.
- **Installer PID tree:** The diff engine uses the **basename of `--guest-installer-path`** (e.g. `installer.exe`) to find root PIDs in the CSV, then keeps **descendant** PIDs via `Parent PID`. If no row matches the installer name, PID filtering is **skipped** (with a warning) so traces are not emptied by mistake.
- **Baseline:** The baseline CSV is **not** PID-filtered (idle traces often have no installer), so path-level subtraction still makes sense.

---

## 5) Authoritative verification (api.pkgprobe.io) vs local draft (OSS)

**Local `pkgprobe-trace`** emits detection **candidates** in `verified_manifest.json` as a **draft** only. Eligibility scoring and “why pass/fail” diagnostics for production Intune workflows are applied **server-side** when the backend ingests `trace_contract.json` and overwrites `verified_manifest.json` on the worker before packaging.

Authoritative verification requires, among other rules:
- a silent command (`silent_args`) is present
- at least one **strong** detection anchor (MSI ProductCode-style uninstall path, Uninstall registry key, or Program Files file)
- strongest anchor confidence >= `0.85` (unless weak-signal fallback is allowed by strictness)

When not eligible, the **API-produced** manifest includes `verification_errors` explaining why.

Detection script generation (`pack-intunewin`) treats `msi_product_code` like a registry key path for `Test-Path`/`HKLM:` normalization.

---

## 6) Package into `.intunewin`

### 6.1 Create `.intunewin` from trace output
```powershell
pkgprobe-trace pack-intunewin `
  --trace-output "C:\traces\job-001" `
  --util "C:\Tools\IntuneWinAppUtil.exe" `
  --out "C:\traces\job-001"
```

This:
1. Reads `verified_manifest.json` from the trace output directory
2. Refuses to package **draft** OSS manifests (`draft: true`) unless `--allow-unverified` / `--community-pack`
3. Refuses to package unless `manifest.verified == true` (authoritative manifests from the API trace flow)
4. Generates:
   - `install.ps1`
   - `detect.ps1`
5. Runs `IntuneWinAppUtil.exe` to produce:
   - `<payload-installer-name>.intunewin`

### 6.2 Unsafe local packaging (`--allow-unverified` / `--community-pack`)

```powershell
pkgprobe-trace pack-intunewin ... --allow-unverified
# or
pkgprobe-trace pack-intunewin ... --community-pack
```

The **api.pkgprobe.io** worker does not use these flags. Production `.intunewin` uses server-side verification only.

---

## 7) In-repo HTTP API (`pkgprobe_trace/trace_api.py`)

The `pkgprobe` package includes a thin **FastAPI** wrapper around `TraceWorker` for local or trusted-network use. It is **not** the same deployment as the production `api.pkgprobe.io` service (which adds tenancy, API keys, caching, and may lag behind CLI flags).

When extending the public backend, mirror new `TraceWorkerConfig` / CLI options in the backend’s trace runner as needed.

---

## 8) API usage (api.pkgprobe.io/backend) — API key only + feature flags

The backend runs trace+pack on a Windows host and gates dangerous compute using:
- API keys (not sessions) by default
- feature flags

### 8.1 Feature flags & required env (backend)
On the API host, configure:

VMware trace:
- `TRACE_VMWARE_ENABLED=true`
- `TRACE_VMX_PATH=C:\VMs\TraceVM\TraceVM.vmx`
- `TRACE_SNAPSHOT_NAME=TRACE_BASE`
- `TRACE_GUEST_USERNAME=Administrator`
- `TRACE_GUEST_PASSWORD=...`
- `TRACE_CLI_PATH=pkgprobe-trace` (or full path to the exe/script)

API key requirement:
- `TRACE_REQUIRES_API_KEY=true` (default)

Intune packaging endpoints:
- `TRACE_INTUNEWIN_ENABLED=true` (enables artifact endpoint)
- `TRACE_INTUNEWIN_MANIFEST_ENABLED=true` (enables manifest+reasons endpoint)

Intune packaging tool:
- `INTUNEWIN_UTIL_PATH` (defaults to `IntuneWinAppUtil.exe`)

TTL caching:
- `trace_intunewin_ttl_seconds` controls cleanup window (default: 7 days)
- artifacts are stored under `trace_intunewin_artifact_dir`

> Exact env var names map 1:1 to backend settings in `app/core/config.py`.

### 8.2 Request format
For all endpoints below:
- Upload with `multipart/form-data`
- field name: `file`
- header:
  - `X-API-Key: <your key>`
  - optional: `X-Workspace-Id: <workspace id>`

Silent install selection:
- `try_silent` (bool, optional)
- `attempt` can be provided multiple times (repeatable form field) to override silent arg strings

### 8.3 Endpoints

#### A) Manifest + eligibility reasons
`POST /v1/trace-install/intunewin/manifest`
Returns JSON:
- `trace_id`
- `installplan`
- `manifest`
- `eligible_for_intunewin`
- `reasons` (mirrors `manifest.verification_errors`)

#### B) Return cached or newly-produced `.intunewin`
`POST /v1/trace-install/intunewin`
Returns the file:
- `application/octet-stream`
- `filename` = produced `.intunewin`

The backend:
- first checks the cache for an **unexpired eligible** artifact for the same `workspace_id + sha256`
- otherwise runs trace+pack and then stores the artifact with TTL

#### C) List cached artifacts
`GET /v1/trace-install/intunewin/artifacts?sha256=<optional>&limit=<n>`

#### D) Download cached artifact
`GET /v1/trace-install/intunewin/artifacts/{artifact_id}`

---

## 9) Cloud replication design notes

To make this replicable across cloud VM fleets:
- the trace worker writes deterministic, job-scoped artifacts into the `--output` directory
- verified manifest + installplan act as a **portable contract** between trace and packaging
- the backend (API service) does not depend on VM internals; it only depends on the CLI contract:
  - “run trace → JSON on stdout + verified_manifest.json”
  - “pack-intunewin → `.intunewin` path on stdout”

To run this in cloud later:
- implement a cloud worker backend that replaces `pkgprobe-trace run` orchestration
- keep the **trace_contract → policy engine → verified_manifest → pack** workflow identical

### Contract between worker and API

- OSS worker writes **`trace_contract.json`** next to trace outputs.
- **api.pkgprobe.io** reads it, runs **verification policy**, writes authoritative **`verified_manifest.json`**, then runs **`pack-intunewin`** (never `--allow-unverified`).

