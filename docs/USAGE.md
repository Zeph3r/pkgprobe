# pkgprobe — Full Usage Documentation

**pkgprobe** is a Windows-first CLI for static installer analysis and optional trace-install validation. This document describes installation, all commands, options, output formats, and behavior.

---

## Table of contents

1. [Installation](#installation)
2. [Quick reference](#quick-reference)
3. [Global options](#global-options)
4. [Commands](#commands)
   - [analyze](#analyze)
   - [schema](#schema)
   - [trace-install](#trace-install)
5. [Output formats](#output-formats)
6. [Trace-install in depth](#trace-install-in-depth)
7. [Limitations and platform notes](#limitations-and-platform-notes)

---

## Installation

### From PyPI (recommended)

```powershell
pip install pkgprobe
pkgprobe --version
```

### From source (development)

```powershell
pip install uv
git clone https://github.com/Zeph3r/pkgprobe.git
cd pkgprobe
uv sync
uv run pkgprobe --help
```

Optional dev dependencies (for tests):

```powershell
uv sync --extra dev
uv run pytest -v
```

---

## Quick reference

| Command | Purpose |
|--------|---------|
| `pkgprobe` | Show banner (interactive only) |
| `pkgprobe --version` | Print version and exit |
| `pkgprobe analyze <path>` | Static analysis → InstallPlan JSON + summary |
| `pkgprobe schema` | Print InstallPlan JSON schema |
| `pkgprobe trace-install <path> --bundle-out <file>` | Run trace session → .pkgtrace bundle |
| `pkgprobe-trace init-vm` | Generate a VMware TraceVM `.vmx` template |
| `pkgprobe-trace run` | Run VMware trace → InstallPlan JSON (+ optional verified manifest) |
| `pkgprobe-trace pack-intunewin` | Package verified trace into `.intunewin` |

---

## Global options

These apply at the top level (before any subcommand).

| Option | Short | Description |
|--------|-------|-------------|
| `--version` | `-v` | Print pkgprobe version and exit. No banner, no subcommand. |
| `--help` | `-h` | Show help. Suppresses banner. |

Running `pkgprobe` with no subcommand and no `--version` shows the startup banner (only when stdout is a TTY and `CI` is not set). Use `--quiet` on individual commands (e.g. `analyze`) to suppress the banner when scripting.

---

## Commands

### analyze

Statically analyzes an MSI or EXE installer and produces an **InstallPlan**: installer type, confidence, install/uninstall command candidates, detection rules, and notes. No installer is executed.

**Usage:**

```text
pkgprobe analyze PATH [--out PATH] [--quiet] [--cve-check]
```

**Arguments**

| Argument | Required | Description |
|----------|----------|-------------|
| `PATH` | Yes | Path to a `.msi` or `.exe` file. |

**Options**

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--out` | `-o` | `./installplan.json` | Path where the InstallPlan JSON is written. |
| `--quiet` | `-q` | `false` | Suppress banner (for CI and scripting). |
| `--cve-check` | — | `false` | Query NVD (NIST) for known CVEs affecting the identified product. Best-effort; requires product metadata. Uses NVD API v2. |

**Behavior**

- **MSI:** Reads Property table (ProductCode, UpgradeCode, ProductVersion, ProductName, Manufacturer) via Windows Installer APIs. Produces high-confidence install (`msiexec /i ... /qn`) and uninstall (`msiexec /x {ProductCode} /qn`) candidates and MSI ProductCode detection rules.
- **EXE:** Uses signature-based heuristics (Inno Setup, NSIS, InstallShield, Burn, etc.) and returns installer type, confidence, and heuristic install/uninstall commands. No execution.
- **CVE check (optional):** With `--cve-check`, queries NVD API v2 (keyword-first for MSI, CPE fallback when all of Manufacturer, ProductName, ProductVersion exist and keyword is low-confidence). EXE: keyword only when ProductName metadata exists; otherwise skipped. Results are cached under `~/.pkgprobe/cache/cve/` for 24 hours. Up to 20 CVEs, sorted by CVSS and publish date. Optional `NVD_API_KEY` env improves rate limits.

**Output**

- Writes InstallPlan JSON to the path given by `--out` (or `installplan.json`).
- Prints a human-readable summary: type, confidence, metadata table, install/uninstall candidates, detection rules, notes.

**Example**

```powershell
pkgprobe analyze .\setup.exe --out installplan.json
pkgprobe analyze .\product.msi -o plan.json -q
```

---

### schema

Prints the **JSON schema** for the InstallPlan model (Pydantic-generated). Useful for tooling and validation.

**Usage:**

```text
pkgprobe schema
```

No arguments or options. Output is the schema to stdout (Rich JSON).

---

### trace-install

Runs a **trace session** for an installer: preflight (hash, metadata), optional execution with one or more silent-switch attempts, and writes a **.pkgtrace** bundle. Used to validate silent install behavior and capture trace metadata.

**Usage:**

```text
pkgprobe trace-install INSTALLER --bundle-out PATH [options]
```

**Arguments**

| Argument | Required | Description |
|----------|----------|-------------|
| `INSTALLER` | Yes | Path to a `.msi` or `.exe` installer. |

**Options**

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--bundle-out` | `-b` | *(required)* | Path for the output `.pkgtrace` file. |
| `--privacy-profile` | — | `community` | Privacy profile in bundle manifest: `community`, `team`, or `enterprise`. |
| `--attempt` | `-a` | *(none)* | Silent switch string to try. Can be repeated. Takes precedence over `--try-silent`. |
| `--try-silent` | — | `false` | Use heuristic silent switches (MSI vs EXE, EXE subtype). Ignored if `--attempt` is used. |
| `--no-exec` | — | `false` | Do not run the installer; preflight only and synthetic attempts (for dry-run and CI). |

**Attempt selection**

- If **`--attempt`** is provided (one or more times): those switch strings are used in order.
- Else if **`--try-silent`**: switch list comes from the candidate layer (MSI: `/qn`, `/quiet`, `/passive`; EXE: subtype-aware ordering, e.g. NSIS `/S`, Inno `/VERYSILENT`, `/SILENT`, etc.), sorted by weight.
- Else: **single attempt with no switch** (interactive-style run).

**Output**

- **Trace Summary** panel: installer path, trace ID, SHA256, selected attempt index and score. With `--no-exec`, an extra line states that execution was disabled.
- **Attempts** table: index, switch, exit code, duration, score, selected flag.
- Writes the **.pkgtrace** bundle to `--bundle-out`.

**Examples**

```powershell
# Dry-run: no execution, only preflight and attempt list (e.g. from --try-silent)
pkgprobe trace-install .\setup.exe --bundle-out trace.pkgtrace --no-exec --try-silent

# Single attempt with no switch (interactive)
pkgprobe trace-install .\installer.msi --bundle-out out.pkgtrace

# Explicit silent switches
pkgprobe trace-install .\setup.exe -b out.pkgtrace -a /S -a /quiet

# Heuristic silent attempts (execution enabled)
pkgprobe trace-install .\setup.exe --bundle-out out.pkgtrace --try-silent
```

---

## Output formats

### InstallPlan (analyze)

JSON written to `--out` (default `installplan.json`). Main fields:

| Field | Type | Description |
|-------|------|-------------|
| `input_path` | string | Path passed to `analyze`. |
| `file_type` | string | `"msi"` or `"exe"`. |
| `installer_type` | string | e.g. `"MSI"`, `"Inno Setup"`, `"NSIS"`. |
| `confidence` | number | 0–1. |
| `metadata` | object | File or MSI properties. |
| `install_candidates` | array | `{ "command", "confidence", "evidence" }`. |
| `uninstall_candidates` | array | Same shape. |
| `detection_rules` | array | `{ "kind", "value", "confidence", "evidence" }`. |
| `notes` | array | Strings (e.g. signature hits). |

Use `pkgprobe schema` to get the full JSON schema.

### .pkgtrace bundle (trace-install)

A ZIP file containing:

| Member | Description |
|--------|-------------|
| `manifest.json` | Schema version, trace ID, installer SHA256, filename, size, timestamp, OS version, privacy profile. |
| `summary.json` | Attempts (index, switch, exit_code, duration_ms, success_score), selected_attempt_index, install_success_score, optional msiexec_pivot, uninstall_entries, file_roots, etc. |
| `events.ndjson.gz` | Gzipped NDJSON of trace events (e.g. process_start, process_exit). |

Success scoring (per attempt): exit code in `{0, 3010}`, new uninstall entries, and MSI pivot detection contribute to a 0–1 score. The session selects the best attempt and can stop early when score ≥ 0.85 or when new uninstall entries appear.

---

## Trace-install in depth

### Flow

1. **Preflight** — SHA256, size, OS version, trace ID. No execution if `--no-exec`.
2. **Attempt list** — From `--attempt`, or from `--try-silent` (weighted candidates by family and EXE subtype), or default single `""`.
3. **Execution (unless `--no-exec`)** — For each attempt: run installer with the switch string, poll for `msiexec` child (Windows), collect process events, diff uninstall registry and file roots before/after, compute score. Early exit on high score or new uninstall entries.
4. **Bundle** — Write manifest, summary, and events to the `.pkgtrace` path.

### Silent switch heuristics (--try-silent)

- **MSI:** `/qn`, `/quiet`, `/passive` (ordered by weight).
- **EXE:** Subtype from binary scan (Nullsoft → NSIS, “Inno Setup” → Inno, “InstallShield” → InstallShield). Then:
  - **NSIS:** `/S` first, then fallbacks.
  - **Inno:** `/VERYSILENT`, `/SILENT` first.
  - **InstallShield:** `/quiet`, `/s` first.
  - **Generic EXE:** `/S` first.
- Filename containing `"bootstrapper"` boosts `/quiet` weight. Results are sorted by weight descending.

### No-exec mode

With `--no-exec`, the installer is never run. Preflight runs; the attempt list (from `--attempt` or `--try-silent`) is honored and one synthetic attempt per switch is emitted (exit 0, duration 0, score 0). Useful for checking candidate list and CLI output without executing anything.

---

## Limitations and platform notes

- **Windows-first:** MSI analysis uses Windows Installer APIs; trace-install uses Windows registry and PowerShell/CIM for msiexec detection. On non-Windows, MSI metadata and trace behavior are limited or empty.
- **EXE analysis:** Heuristic and signature-based; not guaranteed for all packagers.
- **trace-install execution:** Runs the real installer; no elevation. Installers that require admin may prompt UAC or fail in a non-elevated shell. Timeout applies (default 600 s).
- **Switch parsing:** Single attempt string is split naively (`switch.split()`); complex quoted arguments may not be preserved.
- **Banner:** Shown only when stdout is a TTY and `CI` is not set; use `--quiet` on `analyze` for scripted use.

---
## Trace + Intune packaging (runtime trace mode)

This repository also includes a separate CLI for **runtime execution inside disposable VMware VMs**:

- `pkgprobe-trace init-vm` (generate VMX + optional disk)
- `pkgprobe-trace run` (VM snapshot → install → ProcMon capture → diff → InstallPlan + verified manifest)
- `pkgprobe-trace pack-intunewin` (create `.intunewin` using IntuneWinAppUtil)

For the full, step-by-step setup (VMX + guest filesystem paths, snapshot naming, backend feature flags, and API endpoints),
see: **[Trace VM + Intune packaging docs](TRACE-INTUNE.md)**.

---

## See also

- [README](../README.md) — Overview, examples, roadmap.
- [GitHub](https://github.com/Zeph3r/pkgprobe) — Source and issues.
- [PyPI](https://pypi.org/project/pkgprobe/) — Package install.
