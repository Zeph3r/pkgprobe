## pkgprobe


**pkgprobe** is a Windows installer intelligence toolkit for endpoint teams.

It combines:
- **static analysis** (`pkgprobe analyze`) for fast, no-exec prediction of
  silent install commands, detection rules, and uninstall guidance
- **optional runtime verification** (`pkgprobe-trace`) that executes installers
  in disposable VMware snapshots, captures ProcMon-backed system changes, and
  generates verified outputs (including `.intunewin` packaging artifacts)

Think: reliable package intelligence for Intune, SCCM, Jamf, RMM, and Client
Platform Engineering workflows.

Available on [PyPI](https://pypi.org/project/pkgprobe/).

**[Full usage documentation](docs/USAGE.md)** — Commands, options, output formats, and trace-install behavior.

**Trace + Intune packaging (VMware ProcMon trace → verified manifest → `.intunewin`)**:
**[Full trace/intunewin documentation](docs/TRACE-INTUNE.md)**.

------------------------------------------------------------------------

## ✨ Why pkgprobe exists

Packaging software on Windows is still more art than science:

-   Silent install flags are undocumented or inconsistent
-   Installer technologies vary widely (Inno, NSIS, InstallShield, Burn,
    etc.)
-   Detection rules are often copied, guessed, or discovered via
    trial-and-error
-   Testing installers directly is slow and risky on production machines

**pkgprobe** is static-first by design:

> Understand what an installer is likely to do before execution, then
> optionally verify behavior in an isolated VM when confidence needs to be
> production-grade.

------------------------------------------------------------------------

## What it does (v0.1)

Given an `.msi` or `.exe`, pkgprobe outputs a structured **install
plan** containing:

### Installer intelligence

-   Detects installer type (MSI, Inno Setup, NSIS, InstallShield, Burn,
    Squirrel, etc.)
-   Confidence-scored classification with supporting evidence

### Command inference

-   Probable silent install commands, ranked by confidence
-   Probable uninstall commands
-   Evidence explaining why each command was suggested

### Detection guidance

-   MSI ProductCode--based detection (when available)
-   Follow-up guidance for improving detection accuracy
-   Designed to integrate cleanly into Intune / SCCM detection logic

### Automation-friendly output

-   JSON output suitable for pipelines and tooling
-   Human-readable CLI summary for engineers

### Optional runtime trace + packaging

-   `pkgprobe-trace run` executes installers in a disposable VMware VM
    snapshot and captures ProcMon trace data
-   **Guest readiness** uses `vmrun checkToolsState` polling (bounded wait)
    instead of a fixed sleep; optional extra delay via `--boot-wait`
-   **Diff quality:** built-in filters drop common VM/ProcMon noise (VMware
    Tools paths, trace tooling, noisy processes); optional **installer PID
    tree** filtering (ProcMon `PID` / `Parent PID`); optional **baseline CSV**
    subtraction (idle VM capture) to remove boot/OS noise
-   **Reliability:** `vmrun` retries on failed copy/guest operations
-   **Performance:** copy PML to the host first and export CSV with
    `--host-procmon` (local `procmon.exe`) instead of exporting only in the guest
-   **Debugging:** `--pause-after` skips the cleanup snapshot revert so you can
    inspect the VM
-   Produces a **verified trace manifest** with strong detection anchors
    (including **MSI ProductCode**-style `Uninstall\{GUID}` keys when seen)
    and eligibility reasons
-   `pkgprobe-trace pack-intunewin` can generate `.intunewin` artifacts
    from verified traces

**Safety-first by design**\
Default `pkgprobe analyze` is still **static analysis only** (no execution).\
Runtime execution is opt-in and isolated in a disposable VM workflow.

------------------------------------------------------------------------

## Example

``` powershell
pkgprobe analyze .\setup.exe --out installplan.json
```

![demo1](https://github.com/user-attachments/assets/7426fbbf-48f4-4448-80ca-7bc5ff9936ec)

CLI summary:

    Type: Inno Setup (confidence 0.92)

    Install candidates:
      setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- (0.88)
      setup.exe /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-     (0.62)

    Uninstall candidates:
      unins000.exe /VERYSILENT (0.55)

Generated `installplan.json` (excerpt):

``` json
{
  "installer_type": "Inno Setup",
  "confidence": 0.92,
  "install_candidates": [
    {
      "command": "setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-",
      "confidence": 0.88
    }
  ]
}
```

Runtime trace + manifest example:

```powershell
pkgprobe-trace run .\setup.exe `
  --vmx "C:\VMs\TraceVM\TraceVM.vmx" `
  --snapshot TRACE_BASE `
  --guest-user Administrator `
  --guest-pass "..." `
  --output "C:\traces\job-001" `
  --silent-args /S `
  --emit-manifest
```

Optional flags (see [docs/TRACE-INTUNE.md](docs/TRACE-INTUNE.md)): for example
`--baseline-csv` (subtract an idle trace), `--host-procmon` (export PML→CSV on
the host), `--vmrun-retries`, `--pause-after`, `--guest-tools-timeout`.

------------------------------------------------------------------------

## Installation

### From PyPI (recommended)

``` powershell
pip install pkgprobe
pkgprobe --version
pkgprobe analyze .\setup.exe --out installplan.json
```

### From source (development)

This project uses **uv** for fast, reproducible Python environments.

``` powershell
pip install uv
git clone https://github.com/Zeph3r/pkgprobe.git
cd pkgprobe
uv venv
uv sync
uv run pkgprobe --help
```

Use `--quiet` / `-q` to suppress the banner when scripting (CI,
pipelines, etc.).

For runtime tracing and Intune packaging setup, see:
- [docs/TRACE-INTUNE.md](docs/TRACE-INTUNE.md)

------------------------------------------------------------------------

## Supported inputs

  File type     Status   Notes
  ------------- -------- -----------------------------------------------------
  MSI           ✅       Metadata parsed via Windows Installer APIs
  EXE           ✅       Heuristic detection via string & signature analysis
  MSIX / AppX   🔍       Detection hints only (wrapper detection)

------------------------------------------------------------------------

## How detection works

pkgprobe combines:

-   Static string extraction (ASCII + UTF-16LE)
-   Known installer signature patterns
-   Heuristic confidence scoring
-   Evidence tracking (matched strings, metadata clues)

This keeps analysis **fast, safe, and explainable**.

------------------------------------------------------------------------

## Current limitations

-   Windows-first (intentional --- this targets Windows endpoints)
-   EXE analysis is heuristic-based (not guaranteed)
-   Runtime tracing currently targets VMware Workstation-based Windows
    workers (cloud worker backends are future architecture)
-   `pkgprobe-trace` requires guest preparation (VMware Tools, ProcMon,
    baseline snapshot)
-   Trace diffs are **heuristic** (ProcMon CSV); PID-tree and baseline options
    improve signal but are not a substitute for full process-tree replay

------------------------------------------------------------------------

## Roadmap

### v0.2.0 (next)

**CLI UX**

-   JSON to stdout -- Support `pkgprobe analyze <file> --format json`
    (or `-o -`) for pipeline consumption
-   `--summary-only` -- Print only human summary (no file output)
-   Exit codes -- Standardized scripting-friendly exit codes
-   Subcommand examples in `--help`

**Output & format**

-   `--format yaml` -- Optional YAML install plan output

**Later (v0.3.0+)**

-   install4j / Java-based installer detection
-   Partial-read scanning for very large EXEs
-   Cloud VM backends for trace workers
-   Queue-native multi-job orchestration for trace + packaging

------------------------------------------------------------------------

## Who this is for

-   Client Platform Engineers
-   Endpoint / EUC Engineers
-   Intune / SCCM / Jamf admins
-   Security teams validating installer behavior
-   Anyone tired of guessing silent install flags

------------------------------------------------------------------------

## Philosophy

pkgprobe is intentionally conservative.

It prefers:

-   Explainability over magic
-   Confidence scoring over certainty
-   Safety over speed

If it can't be confident, it tells you *why*.

That's how real platform tooling should behave.

------------------------------------------------------------------------

## License

MIT
