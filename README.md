<img width="300" height="300" alt="image" src="https://github.com/user-attachments/assets/e2944351-0bb1-4ac6-b2c7-e7643231b9f2" />


**pkgprobe** is a Windows-first CLI tool that statically analyzes EXE
and MSI installers and produces a **machine-readable install plan** for
endpoint management and packaging workflows.

Think: *package intelligence* for Intune, SCCM, Jamf, RMM, and Client
Platform Engineering teams.

Available on [PyPI](https://pypi.org/project/pkgprobe/).

------------------------------------------------------------------------

## ✨ Why pkgprobe exists

Packaging software on Windows is still more art than science:

-   Silent install flags are undocumented or inconsistent
-   Installer technologies vary widely (Inno, NSIS, InstallShield, Burn,
    etc.)
-   Detection rules are often copied, guessed, or discovered via
    trial-and-error
-   Testing installers directly is slow and risky on production machines

**pkgprobe** focuses on the *analysis* phase first:

> Understand what an installer is likely to do --- *before* you ever run
> it.

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

**Safety-first by design**\
This version performs **static analysis only**.\
No installers are executed.

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
-   No execution or sandbox tracing in v0.1
-   Detection accuracy improves significantly with runtime tracing
    (planned)

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
-   ProcMon-backed trace mode
-   Optional trace-install mode (opt-in, sandboxed)

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
