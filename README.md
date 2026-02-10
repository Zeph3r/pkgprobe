# installer-intel

**installer-intel** is a Windows-first CLI tool that statically analyzes
EXE and MSI installers and produces a **machine-readable install plan**
for endpoint management and packaging workflows.

Think: *package intelligence* for Intune, SCCM, Jamf, RMM, and
Client Platform Engineering teams.

Available on PyPI: https://pypi.org/project/installer-intel/

---

## Why installer-intel exists

Packaging software on Windows is still more art than science:

- Silent install flags are undocumented or inconsistent
- Installer technologies vary widely (Inno, NSIS, InstallShield, Burn, etc.)
- Detection rules are often copied, guessed, or discovered via trial-and-error
- Testing installers directly is slow and risky on production machines

**installer-intel** focuses on the analysis phase first.

> Understand what an installer is likely to do — *before* you ever run it.

---

## What it does (v0.1)

Given an `.msi` or `.exe`, installer-intel outputs a structured
**install plan** suitable for automation and review.

### Installer intelligence

- Detects installer type (MSI, Inno Setup, NSIS, InstallShield, Burn, Squirrel, etc.)
- Confidence-scored classification with supporting evidence

### Command inference

- Probable silent install commands, ranked by confidence
- Probable uninstall commands
- Evidence explaining why each command was suggested

### Detection guidance

- MSI ProductCode–based detection (when available)
- Follow-up guidance for improving detection accuracy
- Designed to integrate cleanly into Intune / SCCM detection logic

### Automation-friendly output

- JSON output suitable for pipelines and tooling
- Human-readable CLI summary for engineers

**Safety-first by design**  
This version performs **static analysis only**.  
No installers are executed.

---

## Example

![installer-intel CLI analysis of MSTeamsSetup.exe](img/demo1.gif)

```powershell
installer-intel analyze .\setup.exe --out installplan.json
```



CLI summary:

```
Type: Inno Setup (confidence 0.92)

Install candidates:
  setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- (0.88)
  setup.exe /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-     (0.62)

Uninstall candidates:
  unins000.exe /VERYSILENT (0.55)
```

Generated `installplan.json` (excerpt):

```json
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

---

## Installation

### From PyPI (recommended)

```powershell
pip install installer-intel
installer-intel --version
installer-intel analyze .\setup.exe --out installplan.json
```

### From source (development)

This project uses **uv** for fast, reproducible Python environments.

```powershell
pip install uv
git clone https://github.com/Zeph3r/installer-intel.git
cd installer-intel
uv venv
uv sync
uv run installer-intel --help
```

Use `--quiet` / `-q` to suppress the banner when scripting (CI, pipelines, etc.).

---

## Supported inputs

| File type | Status | Notes |
|----------|--------|------|
| MSI | ✅ | Metadata parsed via Windows Installer APIs |
| EXE | ✅ | Heuristic detection via string & signature analysis |
| MSIX / AppX | 🔍 | Detection hints only (wrapper detection) |

---

## How detection works

installer-intel combines:

- Static string extraction (ASCII + UTF-16LE)
- Known installer signature patterns
- Heuristic confidence scoring
- Evidence tracking (matched strings, metadata clues)

This keeps analysis **fast, safe, and explainable**.

---

## Current limitations

- Windows-first (intentional — this targets Windows endpoints)
- EXE analysis is heuristic-based (not guaranteed)
- No execution or sandbox tracing in v0.1
- Detection accuracy improves significantly with runtime tracing (planned)

---

## Roadmap

Planned enhancements:

- [x] MSI parsing via Windows Installer COM (ProductCode, UpgradeCode, Version)
- [ ] install4j / Java-based installer detection
- [ ] Partial-read scanning for very large EXEs
- [ ] ProcMon-backed trace mode to summarize filesystem, registry, service, and persistence changes
- [ ] `--format yaml`
- [ ] `--summary-only`
- [ ] Optional sandboxed execution mode (opt-in)

---

## Who this is for

- Client Platform Engineers
- Endpoint / EUC Engineers
- Intune / SCCM / Jamf admins
- Security teams validating installer behavior
- Anyone tired of guessing silent install flags

---

## Philosophy

installer-intel is intentionally conservative.

It prefers:

- Explainability over magic
- Confidence scoring over certainty
- Safety over speed

If it can’t be confident, it tells you *why*.

That’s how real platform tooling should behave.

---

## License

MIT
