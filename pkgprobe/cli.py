from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Literal, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pkgprobe import __version__
from pkgprobe.analyzers import analyze_exe, analyze_msi
from pkgprobe.banner import show_banner, should_show_banner
from pkgprobe.enrichment import enrich_with_cves
from pkgprobe.models import InstallPlan
from pkgprobe.trace.bundle import write_pkgtrace
from pkgprobe.trace.candidates import suggest_silent_attempts
from pkgprobe.trace.session import TraceSession

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version_flag: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show the pkgprobe version and exit.",
    ),
) -> None:
    """
    Global entrypoint for the CLI.

    - Handles --version at the top level.
    - Shows the banner only for interactive runs with no subcommand
      (i.e. `pkgprobe`), not for --help/--version.
    """
    if version_flag:
        console.print(__version__)
        raise typer.Exit(0)

    # Suppress banner when help is requested explicitly
    argv = sys.argv[1:]
    if any(arg in ("-h", "--help") for arg in argv):
        return

    if ctx.invoked_subcommand is None and should_show_banner(quiet=False):
        show_banner()


def _write_json(plan: InstallPlan, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")


def _tier_routing_text(plan: InstallPlan) -> list[str]:
    """Build actionable next-step lines based on packaging tier."""
    d = plan.deployment
    if d is None:
        return []
    lines: list[str] = []
    tier = d.packaging_tier
    cmd = d.suggested_command
    path = plan.input_path

    if tier == "simple":
        if cmd:
            lines.append(f"[green]->[/green] Try silent install: [bold]{cmd}[/bold]")
        else:
            lines.append("[green]->[/green] Silent install should work with standard switches.")

    elif tier == "pro":
        if cmd:
            lines.append(f"[yellow]->[/yellow] Try silent install: [bold]{cmd}[/bold]")
        lines.append(
            f"[yellow]->[/yellow] If it fails, run trace:  "
            f"[bold]pkgprobe trace-install \"{path}\" --bundle-out trace.pkgtrace --try-silent[/bold]"
        )
        if "msix" in plan.installer_type.lower() or "appx" in plan.installer_type.lower():
            lines.append("[yellow]->[/yellow] Consider native MSIX deployment via Add-AppxPackage")

    elif tier == "auto_wrap":
        lines.append("[red]->[/red] This installer is high-risk for silent deployment.")
        lines.append(
            f"[red]->[/red] Run trace:  "
            f"[bold]pkgprobe trace-install \"{path}\" --bundle-out trace.pkgtrace --try-silent[/bold]"
        )
        lines.append(
            "[red]->[/red] Or use auto-wrap ([bold]api.pkgprobe.io[/bold]) for automated repackaging."
        )

    return lines


def _print_clean_summary(plan: InstallPlan, cve_check_requested: bool = False) -> None:
    """Default user-facing output: concise, actionable."""
    console.print()

    conf_tier = "High"
    if plan.family_result:
        conf_tier = plan.family_result.confidence_tier.capitalize()
    elif plan.confidence >= 0.75:
        conf_tier = "High"
    elif plan.confidence >= 0.50:
        conf_tier = "Medium"
    else:
        conf_tier = "Low"

    console.print(f"  [bold]Installer:[/bold] {plan.installer_type:<24} [bold]Confidence:[/bold] {conf_tier}")

    if plan.deployment:
        d = plan.deployment
        risk_color = {"low": "green", "moderate": "yellow", "high": "red"}.get(d.deployment_risk, "white")
        console.print(f"  [bold]Deployment Risk:[/bold] [{risk_color}]{d.deployment_risk.capitalize()}[/{risk_color}]")

    console.print()

    routing = _tier_routing_text(plan)
    if routing:
        console.print("  [bold]Recommended next step:[/bold]")
        for line in routing:
            console.print(f"  {line}")
        console.print()

    if plan.deployment:
        d = plan.deployment
        tier_label = {"simple": "Simple", "pro": "Pro", "auto_wrap": "Auto-Wrap"}.get(d.packaging_tier, d.packaging_tier)
        tier_color = {"simple": "green", "pro": "yellow", "auto_wrap": "red"}.get(d.packaging_tier, "white")
        console.print(f"  [bold]Packaging tier:[/bold] [{tier_color}]{tier_label}[/{tier_color}]")
        if d.tier_reason:
            console.print(f"  [dim]({d.tier_reason})[/dim]")
        console.print()

    if cve_check_requested:
        _print_cve_summary(plan)


def _print_verbose_detail(plan: InstallPlan) -> None:
    """Extended detail tables shown only with --verbose."""
    console.print()
    console.print(Panel.fit(f"[bold]pkgprobe[/bold]  verbose detail\n{plan.input_path}", title="Detail"))

    console.print(f"[bold]Type:[/bold] {plan.installer_type}  (confidence {plan.confidence:.2f})")
    console.print(f"[bold]File:[/bold] {plan.file_type}")

    if plan.family_result:
        fr = plan.family_result
        console.print(
            f"[bold]Family:[/bold] {fr.family}  "
            f"[bold]Tier:[/bold] {fr.confidence_tier}  "
            f"(confidence {fr.confidence:.2f})"
        )
        if fr.evidence:
            ev_parts = [f"{e.detail}" for e in fr.evidence]
            console.print(f"[bold]Evidence:[/bold] {', '.join(ev_parts)}")
        if fr.alternatives_considered:
            alt_parts = [
                f"{a['family']} ({a.get('rejection_reason', 'rejected')})"
                for a in fr.alternatives_considered
            ]
            console.print(f"[dim]Also considered: {'; '.join(alt_parts)}[/dim]")

    console.print(
        f"[bold]Silent viability:[/bold] {plan.silent_viability}   "
        f"[bold]Recommendation:[/bold] {plan.recommendation}"
    )

    if plan.deployment:
        d = plan.deployment
        risk_color = {"low": "green", "moderate": "yellow", "high": "red"}.get(d.deployment_risk, "white")
        console.print(
            f"[bold]Deployment risk:[/bold] [{risk_color}]{d.deployment_risk}[/{risk_color}]   "
            f"[bold]Next step:[/bold] {d.recommended_next_step}"
        )
        if d.risk_factors:
            for rf in d.risk_factors:
                console.print(f"  [dim]- {rf}[/dim]")

    if plan.recommendation == "trace_recommended":
        console.print(
            "[yellow]Prefer VM trace or repackage if silent install keeps failing "
            "(hangs, UI, or unknown EXE).[/yellow]"
        )

    if plan.metadata:
        filled = {k: v for k, v in plan.metadata.items() if v is not None and str(v).strip()}
        if filled:
            meta_table = Table(title="Metadata", show_lines=True)
            meta_table.add_column("Key", style="bold")
            meta_table.add_column("Value")
            for k, v in plan.metadata.items():
                if v is not None and str(v).strip():
                    meta_table.add_row(str(k), str(v))
            console.print(meta_table)
        else:
            console.print("[dim]Metadata: No MSI properties read (use CPython on Windows for ProductCode, ProductName, etc.).[/dim]")

    if plan.install_candidates:
        t = Table(title="Install candidates", show_lines=True)
        t.add_column("Confidence", justify="right")
        t.add_column("Command")
        for c in plan.install_candidates:
            t.add_row(f"{c.confidence:.2f}", c.command)
        console.print(t)

    if plan.uninstall_candidates:
        t = Table(title="Uninstall candidates", show_lines=True)
        t.add_column("Confidence", justify="right")
        t.add_column("Command")
        for c in plan.uninstall_candidates:
            t.add_row(f"{c.confidence:.2f}", c.command)
        console.print(t)

    if plan.detection_rules:
        t = Table(title="Detection rules", show_lines=True)
        t.add_column("Confidence", justify="right")
        t.add_column("Kind")
        t.add_column("Value")
        for d in plan.detection_rules:
            t.add_row(f"{d.confidence:.2f}", d.kind, d.value)
        console.print(t)

    if plan.notes:
        console.print(Panel("\n".join(f"- {n}" for n in plan.notes), title="Notes"))


def _print_cve_summary(plan: InstallPlan) -> None:
    """CVE output shared by both clean and verbose modes."""
    if getattr(plan, "cve_check_message", None):
        console.print(plan.cve_check_message)
    elif getattr(plan, "cve_results", None) and len(plan.cve_results) > 0:
        console.print("[bold]=== Known CVEs (best-effort) ===[/bold]")
        for r in plan.cve_results:
            cvss = ""
            if r.cvss_score is not None or r.cvss_severity:
                cvss = f" {r.cvss_score or 'N/A'}"
                if r.cvss_severity:
                    cvss += f" ({r.cvss_severity})"
            match = f" [{r.match_type or '?'}]" if getattr(r, "match_type", None) else ""
            summary = (r.summary or "")[:120]
            if len(r.summary or "") > 120:
                summary += "..."
            console.print(f"  [bold]{r.cve_id}[/bold]{cvss}{match}")
            console.print(f"    {summary}")
            console.print(f"    [link={r.url}]{r.url}[/link]")
        if len(plan.cve_results) >= 20:
            console.print("Showing first 20 results.")
    else:
        console.print("CVE check: no matching results.")


def _print_summary(plan: InstallPlan, verbose: bool = False, cve_check_requested: bool = False) -> None:
    _print_clean_summary(plan, cve_check_requested=cve_check_requested)
    if verbose:
        _print_verbose_detail(plan)
        if cve_check_requested:
            _print_cve_summary(plan)


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Path to installer (.msi or .exe)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output JSON path (default: ./installplan.json)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner (for scripting and CI)"),
    cve_check: bool = typer.Option(
        False,
        "--cve-check",
        help="Query NVD (NIST) for known CVEs affecting the identified product. Best-effort; requires product metadata. Uses NVD API v2.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Show full detail tables (evidence, all candidates, detection rules, notes).",
    ),
    telemetry: bool = typer.Option(
        False,
        "--telemetry",
        help="Emit internal analyzer telemetry as JSON lines to stderr (diagnostic, not user analytics).",
    ),
) -> None:
    if telemetry:
        from pkgprobe.analyzers.telemetry import init_telemetry
        init_telemetry(enabled=True)

    # Banner before any analysis output (interactive runs only):
    # - not quiet
    # - TTY
    # - no explicit --out scripting path
    if out is None and should_show_banner(quiet=quiet):
        show_banner()

    p = Path(path)
    if not p.exists():
        raise typer.BadParameter(f"File not found: {p}")

    ext = p.suffix.lower().lstrip(".")

    if ext == "msi":
        plan = analyze_msi(str(p))
    elif ext == "exe":
        plan = analyze_exe(str(p))
    else:
        raise typer.BadParameter("Unsupported file type. Provide a .msi or .exe")

    if cve_check:
        plan = enrich_with_cves(plan, on_warning=lambda msg: console.print(f"[yellow]{msg}[/yellow]"))

    out_path = out or Path("installplan.json")
    _write_json(plan, out_path)
    _print_summary(plan, verbose=verbose, cve_check_requested=cve_check)
    console.print(f"  [green]Wrote:[/green] {out_path.resolve()}")


@app.command()
def schema() -> None:
    """
    Print the JSON schema for the InstallPlan model.
    """
    from pkgprobe.models import InstallPlan as _InstallPlan

    console.print_json(data=_InstallPlan.model_json_schema())


@app.command("trace-install")
def trace_install(
    installer: Path = typer.Argument(..., help="Path to installer (.msi or .exe)"),
    bundle_out: Path = typer.Option(
        ...,
        "--bundle-out",
        "-b",
        help="Output .pkgtrace bundle path.",
    ),
    privacy_profile: Literal["community", "team", "enterprise"] = typer.Option(
        "community",
        "--privacy-profile",
        help="Privacy profile for trace bundle metadata.",
    ),
    attempts: List[str] = typer.Option(
        [],
        "--attempt",
        "-a",
        help="Switch string to try (can be passed multiple times). Takes precedence over --try-silent.",
    ),
    try_silent: bool = typer.Option(
        False,
        "--try-silent",
        help="Try a set of common silent switches (no interactive attempt). Ignored if --attempt is passed.",
    ),
    no_exec: bool = typer.Option(
        False,
        "--no-exec",
        help="Do not execute installer; preflight only for dev/testing.",
    ),
) -> None:
    """
    Run a trace-install session and write a .pkgtrace bundle.

    Use --attempt to try specific switches, or --try-silent to try common
    silent switches. Default is a single attempt with no switches.
    """
    if attempts:
        attempt_list: Optional[List[str]] = attempts
    elif try_silent:
        attempt_list = suggest_silent_attempts(installer)
    else:
        attempt_list = None

    session = TraceSession(
        installer_path=installer,
        privacy_profile=privacy_profile,
        no_exec=no_exec,
        attempts=attempt_list,
    )
    bundle, events = session.run()

    out_path = write_pkgtrace(bundle=bundle, events=events, out_path=bundle_out)

    summary = bundle.summary

    panel_lines = (
        f"[bold]trace-install[/bold]\n"
        f"Installer: {installer}\n"
        f"Trace ID: {bundle.manifest.trace_id}\n"
        f"SHA256: {bundle.manifest.installer_sha256}\n"
        f"Selected attempt: {summary.selected_attempt_index} "
        f"(score={summary.install_success_score:.2f})"
    )
    if no_exec:
        panel_lines += "\n[dim]Execution disabled (--no-exec); no installer was run.[/dim]"
    console.print(Panel.fit(panel_lines, title="Trace Summary"))

    # Attempt breakdown
    if summary.attempts:
        table = Table(title="Attempts", show_lines=True)
        table.add_column("Index", justify="right")
        table.add_column("Switch")
        table.add_column("ExitCode", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Selected", justify="center")

        for idx, attempt in enumerate(summary.attempts):
            selected = "✓" if idx == summary.selected_attempt_index else ""
            # Escape quotes so complex switches remain readable
            raw_switch = attempt.switch_string or ""
            display_switch = raw_switch.replace('"', r'\"') or '""'
            duration_s = f"{attempt.duration_ms / 1000.0:.2f}s"
            table.add_row(
                str(idx),
                display_switch,
                str(attempt.exit_code),
                duration_s,
                f"{attempt.success_score:.2f}",
                selected,
            )
        console.print(table)

    console.print(f"[green]Wrote bundle:[/green] {out_path}")


# ── Cloud commands ────────────────────────────────────────────────────

_DEFAULT_API_URL = "https://api.pkgprobe.io"


def _load_cloud_config() -> tuple[str, str]:
    """Load API URL and key from env, config file, or defaults."""
    import os
    api_url = os.environ.get("PKGPROBE_API_URL", "")
    api_key = os.environ.get("PKGPROBE_API_KEY", "")

    if not api_url or not api_key:
        config_path = Path.home() / ".pkgprobe" / "config.toml"
        if config_path.exists():
            text = config_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("api_url") and "=" in line:
                    api_url = api_url or line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("api_key") and "=" in line:
                    api_key = api_key or line.split("=", 1)[1].strip().strip('"').strip("'")

    return api_url or _DEFAULT_API_URL, api_key


def _require_httpx():
    try:
        import httpx
        return httpx
    except ImportError:
        console.print(
            "[red]httpx is required for cloud commands.[/red]\n"
            "Install it with: pip install pkgprobe[cloud]"
        )
        raise typer.Exit(1)


@app.command("login")
def login(
    api_key: str = typer.Option(..., "--api-key", "-k", prompt="API key", help="Your pkgprobe API key."),
    api_url: str = typer.Option(_DEFAULT_API_URL, "--api-url", help="API base URL."),
) -> None:
    """Store API credentials for cloud commands."""
    config_dir = Path.home() / ".pkgprobe"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.toml"
    config_path.write_text(
        f'api_url = "{api_url}"\napi_key = "{api_key}"\n',
        encoding="utf-8",
    )
    console.print(f"[green]Credentials saved to {config_path}[/green]")


@app.command("cloud-analyze")
def cloud_analyze(
    path: Path = typer.Argument(..., help="Path to installer (.msi or .exe)"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Show full detail tables."),
) -> None:
    """Upload an installer to the cloud API for static analysis."""
    httpx = _require_httpx()
    api_url, api_key = _load_cloud_config()

    p = Path(path)
    if not p.exists():
        raise typer.BadParameter(f"File not found: {p}")

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    with httpx.Client(timeout=60.0) as client:
        with p.open("rb") as f:
            resp = client.post(
                f"{api_url}/v1/analyze",
                files={"installer": (p.name, f)},
                headers=headers,
            )

    if resp.status_code != 200:
        console.print(f"[red]API error ({resp.status_code}):[/red] {resp.text}")
        raise typer.Exit(1)

    data = resp.json()
    plan = InstallPlan(**data)
    _print_summary(plan, verbose=verbose)


@app.command("cloud-wrap")
def cloud_wrap(
    path: Path = typer.Argument(..., help="Path to installer (.msi or .exe)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output path for .intunewin artifact."),
    silent_args: str = typer.Option("/S", "--silent-args", help="Silent install arguments."),
) -> None:
    """Upload an installer to the cloud API for auto-wrap (trace + PSADT wrapper + .intunewin)."""
    httpx = _require_httpx()
    api_url, api_key = _load_cloud_config()

    p = Path(path)
    if not p.exists():
        raise typer.BadParameter(f"File not found: {p}")

    if not api_key:
        console.print(
            "[yellow]No API key configured.[/yellow]\n"
            "Run [bold]pkgprobe login[/bold] or set PKGPROBE_API_KEY.\n"
            "Need an account? Run [bold]pkgprobe upgrade[/bold]."
        )
        raise typer.Exit(1)

    headers = {"X-API-Key": api_key}

    console.print(f"[bold]Uploading {p.name} to {api_url}...[/bold]")

    with httpx.Client(timeout=600.0) as client:
        with p.open("rb") as f:
            resp = client.post(
                f"{api_url}/v1/auto-wrap",
                files={"installer": (p.name, f)},
                data={"silent_args": silent_args},
                headers=headers,
            )

    if resp.status_code == 403:
        console.print(
            "[red]Access denied.[/red] Your tier does not include auto-wrap.\n"
            "Upgrade with: [bold]pkgprobe upgrade --tier auto_wrap[/bold]"
        )
        raise typer.Exit(1)

    if resp.status_code != 200:
        console.print(f"[red]API error ({resp.status_code}):[/red] {resp.text}")
        raise typer.Exit(1)

    data = resp.json()
    trace_id = data.get("trace_id", "unknown")
    was_wrapped = data.get("was_wrapped", False)

    console.print(f"[green]Trace complete.[/green] ID: {trace_id}")
    if was_wrapped:
        console.print("[green]PSADT wrapper was generated.[/green]")

    artifact_resp = httpx.get(
        f"{api_url}/v1/artifacts/{trace_id}",
        headers=headers,
        timeout=120.0,
    )

    if artifact_resp.status_code == 200:
        out_path = out or Path(f"{p.stem}.intunewin")
        out_path.write_bytes(artifact_resp.content)
        console.print(f"[green]Downloaded:[/green] {out_path}")
    else:
        console.print(
            f"[yellow]No .intunewin artifact available.[/yellow] "
            f"Check trace results at {api_url}/v1/artifacts/{trace_id}"
        )


@app.command("upgrade")
def upgrade(
    tier: str = typer.Option("pro", "--tier", "-t", help="Tier to upgrade to: pro or auto_wrap."),
    email: str = typer.Option("", "--email", "-e", help="Your email for the Stripe checkout."),
) -> None:
    """Open Stripe Checkout to upgrade your pkgprobe tier."""
    httpx = _require_httpx()
    api_url, api_key = _load_cloud_config()

    if tier not in ("pro", "auto_wrap"):
        console.print("[red]Tier must be 'pro' or 'auto_wrap'.[/red]")
        raise typer.Exit(1)

    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            f"{api_url}/v1/billing/checkout",
            json={"tier": tier, "email": email},
        )

    if resp.status_code != 200:
        console.print(f"[red]Failed to create checkout session:[/red] {resp.text}")
        raise typer.Exit(1)

    checkout_url = resp.json().get("checkout_url", "")
    if checkout_url:
        console.print(f"[bold]Opening checkout in your browser...[/bold]")
        import webbrowser
        webbrowser.open(checkout_url)
        console.print(f"[dim]If the browser didn't open, visit:[/dim]\n{checkout_url}")
    else:
        console.print("[red]No checkout URL returned.[/red]")


@app.command("billing")
def billing() -> None:
    """Open the Stripe Customer Portal to manage your subscription."""
    httpx = _require_httpx()
    api_url, api_key = _load_cloud_config()

    if not api_key:
        console.print(
            "[yellow]No API key configured.[/yellow]\n"
            "Run [bold]pkgprobe login[/bold] first."
        )
        raise typer.Exit(1)

    with httpx.Client(timeout=30.0) as client:
        resp = client.get(
            f"{api_url}/v1/billing/portal",
            headers={"X-API-Key": api_key},
        )

    if resp.status_code != 200:
        console.print(f"[red]Failed to open billing portal:[/red] {resp.text}")
        raise typer.Exit(1)

    portal_url = resp.json().get("portal_url", "")
    if portal_url:
        console.print(f"[bold]Opening billing portal...[/bold]")
        import webbrowser
        webbrowser.open(portal_url)
        console.print(f"[dim]If the browser didn't open, visit:[/dim]\n{portal_url}")


if __name__ == "__main__":
    app()
