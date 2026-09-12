"""Command-line interface entry point for Mobile Sentinel."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from colorama import Fore, Style, init

from sentinel import __app_name__, __version__
from sentinel.environment.doctor import EnvironmentDoctor

init(autoreset=True)

# Ensure Windows terminal handles UTF-8 cleanly
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@click.group(invoke_without_command=True)
@click.option("--version", "-v", "show_version", is_flag=True, help="Show application version and exit.")
@click.pass_context
def cli(ctx: click.Context, show_version: bool) -> None:
    """Mobile Sentinel - Local-First Mobile App Security & QA Analysis Platform."""
    if show_version:
        click.echo(f"{__app_name__} v{__version__}")
        ctx.exit(0)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("version")
def version_cmd() -> None:
    """Display Mobile Sentinel version information."""
    click.echo(f"{Style.BRIGHT}{__app_name__}{Style.RESET_ALL} version {Fore.CYAN}{__version__}{Style.RESET_ALL}")
    click.echo("Target Platform: Flutter / Android APK")
    click.echo("Mode: Local-First Deterministic Security Engine")


@cli.command("doctor")
@click.option("--json-output", is_flag=True, help="Output diagnostic report in JSON format.")
def doctor_cmd(json_output: bool) -> None:
    """Diagnose local system environment, SDKs, and tools."""
    doctor = EnvironmentDoctor()
    report = doctor.diagnose()

    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        click.echo(doctor.render_console_report(report))

    if not report.ready_for_scan:
        sys.exit(1)


@cli.command("scan")
@click.argument("apk_path", type=click.Path(exists=False))
@click.option("--output", "-o", default="reports", help="Directory for generated reports.")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to custom sentinel.yaml config.")
def scan_cmd(apk_path: str, output: str, config: Optional[str]) -> None:
    """Execute complete security and QA scan on an APK."""
    click.echo(f"{Fore.CYAN}[Phase 1+] Scan engine invoked for:{Style.RESET_ALL} {apk_path}")
    click.echo(f"Output directory: {output}")
    click.echo(f"{Fore.YELLOW}Note: Full static pipeline will be enabled in Phase 1.{Style.RESET_ALL}")


@cli.command("analyze")
@click.argument("apk_path", type=click.Path(exists=False))
def analyze_cmd(apk_path: str) -> None:
    """Perform static analysis on an APK without runtime execution."""
    click.echo(f"{Fore.CYAN}[Phase 2+] Static analysis invoked for:{Style.RESET_ALL} {apk_path}")


from sentinel.analyzers.apk.extractor import APKExtractor
from sentinel.core.exceptions import APKValidationError, TargetPackageViolation
from sentinel.orchestrator.pipeline import ScanPipeline
from sentinel.reporting.json_report import JsonReportGenerator
from sentinel.reporting.text_report import TextReportGenerator
from sentinel.runtime.adb import ADBController


@cli.command("test")
@click.argument("apk_path", type=click.Path(exists=False))
@click.option("--output", "-o", default="reports", help="Directory for generated reports.")
@click.option("--auth-config", "-a", type=click.Path(exists=True), help="Path to authorized credentials YAML config.")
@click.option("--no-ui", is_flag=True, help="Skip automated UI exploration.")
@click.option("--no-network", is_flag=True, help="Skip offline network toggle test.")
@click.option("--keep-installed", is_flag=True, help="Retain test application installed on device after run.")
def test_cmd(apk_path: str, output: str, auth_config: Optional[str], no_ui: bool, no_network: bool, keep_installed: bool) -> None:
    """Execute complete automated static and runtime security & QA audit."""
    # 1. Check APK path existence cleanly
    path = Path(apk_path)
    if not path.exists():
        click.echo(f"\n{Fore.RED}[ERROR] APK not found:{Style.RESET_ALL}\n{apk_path}\n")
        sys.exit(1)

    # 2. Check Device availability
    adb = ADBController()
    devices = adb.list_devices()
    if not devices:
        click.echo(f"\n{Fore.RED}[ERROR] No Android device or emulator detected.{Style.RESET_ALL}\n")
        click.echo("Please start an Android emulator or connect an authorized Android device,")
        click.echo("then run the same command again.\n")
        sys.exit(1)

    target_device = devices[0]

    # Inspect APK minimally for terminal header
    extractor = APKExtractor()
    app_label = "Android Application"
    pkg_name = "Detecting..."
    try:
        apk_meta = extractor.extract_metadata(path)
        app_label = apk_meta.app_label
        pkg_name = apk_meta.package_name
    except Exception:
        pass

    # Header banner (clean and concise)
    click.echo(f"\n{Style.BRIGHT}Mobile Sentinel{Style.RESET_ALL}")
    click.echo("---------------")
    click.echo(f"Application: {app_label}")
    click.echo(f"Package: {pkg_name}")
    # Auto-discover authorized credentials if available in config/
    if not auth_config:
        import re
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", app_label).strip("-").lower() if app_label else ""
        candidate = Path("config") / f"{slug}-auth.yaml"
        if candidate.exists():
            auth_config = str(candidate)
            click.echo(f"Loaded credentials from: {candidate}\n")

    def _progress(step: int, total: int, desc: str, status: str) -> None:
        if status == "RUNNING":
            return

        if status.startswith("DETAIL:"):
            click.echo(f"[{step}/{total}] {desc}...")
            for detail_line in status[7:].split(";"):
                if detail_line.strip():
                    click.echo(f"       {detail_line.strip()}")
            return

        if status == "OK":
            stat_str = f"{Fore.GREEN}✓{Style.RESET_ALL}"
        elif status == "WARN":
            stat_str = f"{Fore.YELLOW}✓{Style.RESET_ALL}"
        elif status == "FAIL":
            stat_str = f"{Fore.RED}✗{Style.RESET_ALL}"
        elif status == "SKIPPED":
            stat_str = f"{Fore.CYAN}SKIP{Style.RESET_ALL}"
        else:
            stat_str = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"

        click.echo(f"[{step}/{total}] {desc:<22} {stat_str}")

    pipeline = ScanPipeline(adb=adb, extractor=extractor)
    try:
        result = pipeline.execute_pipeline(
            apk_path=path,
            output_dir=output,
            auth_config=auth_config,
            run_ui=not no_ui,
            run_network=not no_network,
            keep_installed=keep_installed,
            progress_cb=_progress,
        )
    except TargetPackageViolation as e:
        click.echo(f"\n{Fore.RED}[TARGET PACKAGE VIOLATION]{Style.RESET_ALL} {e}\n")
        sys.exit(1)
    except APKValidationError as e:
        click.echo(f"\n{Fore.RED}[ERROR] APK Validation Failed:{Style.RESET_ALL} {e}\n")
        sys.exit(1)
    except Exception as e:
        import traceback
        traceback.print_exc()
        click.echo(f"\n{Fore.RED}[ERROR] Scan execution failed:{Style.RESET_ALL} {e}\n")
        sys.exit(1)

    # Generate Reports in reports/<app_name>/
    report_dir = Path(output).resolve() / result.app_dir_name
    txt_report_path = report_dir / "report.txt"
    json_report_path = report_dir / "report.json"

    txt_gen = TextReportGenerator()
    txt_gen.generate(result, txt_report_path)

    json_gen = JsonReportGenerator()
    json_gen.generate(result, json_report_path)

    click.echo("\nScan completed.\n")
    click.echo(f"Report:\n{txt_report_path}\n")


@cli.command("devices")
def devices_cmd() -> None:
    """List connected Android emulators and physical devices."""
    adb = ADBController()
    devices = adb.list_devices()
    if not devices:
        click.echo(f"{Fore.YELLOW}No connected Android devices found.{Style.RESET_ALL}")
        return

    click.echo(f"{Style.BRIGHT}Connected Android Devices:{Style.RESET_ALL}")
    for d in devices:
        props = adb.get_device_properties(d)
        click.echo(f"  - {Fore.GREEN}{d:<18}{Style.RESET_ALL} (Android {props.get('android_version')}, {props.get('model')})")


def main() -> None:
    """Main entry point."""
    cli(prog_name="sentinel")


if __name__ == "__main__":
    main()
