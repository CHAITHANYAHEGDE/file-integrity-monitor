"""
fim.py — CLI entrypoint for the File Integrity Monitor.

Commands:
    fim baseline  — Create or refresh the baseline
    fim scan      — Compare filesystem against baseline and report
    fim verify    — Verify the tamper-evident log chain integrity
    fim watch     — Real-time polling monitor (runs continuously)

Design: Click chosen over argparse for cleaner subcommand structure.
All configuration loaded from YAML; CLI flags override config values.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path so `from src.X import ...` works
# regardless of how fim.py is invoked (python src/fim.py or python -m src.fim)
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import click
import yaml

from src.alerts import Alert
from src.baseline import BaselineManager
from src.db import BaselineDB
from src.hasher import generate_hmac_key
from src.logger import EventType, Severity, TamperEvidentLogger
from src.monitor import Monitor

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

_DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "fim_config.yaml"
_KEY_ENV_VAR = "FIM_HMAC_KEY"   # Hex-encoded key stored in env for this session


def load_config(config_path: Path) -> dict:
    with config_path.open("r") as fh:
        return yaml.safe_load(fh)


def get_or_generate_key() -> bytes:
    """
    Retrieve the HMAC key from the environment variable FIM_HMAC_KEY.
    If absent, generate a new key, print it, and store in os.environ.

    Interview note: In production, this key would be retrieved from a
    key-management service (e.g., HashiCorp Vault, AWS KMS) rather than
    stored in a process environment variable.
    """
    raw = os.environ.get(_KEY_ENV_VAR)
    if raw:
        return bytes.fromhex(raw)
    key = generate_hmac_key()
    os.environ[_KEY_ENV_VAR] = key.hex()
    click.secho(
        f"\n[FIM] Generated new HMAC key. Export this to continue the log chain:\n"
        f"  export {_KEY_ENV_VAR}={key.hex()}\n",
        fg="yellow",
        err=True,
    )
    return key


def build_components(config: dict) -> tuple[BaselineDB, TamperEvidentLogger]:
    key = get_or_generate_key()
    db = BaselineDB(config["baseline_db"])
    db.init()
    logger = TamperEvidentLogger(config["log_file"], key)
    return db, logger


def print_alerts(alerts: list[Alert]) -> None:
    _colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "cyan",
        "LOW": "green",
    }
    if not alerts:
        click.secho("✓ No integrity violations detected.", fg="green")
        return

    click.secho(f"\n{'='*60}", fg="red")
    click.secho(f"  {len(alerts)} INTEGRITY ALERT(S) DETECTED", fg="red", bold=True)
    click.secho(f"{'='*60}\n", fg="red")
    for alert in alerts:
        color = _colors.get(alert.severity.value, "white")
        click.secho(f"[{alert.severity.value}] {alert.event_type.value}", fg=color, bold=True)
        click.echo(f"  Path:    {alert.path}")
        click.echo(f"  Details: {alert.details}")
        if alert.expected_hash:
            click.echo(f"  Expected SHA-256: {alert.expected_hash}")
        if alert.actual_hash:
            click.echo(f"  Actual   SHA-256: {alert.actual_hash}")
        click.echo()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default=_DEFAULT_CONFIG,
    show_default=True,
    help="Path to YAML configuration file.",
)
@click.pass_context
def cli(ctx: click.Context, config: Path) -> None:
    """File Integrity Monitor — detect unauthorized file changes using SHA-256 hashing."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.option("--path", "-p", multiple=True, help="Additional paths to include in baseline.")
@click.option("--fresh/--no-fresh", default=True, show_default=True,
              help="Wipe existing baseline before scanning.")
@click.pass_context
def baseline(ctx: click.Context, path: tuple, fresh: bool) -> None:
    """Create or refresh the file integrity baseline."""
    config = ctx.obj["config"]
    watch_paths = list(config.get("watch_paths", [])) + list(path)

    if not watch_paths:
        click.secho("Error: No watch paths configured.", fg="red")
        sys.exit(1)

    db, logger = build_components(config)
    logger.log(Severity.LOW, EventType.SCAN_STARTED, f"Creating baseline for: {watch_paths}")

    manager = BaselineManager(
        db=db,
        logger=logger,
        exclude_patterns=config.get("exclude_patterns", []),
    )

    def progress(fp: str) -> None:
        click.echo(f"  Hashing: {fp}")

    count = manager.create_baseline(watch_paths, clear_existing=fresh, progress_callback=progress)
    click.secho(f"\n✓ Baseline created: {count} file(s) recorded.", fg="green")
    db.close()


@cli.command()
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write JSON report to this file.")
@click.option("--path", "-p", multiple=True, help="Additional paths to scan.")
@click.pass_context
def scan(ctx: click.Context, output: Path, path: tuple) -> None:
    """Scan filesystem and compare against baseline."""
    config = ctx.obj["config"]
    watch_paths = list(config.get("watch_paths", [])) + list(path)

    db, logger = build_components(config)
    logger.log(Severity.LOW, EventType.SCAN_STARTED, f"Scan started for: {watch_paths}")

    monitor = Monitor(
        db=db,
        logger=logger,
        exclude_patterns=config.get("exclude_patterns", []),
    )

    alerts = monitor.run_comparison(watch_paths)
    print_alerts(alerts)

    if output:
        report = {
            "scan_summary": {
                "total_alerts": len(alerts),
                "critical": sum(1 for a in alerts if a.severity.value == "CRITICAL"),
                "high": sum(1 for a in alerts if a.severity.value == "HIGH"),
                "medium": sum(1 for a in alerts if a.severity.value == "MEDIUM"),
            },
            "alerts": [a.to_dict() for a in alerts],
        }
        output.write_text(json.dumps(report, indent=2))
        click.secho(f"\nReport written to: {output}", fg="cyan")

    db.close()
    sys.exit(1 if alerts else 0)


@cli.command()
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify the tamper-evident log chain integrity."""
    config = ctx.obj["config"]
    _, logger = build_components(config)
    ok, bad_lines = logger.verify_integrity()

    if ok:
        click.secho("✓ Log chain verified — no tampering detected.", fg="green")
    else:
        click.secho(
            f"✗ TAMPERED ENTRIES DETECTED at line(s): {bad_lines}",
            fg="red", bold=True
        )
        logger.log(Severity.CRITICAL, EventType.LOG_TAMPERED, f"Chain broken at lines: {bad_lines}")
        sys.exit(2)


@cli.command()
@click.option("--interval", "-i", default=None, type=int,
              help="Poll interval in seconds (overrides config).")
@click.option("--path", "-p", multiple=True, help="Paths to monitor.")
@click.pass_context
def watch(ctx: click.Context, interval: int, path: tuple) -> None:
    """Run continuous polling monitor (Ctrl+C to stop)."""
    config = ctx.obj["config"]
    poll_interval = interval or config.get("poll_interval", 5)
    watch_paths = list(config.get("watch_paths", [])) + list(path)

    db, logger = build_components(config)
    monitor = Monitor(
        db=db, logger=logger,
        exclude_patterns=config.get("exclude_patterns", []),
    )

    click.secho(
        f"[FIM] Real-time monitoring started. Poll interval: {poll_interval}s. "
        f"Press Ctrl+C to stop.\n",
        fg="cyan",
    )

    try:
        while True:
            alerts = monitor.run_comparison(watch_paths)
            if alerts:
                print_alerts(alerts)
            else:
                click.echo(f"  [{_timestamp()}] ✓ No changes detected.")
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        click.secho("\n[FIM] Monitoring stopped.", fg="yellow")
    finally:
        db.close()


def _timestamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


if __name__ == "__main__":
    cli()
