"""ramen_cve.cli — argparse tree (`build_parser`/`_shared_flags`),
logging/validation, `main`, and the opml/url/cve/stix subcommand
runners (Layer-5, top of the graph). DEFAULT_CACHE_PATH is read
late via the facade inside main() — see src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
import time  # rate-limit pacing in `_fetch_url_with_rate_limit` (Task 2 Slice B)
from datetime import date
from pathlib import Path

import requests

from .analyze import (
    _best_admiralty,
    _worst_tlp,
    bucket_and_suggest,
    filter_by_date,
)
from .audit import (
    _audit_dispatch,
    _run_audit,
)
from .cache import Cache
from .cliutil import (
    _collect_opml_files,
    _format_spec,
    _install_logging,
    _parse_iso_date,
    _path_arg,
    _validate_cve_id,
    _validate_http_url,
)
from .config import (
    _load_remembered_opml,
    _reset_remembered_opml,
    _save_remembered_opml,
    apply_yaml_config,
    args_to_yaml_payload,
    delete_yaml_preset,
    list_yaml_presets,
    load_yaml_config,
    save_yaml_config,
)
from .constants import (
    CVE_REGEX,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_EPSS_THRESHOLD,
    DEFAULT_HUNT_DIR,
    DEFAULT_PIR_DIR,
    DEFAULT_PRESETS_DIR,
    USER_AGENT,
)
from .daemon import _run_daemon
from .dispatch.digest import _maybe_digest
from .enrich.exploits import enrich_with_exploit_status
from .enrich.orchestrator import enrich_cves
from .extract import (
    DEFAULT_MAX_CRAWL_LINKS,
    MAX_CRAWL_LINKS_CEILING,
    _filter_and_cap_links,
    extract_cves,
    extract_iocs,
    parse_opml,
)
from .hunt import _run_hunt
from .keyring import (
    _is_interactive,
    _prompt_for_api_key,
    _safe_url_for_log,
)
from .models import (
    CveRecord,
    FeedEntry,
    IocRecord,
    OpmlError,
    WebUiError,
)
from .output.stix import (
    parse_stix_bundle,
    pull_taxii,
)
from .pipeline import (
    _decay_and_filter_iocs,
    _get_github_token,
    _maybe_correlate_inventory,
    _maybe_dispatch,
    _maybe_enrich_iocs,
    _maybe_filter_by_sector,
    _output,
    _resolve_associations,
)
from .pir import _run_pir
from .schedule import _run_schedule
from .trend import (
    _record_runs,
    _run_trend,
)
from .web.builder import build_site
from .wizard import _run_wizard

_log = logging.getLogger(__name__)


# Must match [project] version in pyproject.toml — locked by
# tests/test_smoke.py::test_version_constant_matches_pyproject.
VERSION = "0.2.0"


def _shared_flags(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by all three subcommands."""
    parser.add_argument("--start", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--end", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--date-mode", choices=["feed", "disclosure", "epss"], default=None)
    parser.add_argument("--cvss-threshold", type=float, default=DEFAULT_CVSS_THRESHOLD)
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD)
    # Default is None so the help text doesn't show a literal '.'; runtime
    # resolves None → Path.cwd() via _resolve_out_dir(). Threat hunters
    # typically pass a quoted Windows path here ("C:\\Users\\me\\Reports");
    # _path_arg strips the quotes and expands ~.
    parser.add_argument(
        "--out-dir",
        type=_path_arg,
        default=None,
        metavar="DIR",
        help="Directory to write output files into. Defaults to the current "
             "working directory. Surrounding quotes and a leading ~ are handled.",
    )
    parser.add_argument(
        "--basename",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Stem for output files (no extension). Default: ramen-cve-<UTC timestamp>. "
            "Path separators are stripped; -iocs is appended to the IOC CSV; -sigma to "
            "the Sigma rule directory."
        ),
    )
    parser.add_argument(
        "--format",
        type=_format_spec,
        default="both",
        metavar="SPEC",
        help=(
            "Output format(s) — a single value or a comma-separated combination "
            "of: csv, md, stix, sigma, yara, html (e.g. --format csv,html). "
            "Aliases: 'both' = csv,md (default); 'all' = every format. "
            "'html' is the self-contained CVSS x EPSS quadrant chart."
        ),
    )
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--no-exploit-lookup",
        action="store_true",
        help="Skip Exploit-DB / Nuclei / GitHub PoC lookups (offline mode).",
    )
    parser.add_argument(
        "--no-enrich-iocs",
        action="store_true",
        help="Skip per-IOC enrichment (VirusTotal / AbuseIPDB / OTX / MalwareBazaar).",
    )
    parser.add_argument(
        "--ioc-confidence-floor",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help=(
            "Drop IOCs whose decay-weighted confidence is below this floor "
            "(0.0..1.0; default 0.0 keeps every IOC). Half-lives per type: "
            "IPv4 30d, URL 30d, domain 90d, email 90d; file hashes never decay."
        ),
    )
    parser.add_argument(
        "--sector",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Filter the report to CVEs likely relevant to a given sector "
            "(e.g. 'financial', 'healthcare', 'energy', 'government'). "
            "Matches against each linked actor's sectors_targeted in "
            "associations.json. Records with no linked actors are KEPT "
            "(unattributed CVEs are assumed potentially relevant)."
        ),
    )
    parser.add_argument(
        "--allow-tlp-red",
        action="store_true",
        help=(
            "Permit writing TLP:RED records to disk. Default behavior is to "
            "STRIP any TLP:RED records before output and log a warning."
        ),
    )
    parser.add_argument(
        "--allow-large-epss-trajectory",
        action="store_true",
        help=(
            "Bypass the EPSS trajectory volume guard, which hard-errors when "
            "the projected number of EPSS API calls would be >= 500 "
            "(days x ceil(N_cves/100)). A warning is still logged at >= 200."
        ),
    )
    parser.add_argument(
        "--inventory",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CSV asset inventory with columns 'host,product,version' "
            "(or 'host,cpe'). When set, the report annotates each CVE with the "
            "list of inventory hosts whose product+version matches a CVE CPE."
        ),
    )
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help=(
            "After writing reports, push every kev_override / patch_now finding "
            "to configured dispatchers (Slack via SLACK_WEBHOOK_URL, generic "
            "webhook via RAMEN_DISPATCH_WEBHOOK). Off by default."
        ),
    )
    parser.add_argument(
        "--dispatch-on-delta-only",
        action="store_true",
        help=(
            "When --dispatch is on, only push records whose bucket *upgraded* "
            "since the previously recorded run (first-seen CVEs also count). "
            "Suppresses the every-run repeat-dispatch of unchanged findings "
            "that is the dominant source of alert fatigue."
        ),
    )
    parser.add_argument(
        "--digest",
        action="store_true",
        help=(
            "After writing reports, batch-mail one digest email per recipient "
            "(keyed by the inventory CSV's `owner` column, falling back to "
            "RAMEN_DIGEST_TO when set). SMTP via RAMEN_SMTP_* env vars. The "
            "CSV and Markdown reports are attached. Off by default."
        ),
    )
    parser.add_argument(
        "--associations-file",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CVE→adversary associations JSON file. "
            "Defaults to associations.json in the repo. Pass an empty/missing "
            "path to disable adversary attribution."
        ),
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ramen_cve",
        description="Threat intel triage on a ramen budget.",
    )
    # --version is the standard "what release am I running?" affordance for
    # bug reports + scripts. Reads the same VERSION constant pyproject is
    # gated against by tests/test_smoke.py.
    parser.add_argument(
        "--version",
        action="version",
        version=f"ramen-cve {VERSION}",
    )
    # YAML configuration plumbing — top-level (works before any subcommand).
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Load a saved YAML preset by name "
            "(under src/ramen_cve/config/presets/<NAME>.yaml) "
            "or an explicit YAML file path. CLI flags override YAML values."
        ),
    )
    parser.add_argument(
        "--save-config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "After this run, persist the current invocation's arguments as a "
            "YAML preset under that NAME (or write to the explicit YAML path)."
        ),
    )
    parser.add_argument(
        "--list-configs",
        action="store_true",
        help="List every saved YAML preset and exit.",
    )
    # Structured logging — designed for SIEM ingestion. Default ``text`` keeps
    # the historical "LEVEL message" stderr shape byte-identical; ``json``
    # emits one JSON-line per record (ts, level, logger, message, +extras).
    # Top-level so it works before any subcommand: `ramen-cve --log-format
    # json opml feeds.opml`.
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default=None,
        help=(
            "Logging output shape on stderr. 'text' (default) keeps the human-"
            "readable 'LEVEL message' format; 'json' emits one JSON line per "
            "record (ts/level/logger/message + extras) for SIEM ingestion."
        ),
    )
    parser.add_argument(
        "--reset-config",
        type=str,
        default=None,
        metavar="NAME",
        help="Delete the saved YAML preset with that NAME (or path) and exit.",
    )
    parser.add_argument(
        "--reset-opml",
        action="store_true",
        help="Forget the remembered OPML source (clears the last_opml state) "
             "and exit.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=False)

    # opml subcommand
    opml_p = sub.add_parser("opml", help="Process an OPML feed list.")
    opml_p.add_argument(
        "path",
        type=_path_arg,
        nargs="?",
        default=None,
        help="Path to an .opml file OR a directory of *.opml files. "
             "Optional when a remembered OPML exists (see --remember-opml).",
    )
    opml_p.add_argument(
        "--remember-opml",
        action="store_true",
        help="After a successful run, save this OPML source so a later "
             "`opml` with no path argument reuses it automatically.",
    )
    _shared_flags(opml_p)

    # url subcommand
    url_p = sub.add_parser("url", help="Extract CVEs from a single URL.")
    url_p.add_argument(
        "url",
        type=_validate_http_url,
        help="URL of the article or page to scan (http:// or https:// only).",
    )
    url_p.add_argument(
        "--depth",
        type=int,
        choices=[0, 1],
        default=0,
        help=(
            "Follow same-host links up to N hops from the seed URL. 0 (default) "
            "= seed only — byte-identical to today; 1 = seed + every same-host "
            "<a href> found on the seed page (deduped, sorted, capped, "
            "rate-limited per host). Off-host links are never followed."
        ),
    )
    url_p.add_argument(
        "--max-crawl-links",
        type=int,
        default=DEFAULT_MAX_CRAWL_LINKS,
        metavar="N",
        help=(
            f"Maximum followed links per seed when --depth >= 1 "
            f"(default {DEFAULT_MAX_CRAWL_LINKS}, hard ceiling "
            f"{MAX_CRAWL_LINKS_CEILING})."
        ),
    )
    url_p.add_argument(
        "--crawl-delay-ms",
        type=int,
        default=500,
        metavar="MS",
        help=(
            "Minimum milliseconds between successive URL fetches when "
            "--depth >= 1 (default 500). Mirrors the throttle pattern used "
            "for NVD/EPSS fetches."
        ),
    )
    _shared_flags(url_p)

    # cve subcommand
    cve_p = sub.add_parser("cve", help="Enrich named CVE IDs directly.")
    cve_p.add_argument("cves", nargs="*", type=_validate_cve_id, metavar="CVE-ID")
    cve_p.add_argument("--from-file", type=_path_arg, metavar="FILE", help="Text file of CVE IDs.")
    _shared_flags(cve_p)

    # hunt subcommand: list / show / link / log / status against the hunts/ library
    hunt_p = sub.add_parser("hunt", help="Manage threat-hunt hypotheses.")
    hunt_p.add_argument(
        "action",
        choices=["list", "show", "link", "log", "status"],
        help="What to do with the hunts library.",
    )
    hunt_p.add_argument("hunt_id", nargs="?", help="Hunt id (filename stem under hunts/).")
    hunt_p.add_argument(
        "value",
        nargs="?",
        help=(
            "Action argument: CVE-ID for 'link', finding text for 'log', "
            "new status for 'status'."
        ),
    )
    hunt_p.add_argument(
        "--hunt-dir",
        type=_path_arg,
        default=DEFAULT_HUNT_DIR,
        help="Directory of hunt JSON files (default: the package's bundled data/hunts/).",
    )

    # pir subcommand: leadership-blessed Priority Intelligence Requirements
    pir_p = sub.add_parser(
        "pir", help="Manage Priority Intelligence Requirements (PIRs)."
    )
    pir_p.add_argument(
        "action",
        choices=["list", "show", "link", "coverage"],
        help="What to do with the PIR library.",
    )
    pir_p.add_argument(
        "pir_id", nargs="?", help="PIR id (filename stem under pirs/)."
    )
    pir_p.add_argument(
        "value", nargs="?",
        help="Action argument: CVE-ID for 'link' (other actions ignore this).",
    )
    pir_p.add_argument(
        "--pir-dir",
        type=_path_arg,
        default=DEFAULT_PIR_DIR,
        help="Directory of PIR JSON files (default: the package's bundled data/pirs/).",
    )

    # trend subcommand: historical bucket / CVSS / EPSS for one CVE
    trend_p = sub.add_parser(
        "trend", help="Show historical bucket / CVSS / EPSS trend for one CVE."
    )
    trend_p.add_argument("cve_id", type=_validate_cve_id, metavar="CVE-ID")
    trend_p.add_argument(
        "--no-cache",
        action="store_true",
        help="Use an in-memory cache (yields no history, mostly useful for tests).",
    )
    trend_p.add_argument("--quiet", action="store_true")
    trend_p.add_argument("--verbose", action="store_true")

    # audit subcommand: tail the append-only audit log
    audit_p = sub.add_parser(
        "audit",
        help="Show the tail of the append-only audit log of past ramen_cve commands.",
    )
    audit_p.add_argument(
        "--tail", type=int, default=20,
        help="How many of the most recent entries to print (default 20).",
    )
    audit_p.add_argument(
        "--no-cache", action="store_true",
        help="Read the in-memory audit log only (always empty; useful for tests).",
    )
    audit_p.add_argument("--quiet", action="store_true")
    audit_p.add_argument("--verbose", action="store_true")

    # schedule subcommand: emit a Task Scheduler XML or a crontab line that
    # invokes this tool against a saved YAML preset on a recurring schedule.
    schedule_p = sub.add_parser(
        "schedule",
        help="Generate a Windows Task Scheduler XML or a crontab line for "
             "automated daily runs against a saved YAML preset.",
    )
    schedule_p.add_argument(
        "action",
        choices=["windows-task", "cron"],
        help=(
            "Output format: 'windows-task' writes a Task Scheduler XML (importable "
            "via `schtasks /Create /XML`); 'cron' prints a crontab line."
        ),
    )
    schedule_p.add_argument(
        "--for-config", type=str, default=None, metavar="NAME",
        help="Saved YAML preset name (or YAML file path) the scheduled run "
             "should load. The generated command will include --config NAME.",
    )
    schedule_p.add_argument(
        "--time", type=str, default="06:15", metavar="HH:MM",
        help="Wall-clock daily run time in 24-hour HH:MM (default 06:15).",
    )
    schedule_p.add_argument(
        "--task-name", type=str, default="ramen-cve-daily", metavar="NAME",
        help="Task Scheduler task name (Windows only; ignored for cron).",
    )
    schedule_p.add_argument(
        "--python", type=str, default=None, metavar="PATH",
        help="Python interpreter path to embed in the schedule. "
             "Defaults to sys.executable.",
    )
    schedule_p.add_argument(
        "--output", type=_path_arg, default=None, metavar="FILE",
        help="Write the generated XML / crontab line to this file instead "
             "of stdout.",
    )
    schedule_p.add_argument("--quiet", action="store_true")
    schedule_p.add_argument("--verbose", action="store_true")

    # daemon subcommand: first-party long-running mode that loops the pipeline
    # at a fixed interval (Task 3 in tasks/todo.md). Slice A wiring only —
    # the loop / signal / jitter / prune behaviours land in Slices B–D.
    daemon_p = sub.add_parser(
        "daemon",
        help="Run a configured pipeline preset at intervals in one long-lived "
             "process (Slice A: single-shot wiring; Slices B-D add loop, "
             "signal handling, and history pruning).",
    )
    daemon_p.add_argument(
        "--for-config", type=str, required=True, metavar="NAME",
        help="Saved YAML preset name (or YAML file path) the daemon loops. "
             "Must declare a `subcommand` of opml / url / cve / stix.",
    )
    daemon_p.add_argument(
        "--interval", type=int, default=21600, metavar="SECONDS",
        help="Sleep between iterations (default 21600 = 6 hours). "
             "Active from Slice B; ignored in Slice A.",
    )
    daemon_p.add_argument(
        "--jitter", type=int, default=0, metavar="SECONDS",
        help="Random +/- jitter added to --interval (default 0 = exact). "
             "Active from Slice B.",
    )
    daemon_p.add_argument(
        "--max-runs", type=int, default=-1, metavar="N",
        help="Cap on iterations; -1 (default) = unbounded (Slice B+). "
             "Slice A always runs exactly one iteration regardless.",
    )
    daemon_p.add_argument(
        "--out-dir", type=_path_arg, default=None, metavar="DIR",
        help="Base directory for per-iteration output. Each iteration writes "
             "to a fresh timestamped subdir `<DIR>/ramen-cve-<UTC ts>/` so "
             "history is preserved (default: current working directory).",
    )
    daemon_p.add_argument(
        "--prune-after-days", type=int, default=0, metavar="N",
        help="Delete per-iteration output subdirs older than N days "
             "(default 0 = no pruning). Active from Slice D.",
    )
    daemon_p.add_argument("--quiet", action="store_true")
    daemon_p.add_argument("--verbose", action="store_true")

    # web subcommand: static-HTML triage navigator over the SQLite cache
    # (Task 8). Slice A: --site-dir only; later slices add --out-dir,
    # --config, --max-runs-on-home, --cache. See README.md (Web UI).
    web_p = sub.add_parser(
        "web",
        help="Render a static-HTML site over the SQLite runs history "
             "(Slice A: minimal index.html + empty stylesheet; Slices B-G "
             "add per-run + per-CVE pages, bucket-policy threading, and "
             "the showcase regen).",
    )
    web_p.add_argument(
        "--site-dir", type=_path_arg, required=True, metavar="DIR",
        help="Required. Site is written to <DIR>/index.html + "
             "<DIR>/static/style.css. No default — explicit by design "
             "(no surprise overwrites).",
    )
    web_p.add_argument(
        "--out-dir", type=_path_arg, metavar="DIR",
        help="Optional. Override the per-run artefact directory recorded "
             "in run_artefacts when the cache was written — useful when "
             "the CSV/MD/STIX/etc. files have been moved since the "
             "original pipeline run. Without this flag, the Web UI uses "
             "the absolute path stamped at write time.",
    )
    web_p.add_argument("--quiet", action="store_true")
    web_p.add_argument("--verbose", action="store_true")

    # stix subcommand: ingest a STIX 2.1 bundle from disk or via TAXII 2.1
    stix_p = sub.add_parser("stix", help="Ingest a STIX 2.1 bundle (file or TAXII).")
    stix_p.add_argument("path", nargs="?", type=_path_arg, help="Path to a STIX bundle JSON file.")
    stix_p.add_argument("--taxii-url", help="TAXII 2.1 API root URL.")
    stix_p.add_argument("--taxii-collection", help="TAXII 2.1 collection ID.")
    stix_p.add_argument("--taxii-user", help="Optional TAXII basic-auth username.")
    stix_p.add_argument("--taxii-pass", help="Optional TAXII basic-auth password.")
    _shared_flags(stix_p)

    return parser


def _configure_logging(args: argparse.Namespace) -> None:
    """Set log level + format from --quiet / --verbose / --log-format.

    The hunt subcommand doesn't share the analysis flags, so we read them
    defensively via getattr so logging works for every subcommand. The
    ``--log-format`` flag is top-level (any subcommand sees it) and
    defaults to ``text`` so the historical stderr shape is preserved
    byte-identically.
    """
    if getattr(args, "quiet", False):
        level = logging.WARNING
    elif getattr(args, "verbose", False):
        level = logging.DEBUG
    else:
        level = logging.INFO
    log_format = getattr(args, "log_format", None) or "text"
    _install_logging(sys.stderr, level, log_format)


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Cross-field validation that argparse can't express natively."""
    if args.start is not None and args.end is not None and args.start > args.end:
        parser.error(f"--start ({args.start}) must not be later than --end ({args.end}).")
    # --date-mode epss requires both bounds; start != end is allowed and
    # triggers EPSS trajectory mode (orchestrator fetches historical EPSS
    # once per day in the range and stashes it on EnrichedCve.epss_trajectory).
    if args.date_mode == "epss" and (args.start is None or args.end is None):
        parser.error(
            "--date-mode epss requires both --start and --end (set them to the same "
            "date for a single-day snapshot, or to a range for trajectory mode)."
        )


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    import ramen_cve  # §5.2: late-bind DEFAULT_CACHE_PATH via facade
    if argv is None and len(sys.argv) <= 1:
        if _is_interactive():
            try:
                argv = _run_wizard()
            except KeyboardInterrupt:
                print("\nCancelled.", file=sys.stderr)
                return 130
        else:
            print(
                "ramen_cve: no arguments supplied and stdin is not a TTY.\n"
                "Run with --help for usage, or invoke interactively to use the wizard.",
                file=sys.stderr,
            )
            return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    # --list-configs: dump every saved preset name + path and exit.
    if getattr(args, "list_configs", False):
        presets = list_yaml_presets()
        if not presets:
            print(f"(no saved presets under {DEFAULT_PRESETS_DIR})")
        else:
            for p in presets:
                print(f"{p.stem}\t{p}")
        return 0

    # --reset-config NAME: delete one preset and exit.
    if getattr(args, "reset_config", None):
        removed = delete_yaml_preset(args.reset_config)
        if removed:
            print(f"Deleted preset → {removed}")
            return 0
        print(f"error: no such preset: {args.reset_config}", file=sys.stderr)
        return 1

    # --reset-opml: forget the remembered OPML source and exit.
    if getattr(args, "reset_opml", False):
        if _reset_remembered_opml():
            print("Forgot the remembered OPML source.")
        else:
            print("No remembered OPML source to clear.")
        return 0

    # --config NAME / --config path/to.yaml: load YAML and overlay onto args
    # BEFORE _configure_logging so logging.level keys take effect.
    if getattr(args, "config", None):
        try:
            yaml_cfg = load_yaml_config(args.config)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        apply_yaml_config(args, yaml_cfg)
        # The YAML may have supplied the subcommand. If the parser couldn't
        # bind one, reparse the args namespace into the chosen subcommand
        # context now. The pragmatic shortcut: pass attributes through as-is
        # and let the existing dispatch logic below pick the runner.
        if not getattr(args, "subcommand", None):
            print(
                "error: no subcommand was provided and the config did not "
                "supply one (set `subcommand:` in the YAML).",
                file=sys.stderr,
            )
            return 1

    # Subcommand is required after --config / --list-configs handling.
    if not getattr(args, "subcommand", None):
        parser.error("a subcommand is required (or use --config / --list-configs).")

    _configure_logging(args)

    # If --save-config was passed, persist the (post-YAML-overlay) namespace
    # before running so the preset captures the actual run shape even on
    # later failure. The save happens regardless of run outcome.
    if getattr(args, "save_config", None):
        try:
            written = save_yaml_config(args.save_config, args_to_yaml_payload(args))
            _log.info("Saved YAML preset → %s", written)
        except Exception as exc:
            _log.warning("Could not save YAML preset %r: %s", args.save_config, exc)

    # The hunt subcommand is a pure local-file workflow but we still open
    # the cache so audit logging can persist. trend / pir / audit are similar
    # — all skip _validate_args (which expects analysis-specific args).
    if args.subcommand == "hunt":
        cache_path = ramen_cve.DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "hunt", args, lambda: _run_hunt(args, cache, None))

    if args.subcommand == "pir":
        cache_path = ramen_cve.DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "pir", args, lambda: _run_pir(args, cache, None))

    if args.subcommand == "trend":
        cache_path = ":memory:" if args.no_cache else ramen_cve.DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "trend", args, lambda: _run_trend(args, cache, None))

    # The audit subcommand reads the log; it must NOT log itself (every
    # `ramen_cve audit` would otherwise grow the table it's trying to read).
    if args.subcommand == "audit":
        cache_path = ":memory:" if args.no_cache else ramen_cve.DEFAULT_CACHE_PATH
        return _run_audit(args, Cache(cache_path), api_key=None)

    # The schedule subcommand only emits text (XML / crontab). It needs no
    # cache, no network, and no API key — but we still audit-log it so an
    # operator can see when a scheduled task was (re)generated.
    if args.subcommand == "schedule":
        cache = Cache(ramen_cve.DEFAULT_CACHE_PATH)
        return _audit_dispatch(
            cache, "schedule", args, lambda: _run_schedule(args, cache, None)
        )

    # daemon subcommand: dispatch alongside schedule (audit-logged so an
    # operator can trace when the daemon was (re)started). The recursive
    # main() call inside _run_daemon resolves its own api_key for each
    # inner iteration, so the outer call passes None — preventing the
    # dispatch from depending on api_key resolution this early in main().
    if args.subcommand == "daemon":
        cache = Cache(ramen_cve.DEFAULT_CACHE_PATH)
        return _audit_dispatch(
            cache, "daemon", args, lambda: _run_daemon(args, cache, None)
        )

    # web subcommand: static-HTML renderer over the SQLite cache. No API
    # key needed (no network) — dispatch alongside daemon, before the
    # key-resolution block below. See README.md (Web UI).
    if args.subcommand == "web":
        cache = Cache(ramen_cve.DEFAULT_CACHE_PATH)
        return _audit_dispatch(
            cache, "web", args, lambda: _run_web(args, cache, None)
        )

    _validate_args(args, parser)

    cache_path = ":memory:" if args.no_cache else ramen_cve.DEFAULT_CACHE_PATH
    cache = Cache(cache_path)

    import os

    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.getenv("NVD_API_KEY") or None
    if api_key is None:
        prompted = _prompt_for_api_key(reason="missing")
        if prompted:
            api_key = prompted

    if args.subcommand == "opml":
        return _audit_dispatch(cache, "opml", args, lambda: _run_opml(args, cache, api_key))
    if args.subcommand == "url":
        return _audit_dispatch(cache, "url", args, lambda: _run_url(args, cache, api_key))
    if args.subcommand == "cve":
        return _audit_dispatch(cache, "cve", args, lambda: _run_cve(args, cache, api_key))
    if args.subcommand == "stix":
        return _audit_dispatch(cache, "stix", args, lambda: _run_stix(args, cache, api_key))
    return 1


def _epss_date_range_for(args: argparse.Namespace) -> tuple[date, date] | None:
    """Return (start, end) when EPSS trajectory mode applies; otherwise None.

    Trajectory mode is opt-in via `--date-mode epss` plus both `--start`
    and `--end`. When start == end the orchestrator's behaviour is byte-
    identical to today's single-shot EPSS fetch; when start != end it loops
    once per day in the inclusive range and stashes the time-series on
    EnrichedCve.epss_trajectory.
    """
    if (
        getattr(args, "date_mode", None) == "epss"
        and getattr(args, "start", None) is not None
        and getattr(args, "end", None) is not None
    ):
        return (args.start, args.end)
    return None


def _run_opml(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the opml subcommand.

    `args.path` may point at:
      - a single .opml file (the historical behavior),
      - a directory containing one or more .opml files (every top-level
        *.opml is loaded and merged into a single run), or
      - nothing, in which case a previously-remembered OPML source
        (--remember-opml on an earlier run, or a YAML `remember_opml`)
        is reused.

    Bad / missing paths raise OpmlError, surfaced as a friendly stderr
    message + non-zero exit code instead of a traceback. When
    --remember-opml (or remember_opml: true in YAML) is set, the resolved
    source is persisted at the end of a successful run.
    """
    import feedparser

    opml_source: Path | None = args.path
    if opml_source is None:
        opml_source = _load_remembered_opml()
        if opml_source is None:
            _log.error(
                "No OPML path given and nothing remembered. Provide a path "
                "(file or directory of *.opml), or run once with "
                "--remember-opml so a later bare `opml` can reuse it."
            )
            return 1
        _log.info("Reusing remembered OPML source: %s", opml_source)

    try:
        opml_files = _collect_opml_files(opml_source)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    entries: list[FeedEntry] = []
    for opml_file in opml_files:
        _log.info("Loading OPML file: %s", opml_file)
        entries.extend(parse_opml(opml_file))

    if not entries:
        _log.warning("No <outline> entries with xmlUrl found across %d OPML file(s).",
                     len(opml_files))

    records: list[CveRecord] = []
    iocs: list[IocRecord] = []
    sources: list[str] = []

    for entry in entries:
        safe_url = _safe_url_for_log(entry.url)
        _log.info("Fetching feed: %s", safe_url)
        sources.append(entry.title or entry.url)
        feed = feedparser.parse(entry.url)
        if getattr(feed, "bozo", 0):
            reason = getattr(feed, "bozo_exception", "unknown parse error")
            _log.warning("Feed %s parsed with errors: %s", safe_url, reason)
        feed_source = entry.title or entry.url
        for item in feed.entries or []:
            pub = item.get("published_parsed") or item.get("updated_parsed")
            item_date = date(*pub[:3]) if pub else date.today()
            text = " ".join(
                [
                    item.get("title", ""),
                    item.get("summary", ""),
                    item.get("content", [{}])[0].get("value", "") if item.get("content") else "",
                ]
            )
            item_cves = extract_cves(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
            )
            records.extend(item_cves)
            # Per-feed-item CVE attribution: an IOC mentioned in the same
            # text blob as N CVEs gets all N ids stamped onto it. Slice E.5
            # surfaces these in the `cve_ids` IOC-CSV column, and the Web UI
            # filters per-CVE pages with substring match.
            iocs.extend(extract_iocs(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
                cve_ids=[r.cve_id for r in item_cves],
            ))

    iocs = _dedupe_iocs(iocs)

    date_mode = args.date_mode or "feed"
    enriched = enrich_cves(
        records, cache, api_key,
        associations=_resolve_associations(args),
        epss_date_range=_epss_date_range_for(args),
        confirm_large_trajectory=getattr(args, 'allow_large_epss_trajectory', False),
    )
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(
        enriched,
        args.cvss_threshold,
        args.epss_threshold,
        policy=getattr(args, "bucket_policy", None),
    )
    args._bucket_deltas = _record_runs(
        cache, enriched, policy=getattr(args, "bucket_policy", None),
    )
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"opml {opml_source}",
        "sources": sources,
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs, cache=cache)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)

    # OPML persistence: only after a fully successful run, so a failed
    # fetch doesn't pin a bad source for next time.
    if getattr(args, "remember_opml", False):
        try:
            state = _save_remembered_opml(opml_source)
            _log.info("Remembered OPML source for next run → %s", state)
        except OSError as exc:
            _log.warning("Could not persist remembered OPML: %s", exc)
    return 0


def _fetch_url_with_rate_limit(url: str, delay_ms: int = 500) -> str:
    """Fetch `url` and return its body text, pacing successive calls.

    Mirrors the `_last_call` function-attribute pattern used by
    `enrich/nvd.py:fetch_nvd`. The throttle is global across all
    URL-mode fetches in one process: `--depth 1` follows same-host
    links from a single seed so one global bucket suffices. `time.sleep`
    and `time.monotonic` are looked up through the shared `time` module
    so `patch("ramen_cve.time.sleep")` continues to work in tests
    (see src/ramen_cve/__init__.py).

    Raises `OpmlError` on any HTTP-level failure, with the safe-logged
    URL embedded, so callers can fail-soft per followed link via a
    single except clause.
    """
    delay = max(0.0, delay_ms / 1000.0)
    last = getattr(_fetch_url_with_rate_limit, "_last_call", 0.0)
    elapsed = time.monotonic() - last
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _fetch_url_with_rate_limit._last_call = time.monotonic()
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        raise OpmlError(
            f"Failed to fetch {_safe_url_for_log(url)}: {exc}"
        ) from exc
    return resp.text


def _run_url(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the url subcommand.

    With `--depth 0` (default): single-fetch behaviour, byte-identical to
    pre-feature output. With `--depth 1`: also extracts every same-host
    `<a href>` from the seed page, fetches each one (rate-limited per host,
    fail-soft per link), and runs CVE/IOC extraction over the union.
    """
    safe_url = _safe_url_for_log(args.url)
    _log.info("Fetching URL: %s", safe_url)
    delay_ms = getattr(args, "crawl_delay_ms", 500)
    try:
        text = _fetch_url_with_rate_limit(args.url, delay_ms=delay_ms)
    except OpmlError as exc:
        _log.error("%s", exc)
        return 1

    pub_date = date.today()
    for pattern in [
        r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
        r'<time[^>]+datetime=["\'](\d{4}-\d{2}-\d{2})',
        r'<meta[^>]+property=["\']og:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
    ]:
        m = re.search(pattern, text)
        if m:
            try:
                pub_date = date.fromisoformat(m.group(1))
                break
            except ValueError:
                _log.warning(
                    "Found publication-date-like string %r in %s but could not parse it; "
                    "trying next pattern.",
                    m.group(1),
                    safe_url,
                )
                continue
    else:
        _log.warning("Could not find publication date in %s; using today.", safe_url)

    # Build the page list: seed first, then optionally one hop of same-host
    # links. The seed's discovered pub_date is reused for linked pages —
    # follow-up pages are usually undated index/blog list pages without a
    # better signal, so the seed date is the best per-run anchor.
    visited: list[tuple[str, str]] = [(args.url, text)]
    depth = int(getattr(args, "depth", 0) or 0)
    if depth >= 1:
        raw_cap = getattr(args, "max_crawl_links", DEFAULT_MAX_CRAWL_LINKS)
        cap = int(raw_cap or DEFAULT_MAX_CRAWL_LINKS)
        followed = _filter_and_cap_links(args.url, text, cap=cap)
        if followed:
            _log.info(
                "Following %d same-host link(s) from seed (cap %d, throttle %dms).",
                len(followed), cap, delay_ms,
            )
        for url in followed:
            try:
                page_text = _fetch_url_with_rate_limit(url, delay_ms=delay_ms)
            except OpmlError as exc:
                _log.warning("%s", exc)
                continue
            visited.append((url, page_text))

    date_mode = args.date_mode or "feed"
    records = []
    iocs = []
    for src_url, page_text in visited:
        records.extend(extract_cves(page_text, src_url, pub_date, "feed_pub"))
        iocs.extend(extract_iocs(page_text, src_url, pub_date, "feed_pub"))
    enriched = enrich_cves(
        records, cache, api_key,
        associations=_resolve_associations(args),
        epss_date_range=_epss_date_range_for(args),
        confirm_large_trajectory=getattr(args, 'allow_large_epss_trajectory', False),
    )
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(
        enriched,
        args.cvss_threshold,
        args.epss_threshold,
        policy=getattr(args, "bucket_policy", None),
    )
    args._bucket_deltas = _record_runs(
        cache, enriched, policy=getattr(args, "bucket_policy", None),
    )
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"url {args.url}",
        # Every page actually visited (seed + any followed depth-1 links).
        # At --depth 0 this is just [args.url] — byte-identical to today.
        "sources": [u for u, _ in visited],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs, cache=cache)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


def _dedupe_iocs(iocs: list[IocRecord]) -> list[IocRecord]:
    """Collapse duplicates across multiple feed items into one record per (type, value).

    Keeps the earliest first_seen, OR-merges defanged_in_source, joins distinct
    sources with '; ', and propagates the worst-TLP + best-Admiralty tags so
    the merged IOC carries provenance from every feed it appeared in.
    """
    by_key: dict[tuple[str, str], IocRecord] = {}
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = IocRecord(
                ioc_type=ioc.ioc_type,
                value=ioc.value,
                source=ioc.source,
                first_seen=ioc.first_seen,
                first_seen_type=ioc.first_seen_type,
                defanged_in_source=ioc.defanged_in_source,
                tlp=ioc.tlp,
                admiralty=ioc.admiralty,
                last_seen=ioc.last_seen or ioc.first_seen,
                cve_ids=list(ioc.cve_ids),
            )
            continue
        if ioc.first_seen < existing.first_seen:
            existing.first_seen = ioc.first_seen
            existing.first_seen_type = ioc.first_seen_type
        # last_seen: maximum across all observations wins (most recent sighting
        # is the decay anchor).
        new_last = ioc.last_seen or ioc.first_seen
        if existing.last_seen is None or new_last > existing.last_seen:
            existing.last_seen = new_last
        if ioc.defanged_in_source and not existing.defanged_in_source:
            existing.defanged_in_source = True
        # Union cve_ids across feed-item observations of the same IOC,
        # preserving discovery order for deterministic serialization.
        for cve_id in ioc.cve_ids:
            if cve_id not in existing.cve_ids:
                existing.cve_ids.append(cve_id)
        if ioc.source and ioc.source not in existing.source.split("; "):
            existing.source = f"{existing.source}; {ioc.source}"
        existing.tlp = _worst_tlp(existing.tlp, ioc.tlp)
        existing.admiralty = _best_admiralty(existing.admiralty, ioc.admiralty)
    return list(by_key.values())


def _run_cve(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the cve subcommand."""
    cve_ids: list[str] = list(args.cves or [])

    if args.from_file:
        try:
            file_text = args.from_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            _log.error("--from-file path does not exist: %s", args.from_file)
            return 1
        except OSError as exc:
            _log.error("Could not read --from-file %s: %s", args.from_file, exc)
            return 1
        for line in file_text.splitlines():
            line = line.strip()
            if CVE_REGEX.fullmatch(line.upper()):
                cve_ids.append(line.upper())
            elif line:
                _log.warning("Skipping invalid CVE ID from file: %s", line)

    if not cve_ids:
        # Expected shape (kept in this comment so the error message doesn't
        # echo a literal placeholder the user has to delete):
        #   `ramen_cve cve CVE-2021-44228 CVE-2021-26855 ...`
        # or a --from-file argument whose lines each match CVE-YYYY-NNNN
        # (4-7 digit suffix).
        _log.error(
            "No valid CVE IDs provided. Pass them as positional arguments "
            "or via --from-file. Each ID must match CVE-YYYY-NNNN."
        )
        return 1

    # Default for manual CVE input is "disclosure" because there is no feed date.
    # Honor an explicit --date-mode from the user without overriding it.
    date_mode = args.date_mode or "disclosure"

    today = date.today()
    records = [CveRecord(cve_id, "manual_input", today, "manual_input") for cve_id in cve_ids]
    enriched = enrich_cves(
        records, cache, api_key,
        associations=_resolve_associations(args),
        epss_date_range=_epss_date_range_for(args),
        confirm_large_trajectory=getattr(args, 'allow_large_epss_trajectory', False),
    )
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(
        enriched,
        args.cvss_threshold,
        args.epss_threshold,
        policy=getattr(args, "bucket_policy", None),
    )
    args._bucket_deltas = _record_runs(
        cache, enriched, policy=getattr(args, "bucket_policy", None),
    )
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"cve {' '.join(cve_ids)}",
        "sources": ["manual_input"],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _output(enriched, args, metadata, cache=cache)
    return 0


def _run_stix(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the stix subcommand (file or TAXII source).

    The user supplies EITHER `path` or both `--taxii-url` and `--taxii-collection`.
    Combining the two is rejected so the source is unambiguous.
    """
    has_file = bool(args.path)
    has_taxii = bool(args.taxii_url and args.taxii_collection)
    if not (has_file or has_taxii):
        _log.error(
            "stix: provide a bundle path OR both --taxii-url and --taxii-collection."
        )
        return 1
    if has_file and has_taxii:
        _log.error("stix: --taxii-url is mutually exclusive with a bundle path.")
        return 1

    try:
        if has_file:
            cve_records, iocs = parse_stix_bundle(args.path)
            source_label = str(args.path)
        else:
            cve_records, iocs = pull_taxii(
                args.taxii_url,
                args.taxii_collection,
                username=args.taxii_user,
                password=args.taxii_pass,
            )
            source_label = f"taxii:{args.taxii_url}/{args.taxii_collection}"
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    if not cve_records and not iocs:
        _log.warning("STIX source produced no CVEs or IOCs.")

    date_mode = args.date_mode or "disclosure"
    enriched = enrich_cves(
        cve_records, cache, api_key,
        epss_date_range=_epss_date_range_for(args),
        confirm_large_trajectory=getattr(args, 'allow_large_epss_trajectory', False),
    )
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(
        enriched,
        args.cvss_threshold,
        args.epss_threshold,
        policy=getattr(args, "bucket_policy", None),
    )
    args._bucket_deltas = _record_runs(
        cache, enriched, policy=getattr(args, "bucket_policy", None),
    )
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"stix {source_label}",
        "sources": [source_label],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs, cache=cache)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


def _run_web(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Render the static-HTML Web UI to `args.site_dir` (Task 8).

    Slice A: minimal `index.html` (H1 + "N runs recorded.") plus an
    empty `static/style.css`. Slices B-G extend per
    README.md (Web UI).

    Returns rc=1 when the cache's `runs` table is empty — there's
    nothing to render, and the empty-state landing page would obscure
    the misconfiguration that led here (design-doc §D11). `api_key`
    is accepted to match the standard `_run_<name>` signature but
    unused; the Web UI never touches the network.
    """
    del api_key
    try:
        paths = build_site(
            cache, args.site_dir,
            policy=getattr(args, "bucket_policy", None),
            out_dir=getattr(args, "out_dir", None),
        )
    except WebUiError as exc:
        _log.warning("%s", exc)
        return 1
    for path in paths.values():
        print(str(path))
    return 0

