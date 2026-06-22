"""ramen_cve.pipeline — post-enrichment glue: optional IOC enrich,
sector/decay filters, associations, dispatch, inventory digest, and
the multi-format `_output` writer (Layer-4). See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import argparse
import logging
import os
import re
from pathlib import Path

from .associations import load_associations
from .cache import Cache
from .cliutil import _format_includes, _resolve_out_dir
from .decay import apply_ioc_decay, filter_iocs_by_confidence
from .dispatch.runner import dispatch_records
from .enrich.inventory import correlate_inventory, load_inventory
from .enrich.iocs import enrich_iocs
from .models import EnrichedCve, IocRecord, OpmlError, _utcnow
from .output.csv_writer import write_csv, write_epss_trajectory_csv
from .output.html_quadrant import write_quadrant_html
from .output.markdown import write_markdown
from .output.navigator import write_navigator
from .output.siem_queries import SIEM_QUERY_PLATFORMS, write_siem_query_stubs
from .output.sigma import write_sigma_stubs
from .output.stix import write_iocs_csv, write_stix
from .output.yara import write_yara_stubs
from .plugins import discover_writers, invoke_writer

_log = logging.getLogger(__name__)


def _maybe_enrich_iocs(args: argparse.Namespace, iocs: list[IocRecord], cache: Cache) -> None:
    """Run enrich_iocs unless --no-enrich-iocs was passed."""
    if iocs and not args.no_enrich_iocs:
        enrich_iocs(iocs, cache)


def _maybe_filter_by_sector(
    args: argparse.Namespace, enriched: list[EnrichedCve]
) -> list[EnrichedCve]:
    """Drop CVEs whose only adversary attribution targets a different sector.

    Safe-by-default policy: a CVE with NO linked_actors stays in the report
    (we can't claim it isn't relevant). A CVE with linked_actors stays only
    if at least one actor's sectors_targeted includes the chosen sector.

    A blank `args.sector` (the default) returns the list untouched.
    """
    sector = (getattr(args, "sector", None) or "").strip().lower()
    if not sector:
        return enriched
    kept: list[EnrichedCve] = []
    dropped = 0
    for rec in enriched:
        if not rec.linked_actors:
            kept.append(rec)
            continue
        if any(sector in (a.sectors_targeted or []) for a in rec.linked_actors):
            kept.append(rec)
        else:
            dropped += 1
    if dropped:
        _log.info(
            "Dropped %d CVE(s) whose only adversary attribution did not target %r.",
            dropped, sector,
        )
    return kept


def _decay_and_filter_iocs(
    args: argparse.Namespace, iocs: list[IocRecord]
) -> list[IocRecord]:
    """Stamp every IOC with its decay-weighted confidence and drop any below the floor.

    Mutates each IOC's confidence in place, then returns a (possibly shorter)
    list with sub-floor entries excluded. The floor defaults to 0.0 — without
    --ioc-confidence-floor every input survives.
    """
    apply_ioc_decay(iocs)
    floor = float(getattr(args, "ioc_confidence_floor", 0.0) or 0.0)
    before = len(iocs)
    out = filter_iocs_by_confidence(iocs, floor)
    dropped = before - len(out)
    if dropped:
        _log.info(
            "Dropped %d IOC(s) below the confidence floor (%.3f).", dropped, floor,
        )
    return out


def _resolve_associations(args: argparse.Namespace) -> dict[str, dict[str, list]]:
    """Resolve which associations file to use for this run.

    Falls back to the bundled DEFAULT_ASSOCIATIONS_PATH unless the user passed
    --associations-file. A missing file produces an empty dict + warning so the
    rest of the pipeline still runs.
    """
    return load_associations(args.associations_file)


def _maybe_apply_ssvc(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """If --ssvc-profile is set, populate ssvc_action + ssvc_decision_points.

    Inert unless the flag was passed. A missing / malformed profile JSON
    logs a WARNING and the run continues without SSVC populated — same
    fail-soft pattern as every network fetcher; SSVC is auxiliary, not
    load-bearing.
    """
    import json as _json

    from .ssvc import apply_ssvc

    profile_path = getattr(args, "ssvc_profile", None)
    if profile_path is None:
        return
    try:
        raw = _json.loads(Path(profile_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log.warning("Skipping SSVC: profile %r unreadable (%s)", str(profile_path), exc)
        return
    apply_ssvc(enriched, raw if isinstance(raw, dict) else None)
    _log.info("SSVC applied to %d CVE(s) using profile %s", len(enriched), profile_path)


def _maybe_dispatch(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """If --dispatch is set, push high-priority records to configured dispatchers.

    Bucket-transition deltas computed by `_record_runs` are read off
    `args._bucket_deltas` and forwarded so payloads can include the
    transition and `--dispatch-on-delta-only` can filter on it.
    """
    if not getattr(args, "dispatch", False):
        return
    deltas = getattr(args, "_bucket_deltas", None) or {}
    delta_only = getattr(args, "dispatch_on_delta_only", False)
    sent = dispatch_records(enriched, deltas=deltas, delta_only=delta_only)
    _log.info("Dispatch complete: %d successful posts.", sent)


def _maybe_correlate_inventory(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """Load --inventory (if set) and annotate each EnrichedCve with affected_hosts.

    A missing or unreadable inventory file is logged as an error but does NOT
    abort the run — the rest of the report is still useful without correlation.
    The parsed inventory rows are stashed on args._inventory_rows so the email
    digest dispatcher can map hosts → owner email addresses later.
    """
    inv_path: Path | None = getattr(args, "inventory", None)
    if not inv_path:
        args._inventory_rows = []
        return
    try:
        inventory = load_inventory(inv_path)
    except OpmlError as exc:
        _log.error("Inventory correlation skipped: %s", exc)
        args._inventory_rows = []
        return
    correlate_inventory(enriched, inventory)
    affected = sum(1 for r in enriched if r.affected_hosts)
    _log.info(
        "Inventory correlation: %d/%d CVEs affect at least one host (%d inventory rows).",
        affected, len(enriched), len(inventory),
    )
    args._inventory_rows = inventory


def _get_github_token() -> str | None:
    """Return GITHUB_TOKEN from the environment, or None if absent.

    The token is only used to lift GitHub Search rate limits when
    enrich_with_exploit_status is enabled. We never log it and never persist it.
    """

    token = os.getenv("GITHUB_TOKEN") or None
    return token


# Output-format file extensions that _safe_basename strips off a user-supplied
# basename so we don't end up with `my-report.csv.csv`. Edit here when adding
# new --format choices.
_KNOWN_OUTPUT_EXTENSIONS: tuple[str, ...] = (
    ".csv", ".md", ".json", ".yar", ".yaml", ".yml",
)


def _safe_basename(value: str | None) -> str:
    """Sanitize a user-supplied basename for use as an output-file stem.

    Steps applied in order:
      1. Strip surrounding whitespace.
      2. Replace path / glob / shell-meta characters ( \\ / : * ? " < > | )
         with ``_``.
      3. Strip leading dot / dash / underscore runs so traversal artefacts
         (``../etc/passwd``) and hidden-file shapes (``.cache``) collapse
         to a clean stem.
      4. Strip one trailing recognized output extension (``.csv``, ``.md``,
         ``.json``, ``.yar``, ``.yaml``, ``.yml``). The writer re-appends
         the correct extension based on the actual format being written,
         so a user pasting ``my-report.csv`` ends up with one ``.csv``,
         not two.

    Empty input returns ``''`` (the caller falls back to a timestamped stem).
    """
    if not value:
        return ""
    cleaned = re.sub(r"[\\/:*?\"<>|]+", "_", value.strip())
    cleaned = cleaned.lstrip(". -_")
    # Strip ONE known output extension if present (case-insensitive).
    lower = cleaned.lower()
    for ext in _KNOWN_OUTPUT_EXTENSIONS:
        if lower.endswith(ext):
            cleaned = cleaned[: -len(ext)]
            break
    return cleaned or ""


def _unique_output_path(
    out_dir: Path, ts: str, suffix: str, basename: str | None = None
) -> Path:
    """Return a path that does not yet exist by appending -N if needed.

    If `basename` is provided it becomes the file stem (e.g. 'q2-triage.csv').
    Otherwise we fall back to the timestamped 'ramen-cve-<ts>.<suffix>' shape.
    Two runs that land on the same stem must not silently overwrite each other:
    we probe -1, -2, ... up to 1000 and return the first free name.
    """
    stem = _safe_basename(basename) or f"ramen-cve-{ts}"
    base = out_dir / f"{stem}.{suffix}"
    if not base.exists():
        return base
    for i in range(1, 1000):
        candidate = out_dir / f"{stem}-{i}.{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate a unique output filename in {out_dir}")


def _output(
    enriched: list[EnrichedCve],
    args: argparse.Namespace,
    metadata: dict,
    iocs: list[IocRecord] | None = None,
    cache: Cache | None = None,
) -> dict[str, Path | None]:
    """Write CSV and/or Markdown output based on --format flag.

    Returns a dict mapping output kind ('csv', 'iocs_csv', 'md', 'stix',
    'sigma_dir', 'yara_dir', 'html') to the Path that was written, or
    None for the kinds that --format didn't ask for. Callers use that
    dict to attach the rendered files in downstream pushes (see
    _maybe_digest).

    When `iocs` is non-empty and --format includes csv, an additional
    `<basename>-iocs.csv` file is written next to the main CVE CSV. The
    Markdown report grows an Indicators of Compromise section regardless.

    TLP:RED records are stripped from the output unless --allow-tlp-red was
    passed; the count of stripped records is logged at WARNING.

    `cache` (Task 8 Slice B): when provided AND at least one file was
    written, stamps a row into `run_artefacts(ts_iso, disk_stamp,
    out_dir)` so the Web UI can join the never-purged `runs` history to
    the actual on-disk artefacts. `cache=None` is the back-compat path
    used by tests that monkeypatch `_output` (no cache reach-through).
    """
    # Microsecond resolution makes single-process collisions essentially
    # impossible; the -N suffix loop in _unique_output_path covers
    # cross-process collisions and any clock that lacks sub-second
    # resolution. The same _utcnow() instant supplies both the disk
    # stamp (`ts`) and the second-precision `ts_iso` used by Slice B's
    # run_artefacts row — so the JOIN against `runs.ts_iso` works
    # literally (modulo the rare second-boundary cross, which the LEFT
    # JOIN handles by rendering an empty artefact link per design-doc).
    _now = _utcnow()
    ts = _now.strftime("%Y%m%dT%H%M%S%f")
    ts_iso = _now.isoformat(timespec="seconds")
    # Resolve --out-dir = None / '' / '.' to the actual cwd so the on-disk
    # path is unambiguous (no leading-period surprises on Windows).
    out_dir: Path = _resolve_out_dir(getattr(args, "out_dir", None))
    out_dir.mkdir(parents=True, exist_ok=True)
    iocs = iocs or []
    basename = _safe_basename(getattr(args, "basename", None))
    sigma_stem = basename or f"ramen-cve-{ts}"

    if not getattr(args, "allow_tlp_red", False):
        before = (len(enriched), len(iocs))
        enriched = [r for r in enriched if (r.tlp or "CLEAR").upper() != "RED"]
        iocs = [i for i in iocs if (i.tlp or "CLEAR").upper() != "RED"]
        stripped_cve = before[0] - len(enriched)
        stripped_ioc = before[1] - len(iocs)
        if stripped_cve or stripped_ioc:
            _log.warning(
                "Stripped %d TLP:RED CVE record(s) and %d TLP:RED IOC record(s); "
                "pass --allow-tlp-red to include them.",
                stripped_cve,
                stripped_ioc,
            )

    # Risk-weighted prioritization — always on. Reads CVSS / EPSS / KEV
    # (already populated) plus rec.affected_host_criticality (which
    # correlate_inventory has filled in earlier when --inventory was
    # supplied with a `criticality` column). With no inventory data the
    # host-weight collapses to 1.0 so the score still differentiates by
    # CVSS / EPSS / KEV — the field is never blank.
    from .risk import apply_risk_scores
    apply_risk_scores(enriched)

    # SSVC scoring (additive, opt-in via --ssvc-profile). Runs AFTER the
    # TLP filter so we don't waste cycles scoring records that won't be
    # written, BEFORE every writer so the new fields land in CSV / MD /
    # STIX / Web UI consistently.
    _maybe_apply_ssvc(args, enriched)

    paths: dict[str, Path | None] = {
        "csv": None, "iocs_csv": None, "epss_trajectory_csv": None, "md": None,
        "stix": None, "sigma_dir": None, "yara_dir": None, "html": None,
        "navigator": None,
        "kql_dir": None, "spl_dir": None, "eql_dir": None,
    }

    if _format_includes(args.format, "csv"):
        csv_path = _unique_output_path(out_dir, ts, "csv", basename=basename)
        _log.info("Writing CVE CSV report → %s", csv_path)
        write_csv(enriched, csv_path)
        print(str(csv_path))
        paths["csv"] = csv_path
        if iocs:
            # Without a basename, we want `ramen-cve-<ts>-iocs.csv`. Encoding
            # the "-iocs" tail via the suffix kwarg keeps that shape. With a
            # basename, we instead set the stem to `<basename>-iocs` and use
            # a plain ".csv" suffix so we don't end up with `*-iocs.iocs.csv`.
            if basename:
                iocs_path = _unique_output_path(
                    out_dir, ts, "csv", basename=f"{basename}-iocs"
                )
            else:
                iocs_path = _unique_output_path(out_dir, ts, "iocs.csv")
            _log.info("Writing IOC CSV report → %s", iocs_path)
            write_iocs_csv(iocs, iocs_path)
            print(str(iocs_path))
            paths["iocs_csv"] = iocs_path
        # EPSS trajectory sidecar — only emitted when --date-mode epss was
        # given a multi-day range (the orchestrator populates each record's
        # epss_trajectory dict). Records with an empty dict contribute no
        # rows; the file is suppressed entirely when no record has any.
        if any(r.epss_trajectory for r in enriched):
            if basename:
                traj_path = _unique_output_path(
                    out_dir, ts, "csv", basename=f"{basename}-epss-trajectory"
                )
            else:
                traj_path = _unique_output_path(out_dir, ts, "epss-trajectory.csv")
            _log.info("Writing EPSS trajectory sidecar → %s", traj_path)
            write_epss_trajectory_csv(enriched, traj_path)
            print(str(traj_path))
            paths["epss_trajectory_csv"] = traj_path

    if _format_includes(args.format, "md"):
        md_path = _unique_output_path(out_dir, ts, "md", basename=basename)
        _log.info("Writing Markdown report → %s", md_path)
        write_markdown(
            enriched,
            md_path,
            metadata,
            iocs=iocs,
            policy=getattr(args, "bucket_policy", None),
        )
        print(str(md_path))
        paths["md"] = md_path

    if _format_includes(args.format, "stix"):
        stix_path = _unique_output_path(out_dir, ts, "stix.json", basename=basename)
        _log.info("Writing STIX 2.1 bundle → %s", stix_path)
        write_stix(enriched, stix_path, iocs=iocs, run_metadata=metadata)
        print(str(stix_path))
        paths["stix"] = stix_path

    if _format_includes(args.format, "sigma"):
        sigma_dir = out_dir / f"{sigma_stem}-sigma"
        _log.info("Writing Sigma rule stubs → %s", sigma_dir)
        files = write_sigma_stubs(enriched, sigma_dir)
        if files:
            print(str(sigma_dir))
            paths["sigma_dir"] = sigma_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs in this run; no Sigma stubs written."
            )

    if _format_includes(args.format, "yara"):
        yara_dir = out_dir / f"{sigma_stem}-yara"
        _log.info("Writing YARA rule stubs → %s", yara_dir)
        files = write_yara_stubs(enriched, yara_dir)
        if files:
            print(str(yara_dir))
            paths["yara_dir"] = yara_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs with linked malware; "
                "no YARA stubs written."
            )

    # Native SIEM query stubs — one writer per platform, same eligibility as
    # Sigma (KEV / patch-now). Empty result is logged and skipped, no dir.
    for platform in SIEM_QUERY_PLATFORMS:
        if not _format_includes(args.format, platform):
            continue
        siem_dir = out_dir / f"{sigma_stem}-{platform}"
        _log.info("Writing %s query stubs → %s", platform.upper(), siem_dir)
        files = write_siem_query_stubs(enriched, siem_dir, platform)
        if files:
            print(str(siem_dir))
            paths[f"{platform}_dir"] = siem_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs in this run; no %s stubs written.",
                platform.upper(),
            )

    if _format_includes(args.format, "html"):
        html_path = _unique_output_path(out_dir, ts, "html", basename=basename)
        _log.info("Writing HTML quadrant report → %s", html_path)
        write_quadrant_html(enriched, html_path, metadata)
        print(str(html_path))
        paths["html"] = html_path

    if _format_includes(args.format, "navigator"):
        # `<basename>.attack-layer.json` so the extension reads as ATT&CK
        # Navigator to anyone in a file picker (the layer JSON spec
        # recognises any *.json — the dual suffix is convention, not strict).
        nav_path = _unique_output_path(
            out_dir, ts, "attack-layer.json", basename=basename
        )
        _log.info("Writing ATT&CK Navigator layer → %s", nav_path)
        write_navigator(enriched, nav_path, run_metadata=metadata)
        print(str(nav_path))
        paths["navigator"] = nav_path

    # Third-party plugin writers (entry-point group ramen_cve.writers).
    # Discovered lazily — calling discover_writers() with no plugins
    # installed is ~microseconds and produces an empty dict. Each plugin
    # whose token is in --format gets a suggested path under out_dir; the
    # plugin returns the actual path it wrote (may have a different
    # extension), or None to skip. Failures are fail-soft per the
    # documented contract: a bad plugin warns and is skipped, never
    # aborts the run.
    for token, writer in discover_writers().items():
        if not _format_includes(args.format, token):
            continue
        plugin_stem = basename or f"ramen-cve-{ts}"
        suggested = out_dir / f"{plugin_stem}-{token}.out"
        _log.info("Invoking plugin writer %r → %s", token, suggested)
        actual = invoke_writer(
            token, writer, enriched, suggested,
            run_metadata=metadata, iocs=iocs,
            policy=getattr(args, "bucket_policy", None),
        )
        if actual is not None:
            print(str(actual))
            paths[f"plugin:{token}"] = actual

    # Slice B: stamp the run_artefacts row only if a cache is plumbed
    # through AND we actually wrote at least one file. A run that
    # produces no artefacts (e.g., all records TLP:RED-stripped under
    # --format csv, or a format whose writer skipped — see Sigma /
    # YARA "no eligible records" branches) is left out so the Web UI's
    # discovery LEFT JOIN doesn't surface ghost entries.
    if cache is not None and any(p is not None for p in paths.values()):
        cache.record_artefacts(ts_iso, ts, str(out_dir))

    return paths

