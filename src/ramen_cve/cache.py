"""ramen_cve.cache — SQLite response cache (Layer-0 leaf).

Per-source TTL tables + non-purged `runs` history + append-only
`audit_log`. Depends only on stdlib + the constants/models leaves.
See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from .constants import DEFAULT_CACHE_TTL_HOURS
from .models import _utcnow

_log = logging.getLogger(__name__)


class Cache:
    """SQLite-backed cache for NVD and EPSS API responses.

    Both tables store ISO-8601 timestamps in fetched_at. TTL is checked at
    read time; stale rows are left in place until purge() is called.
    Pass path=':memory:' for a transient in-memory cache (used by --no-cache).
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cve_id      TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS epss_cache (
            cve_id      TEXT NOT NULL,
            score_date  TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL,
            PRIMARY KEY (cve_id, score_date)
        );
        CREATE TABLE IF NOT EXISTS kev_cache (
            id          TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS exploit_cache (
            source      TEXT NOT NULL,
            key         TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL,
            PRIMARY KEY (source, key)
        );
        CREATE TABLE IF NOT EXISTS enrichment_cache (
            enricher    TEXT NOT NULL,
            ioc_type    TEXT NOT NULL,
            value       TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL,
            PRIMARY KEY (enricher, ioc_type, value)
        );
        CREATE TABLE IF NOT EXISTS runs (
            cve_id      TEXT NOT NULL,
            ts_iso      TEXT NOT NULL,
            bucket      TEXT NOT NULL,
            cvss_score  REAL,
            epss_score  REAL,
            PRIMARY KEY (cve_id, ts_iso)
        );
        CREATE TABLE IF NOT EXISTS run_artefacts (
            ts_iso      TEXT PRIMARY KEY,
            disk_stamp  TEXT NOT NULL,
            out_dir     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_iso          TEXT NOT NULL,
            actor           TEXT NOT NULL,
            command         TEXT NOT NULL,
            args_redacted   TEXT NOT NULL,
            outcome         TEXT NOT NULL
        );
    """

    def __init__(self, path: Path | str, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS) -> None:
        """Open (or create) the cache database and ensure the schema exists."""
        self._ttl = timedelta(hours=ttl_hours)
        # timeout=30 lets sqlite retry briefly when another process holds the
        # write lock (concurrent daemon / scheduled run) instead of raising
        # OperationalError("database is locked") on the first contended commit.
        self._conn = sqlite3.connect(str(path), timeout=30)
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    def _is_fresh(self, fetched_at: str) -> bool:
        """Return True if fetched_at timestamp is within the TTL window.

        A corrupt timestamp (from a hand-edited cache, a downgrade, or
        a partial write) is treated as stale rather than raising — the
        row will be re-fetched from the API and overwritten.
        """
        try:
            ts = datetime.fromisoformat(fetched_at)
        except (TypeError, ValueError):
            _log.warning("Cache row has unparseable fetched_at %r; treating as stale.", fetched_at)
            return False
        return _utcnow() - ts < self._ttl

    def get_nvd(self, cve_id: str) -> dict | None:
        """Return cached NVD payload if present and within TTL, else None."""
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM nvd_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_nvd(self, cve_id: str, payload: dict) -> None:
        """Upsert an NVD payload into the cache."""
        self._conn.execute(
            "INSERT OR REPLACE INTO nvd_cache VALUES (?, ?, ?)",
            (cve_id, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def get_epss(self, cve_id: str, score_date: str) -> dict | None:
        """Return cached EPSS payload if present and within TTL, else None."""
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM epss_cache WHERE cve_id = ? AND score_date = ?",
            (cve_id, score_date),
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_epss(self, cve_id: str, score_date: str, payload: dict) -> None:
        """Upsert an EPSS payload into the cache."""
        self._conn.execute(
            "INSERT OR REPLACE INTO epss_cache VALUES (?, ?, ?, ?)",
            (cve_id, score_date, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def get_kev_catalog(self) -> dict[str, dict] | None:
        """Return the cached CISA KEV catalog if fresh, else None.

        The catalog is stored as a single row keyed on 'catalog'; we treat the
        whole JSON-serialized {cve_id: kev_record} dict as the cache payload.
        """
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM kev_cache WHERE id = ?",
            ("catalog",),
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_kev_catalog(self, catalog: dict[str, dict]) -> None:
        """Upsert the CISA KEV catalog into the cache as a single blob."""
        self._conn.execute(
            "INSERT OR REPLACE INTO kev_cache VALUES (?, ?, ?)",
            ("catalog", json.dumps(catalog), _utcnow().isoformat()),
        )
        self._conn.commit()

    def get_exploit(self, source: str, key: str) -> dict | None:
        """Return cached exploit-tracker payload for (source, key) if fresh, else None.

        `source` is one of 'exploitdb' | 'nuclei' | 'github'. `key` is 'index' for
        global indices, or a CVE ID for per-CVE GitHub-search results.
        """
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM exploit_cache WHERE source = ? AND key = ?",
            (source, key),
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_exploit(self, source: str, key: str, payload: dict) -> None:
        """Upsert an exploit-tracker payload."""
        self._conn.execute(
            "INSERT OR REPLACE INTO exploit_cache VALUES (?, ?, ?, ?)",
            (source, key, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def get_enrichment(self, enricher: str, ioc_type: str, value: str) -> dict | None:
        """Return a cached enrichment payload if fresh, else None."""
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM enrichment_cache "
            "WHERE enricher = ? AND ioc_type = ? AND value = ?",
            (enricher, ioc_type, value),
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_enrichment(self, enricher: str, ioc_type: str, value: str, payload: dict) -> None:
        """Upsert an enrichment payload keyed on (enricher, ioc_type, value)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache VALUES (?, ?, ?, ?, ?)",
            (enricher, ioc_type, value, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def record_run(
        self,
        cve_id: str,
        bucket: str,
        cvss_score: float | None,
        epss_score: float | None,
    ) -> None:
        """Append (or update) a single CVE's snapshot for this run."""
        self._conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?)",
            (cve_id, _utcnow().isoformat(timespec="seconds"), bucket, cvss_score, epss_score),
        )
        self._conn.commit()

    def list_run_timestamps(self) -> list[str]:
        """Return distinct `ts_iso` values in the `runs` table, newest first.

        Used by the Web UI (Task 8) to enumerate every pipeline invocation
        that has touched the cache. Each `ts_iso` groups all CVE rows from
        a single `_record_runs` call (one shared second-precision stamp).
        """
        rows = self._conn.execute(
            "SELECT DISTINCT ts_iso FROM runs ORDER BY ts_iso DESC"
        ).fetchall()
        return [r[0] for r in rows]

    def record_artefacts(self, ts_iso: str, disk_stamp: str, out_dir: str) -> None:
        """Record the on-disk artefacts produced by one pipeline invocation.

        `ts_iso` joins to `runs.ts_iso` (second-precision ISO from
        `_record_runs`). `disk_stamp` is the microsecond stamp embedded
        in artefact filenames by `pipeline._output`. `out_dir` is the
        absolute directory those files were written to.

        Uses `INSERT OR IGNORE` (design-doc §D25): a second invocation
        sharing a second with an earlier one silently keeps the earlier
        row. Realistic only under daemon mode at sub-second intervals,
        which is not a supported configuration; the Web UI's LEFT JOIN
        against `runs` still works either way.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO run_artefacts (ts_iso, disk_stamp, out_dir) "
            "VALUES (?, ?, ?)",
            (ts_iso, disk_stamp, out_dir),
        )
        self._conn.commit()

    def get_artefacts(self, ts_iso: str) -> dict | None:
        """Return the `run_artefacts` row for `ts_iso`, or None if absent.

        Used by the Web UI's discovery step to attach disk-artefact
        links to each run from the canonical `runs.ts_iso` set.
        """
        row = self._conn.execute(
            "SELECT ts_iso, disk_stamp, out_dir FROM run_artefacts WHERE ts_iso = ?",
            (ts_iso,),
        ).fetchone()
        if row is None:
            return None
        return {"ts_iso": row[0], "disk_stamp": row[1], "out_dir": row[2]}

    def get_nvd_raw(self, cve_id: str) -> dict | None:
        """Return the cached NVD payload regardless of TTL, or None if absent.

        TTL-bypassing reader for the offline Web UI (Task 8): a per-CVE
        detail page must render whatever the cache last stored, even if
        the row is older than `--cache-ttl`. Live API lookups still use
        `get_nvd`, which preserves the TTL contract.
        """
        row = self._conn.execute(
            "SELECT payload_json FROM nvd_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_epss_raw(self, cve_id: str) -> dict | None:
        """Return the most-recent cached EPSS payload for `cve_id`, ignoring TTL.

        Picks the latest `score_date` (newest assessment). Used by the
        Web UI's per-CVE summary; live enrichment still flows through
        `get_epss(cve_id, score_date)` with its TTL contract.
        """
        row = self._conn.execute(
            "SELECT payload_json FROM epss_cache WHERE cve_id = ? "
            "ORDER BY score_date DESC LIMIT 1",
            (cve_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_kev_catalog_raw(self) -> dict[str, dict] | None:
        """Return the cached CISA KEV catalog regardless of TTL, or None.

        TTL-bypassing reader for the offline Web UI. Live enrichment
        uses `get_kev_catalog` to refresh stale catalogs from CISA.
        """
        row = self._conn.execute(
            "SELECT payload_json FROM kev_cache WHERE id = ?",
            ("catalog",),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_runs(self, cve_id: str) -> list[dict]:
        """Return every recorded run for `cve_id` in chronological order."""
        rows = self._conn.execute(
            "SELECT ts_iso, bucket, cvss_score, epss_score FROM runs "
            "WHERE cve_id = ? ORDER BY ts_iso ASC",
            (cve_id,),
        ).fetchall()
        return [
            {"ts_iso": r[0], "bucket": r[1], "cvss_score": r[2], "epss_score": r[3]}
            for r in rows
        ]

    def log_audit(
        self,
        actor: str,
        command: str,
        args_redacted: str,
        outcome: str,
        ts_iso: str | None = None,
    ) -> None:
        """Append-only audit record.

        Intentionally NEVER updates or deletes — the table is the on-disk
        chain-of-custody for who ran what when. `ts_iso` may be pre-recorded
        from the start of the action; if omitted, we stamp now.
        """
        self._conn.execute(
            "INSERT INTO audit_log (ts_iso, actor, command, args_redacted, outcome) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                ts_iso or _utcnow().isoformat(timespec="seconds"),
                actor,
                command,
                args_redacted,
                outcome,
            ),
        )
        self._conn.commit()

    def get_audit(self, limit: int = 100) -> list[dict]:
        """Return the most recent `limit` audit entries in chronological order."""
        rows = self._conn.execute(
            "SELECT id, ts_iso, actor, command, args_redacted, outcome "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return [
            {
                "id": r[0],
                "ts_iso": r[1],
                "actor": r[2],
                "command": r[3],
                "args_redacted": r[4],
                "outcome": r[5],
            }
            for r in reversed(rows)
        ]

    def purge(self) -> None:
        """Delete entries older than the TTL from all tables.

        Note: the `runs` table is intentionally NOT purged — historical
        trending is the whole point of the table.
        """
        cutoff = (_utcnow() - self._ttl).isoformat()
        self._conn.execute("DELETE FROM nvd_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM epss_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM kev_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM exploit_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM enrichment_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.commit()
