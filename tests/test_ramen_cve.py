"""Tests for ramen_cve.py — grown slice by slice."""

import csv
import json
import os
import tempfile
import textwrap
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

from ramen_cve import Cache, EnrichedCve, OpmlError, extract_cves, parse_opml

TODAY = date(2024, 6, 1)
SRC = "test-source"
FT = "feed_pub"


# ---------------------------------------------------------------------------
# Slice 1.1 — extract_cves
# ---------------------------------------------------------------------------


def test_extract_cves_plain_match():
    """Single CVE in text returns one record."""
    records = extract_cves("CVE-2021-44228 was bad", SRC, TODAY, FT)
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2021-44228"


def test_extract_cves_deduplicates():
    """Same CVE mentioned twice returns one record."""
    records = extract_cves("CVE-2021-44228 and again CVE-2021-44228", SRC, TODAY, FT)
    assert len(records) == 1


def test_extract_cves_multiple_distinct():
    """Two different CVEs returns two records in order of first occurrence."""
    records = extract_cves("CVE-2021-44228 and CVE-2021-26855", SRC, TODAY, FT)
    assert len(records) == 2
    assert records[0].cve_id == "CVE-2021-44228"
    assert records[1].cve_id == "CVE-2021-26855"


def test_extract_cves_normalizes_case():
    """Lower-case or mixed-case input is normalized to upper-case."""
    records = extract_cves("cve-2021-44228 and Cve-2021-26855", SRC, TODAY, FT)
    assert all(r.cve_id == r.cve_id.upper() for r in records)
    assert records[0].cve_id == "CVE-2021-44228"


def test_extract_cves_mixed_case_deduplicates():
    """Lower-case and upper-case of the same CVE count as one record."""
    records = extract_cves("cve-2021-44228 CVE-2021-44228", SRC, TODAY, FT)
    assert len(records) == 1


def test_extract_cves_no_match_returns_empty():
    """Text with no CVE IDs returns an empty list."""
    records = extract_cves("Nothing to see here.", SRC, TODAY, FT)
    assert records == []


def test_extract_cves_adjacent_text():
    """CVE immediately surrounded by non-space characters is still matched."""
    records = extract_cves("...CVE-2024-1234.See more...", SRC, TODAY, FT)
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1234"


def test_extract_cves_no_false_match_prefix_only():
    """'CVE-' without a year-sequence is not matched."""
    records = extract_cves("CVE- is not a CVE ID", SRC, TODAY, FT)
    assert records == []


def test_extract_cves_no_false_match_too_few_digits():
    """A sequence with fewer than 4 trailing digits is not matched."""
    records = extract_cves("CVE-2024-123 is malformed", SRC, TODAY, FT)
    assert records == []


def test_extract_cves_seven_digit_id_valid():
    """Seven-digit CVE ID (upper bound) is matched."""
    records = extract_cves("CVE-2024-1234567 found", SRC, TODAY, FT)
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1234567"


def test_extract_cves_eight_digit_id_not_matched():
    """Eight or more trailing digits is not a valid CVE ID per the regex."""
    records = extract_cves("CVE-2024-12345678 should not match", SRC, TODAY, FT)
    assert records == []


def test_extract_cves_record_fields():
    """Returned CveRecord carries the correct source, date, and type."""
    records = extract_cves("CVE-2021-44228", SRC, TODAY, FT)
    r = records[0]
    assert r.source == SRC
    assert r.first_seen == TODAY
    assert r.first_seen_type == FT


# ---------------------------------------------------------------------------
# Slice 1.2 — parse_opml
# ---------------------------------------------------------------------------

FLAT_OPML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <opml version="2.0">
      <head><title>Test</title></head>
      <body>
        <outline type="rss" text="Feed A" xmlUrl="https://a.example/feed" htmlUrl="https://a.example/"/>
        <outline type="rss" text="Feed B" xmlUrl="https://b.example/feed" htmlUrl="https://b.example/"/>
      </body>
    </opml>
""")

NESTED_OPML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <opml version="2.0">
      <head><title>Test</title></head>
      <body>
        <outline text="Security">
          <outline type="rss" text="Feed A" xmlUrl="https://a.example/feed" htmlUrl="https://a.example/"/>
          <outline text="SubGroup">
            <outline type="rss" text="Feed B" xmlUrl="https://b.example/feed" htmlUrl="https://b.example/"/>
          </outline>
        </outline>
        <outline type="rss" text="Feed C" xmlUrl="https://c.example/feed" htmlUrl="https://c.example/"/>
      </body>
    </opml>
""")

FOLDER_ONLY_OPML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <opml version="2.0">
      <head><title>Test</title></head>
      <body>
        <outline text="Just a folder" />
      </body>
    </opml>
""")

MALFORMED_OPML = "<?xml version='1.0'?><opml><unclosed>"


def _write_opml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "test.opml"
    p.write_text(content)
    return p


def test_parse_opml_flat(tmp_path):
    """Flat OPML with 2 feeds returns 2 FeedEntry objects."""
    path = _write_opml(tmp_path, FLAT_OPML)
    entries = parse_opml(path)
    assert len(entries) == 2
    urls = {e.url for e in entries}
    assert "https://a.example/feed" in urls
    assert "https://b.example/feed" in urls


def test_parse_opml_nested_categories(tmp_path):
    """Nested OPML captures feeds at all depths and records category."""
    path = _write_opml(tmp_path, NESTED_OPML)
    entries = parse_opml(path)
    assert len(entries) == 3
    by_url = {e.url: e for e in entries}
    assert by_url["https://a.example/feed"].category == "Security"
    # category is immediate parent outline text, not the grandparent
    assert by_url["https://b.example/feed"].category == "SubGroup"
    assert by_url["https://c.example/feed"].category == ""


def test_parse_opml_folder_outlines_skipped(tmp_path):
    """Outline elements without xmlUrl are not returned."""
    path = _write_opml(tmp_path, FOLDER_ONLY_OPML)
    entries = parse_opml(path)
    assert entries == []


def test_parse_opml_malformed_xml(tmp_path):
    """Malformed XML raises OpmlError, not ET.ParseError."""
    path = _write_opml(tmp_path, MALFORMED_OPML)
    with pytest.raises(OpmlError):
        parse_opml(path)


def test_parse_opml_missing_file(tmp_path):
    """Non-existent file raises OpmlError."""
    with pytest.raises(OpmlError):
        parse_opml(tmp_path / "does_not_exist.opml")


def test_parse_opml_sample_file_valid():
    """The bundled examples/sample.opml is well-formed and returns feeds."""
    sample = Path("examples/sample.opml")
    entries = parse_opml(sample)
    assert len(entries) >= 1
    for e in entries:
        assert e.url.startswith("http")


# ---------------------------------------------------------------------------
# Slice 2.1 — Cache
# ---------------------------------------------------------------------------

NVD_PAYLOAD = {"cvss_score": 10.0, "cvss_severity": "CRITICAL"}
EPSS_PAYLOAD = {"epss": 0.97, "percentile": 0.99, "date": "2024-06-01"}


def _mem_cache(ttl_hours: int = 24) -> Cache:
    """Return an in-memory Cache instance for testing."""
    return Cache(":memory:", ttl_hours=ttl_hours)


def test_cache_nvd_round_trip():
    """set_nvd followed by get_nvd returns the same payload."""
    c = _mem_cache()
    c.set_nvd("CVE-2021-44228", NVD_PAYLOAD)
    assert c.get_nvd("CVE-2021-44228") == NVD_PAYLOAD


def test_cache_nvd_miss_returns_none():
    """get_nvd for an unknown CVE returns None."""
    c = _mem_cache()
    assert c.get_nvd("CVE-9999-9999") is None


def test_cache_nvd_stale_returns_none():
    """get_nvd returns None when the cached entry is older than the TTL."""
    c = _mem_cache(ttl_hours=1)
    past = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    c._conn.execute(
        "INSERT INTO nvd_cache VALUES (?, ?, ?)",
        ("CVE-2021-44228", '{"stale": true}', past),
    )
    c._conn.commit()
    assert c.get_nvd("CVE-2021-44228") is None


def test_cache_corrupt_timestamp_treated_as_stale(caplog):
    """A row with a malformed fetched_at must not crash get_nvd (regression for H1)."""
    import logging

    c = _mem_cache()
    c._conn.execute(
        "INSERT INTO nvd_cache VALUES (?, ?, ?)",
        ("CVE-2021-44228", '{"x": 1}', "NOT-A-TIMESTAMP"),
    )
    c._conn.commit()

    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        result = c.get_nvd("CVE-2021-44228")

    assert result is None
    assert any("unparseable fetched_at" in rec.message for rec in caplog.records)


def test_utcnow_returns_naive_utc():
    """_utcnow() must return a naive datetime that is close to real UTC (regression for H2)."""
    from datetime import timezone

    import ramen_cve

    result = ramen_cve._utcnow()
    assert result.tzinfo is None, "_utcnow() must return a naive datetime"
    delta = abs((result - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())
    assert delta < 2, f"_utcnow() drifted {delta}s from UTC"


def test_cache_epss_round_trip():
    """set_epss followed by get_epss returns the same payload."""
    c = _mem_cache()
    c.set_epss("CVE-2021-44228", "2024-06-01", EPSS_PAYLOAD)
    assert c.get_epss("CVE-2021-44228", "2024-06-01") == EPSS_PAYLOAD


def test_cache_epss_different_date_is_miss():
    """EPSS cached for one date does not satisfy a query for a different date."""
    c = _mem_cache()
    c.set_epss("CVE-2021-44228", "2024-06-01", EPSS_PAYLOAD)
    assert c.get_epss("CVE-2021-44228", "2024-06-02") is None


def test_cache_in_memory_mode():
    """Cache(':memory:') works without touching the filesystem."""
    c = Cache(":memory:")
    c.set_nvd("CVE-2021-44228", NVD_PAYLOAD)
    assert c.get_nvd("CVE-2021-44228") == NVD_PAYLOAD


def test_cache_schema_idempotent():
    """Constructing a second Cache on the same path doesn't drop data."""
    c1 = _mem_cache()
    # Use a real file to verify the schema is idempotent across two opens
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        c1 = Cache(db_path)
        c1.set_nvd("CVE-2021-44228", NVD_PAYLOAD)
        c2 = Cache(db_path)  # second open on same file
        assert c2.get_nvd("CVE-2021-44228") == NVD_PAYLOAD
    finally:
        os.unlink(db_path)


# ---------------------------------------------------------------------------
# Slice 3.1 — fetch_nvd
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class _MockNvd:
    """Context manager that patches requests.get AND time.sleep for NVD tests."""

    def __init__(self, fixture_name: str, status_code: int = 200) -> None:
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        if status_code >= 400:
            import requests as _req

            mock_resp.raise_for_status.side_effect = _req.HTTPError(response=mock_resp)
        else:
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = _load_fixture(fixture_name)
        self._patch_get = patch("ramen_cve.requests.get", return_value=mock_resp)
        self._patch_sleep = patch("ramen_cve.time.sleep")

    def __enter__(self):
        self._patch_get.__enter__()
        self._patch_sleep.__enter__()
        return self

    def __exit__(self, *args):
        self._patch_sleep.__exit__(*args)
        self._patch_get.__exit__(*args)


def _mock_get(fixture_name: str, status_code: int = 200) -> _MockNvd:
    """Return a context manager that patches requests.get and time.sleep."""
    return _MockNvd(fixture_name, status_code)


def test_fetch_nvd_v31_fields():
    """Successful v3.1 response populates all CVSS fields."""
    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    with _mock_get("nvd_log4shell_v31.json"):
        result = fetch_nvd("CVE-2021-44228", cache, api_key=None)

    assert result["cvss_score"] == 10.0
    assert result["cvss_severity"] == "CRITICAL"
    assert result["cvss_version"] == "3.1"
    assert result["kev_listed"] is True
    assert "CWE-502" in result["cwe"]
    assert result["nvd_published"] == "2021-12-10"
    assert result["nvd_status"] == "ok"


def test_fetch_nvd_v30_fallback():
    """Response with only v3.0 metric falls back correctly."""
    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    with _mock_get("nvd_proxylogon_v30.json"):
        result = fetch_nvd("CVE-2021-26855", cache, api_key=None)

    assert result["cvss_score"] == 9.8
    assert result["cvss_version"] == "3.0"
    assert result["kev_listed"] is False


def test_fetch_nvd_kev_null_value_is_false():
    """cisaExploitAdd present but null must not set kev_listed=True (regression M2)."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    # Build a minimal NVD response where cisaExploitAdd is present but null.
    payload = {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "cisaExploitAdd": None,
                    "metrics": {},
                    "weaknesses": [],
                    "published": "2021-12-10T00:00:00.000",
                }
            }
        ],
    }
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    with (
        patch("ramen_cve.requests.get", return_value=resp),
        patch("ramen_cve.time.sleep"),
    ):
        result = fetch_nvd("CVE-2021-44228", cache, api_key=None)

    assert result["kev_listed"] is False, "null cisaExploitAdd must not be treated as KEV"


def test_fetch_nvd_no_cvss():
    """Old CVE with no CVSS metrics returns empty score fields, no crash."""
    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    with _mock_get("nvd_no_cvss.json"):
        result = fetch_nvd("CVE-1999-0001", cache, api_key=None)

    assert result["cvss_score"] is None
    assert result["cvss_severity"] is None
    assert result["nvd_status"] == "ok"


def test_fetch_nvd_404_returns_error_record():
    """HTTP 404 returns a record with nvd_status='error', no exception raised."""
    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    with _mock_get("nvd_not_found.json", status_code=404):
        result = fetch_nvd("CVE-9999-9999", cache, api_key=None)

    assert result["nvd_status"] == "error"
    assert result["cvss_score"] is None


def test_fetch_nvd_cache_hit_skips_network():
    """A cache hit does not call requests.get."""
    from unittest.mock import patch

    from ramen_cve import fetch_nvd

    cache = _mem_cache()
    cache.set_nvd("CVE-2021-44228", {"cvss_score": 10.0, "nvd_status": "ok"})
    with patch("ramen_cve.requests.get") as mock_get:
        result = fetch_nvd("CVE-2021-44228", cache, api_key=None)
        mock_get.assert_not_called()
    assert result["cvss_score"] == 10.0


# ---------------------------------------------------------------------------
# Slice 3.2 — fetch_epss
# ---------------------------------------------------------------------------


def _mock_epss(fixture_name: str, status_code: int = 200):
    """Patch requests.get for EPSS tests (no sleep to mock)."""
    from unittest.mock import MagicMock, patch

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if status_code >= 400:
        import requests as _req

        mock_resp.raise_for_status.side_effect = _req.HTTPError(response=mock_resp)
    else:
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _load_fixture(fixture_name)
    return patch("ramen_cve.requests.get", return_value=mock_resp)


def test_fetch_epss_basic_batch():
    """2 CVEs all uncached → one batched request, results returned."""
    from ramen_cve import fetch_epss

    cache = _mem_cache()
    cves = ["CVE-2021-44228", "CVE-2021-26855"]
    with _mock_epss("epss_batch.json"):
        result = fetch_epss(cves, cache)
    assert "CVE-2021-44228" in result
    assert result["CVE-2021-44228"]["epss"] == pytest.approx(0.97565, rel=1e-4)


def test_fetch_epss_batches_at_100():
    """105 CVEs → two request calls (100 + 5)."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_epss

    cache = _mem_cache()
    cves = [f"CVE-2024-{i:04d}" for i in range(105)]

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"data": []}

    with patch("ramen_cve.requests.get", return_value=mock_resp) as mock_get:
        fetch_epss(cves, cache)

    assert mock_get.call_count == 2


def test_fetch_epss_cache_hit_skips_request():
    """All CVEs cached → zero network requests."""
    from unittest.mock import patch

    from ramen_cve import fetch_epss

    cache = _mem_cache()
    cache.set_epss("CVE-2021-44228", "current", {"epss": 0.97, "percentile": 0.99, "date": ""})

    with patch("ramen_cve.requests.get") as mock_get:
        result = fetch_epss(["CVE-2021-44228"], cache)
        mock_get.assert_not_called()
    assert "CVE-2021-44228" in result


def test_fetch_epss_partial_cache():
    """30 cached out of 50 → one request for 20 misses."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_epss

    cache = _mem_cache()
    for i in range(30):
        cache.set_epss(f"CVE-2024-{i:04d}", "current", {"epss": 0.1, "percentile": 0.5, "date": ""})

    all_cves = [f"CVE-2024-{i:04d}" for i in range(50)]
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"data": []}

    with patch("ramen_cve.requests.get", return_value=mock_resp) as mock_get:
        fetch_epss(all_cves, cache)

    assert mock_get.call_count == 1
    call_args = mock_get.call_args
    cve_param = call_args.kwargs.get("params", {}).get("cve", "")
    assert len(cve_param.split(",")) == 20


def test_fetch_epss_historical_date_in_url():
    """When score_date is given, the request URL includes date= parameter."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_epss

    cache = _mem_cache()
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"data": []}

    with patch("ramen_cve.requests.get", return_value=mock_resp) as mock_get:
        fetch_epss(["CVE-2021-44228"], cache, score_date="2024-01-01")

    call_params = mock_get.call_args.kwargs.get("params", {})
    assert call_params.get("date") == "2024-01-01"


def test_fetch_epss_empty_input():
    """Empty input returns empty dict with no requests."""
    from unittest.mock import patch

    from ramen_cve import fetch_epss

    cache = _mem_cache()
    with patch("ramen_cve.requests.get") as mock_get:
        result = fetch_epss([], cache)
        mock_get.assert_not_called()
    assert result == {}


# ---------------------------------------------------------------------------
# Slice 3.3 — enrich_cves
# ---------------------------------------------------------------------------


def test_fetch_nvd_does_not_sleep_on_first_call():
    """The first NVD fetch in a fresh process should not pay the full per-call delay (L1)."""
    from unittest.mock import MagicMock, patch

    import ramen_cve

    # Reset the module-level last-call timestamp so the test is deterministic
    if hasattr(ramen_cve.fetch_nvd, "_last_call"):
        del ramen_cve.fetch_nvd._last_call

    cache = _mem_cache()
    fixture = _load_fixture("nvd_log4shell_v31.json")

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = fixture
        return resp

    sleep_calls: list[float] = []

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep", side_effect=lambda s: sleep_calls.append(s)),
    ):
        ramen_cve.fetch_nvd("CVE-2021-44228", cache, api_key=None)

    # First call: elapsed since the (uninitialized) last_call is huge,
    # so the if-guard short-circuits and no sleep should have fired.
    assert sleep_calls == [], f"first-call slept unexpectedly: {sleep_calls}"


def test_unique_output_path_disambiguates_collisions(tmp_path):
    """Two _output() calls in the same wall-clock second must not overwrite each other (C1)."""
    from ramen_cve import _unique_output_path

    ts = "20260101T120000123456"
    p1 = _unique_output_path(tmp_path, ts, "csv")
    assert p1.name == f"ramen-cve-{ts}.csv"
    p1.write_text("first")  # simulate the first run claiming the name

    p2 = _unique_output_path(tmp_path, ts, "csv")
    assert p2 != p1
    assert p2.name == f"ramen-cve-{ts}-1.csv"
    p2.write_text("second")

    p3 = _unique_output_path(tmp_path, ts, "csv")
    assert p3.name == f"ramen-cve-{ts}-2.csv"

    # First file is untouched
    assert p1.read_text() == "first"
    assert p2.read_text() == "second"


def test_safe_url_for_log_strips_query_and_fragment():
    """Query strings and fragments must be stripped before logging (regression for M3)."""
    from ramen_cve import _safe_url_for_log

    out = _safe_url_for_log("https://example.com/path?token=secret&id=1#trackingid")
    assert "secret" not in out
    assert "token" not in out
    assert "trackingid" not in out
    assert out.startswith("https://example.com/path")
    assert "redacted" in out

    # No query/fragment → unchanged, no redaction note
    plain = _safe_url_for_log("https://example.com/path")
    assert plain == "https://example.com/path"


def test_write_markdown_sanitizes_newlines_in_source(tmp_path):
    """A source string containing newlines must not break the bullet layout (regression for M2)."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="Multi\nline\rsource\twith\nweird whitespace",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        cvss_severity="CRITICAL",
        epss_score=0.5,
        epss_percentile=0.99,
        bucket="patch_now",
        suggested_action="Patch.",
    )
    out = tmp_path / "report.md"
    write_markdown(
        [rec],
        out,
        {
            "version": "0.1",
            "sources": ["Feed\nName\rwith breaks"],
            "cvss_threshold": 7.0,
            "epss_threshold": 0.10,
        },
    )
    text = out.read_text()
    # Every "- **Source:**" or "- " bullet should occupy exactly one line
    for line in text.splitlines():
        assert "\n" not in line and "\r" not in line
    assert "Multi line source with weird whitespace" in text
    assert "Feed Name with breaks" in text


def test_validate_args_rejects_epss_mode_without_dates():
    """--date-mode epss with no --start/--end must error out, not crash mid-run (M1)."""
    import ramen_cve

    with pytest.raises(SystemExit):
        ramen_cve.main(["cve", "CVE-2021-44228", "--date-mode", "epss", "--no-cache"])


def test_run_url_handles_invalid_meta_date(tmp_path, caplog):
    """A valid-looking but impossible date (e.g. 2024-13-45) in HTML must not crash _run_url
    (regression for H3)."""
    import logging
    from unittest.mock import MagicMock, patch

    import ramen_cve

    html = (
        '<html><head>'
        '<meta property="article:published_time" content="2024-13-45T10:00:00Z">'
        '</head><body>No CVEs here.</body></html>'
    )

    def _fake_get(url, params=None, headers=None, timeout=None):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.text = html
        mock_resp.json.return_value = {}
        return mock_resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        caplog.at_level(logging.WARNING, logger="ramen_cve"),
    ):
        rc = ramen_cve.main(
            ["url", "https://example.com/post", "--no-cache",
             "--out-dir", str(tmp_path), "--format", "csv"]
        )

    assert rc == 0
    assert any("could not parse" in rec.message.lower() for rec in caplog.records)


def test_enrich_cves_handles_unparseable_nvd_published_date(caplog):
    """A garbage nvd_published string must not crash enrich_cves (regression for H2)."""
    import logging
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    records = [CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub")]
    epss_resp = _load_fixture("epss_batch.json")

    def _fake_get(url, params=None, headers=None, timeout=None):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        if "epss" in url:
            mock_resp.json.return_value = epss_resp
        else:
            # Build a minimal NVD payload with a malformed published date
            mock_resp.json.return_value = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-44228",
                            "published": "not-a-real-date",
                            "metrics": {},
                            "weaknesses": [],
                            "cisaExploitAdd": None,
                        }
                    }
                ]
            }
        return mock_resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        caplog.at_level(logging.WARNING, logger="ramen_cve"),
    ):
        result = enrich_cves(records, cache, api_key=None)

    assert len(result) == 1
    assert result[0].nvd_published is None
    assert any("unparseable" in rec.message for rec in caplog.records)


def test_enrich_cves_deduplicates_and_picks_earliest():
    """3 records covering 2 unique CVEs → 2 enriched, earliest first_seen kept."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    records = [
        CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub"),
        CveRecord("CVE-2021-44228", "feed-b", date(2024, 1, 5), "feed_pub"),  # duplicate, later
        CveRecord("CVE-2021-26855", "feed-a", date(2024, 1, 2), "feed_pub"),
    ]

    nvd_resp_log4shell = _load_fixture("nvd_log4shell_v31.json")
    nvd_resp_proxylogon = _load_fixture("nvd_proxylogon_v30.json")
    epss_resp = _load_fixture("epss_batch.json")

    def _fake_get(url, params=None, headers=None, timeout=None):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        if "epss" in url:
            mock_resp.json.return_value = epss_resp
        else:
            cve_id = (params or {}).get("cveId", "")
            if cve_id == "CVE-2021-44228":
                mock_resp.json.return_value = nvd_resp_log4shell
            else:
                mock_resp.json.return_value = nvd_resp_proxylogon
        return mock_resp

    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)

    assert len(result) == 2
    by_id = {r.cve_id: r for r in result}
    # Earliest first_seen wins for the duplicate
    assert by_id["CVE-2021-44228"].first_seen == date(2024, 1, 1)
    assert by_id["CVE-2021-44228"].source == "feed-a"
    assert by_id["CVE-2021-44228"].cvss_score == 10.0
    assert by_id["CVE-2021-44228"].kev_listed is True


# ---------------------------------------------------------------------------
# Slice 4.1 — bucket_and_suggest
# ---------------------------------------------------------------------------


def _make_enriched(
    *,
    cvss: float | None,
    epss: float | None,
    kev: bool = False,
    cvss_thr: float = 7.0,
    epss_thr: float = 0.10,
) -> str:
    """Helper: build an EnrichedCve, run bucket_and_suggest, return bucket name."""
    from ramen_cve import EnrichedCve, bucket_and_suggest

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="test",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=cvss,
        epss_score=epss,
        kev_listed=kev,
    )
    bucket_and_suggest([rec], cvss_thr=cvss_thr, epss_thr=epss_thr)
    return rec.bucket


def test_bucket_kev_override():
    """KEV wins regardless of CVSS/EPSS values."""
    assert _make_enriched(cvss=1.0, epss=0.01, kev=True) == "kev_override"


def test_bucket_patch_now():
    """High CVSS + high EPSS → patch_now."""
    assert _make_enriched(cvss=9.0, epss=0.50) == "patch_now"


def test_bucket_plan_and_patch():
    """High CVSS + low EPSS → plan_and_patch."""
    assert _make_enriched(cvss=9.0, epss=0.01) == "plan_and_patch"


def test_bucket_watch_closely():
    """Low CVSS + high EPSS → watch_closely."""
    assert _make_enriched(cvss=3.0, epss=0.50) == "watch_closely"


def test_bucket_deprioritize():
    """Low CVSS + low EPSS → deprioritize."""
    assert _make_enriched(cvss=3.0, epss=0.01) == "deprioritize"


def test_bucket_unknown_missing_cvss():
    """Missing CVSS → unknown."""
    assert _make_enriched(cvss=None, epss=0.50) == "unknown"


def test_bucket_unknown_missing_epss():
    """Missing EPSS → unknown."""
    assert _make_enriched(cvss=9.0, epss=None) == "unknown"


def test_bucket_kev_beats_unknown():
    """KEV=True with missing CVSS/EPSS still produces kev_override (KEV is highest precedence)."""
    assert _make_enriched(cvss=None, epss=None, kev=True) == "kev_override"


def test_bucket_threshold_at_boundary():
    """Score exactly at threshold is counted as 'high' (>= semantics)."""
    assert _make_enriched(cvss=7.0, epss=0.10) == "patch_now"
    assert _make_enriched(cvss=6.9, epss=0.10) == "watch_closely"
    assert _make_enriched(cvss=7.0, epss=0.09) == "plan_and_patch"


def test_bucket_custom_thresholds():
    """Custom thresholds change bucket assignment."""
    # With tight thresholds, a 5.0/0.05 CVE should be patch_now
    assert _make_enriched(cvss=5.0, epss=0.05, cvss_thr=4.0, epss_thr=0.04) == "patch_now"


def test_bucket_suggested_action_populated():
    """bucket_and_suggest fills in suggested_action for each bucket."""
    from ramen_cve import BUCKET_ACTIONS, EnrichedCve, bucket_and_suggest

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="test",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.50,
    )
    bucket_and_suggest([rec])
    assert rec.suggested_action == BUCKET_ACTIONS["patch_now"]


# ---------------------------------------------------------------------------
# Slice 5.1 — filter_by_date
# ---------------------------------------------------------------------------


def _enriched_with_dates(
    *,
    first_seen: date | None = None,
    nvd_published: date | None = None,
) -> EnrichedCve:
    from ramen_cve import EnrichedCve

    return EnrichedCve(
        cve_id="CVE-2024-0001",
        source="test",
        first_seen=first_seen or date(2024, 6, 1),
        first_seen_type="feed_pub",
        nvd_published=nvd_published,
    )


def test_filter_feed_mode_in_range():
    """Feed mode: record with first_seen in range is kept."""
    from ramen_cve import filter_by_date

    rec = _enriched_with_dates(first_seen=date(2024, 6, 1))
    result = filter_by_date([rec], date(2024, 1, 1), date(2024, 12, 31), "feed")
    assert len(result) == 1


def test_filter_feed_mode_out_of_range():
    """Feed mode: record with first_seen outside range is dropped."""
    from ramen_cve import filter_by_date

    rec = _enriched_with_dates(first_seen=date(2023, 1, 1))
    result = filter_by_date([rec], date(2024, 1, 1), date(2024, 12, 31), "feed")
    assert result == []


def test_filter_disclosure_uses_nvd_published():
    """Disclosure mode filters on nvd_published, ignoring first_seen."""
    from ramen_cve import filter_by_date

    # first_seen in range but nvd_published out of range → dropped
    rec = _enriched_with_dates(first_seen=date(2024, 6, 1), nvd_published=date(2021, 12, 10))
    result = filter_by_date([rec], date(2024, 1, 1), date(2024, 12, 31), "disclosure")
    assert result == []

    # nvd_published in range → kept
    rec2 = _enriched_with_dates(first_seen=date(2023, 1, 1), nvd_published=date(2024, 6, 1))
    result2 = filter_by_date([rec2], date(2024, 1, 1), date(2024, 12, 31), "disclosure")
    assert len(result2) == 1


def test_filter_feed_mode_missing_date_is_dropped():
    """Record with no relevant date is dropped (and a warning is logged)."""
    from ramen_cve import filter_by_date

    rec = _enriched_with_dates(nvd_published=None)
    rec.first_seen = None  # force missing  # type: ignore[assignment]
    result = filter_by_date([rec], date(2024, 1, 1), date(2024, 12, 31), "feed")
    assert result == []


def test_filter_epss_mode_single_date_ok():
    """EPSS mode with start==end does not raise."""
    from ramen_cve import filter_by_date

    rec = _enriched_with_dates(nvd_published=date(2024, 6, 1))
    result = filter_by_date([rec], date(2024, 6, 1), date(2024, 6, 1), "epss")
    assert len(result) == 1


def test_filter_epss_mode_date_range_raises():
    """EPSS mode with start != end raises ValueError."""
    from ramen_cve import filter_by_date

    rec = _enriched_with_dates(nvd_published=date(2024, 6, 1))
    with pytest.raises(ValueError, match="epss"):
        filter_by_date([rec], date(2024, 1, 1), date(2024, 12, 31), "epss")


def test_filter_empty_list():
    """Empty input returns empty list without error."""
    from ramen_cve import filter_by_date

    assert filter_by_date([], date(2024, 1, 1), date(2024, 12, 31), "feed") == []


def test_filter_inclusive_boundaries():
    """Start and end dates are inclusive."""
    from ramen_cve import filter_by_date

    rec_start = _enriched_with_dates(first_seen=date(2024, 1, 1))
    rec_end = _enriched_with_dates(first_seen=date(2024, 12, 31))
    result = filter_by_date([rec_start, rec_end], date(2024, 1, 1), date(2024, 12, 31), "feed")
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Slice 6.1 — write_csv
# ---------------------------------------------------------------------------


def _sample_enriched() -> EnrichedCve:
    from ramen_cve import EnrichedCve

    return EnrichedCve(
        cve_id="CVE-2021-44228",
        source="krebs-feed",
        first_seen=date(2024, 6, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_version="3.1",
        kev_listed=True,
        cwe=["CWE-502", "CWE-917"],
        nvd_published=date(2021, 12, 10),
        epss_score=0.97565,
        epss_percentile=0.99968,
        epss_date="2024-06-01",
        bucket="kev_override",
    )


def test_write_csv_round_trip(tmp_path):
    """write_csv then read back: column count and CVE ID survive."""
    from ramen_cve import CSV_COLUMNS, write_csv

    rec = _sample_enriched()
    out = tmp_path / "out.csv"
    write_csv([rec], out)

    rows = list(csv.reader(out.open()))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 2  # header + 1 data row
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["cve_id"] == "CVE-2021-44228"
    assert row["cvss_score"] == "10.0"
    assert row["epss_score"] == "0.9757"  # 4 decimal places
    assert row["kev_listed"] == "true"
    assert row["cwe"] == "CWE-502;CWE-917"


def test_write_csv_suggested_action_with_comma(tmp_path):
    """Suggested action containing a dash or comma is properly quoted."""
    from ramen_cve import write_csv

    rec = _sample_enriched()
    rec.suggested_action = "Patch now, urgently"
    out = tmp_path / "out.csv"
    write_csv([rec], out)

    rows = list(csv.reader(out.open()))
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["suggested_action"] == "Patch now, urgently"


def test_write_csv_empty_cvss_as_empty_string(tmp_path):
    """Record with no CVSS writes an empty string, not 'None'."""
    from ramen_cve import write_csv

    rec = _sample_enriched()
    rec.cvss_score = None
    rec.cvss_severity = None
    out = tmp_path / "out.csv"
    write_csv([rec], out)

    rows = list(csv.reader(out.open()))
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["cvss_score"] == ""
    assert row["cvss_severity"] == ""


# ---------------------------------------------------------------------------
# Slice 6.2 — write_markdown
# ---------------------------------------------------------------------------


METADATA = {
    "version": "0.1",
    "args": "opml examples/sample.opml",
    "sources": ["krebs-feed"],
    "start": "2024-01-01",
    "end": "2024-12-31",
    "date_mode": "feed",
    "cvss_threshold": 7.0,
    "epss_threshold": 0.10,
}


def test_write_markdown_empty_produces_valid_report(tmp_path):
    """Empty CVE list renders a valid Markdown report with zero-count notice."""
    from ramen_cve import write_markdown

    out = tmp_path / "report.md"
    write_markdown([], out, METADATA)

    text = out.read_text()
    assert "# Ramen CVE Triage Report" in text
    assert "Total CVEs: **0**" in text
    assert "No CVEs found" in text


def test_write_markdown_bucket_sections(tmp_path):
    """One CVE per bucket produces the expected number of sections."""
    from ramen_cve import EnrichedCve, write_markdown

    recs = [
        EnrichedCve(
            "CVE-2021-44228",
            "f1",
            date(2024, 1, 1),
            "feed_pub",
            cvss_score=10.0,
            epss_score=0.97,
            kev_listed=True,
            bucket="kev_override",
        ),
        EnrichedCve(
            "CVE-2021-26855",
            "f1",
            date(2024, 1, 1),
            "feed_pub",
            cvss_score=9.8,
            epss_score=0.97,
            bucket="patch_now",
        ),
        EnrichedCve(
            "CVE-2024-1234",
            "f1",
            date(2024, 1, 1),
            "feed_pub",
            cvss_score=5.0,
            epss_score=0.01,
            bucket="deprioritize",
        ),
    ]
    out = tmp_path / "report.md"
    write_markdown(recs, out, METADATA)

    text = out.read_text()
    assert "## KEV Override" in text
    assert "## Patch Now" in text
    assert "## Deprioritize" in text
    # Each CVE appears as an H3
    assert "### CVE-2021-44228" in text
    assert "### CVE-2021-26855" in text
    assert "### CVE-2024-1234" in text


def test_write_markdown_cve_id_appears_once(tmp_path):
    """A CVE ID should appear exactly once as an H3 heading in the report."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        "CVE-2021-44228",
        "f1",
        date(2024, 1, 1),
        "feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        kev_listed=True,
        bucket="kev_override",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)

    text = out.read_text()
    heading_count = text.count("### CVE-2021-44228")
    assert heading_count == 1


def test_write_markdown_cvss_zero_is_not_falsy(tmp_path):
    """A CVSS score of 0.0 must render as '0.0', not 'N/A' (regression)."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        "CVE-2024-9999",
        "test",
        date(2024, 1, 1),
        "feed_pub",
        cvss_score=0.0,
        cvss_severity="NONE",
        epss_score=0.5,
        epss_percentile=0.8,
        bucket="watch_closely",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "**CVSS:** 0.0 (NONE)" in text
    assert "**CVSS:** N/A" not in text


# ---------------------------------------------------------------------------
# Slice 7.1 — CLI / argparse
# ---------------------------------------------------------------------------


def test_cli_opml_subcommand_parses():
    """opml subcommand parses its path argument."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["opml", "examples/sample.opml"])
    assert args.subcommand == "opml"
    assert str(args.path) == "examples/sample.opml"


def test_cli_url_subcommand_parses():
    """url subcommand parses its URL argument."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["url", "https://example.com/article"])
    assert args.subcommand == "url"
    assert args.url == "https://example.com/article"


def test_cli_cve_subcommand_parses():
    """cve subcommand parses one or more CVE IDs."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["cve", "CVE-2021-44228", "CVE-2021-26855"])
    assert args.subcommand == "cve"
    assert "CVE-2021-44228" in args.cves


def test_cli_cve_date_mode_defaults_to_disclosure():
    """cve subcommand argparse default is None (resolved to disclosure at runtime) — H3."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["cve", "CVE-2021-44228"])
    assert args.date_mode is None, "sentinel must be None so _run_cve defaults to disclosure"


def test_cli_cve_date_mode_feed_is_honored():
    """Explicit --date-mode feed on the cve subcommand must not be overridden (regression H3)."""
    from ramen_cve import build_parser

    # Argparse must preserve the user's explicit choice.
    args = build_parser().parse_args(["cve", "CVE-2021-44228", "--date-mode", "feed"])
    assert args.date_mode == "feed"


def test_cli_invalid_date_rejected():
    """A bad --start date format is rejected before any work runs."""
    import subprocess

    result = subprocess.run(
        [".venv/bin/python", "ramen_cve.py", "opml", "x.opml", "--start", "not-a-date"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Invalid date" in result.stderr or "error" in result.stderr.lower()


def test_cli_start_after_end_rejected():
    """--start later than --end must be rejected with a non-zero exit code (regression M1)."""
    import subprocess

    result = subprocess.run(
        [
            ".venv/bin/python", "ramen_cve.py", "opml", "x.opml",
            "--start", "2024-12-31", "--end", "2024-01-01",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "start" in result.stderr.lower() or "end" in result.stderr.lower()


def test_cli_invalid_cve_id_rejected():
    """A CVE ID that doesn't match the regex is rejected before any work runs."""
    import subprocess

    result = subprocess.run(
        [".venv/bin/python", "ramen_cve.py", "cve", "NOT-A-CVE"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_cli_from_file_missing_returns_friendly_error(tmp_path):
    """A non-existent --from-file path exits with code 1 and no traceback (regression for H1)."""
    import subprocess

    missing = tmp_path / "does-not-exist.txt"
    result = subprocess.run(
        [".venv/bin/python", "ramen_cve.py", "cve", "--from-file", str(missing), "--no-cache"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "does not exist" in result.stderr or "from-file" in result.stderr


# ---------------------------------------------------------------------------
# Slice 8 — CISA KEV catalog ingestion
# ---------------------------------------------------------------------------


def _kev_catalog_fixture() -> dict:
    return _load_fixture("cisa_kev_catalog.json")


def _patch_kev(catalog_payload: dict | None = None, status_code: int = 200):
    """Patch requests.get so any KEV URL hit returns catalog_payload."""
    from unittest.mock import MagicMock, patch

    catalog_payload = catalog_payload if catalog_payload is not None else _kev_catalog_fixture()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = status_code
        if status_code >= 400:
            import requests as _req

            resp.raise_for_status.side_effect = _req.HTTPError(response=resp)
        else:
            resp.raise_for_status.return_value = None
            resp.json.return_value = catalog_payload
        return resp

    return patch("ramen_cve.requests.get", side_effect=_fake_get)


def test_fetch_kev_catalog_basic():
    """A successful fetch returns a dict keyed on upper-case CVE ID."""
    from ramen_cve import fetch_kev_catalog

    cache = _mem_cache()
    with _patch_kev():
        catalog = fetch_kev_catalog(cache)

    assert "CVE-2021-44228" in catalog
    assert catalog["CVE-2021-44228"]["vendorProject"] == "Apache"
    # Empty cveID entries are filtered out so we don't pollute the lookup
    assert "" not in catalog


def test_fetch_kev_catalog_uses_cache_on_second_call():
    """Two calls in the same TTL window should produce only one HTTP request."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_kev_catalog

    cache = _mem_cache()
    payload = _kev_catalog_fixture()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = payload
        return resp

    with patch("ramen_cve.requests.get", side_effect=_fake_get) as mock_get:
        first = fetch_kev_catalog(cache)
        second = fetch_kev_catalog(cache)

    assert mock_get.call_count == 1
    assert first == second
    assert "CVE-2021-44228" in second


def test_fetch_kev_catalog_network_error_returns_empty(caplog):
    """A 5xx (or any exception) must yield an empty dict, not a crash."""
    import logging

    from ramen_cve import fetch_kev_catalog

    cache = _mem_cache()
    with _patch_kev(status_code=503), caplog.at_level(logging.WARNING, logger="ramen_cve"):
        catalog = fetch_kev_catalog(cache)

    assert catalog == {}
    assert any("CISA KEV catalog fetch failed" in rec.message for rec in caplog.records)


def test_parse_kev_due_date_handles_malformed():
    """An unparseable dueDate must not crash the joiner."""
    import logging

    from ramen_cve import _parse_kev_due_date

    assert _parse_kev_due_date(None) is None
    assert _parse_kev_due_date("") is None
    assert _parse_kev_due_date("2024-06-01") == date(2024, 6, 1)

    logger = logging.getLogger("ramen_cve")
    with pytest.MonkeyPatch.context() as mp:
        warnings: list[str] = []
        original = logger.warning
        mp.setattr(logger, "warning", lambda msg, *a, **kw: warnings.append(msg % a))
        assert _parse_kev_due_date("not-a-date") is None
        assert any("unparseable dueDate" in w for w in warnings)
        logger.warning = original


def test_enrich_cves_populates_kev_authoritative_fields():
    """CVEs in the CISA KEV catalog are joined with due date, ransomware flag, etc."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    log4shell = _load_fixture("nvd_log4shell_v31.json")
    epss = _load_fixture("epss_batch.json")
    kev = _kev_catalog_fixture()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = kev
        else:
            resp.json.return_value = log4shell
        return resp

    records = [CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)

    assert len(result) == 1
    rec = result[0]
    assert rec.kev_listed is True
    assert rec.kev_due_date == date(2021, 12, 24)
    assert rec.kev_known_ransomware_use is True
    assert rec.kev_vendor_project == "Apache"
    assert rec.kev_product == "Log4j2"
    assert rec.kev_required_action and "vendor" in rec.kev_required_action.lower()
    assert rec.kev_short_description and "deserialization" in rec.kev_short_description


def test_enrich_cves_kev_listed_when_only_catalog_says_so():
    """Even if NVD response lacks cisaExploitAdd, a KEV catalog hit sets kev_listed=True."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    epss = _load_fixture("epss_batch.json")
    kev = _kev_catalog_fixture()
    # NVD response with NO cisaExploitAdd field at all
    nvd_no_kev = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "metrics": {},
                    "weaknesses": [],
                    "published": "2021-12-10T00:00:00.000",
                }
            }
        ]
    }

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = kev
        else:
            resp.json.return_value = nvd_no_kev
        return resp

    records = [CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)

    assert result[0].kev_listed is True
    assert result[0].kev_due_date == date(2021, 12, 24)


def test_enrich_cves_no_kev_match_leaves_authoritative_fields_default():
    """A CVE not in the KEV catalog has the authoritative KEV fields at default values."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    epss = _load_fixture("epss_batch.json")
    nvd_no_kev = _load_fixture("nvd_proxylogon_v30.json")
    # Empty KEV catalog
    kev: dict = {"vulnerabilities": []}

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = kev
        else:
            resp.json.return_value = nvd_no_kev
        return resp

    records = [CveRecord("CVE-2021-26855", "feed-a", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)

    rec = result[0]
    assert rec.kev_due_date is None
    assert rec.kev_required_action is None
    assert rec.kev_known_ransomware_use is False
    assert rec.kev_vendor_project is None
    assert rec.kev_product is None


def test_write_csv_includes_kev_columns(tmp_path):
    """CSV header now lists the new KEV columns and rows carry the values."""
    from ramen_cve import CSV_COLUMNS, EnrichedCve, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="krebs",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        kev_known_ransomware_use=True,
        kev_vendor_project="Apache",
        kev_product="Log4j2",
        kev_required_action="Apply patches.",
        bucket="kev_override",
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    for col in (
        "kev_due_date",
        "kev_known_ransomware_use",
        "kev_vendor_project",
        "kev_product",
    ):
        assert col in header, f"missing column {col} in CSV header: {header}"
    assert header == CSV_COLUMNS
    row = dict(zip(header, rows[1], strict=True))
    assert row["kev_due_date"] == "2021-12-24"
    assert row["kev_known_ransomware_use"] == "true"
    assert row["kev_vendor_project"] == "Apache"
    assert row["kev_product"] == "Log4j2"


def test_write_markdown_kev_section_renders_authoritative_fields(tmp_path):
    """KEV markdown surfaces vendor, due date, ransomware flag, and required action."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="krebs",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        kev_listed=True,
        bucket="kev_override",
        kev_due_date=date(2021, 12, 24),
        kev_known_ransomware_use=True,
        kev_vendor_project="Apache",
        kev_product="Log4j2",
        kev_required_action="Apply updates per vendor instructions.",
        kev_short_description="Apache Log4j2 RCE.",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "Apache Log4j2" in text
    assert "2021-12-24" in text
    assert "OVERDUE" in text  # past dueDate marker
    assert "Ransomware Use" in text
    assert "Required Action" in text
    assert "Apply updates per vendor instructions." in text


def test_write_markdown_no_overdue_marker_when_due_in_future(tmp_path):
    """A KEV due date in the future must NOT show OVERDUE."""
    from ramen_cve import EnrichedCve, write_markdown

    far_future = date.today().replace(year=date.today().year + 1)
    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date.today(),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        cvss_severity="CRITICAL",
        epss_score=0.5,
        kev_listed=True,
        bucket="kev_override",
        kev_due_date=far_future,
        kev_vendor_project="Vendor",
        kev_product="Product",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert str(far_future) in text
    assert "OVERDUE" not in text


def test_cache_kev_catalog_round_trip():
    """Cache.get_kev_catalog round-trips the dict written by Cache.set_kev_catalog."""
    c = _mem_cache()
    catalog = {"CVE-2021-44228": {"dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"}}
    c.set_kev_catalog(catalog)
    assert c.get_kev_catalog() == catalog


def test_cache_kev_catalog_stale_returns_none():
    """A KEV catalog older than the TTL is treated as a miss."""
    from ramen_cve import Cache

    c = Cache(":memory:", ttl_hours=1)
    past = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    c._conn.execute(
        "INSERT INTO kev_cache VALUES (?, ?, ?)",
        ("catalog", '{"CVE-2024-0001": {}}', past),
    )
    c._conn.commit()
    assert c.get_kev_catalog() is None


# ---------------------------------------------------------------------------
# Slice 9 — Multi-IOC extraction
# ---------------------------------------------------------------------------


def test_defang_text_handles_common_obfuscations():
    """Defang map covers hxxp, [.]/(.)/[dot]/(dot), [at]/(at), [:]."""
    from ramen_cve import _defang_text

    assert _defang_text("hxxp://evil[.]example[.]com") == "http://evil.example.com"
    assert _defang_text("hxxps://bad(.)example(.)com") == "https://bad.example.com"
    assert _defang_text("user[at]example[.]com") == "user@example.com"
    assert _defang_text("admin(at)bad(dot)tld") == "admin@bad.tld"
    assert _defang_text("plain text with nothing to defang") == "plain text with nothing to defang"


def test_extract_iocs_url_basic():
    """A plain http/https URL is captured as an 'url' IOC."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs("Visit https://example.com/path for info", "src", TODAY, "feed_pub")
    assert any(i.ioc_type == "url" and i.value == "https://example.com/path" for i in iocs)


def test_extract_iocs_url_strips_trailing_punctuation():
    """A URL followed by a period or comma drops the punctuation in the IOC value."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs(
        "Beacon to https://malware.example.com/c2. Then exfil to https://other.example.com/x,",
        "src", TODAY, "feed_pub",
    )
    urls = [i.value for i in iocs if i.ioc_type == "url"]
    assert "https://malware.example.com/c2" in urls
    assert "https://other.example.com/x" in urls


def test_extract_iocs_defanged_url_refanged():
    """A defanged hxxp[://]bad[.]example URL is captured as the refanged form."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs("C2: hxxps://evil[.]example[.]com/abc", "src", TODAY, "feed_pub")
    urls = [i for i in iocs if i.ioc_type == "url"]
    assert any(u.value == "https://evil.example.com/abc" for u in urls)
    assert all(u.defanged_in_source for u in urls)


def test_extract_iocs_email_basic():
    """A plain user@domain.tld email is captured."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs("Contact admin@example.com for details", "src", TODAY, "feed_pub")
    assert any(i.ioc_type == "email" and i.value == "admin@example.com" for i in iocs)


def test_extract_iocs_ipv4_public_only():
    """Public IPv4 is captured; private/loopback/multicast are dropped."""
    from ramen_cve import extract_iocs

    text = "Beacon 8.8.8.8 from 192.168.1.1, 10.0.0.5, 127.0.0.1, and 1.1.1.1"
    iocs = extract_iocs(text, "src", TODAY, "feed_pub")
    ips = {i.value for i in iocs if i.ioc_type == "ipv4"}
    assert "8.8.8.8" in ips
    assert "1.1.1.1" in ips
    assert "192.168.1.1" not in ips
    assert "10.0.0.5" not in ips
    assert "127.0.0.1" not in ips


def test_extract_iocs_md5_sha1_sha256_distinct_lengths():
    """Each hash regex matches only its own length, not shorter or longer hex."""
    from ramen_cve import extract_iocs

    md5 = "d41d8cd98f00b204e9800998ecf8427e"  # 32
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64

    text = f"Hashes: {md5} {sha1} {sha256}"
    iocs = extract_iocs(text, "src", TODAY, "feed_pub")
    by_type = {i.ioc_type: i.value for i in iocs if i.ioc_type in ("md5", "sha1", "sha256")}
    assert by_type == {"md5": md5, "sha1": sha1, "sha256": sha256}


def test_extract_iocs_hashes_emit_lowercase():
    """An upper-case hash is normalized to lower-case in the emitted IOC."""
    from ramen_cve import extract_iocs

    upper_md5 = "D41D8CD98F00B204E9800998ECF8427E"
    iocs = extract_iocs(f"hash: {upper_md5}", "src", TODAY, "feed_pub")
    md5s = [i.value for i in iocs if i.ioc_type == "md5"]
    assert md5s == [upper_md5.lower()]


def test_extract_iocs_domain_only_when_defanged():
    """A bare 'example.com' is NOT emitted unless the source contains defang markers."""
    from ramen_cve import extract_iocs

    fanged = extract_iocs("see example.com for details", "src", TODAY, "feed_pub")
    assert all(i.ioc_type != "domain" for i in fanged)

    defanged = extract_iocs(
        "Beacon to evil[.]example[.]com — see also bad[.]tld", "src", TODAY, "feed_pub"
    )
    domains = {i.value for i in defanged if i.ioc_type == "domain"}
    assert "evil.example.com" in domains
    assert "bad.tld" in domains


def test_extract_iocs_skips_filename_shaped_domains():
    """Defanged 'report[.]pdf' must NOT be emitted as a domain (file extension TLD)."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs(
        "Drops payload[.]exe and decoy report[.]pdf from evil[.]example[.]com",
        "src", TODAY, "feed_pub",
    )
    domains = {i.value for i in iocs if i.ioc_type == "domain"}
    assert "evil.example.com" in domains
    assert "payload.exe" not in domains
    assert "report.pdf" not in domains


def test_extract_iocs_dedupe_within_text():
    """The same hash repeated twice produces one IOC."""
    from ramen_cve import extract_iocs

    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(f"{md5} ... again {md5}", "src", TODAY, "feed_pub")
    md5s = [i for i in iocs if i.ioc_type == "md5"]
    assert len(md5s) == 1


def test_extract_iocs_defanged_marker_propagates_to_all_iocs_in_text():
    """If the text contains any defang token, every IOC from that text is flagged defanged."""
    from ramen_cve import extract_iocs

    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    text = f"hxxps://evil[.]example[.]com drops {md5} from 8.8.8.8"
    iocs = extract_iocs(text, "src", TODAY, "feed_pub")
    assert iocs and all(i.defanged_in_source for i in iocs)


def test_extract_iocs_no_iocs_returns_empty_list():
    """Plain text with nothing IOC-shaped returns an empty list (not None, not error)."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs("Nothing to see here.", "src", TODAY, "feed_pub")
    assert iocs == []


def test_extract_iocs_url_skips_domain_match_for_same_host():
    """A defanged URL host should not also be emitted as a separate domain IOC."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs(
        "C2: hxxps://evil[.]example[.]com/abc and another bad[.]tld",
        "src", TODAY, "feed_pub",
    )
    domains = {i.value for i in iocs if i.ioc_type == "domain"}
    # 'evil.example.com' is the URL host; only the un-URL'd 'bad.tld' should remain
    assert "evil.example.com" not in domains
    assert "bad.tld" in domains


def test_dedupe_iocs_merges_sources_and_keeps_earliest():
    """Same (type, value) across feeds: earliest first_seen wins, sources joined with '; '."""
    from ramen_cve import IocRecord, _dedupe_iocs

    a = IocRecord("ipv4", "8.8.8.8", "feed-a", date(2024, 1, 5), "feed_pub")
    b = IocRecord(
        "ipv4", "8.8.8.8", "feed-b", date(2024, 1, 1), "feed_pub", defanged_in_source=True,
    )
    c = IocRecord("ipv4", "8.8.8.8", "feed-a", date(2024, 1, 7), "feed_pub")  # dup of a's source

    out = _dedupe_iocs([a, b, c])
    assert len(out) == 1
    rec = out[0]
    assert rec.first_seen == date(2024, 1, 1)
    assert rec.defanged_in_source is True
    assert "feed-a" in rec.source and "feed-b" in rec.source
    # 'feed-a' should appear once even though the input had it twice
    assert rec.source.split("; ").count("feed-a") == 1


def test_write_iocs_csv_round_trip(tmp_path):
    """write_iocs_csv emits the columns in IOC_CSV_COLUMNS order."""
    from ramen_cve import IOC_CSV_COLUMNS, IocRecord, write_iocs_csv

    iocs = [
        IocRecord("url", "https://evil.example.com/x", "feed-a",
                  date(2024, 1, 1), "feed_pub", defanged_in_source=True),
        IocRecord("md5", "d41d8cd98f00b204e9800998ecf8427e", "feed-b",
                  date(2024, 2, 1), "feed_pub"),
    ]
    out = tmp_path / "iocs.csv"
    write_iocs_csv(iocs, out)
    rows = list(csv.reader(out.open()))
    assert rows[0] == IOC_CSV_COLUMNS
    assert len(rows) == 3
    assert rows[1][0] == "url"
    assert rows[1][-1] == "true"
    assert rows[2][0] == "md5"
    assert rows[2][-1] == "false"


def test_write_markdown_renders_iocs_section(tmp_path):
    """When iocs is non-empty, the Markdown report includes an IOC section."""
    from ramen_cve import IocRecord, write_markdown

    iocs = [
        IocRecord("url", "https://evil.example.com/c2", "feed-a",
                  date(2024, 1, 1), "feed_pub", defanged_in_source=True),
        IocRecord("ipv4", "8.8.8.8", "feed-a",
                  date(2024, 1, 2), "feed_pub"),
        IocRecord("md5", "d41d8cd98f00b204e9800998ecf8427e", "feed-a",
                  date(2024, 1, 3), "feed_pub"),
    ]
    out = tmp_path / "report.md"
    write_markdown([], out, METADATA, iocs=iocs)
    text = out.read_text()
    assert "## Indicators of Compromise" in text
    assert "### URLs" in text
    assert "https://evil.example.com/c2" in text
    assert "### IPv4 Addresses" in text
    assert "8.8.8.8" in text
    assert "### MD5 Hashes" in text
    assert "d41d8cd98f00b204e9800998ecf8427e" in text
    assert "Total IOCs: **3** (1 defanged in source)" in text
    assert "*(defanged in source)*" in text


def test_write_markdown_no_iocs_section_when_empty(tmp_path):
    """When iocs is None or empty, no 'Indicators of Compromise' section is rendered."""
    from ramen_cve import write_markdown

    out = tmp_path / "report.md"
    write_markdown([], out, METADATA, iocs=None)
    text = out.read_text()
    assert "## Indicators of Compromise" not in text
    assert "Total IOCs" not in text


def test_extract_iocs_defanged_at_marker_email():
    """A '(at)'-defanged email refangs to '@' and is captured."""
    from ramen_cve import extract_iocs

    iocs = extract_iocs("contact attacker(at)evil[.]example", "src", TODAY, "feed_pub")
    emails = [i.value for i in iocs if i.ioc_type == "email"]
    # Note: this test will only succeed if the TLD has length ≥ 2; "example" is 7 chars
    assert "attacker@evil.example" in emails
