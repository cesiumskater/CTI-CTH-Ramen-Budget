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
        [".venv/bin/python", "threat_intel_hunter.py", "opml", "x.opml", "--start", "not-a-date"],
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
            ".venv/bin/python", "threat_intel_hunter.py", "opml", "x.opml",
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
        [".venv/bin/python", "threat_intel_hunter.py", "cve", "NOT-A-CVE"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_cli_from_file_missing_returns_friendly_error(tmp_path):
    """A non-existent --from-file path exits with code 1 and no traceback (regression for H1)."""
    import subprocess

    missing = tmp_path / "does-not-exist.txt"
    result = subprocess.run(
        [
            ".venv/bin/python", "threat_intel_hunter.py",
            "cve", "--from-file", str(missing), "--no-cache",
        ],
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
    # defanged_in_source is the second-to-last column now that 'enrichments' was added
    assert rows[1][IOC_CSV_COLUMNS.index("defanged_in_source")] == "true"
    assert rows[2][0] == "md5"
    assert rows[2][IOC_CSV_COLUMNS.index("defanged_in_source")] == "false"
    # enrichments column exists and is empty for unenriched records
    assert rows[1][IOC_CSV_COLUMNS.index("enrichments")] == ""


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


# ---------------------------------------------------------------------------
# Slice 10 — MITRE ATT&CK technique mapping
# ---------------------------------------------------------------------------


def test_map_cwes_to_attack_basic():
    """Known CWEs map to their curated technique IDs."""
    from ramen_cve import map_cwes_to_attack_techniques

    assert "T1190" in map_cwes_to_attack_techniques(["CWE-89"])
    assert "T1059" in map_cwes_to_attack_techniques(["CWE-78"])
    assert "T1190" in map_cwes_to_attack_techniques(["CWE-502"])
    assert "T1059" in map_cwes_to_attack_techniques(["CWE-502"])


def test_map_cwes_to_attack_dedupes_and_sorts():
    """Multiple CWEs that share a technique produce one sorted output."""
    from ramen_cve import map_cwes_to_attack_techniques

    out = map_cwes_to_attack_techniques(["CWE-89", "CWE-352", "CWE-306"])
    # All three map to T1190 → expect a single T1190 entry
    assert out == sorted(set(out))
    assert out.count("T1190") == 1


def test_map_cwes_to_attack_unknown_returns_empty():
    """An unmapped CWE produces no techniques (and no error)."""
    from ramen_cve import map_cwes_to_attack_techniques

    assert map_cwes_to_attack_techniques(["CWE-99999"]) == []


def test_map_cwes_to_attack_case_insensitive():
    """Lower-case CWE input is normalized before lookup."""
    from ramen_cve import map_cwes_to_attack_techniques

    assert "T1190" in map_cwes_to_attack_techniques(["cwe-89"])


def test_map_cwes_to_attack_empty_input():
    """Empty CWE list returns an empty technique list."""
    from ramen_cve import map_cwes_to_attack_techniques

    assert map_cwes_to_attack_techniques([]) == []


def test_attack_technique_names_cover_mapping():
    """Every technique referenced in CWE_TO_ATTACK has a display name."""
    from ramen_cve import ATTACK_TECHNIQUE_NAMES, CWE_TO_ATTACK

    referenced = {tid for tids in CWE_TO_ATTACK.values() for tid in tids}
    missing = referenced - ATTACK_TECHNIQUE_NAMES.keys()
    assert not missing, f"missing technique names for: {sorted(missing)}"


def test_enrich_cves_populates_attack_techniques():
    """End-to-end: CWE-502 in the NVD response surfaces T1190 + T1059 on the EnrichedCve."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    log4shell = _load_fixture("nvd_log4shell_v31.json")
    epss = _load_fixture("epss_batch.json")

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = log4shell
        return resp

    records = [CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)

    # Log4Shell CWE-502 → T1059 + T1190 per CWE_TO_ATTACK
    techniques = result[0].attack_techniques
    assert "T1190" in techniques
    assert "T1059" in techniques
    # Output is deterministic (sorted)
    assert techniques == sorted(techniques)


def test_write_csv_includes_attack_techniques_column(tmp_path):
    """CSV header includes attack_techniques and the row joins values with ';'."""
    from ramen_cve import CSV_COLUMNS, EnrichedCve, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        cvss_severity="CRITICAL",
        epss_score=0.5,
        attack_techniques=["T1059", "T1190"],
        bucket="patch_now",
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    assert "attack_techniques" in rows[0]
    assert rows[0] == CSV_COLUMNS
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["attack_techniques"] == "T1059;T1190"


def test_write_markdown_renders_attack_per_cve_and_cross_tab(tmp_path):
    """Markdown shows per-CVE ATT&CK list and a 'By ATT&CK Technique' summary table."""
    from ramen_cve import EnrichedCve, write_markdown

    recs = [
        EnrichedCve(
            cve_id="CVE-2021-44228",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            epss_score=0.97,
            attack_techniques=["T1059", "T1190"],
            bucket="patch_now",
        ),
        EnrichedCve(
            cve_id="CVE-2021-26855",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            epss_score=0.97,
            attack_techniques=["T1190"],
            bucket="patch_now",
        ),
    ]
    out = tmp_path / "report.md"
    write_markdown(recs, out, METADATA)
    text = out.read_text()
    # Per-CVE
    assert "**ATT&CK:** T1059" in text
    assert "T1190 (Exploit Public-Facing Application)" in text
    # Cross-tab
    assert "## By ATT&CK Technique" in text
    assert "| T1190 | Exploit Public-Facing Application | 2 |" in text
    assert "| T1059 | Command and Scripting Interpreter | 1 |" in text


def test_write_markdown_no_attack_section_when_empty(tmp_path):
    """If no enriched record has attack_techniques, the cross-tab section is omitted."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        attack_techniques=[],
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "## By ATT&CK Technique" not in text
    assert "**ATT&CK:**" not in text


# ---------------------------------------------------------------------------
# Slice 11 — Exploit / PoC availability tracking
# ---------------------------------------------------------------------------


_EDB_CSV_FIXTURE = (
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    "50562,exploits/multiple/remote/50562.py,Apache Log4j 2 - RCE,2021-12-14,Anonymous,"
    "remote,multiple,,2021-12-14,2022-04-12,1,CVE-2021-44228;CVE-2021-45046,,,,,\n"
    "49637,exploits/windows/remote/49637.py,Microsoft Exchange Server SSRF,2021-03-15,"
    "Anonymous,remote,windows,,2021-03-15,2022-04-12,1,CVE-2021-26855,,,,,\n"
    "10000,exploits/local/foo.py,Stub,2024-01-01,A,local,linux,,2024-01-01,2024-01-01,1,,,,,,\n"
)

_NUCLEI_TREE_FIXTURE = {
    "tree": [
        {"path": "http/cves/2021/CVE-2021-44228.yaml", "type": "blob"},
        {"path": "http/cves/2021/CVE-2021-26855.yaml", "type": "blob"},
        {"path": "README.md", "type": "blob"},
        {"path": "http/cves/2024/CVE-2024-9999.yaml", "type": "blob"},
        {"path": "http/cves/", "type": "tree"},  # not a yaml file
    ]
}


def _patch_exploit_get(edb_text: str | None = None, nuclei_data: dict | None = None,
                      github_total: int | None = None):
    """Patch requests.get to differentiate the EDB / Nuclei / GitHub URLs."""
    from unittest.mock import MagicMock, patch

    edb_text = edb_text if edb_text is not None else _EDB_CSV_FIXTURE
    nuclei_data = nuclei_data if nuclei_data is not None else _NUCLEI_TREE_FIXTURE

    def _fake(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "exploit-database" in url or "exploitdb" in url:
            resp.text = edb_text
        elif "nuclei-templates" in url:
            resp.json.return_value = nuclei_data
        elif "search/repositories" in url:
            resp.json.return_value = {"total_count": github_total or 0}
        else:
            resp.json.return_value = {}
        return resp

    return patch("ramen_cve.requests.get", side_effect=_fake)


def test_fetch_exploitdb_cve_set_parses_codes_column():
    """Each non-empty 'codes' cell yields one or more CVE IDs."""
    from ramen_cve import fetch_exploitdb_cve_set

    cache = _mem_cache()
    with _patch_exploit_get():
        edb = fetch_exploitdb_cve_set(cache)

    assert "CVE-2021-44228" in edb
    assert "CVE-2021-45046" in edb
    assert "CVE-2021-26855" in edb


def test_fetch_exploitdb_cve_set_caches_index():
    """A second call returns the cached set without an HTTP request."""

    from ramen_cve import fetch_exploitdb_cve_set

    cache = _mem_cache()
    with _patch_exploit_get() as mock_get:
        first = fetch_exploitdb_cve_set(cache)
        second = fetch_exploitdb_cve_set(cache)
    # Only one call to the EDB URL on the first invocation
    assert first == second
    edb_calls = [c for c in mock_get.call_args_list if "exploit" in c.args[0]]
    assert len(edb_calls) == 1


def test_fetch_exploitdb_cve_set_handles_error(caplog):
    """A network error returns an empty set and logs a warning."""
    import logging
    from unittest.mock import MagicMock, patch

    from ramen_cve import fetch_exploitdb_cve_set

    cache = _mem_cache()
    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("boom")
    with patch("ramen_cve.requests.get", return_value=bad), caplog.at_level(
        logging.WARNING, logger="ramen_cve"
    ):
        result = fetch_exploitdb_cve_set(cache)
    assert result == set()
    assert any("Exploit-DB index fetch failed" in r.message for r in caplog.records)


def test_fetch_nuclei_cve_set_extracts_from_paths():
    """Paths under 'cves/' ending in '.yaml' yield the CVE IDs in the path."""
    from ramen_cve import fetch_nuclei_cve_set

    cache = _mem_cache()
    with _patch_exploit_get():
        nuclei = fetch_nuclei_cve_set(cache)

    assert "CVE-2021-44228" in nuclei
    assert "CVE-2021-26855" in nuclei
    assert "CVE-2024-9999" in nuclei


def test_fetch_nuclei_cve_set_caches():
    """A second call returns cached results without re-hitting the HTTP API."""

    from ramen_cve import fetch_nuclei_cve_set

    cache = _mem_cache()
    with _patch_exploit_get() as mock_get:
        first = fetch_nuclei_cve_set(cache)
        second = fetch_nuclei_cve_set(cache)
    assert first == second
    nuclei_calls = [c for c in mock_get.call_args_list if "nuclei-templates" in c.args[0]]
    assert len(nuclei_calls) == 1


def test_search_github_no_token_returns_false_without_http():
    """Without GITHUB_TOKEN, no HTTP call happens and the function returns False."""
    from unittest.mock import patch

    from ramen_cve import search_github_for_cve

    cache = _mem_cache()
    with patch("ramen_cve.requests.get") as mock_get:
        result = search_github_for_cve("CVE-2021-44228", cache, github_token=None)
    assert result is False
    mock_get.assert_not_called()


def test_search_github_returns_true_when_total_count_positive():
    """When the GitHub API reports total_count > 0, the function returns True."""
    from ramen_cve import search_github_for_cve

    cache = _mem_cache()
    with _patch_exploit_get(github_total=5):
        result = search_github_for_cve("CVE-2099-9999", cache, github_token="ghp_test")
    assert result is True


def test_search_github_caches_per_cve():
    """A second call for the same CVE comes from cache."""

    from ramen_cve import search_github_for_cve

    cache = _mem_cache()
    with _patch_exploit_get(github_total=3) as mock_get:
        first = search_github_for_cve("CVE-2099-1234", cache, github_token="ghp_test")
        second = search_github_for_cve("CVE-2099-1234", cache, github_token="ghp_test")
    assert first is True and second is True
    gh_calls = [c for c in mock_get.call_args_list if "search/repositories" in c.args[0]]
    assert len(gh_calls) == 1


def test_enrich_with_exploit_status_priority_exploitdb_wins():
    """If a CVE is in Exploit-DB it is tagged exploit_db regardless of nuclei/github."""
    from ramen_cve import EnrichedCve, enrich_with_exploit_status

    rec = EnrichedCve("CVE-2021-44228", "x", date(2024, 1, 1), "feed_pub")
    cache = _mem_cache()
    with _patch_exploit_get(github_total=10):
        enrich_with_exploit_status([rec], cache, github_token="ghp_test")
    assert rec.exploit_status == "exploit_db"


def test_enrich_with_exploit_status_falls_back_to_nuclei_then_github():
    """A CVE only in nuclei is tagged nuclei_template; only in GH is tagged github_poc."""
    from ramen_cve import EnrichedCve, enrich_with_exploit_status

    nuclei_rec = EnrichedCve("CVE-2024-9999", "x", date(2024, 1, 1), "feed_pub")
    only_gh_rec = EnrichedCve("CVE-2099-0001", "x", date(2024, 1, 1), "feed_pub")
    cache = _mem_cache()

    # CVE-2024-9999 is in our nuclei fixture; CVE-2099-0001 is in neither so
    # falls through to GitHub which we mock as having matches.
    with _patch_exploit_get(github_total=2):
        enrich_with_exploit_status(
            [nuclei_rec, only_gh_rec], cache, github_token="ghp_test"
        )
    assert nuclei_rec.exploit_status == "nuclei_template"
    assert only_gh_rec.exploit_status == "github_poc"


def test_enrich_with_exploit_status_skip_github_flag():
    """skip_github=True suppresses the GitHub fallback even when a token is set."""
    from ramen_cve import EnrichedCve, enrich_with_exploit_status

    only_gh_rec = EnrichedCve("CVE-2099-0001", "x", date(2024, 1, 1), "feed_pub")
    cache = _mem_cache()
    with _patch_exploit_get(github_total=10):
        enrich_with_exploit_status(
            [only_gh_rec], cache, github_token="ghp_test", skip_github=True
        )
    assert only_gh_rec.exploit_status == "none"


def test_enrich_with_exploit_status_default_none():
    """A CVE that nobody has exploit code for stays exploit_status='none'."""
    from ramen_cve import EnrichedCve, enrich_with_exploit_status

    rec = EnrichedCve("CVE-2099-0001", "x", date(2024, 1, 1), "feed_pub")
    cache = _mem_cache()
    with _patch_exploit_get(github_total=0):
        enrich_with_exploit_status([rec], cache, github_token=None)
    assert rec.exploit_status == "none"


def test_cache_exploit_round_trip():
    """Cache.set_exploit / get_exploit round-trips a payload."""
    c = _mem_cache()
    c.set_exploit("exploitdb", "index", {"cve_ids": ["CVE-2021-44228"]})
    assert c.get_exploit("exploitdb", "index") == {"cve_ids": ["CVE-2021-44228"]}


def test_cache_exploit_keyed_separately_per_source():
    """Same key under different sources are independent rows."""
    c = _mem_cache()
    c.set_exploit("exploitdb", "index", {"cve_ids": ["CVE-A"]})
    c.set_exploit("nuclei", "index", {"cve_ids": ["CVE-B"]})
    assert c.get_exploit("exploitdb", "index") == {"cve_ids": ["CVE-A"]}
    assert c.get_exploit("nuclei", "index") == {"cve_ids": ["CVE-B"]}


def test_write_csv_includes_exploit_status_column(tmp_path):
    """exploit_status appears in the CSV header and rows."""
    from ramen_cve import EnrichedCve, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        exploit_status="exploit_db",
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    assert "exploit_status" in header
    row = dict(zip(header, rows[1], strict=True))
    assert row["exploit_status"] == "exploit_db"


def test_write_markdown_renders_exploit_status_when_not_none(tmp_path):
    """Markdown shows the Exploit Status line for CVEs with exploit_status != 'none'."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        exploit_status="nuclei_template",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "**Exploit Status:** `nuclei_template`" in text


def test_write_markdown_omits_exploit_status_line_when_none(tmp_path):
    """A 'none' exploit_status does not produce an Exploit Status line."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        exploit_status="none",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "Exploit Status" not in text


def test_cli_no_exploit_lookup_flag_parses():
    """--no-exploit-lookup is accepted on every subcommand."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--no-exploit-lookup"]
    )
    assert args.no_exploit_lookup is True
    args2 = build_parser().parse_args(["opml", "x.opml"])
    assert args2.no_exploit_lookup is False


# ---------------------------------------------------------------------------
# Slice 12 — STIX 2.1 / TAXII interoperability
# ---------------------------------------------------------------------------


def test_stix_uuid_is_deterministic_and_uuid4_shaped():
    """_stix_uuid returns the same string for the same seed and matches UUIDv4 form."""
    import re as _re

    from ramen_cve import _stix_uuid

    a = _stix_uuid("CVE-2021-44228")
    b = _stix_uuid("CVE-2021-44228")
    assert a == b
    assert _re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}", a
    )
    assert _stix_uuid("CVE-2099-9999") != a


def test_ioc_to_stix_pattern_covers_all_types():
    """Every IOC type produces a valid STIX equality pattern; unknown types return None."""
    from ramen_cve import IocRecord, _ioc_to_stix_pattern

    cases = [
        ("ipv4", "8.8.8.8", "[ipv4-addr:value = '8.8.8.8']"),
        ("url", "https://evil.example/c2", "[url:value = 'https://evil.example/c2']"),
        ("domain", "evil.example.com", "[domain-name:value = 'evil.example.com']"),
        ("email", "x@y.com", "[email-addr:value = 'x@y.com']"),
        (
            "md5",
            "d41d8cd98f00b204e9800998ecf8427e",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        ),
        (
            "sha1",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
        ),
        (
            "sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "[file:hashes.'SHA-256' = "
            "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
        ),
    ]
    for ioc_type, value, expected in cases:
        rec = IocRecord(ioc_type, value, "src", date(2024, 1, 1), "feed_pub")
        assert _ioc_to_stix_pattern(rec) == expected

    unknown = IocRecord("invented", "x", "src", date(2024, 1, 1), "feed_pub")
    assert _ioc_to_stix_pattern(unknown) is None


def test_ioc_to_stix_pattern_escapes_quotes():
    """An IOC value containing a single quote is escaped so the STIX pattern stays valid."""
    from ramen_cve import IocRecord, _ioc_to_stix_pattern

    rec = IocRecord("url", "https://evil/'a", "src", date(2024, 1, 1), "feed_pub")
    pattern = _ioc_to_stix_pattern(rec)
    assert pattern is not None and "\\'" in pattern


def test_write_stix_emits_bundle_with_vuln_note_indicator(tmp_path):
    """write_stix produces a JSON bundle with the expected SDO mix."""
    from ramen_cve import EnrichedCve, IocRecord, write_stix

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        kev_short_description="Apache Log4j2 RCE.",
        cwe=["CWE-502"],
        attack_techniques=["T1059", "T1190"],
        exploit_status="exploit_db",
        bucket="kev_override",
        suggested_action="Patch immediately.",
    )
    iocs = [
        IocRecord("ipv4", "8.8.8.8", "x", date(2024, 1, 1), "feed_pub"),
        IocRecord(
            "md5", "d41d8cd98f00b204e9800998ecf8427e", "x", date(2024, 1, 2), "feed_pub",
        ),
    ]
    out = tmp_path / "report.stix.json"
    write_stix([rec], out, iocs=iocs)
    bundle = json.loads(out.read_text())
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types
    assert types.count("vulnerability") == 1
    assert types.count("note") == 1
    assert types.count("indicator") == 2

    vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert vuln["name"] == "CVE-2021-44228"
    assert any(
        ref.get("source_name") == "cve" and ref.get("external_id") == "CVE-2021-44228"
        for ref in vuln["external_references"]
    )
    assert any(ref.get("source_name") == "cwe" for ref in vuln["external_references"])

    note = next(o for o in bundle["objects"] if o["type"] == "note")
    assert "Bucket: kev_override" in note["content"]
    assert "Apache Log4j2 RCE." in vuln["description"]
    assert "ATT&CK: T1059, T1190" in note["content"]
    assert "Exploit Status: exploit_db" in note["content"]
    assert vuln["id"] in note["object_refs"]


def test_write_stix_uses_stable_ids_across_runs(tmp_path):
    """Two writes for the same CVE should produce the same Vulnerability SDO id."""
    from ramen_cve import EnrichedCve, write_stix

    rec = EnrichedCve(
        cve_id="CVE-2099-1234",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
    )
    p1 = tmp_path / "a.stix.json"
    p2 = tmp_path / "b.stix.json"
    write_stix([rec], p1)
    write_stix([rec], p2)
    a = json.loads(p1.read_text())
    b = json.loads(p2.read_text())
    a_vuln = next(o for o in a["objects"] if o["type"] == "vulnerability")
    b_vuln = next(o for o in b["objects"] if o["type"] == "vulnerability")
    assert a_vuln["id"] == b_vuln["id"]


def test_extract_iocs_from_pattern_round_trips():
    """The patterns we emit can be parsed back into the same (type, value) pairs."""
    from ramen_cve import IocRecord, _extract_iocs_from_pattern, _ioc_to_stix_pattern

    pairs = [
        ("ipv4", "8.8.8.8"),
        ("url", "https://evil.example/c2"),
        ("domain", "evil.example.com"),
        ("email", "x@y.com"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ]
    for ioc_type, value in pairs:
        rec = IocRecord(ioc_type, value, "src", date(2024, 1, 1), "feed_pub")
        pattern = _ioc_to_stix_pattern(rec)
        assert pattern is not None
        parsed = _extract_iocs_from_pattern(pattern)
        assert parsed == [(ioc_type, value)], f"round-trip mismatch for {ioc_type}={value}"


def test_parse_stix_bundle_extracts_vulns_and_indicators(tmp_path):
    """parse_stix_bundle reads CVE IDs from Vulnerability SDOs and IOCs from patterns."""
    from ramen_cve import parse_stix_bundle

    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "vulnerability",
                "id": "vulnerability--00000000-0000-4000-8000-000000000001",
                "name": "CVE-2021-44228",
                "external_references": [{"source_name": "cve", "external_id": "CVE-2021-44228"}],
            },
            {
                "type": "vulnerability",
                "id": "vulnerability--00000000-0000-4000-8000-000000000002",
                "name": "Some narrative name",
                "external_references": [{"source_name": "cve", "external_id": "CVE-2021-26855"}],
            },
            {
                "type": "indicator",
                "id": "indicator--00000000-0000-4000-8000-000000000003",
                "pattern": "[ipv4-addr:value = '203.0.113.5']",
                "pattern_type": "stix",
            },
            {
                "type": "indicator",
                "id": "indicator--00000000-0000-4000-8000-000000000004",
                "pattern": "[file:hashes.'SHA-256' = "
                "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                "pattern_type": "stix",
            },
            {"type": "identity", "id": "identity--00000000-0000-4000-8000-000000000005"},
        ],
    }
    bundle_path = tmp_path / "in.stix.json"
    bundle_path.write_text(json.dumps(bundle))

    cves, iocs = parse_stix_bundle(bundle_path)
    cve_ids = {r.cve_id for r in cves}
    assert cve_ids == {"CVE-2021-44228", "CVE-2021-26855"}
    by_type = {(i.ioc_type, i.value) for i in iocs}
    assert ("ipv4", "203.0.113.5") in by_type
    assert (
        "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ) in by_type


def test_parse_stix_bundle_missing_file_raises_friendly_error(tmp_path):
    """A missing bundle path raises OpmlError, not FileNotFoundError."""
    from ramen_cve import OpmlError, parse_stix_bundle

    with pytest.raises(OpmlError, match="not found"):
        parse_stix_bundle(tmp_path / "nope.json")


def test_parse_stix_bundle_invalid_json_raises_friendly_error(tmp_path):
    """A malformed bundle file raises OpmlError, not JSONDecodeError."""
    from ramen_cve import OpmlError, parse_stix_bundle

    p = tmp_path / "bad.json"
    p.write_text("{not: valid json")
    with pytest.raises(OpmlError, match="parse"):
        parse_stix_bundle(p)


def test_pull_taxii_basic_fetch_returns_records():
    """pull_taxii hits the collection-objects endpoint and parses the response."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import pull_taxii

    payload = {
        "objects": [
            {
                "type": "vulnerability",
                "id": "vulnerability--00000000-0000-4000-8000-000000000001",
                "name": "CVE-2024-1234",
            },
            {
                "type": "indicator",
                "id": "indicator--00000000-0000-4000-8000-000000000002",
                "pattern": "[ipv4-addr:value = '198.51.100.7']",
                "pattern_type": "stix",
            },
        ]
    }
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload

    with patch("ramen_cve.requests.get", return_value=resp) as mock_get:
        cves, iocs = pull_taxii(
            "https://taxii.example/api1",
            "00000000-0000-4000-8000-000000000099",
            username="alice",
            password="hunter2",
        )

    assert {r.cve_id for r in cves} == {"CVE-2024-1234"}
    assert {(i.ioc_type, i.value) for i in iocs} == {("ipv4", "198.51.100.7")}
    call = mock_get.call_args
    assert call.args[0].endswith(
        "/collections/00000000-0000-4000-8000-000000000099/objects/"
    )
    assert call.kwargs.get("auth") == ("alice", "hunter2")


def test_pull_taxii_network_error_returns_empty(caplog):
    """A network error returns ([], []) and logs a warning instead of raising."""
    import logging
    from unittest.mock import MagicMock, patch

    from ramen_cve import pull_taxii

    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("nope")
    with patch("ramen_cve.requests.get", return_value=bad), caplog.at_level(
        logging.WARNING, logger="ramen_cve"
    ):
        cves, iocs = pull_taxii(
            "https://taxii.example/api1", "00000000-0000-4000-0000-000000000099",
        )
    assert cves == [] and iocs == []
    assert any("TAXII pull failed" in r.message for r in caplog.records)


def test_cli_format_choices_include_stix_and_all():
    """--format accepts 'stix' and 'all' in addition to csv/md/both."""
    from ramen_cve import build_parser

    for fmt in ("csv", "md", "both", "stix", "all"):
        args = build_parser().parse_args(["opml", "x.opml", "--format", fmt])
        assert args.format == fmt


def test_cli_stix_subcommand_parses_path_and_taxii_flags():
    """The stix subcommand accepts an optional path and --taxii-* flags."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["stix", "bundle.json"])
    assert args.subcommand == "stix"
    assert str(args.path) == "bundle.json"

    args2 = build_parser().parse_args([
        "stix",
        "--taxii-url", "https://taxii.example/api1",
        "--taxii-collection", "00000000-0000-4000-0000-000000000001",
    ])
    assert args2.subcommand == "stix"
    assert args2.taxii_url == "https://taxii.example/api1"
    assert args2.taxii_collection == "00000000-0000-4000-0000-000000000001"


def test_run_stix_rejects_missing_source(tmp_path, caplog):
    """stix subcommand without path or --taxii-* args exits with code 1 and logs an error."""
    import logging

    import ramen_cve

    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "stix", "--no-cache", "--out-dir", str(tmp_path), "--format", "csv",
        ])
    assert rc == 1
    assert any("provide a bundle path" in r.message for r in caplog.records)


def test_run_stix_rejects_combined_path_and_taxii(tmp_path, caplog):
    """Providing both a path and TAXII flags must error before any HTTP work."""
    import logging

    import ramen_cve

    bundle = tmp_path / "x.json"
    bundle.write_text("{}")
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "stix", str(bundle),
            "--taxii-url", "https://taxii.example/api1",
            "--taxii-collection", "00000000-0000-4000-0000-000000000001",
            "--no-cache", "--out-dir", str(tmp_path), "--format", "csv",
        ])
    assert rc == 1
    assert any("mutually exclusive" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Slice 13 — Threat actor / campaign / malware modeling
# ---------------------------------------------------------------------------


def _write_assoc_file(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "assoc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_load_associations_basic(tmp_path):
    """A well-formed associations file is loaded into ThreatActor / Malware / Campaign objects."""
    from ramen_cve import Campaign, Malware, ThreatActor, load_associations

    payload = {
        "CVE-2021-44228": {
            "actors": [{"name": "APT41", "aliases": ["Wicked Panda"], "url": "https://x"}],
            "malware": [{"name": "Cobalt Strike"}],
            "campaigns": [{"name": "Holiday RCE"}],
        }
    }
    p = _write_assoc_file(tmp_path, payload)
    out = load_associations(p)
    assert "CVE-2021-44228" in out
    actors = out["CVE-2021-44228"]["actors"]
    assert len(actors) == 1 and isinstance(actors[0], ThreatActor)
    assert actors[0].name == "APT41" and actors[0].aliases == ["Wicked Panda"]
    assert isinstance(out["CVE-2021-44228"]["malware"][0], Malware)
    assert isinstance(out["CVE-2021-44228"]["campaigns"][0], Campaign)


def test_load_associations_normalizes_cve_case(tmp_path):
    """Lower-case CVE keys are normalized to upper-case in the loaded dict."""
    from ramen_cve import load_associations

    p = _write_assoc_file(tmp_path, {"cve-2021-44228": {"actors": [{"name": "x"}]}})
    out = load_associations(p)
    assert "CVE-2021-44228" in out


def test_load_associations_skips_invalid_cve_keys(tmp_path):
    """Non-CVE keys (e.g. _README) are silently skipped."""
    from ramen_cve import load_associations

    p = _write_assoc_file(tmp_path, {
        "_README": "comment",
        "CVE-2021-44228": {"actors": []},
    })
    out = load_associations(p)
    assert "_README" not in out
    assert "CVE-2021-44228" in out


def test_load_associations_missing_file_returns_empty(tmp_path, caplog):
    """A missing file yields an empty dict and a WARNING (no exception)."""
    import logging

    from ramen_cve import load_associations

    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        out = load_associations(tmp_path / "does-not-exist.json")
    assert out == {}
    assert any("not found" in r.message for r in caplog.records)


def test_load_associations_invalid_json_returns_empty(tmp_path, caplog):
    """A malformed file yields {} + WARNING, never crashes the run."""
    import logging

    from ramen_cve import load_associations

    p = tmp_path / "bad.json"
    p.write_text("{not: valid json")
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        out = load_associations(p)
    assert out == {}
    assert any("Could not parse associations" in r.message for r in caplog.records)


def test_default_associations_file_loads():
    """The bundled associations.json is well-formed and seeds at least one CVE."""
    from ramen_cve import DEFAULT_ASSOCIATIONS_PATH, load_associations

    assert DEFAULT_ASSOCIATIONS_PATH.exists()
    out = load_associations(DEFAULT_ASSOCIATIONS_PATH)
    assert "CVE-2021-44228" in out
    assert any(a.name == "APT41" for a in out["CVE-2021-44228"]["actors"])


def test_enrich_cves_attaches_associations():
    """enrich_cves(associations=...) populates linked_actors / linked_malware / linked_campaigns."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, ThreatActor, enrich_cves

    associations = {
        "CVE-2021-44228": {
            "actors": [ThreatActor(name="APT41")],
            "campaigns": [],
            "malware": [],
        }
    }
    cache = _mem_cache()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = _load_fixture("epss_batch.json")
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = _load_fixture("nvd_log4shell_v31.json")
        return resp

    records = [CveRecord("CVE-2021-44228", "f", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None, associations=associations)

    assert len(result) == 1
    assert [a.name for a in result[0].linked_actors] == ["APT41"]


def test_enrich_cves_no_match_leaves_linked_fields_empty():
    """A CVE not present in the associations dict has empty linked_* lists."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = _load_fixture("epss_batch.json")
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = _load_fixture("nvd_log4shell_v31.json")
        return resp

    records = [CveRecord("CVE-2021-44228", "f", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None, associations={})
    assert result[0].linked_actors == []


def test_write_csv_includes_linked_columns(tmp_path):
    """CSV header includes linked_actors / linked_campaigns / linked_malware."""
    from ramen_cve import EnrichedCve, ThreatActor, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
        linked_actors=[ThreatActor("APT41"), ThreatActor("HAFNIUM")],
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    assert "linked_actors" in header
    assert "linked_campaigns" in header
    assert "linked_malware" in header
    row = dict(zip(header, rows[1], strict=True))
    assert row["linked_actors"] == "APT41;HAFNIUM"


def test_write_markdown_renders_actors_and_cross_tab(tmp_path):
    """Markdown shows per-CVE Linked Actors and a Linked Adversaries cross-tab."""
    from ramen_cve import EnrichedCve, ThreatActor, write_markdown

    recs = [
        EnrichedCve(
            cve_id="CVE-2021-44228",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=10.0,
            epss_score=0.97,
            bucket="kev_override",
            linked_actors=[
                ThreatActor("APT41", url="https://attack.mitre.org/groups/G0096/"),
                ThreatActor("HAFNIUM"),
            ],
        ),
        EnrichedCve(
            cve_id="CVE-2021-26855",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=9.8,
            epss_score=0.97,
            bucket="patch_now",
            linked_actors=[ThreatActor("HAFNIUM")],
        ),
    ]
    out = tmp_path / "report.md"
    write_markdown(recs, out, METADATA)
    text = out.read_text()
    # Per-CVE
    assert "**Linked Actors:**" in text
    assert "[APT41](https://attack.mitre.org/groups/G0096/)" in text
    # Cross-tab
    assert "## Linked Adversaries" in text
    assert "| HAFNIUM | 2 |" in text
    assert "| APT41 | 1 |" in text


def test_write_markdown_no_actor_section_when_empty(tmp_path):
    """If no enriched record has linked_actors, the cross-tab is omitted."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2024-0001", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
        linked_actors=[],
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "## Linked Adversaries" not in text


def test_cli_associations_file_flag_parses(tmp_path):
    """--associations-file takes a path that survives parsing."""
    from ramen_cve import build_parser

    args = build_parser().parse_args([
        "cve", "CVE-2021-44228",
        "--associations-file", str(tmp_path / "x.json"),
    ])
    assert str(args.associations_file).endswith("x.json")


# ---------------------------------------------------------------------------
# Slice 14 — Sigma rule generation
# ---------------------------------------------------------------------------


def _kev_rec(**overrides) -> "EnrichedCve":  # type: ignore[name-defined]
    """Return a kev_override EnrichedCve suitable for Sigma generation."""
    from ramen_cve import EnrichedCve

    base = dict(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        kev_known_ransomware_use=True,
        cwe=["CWE-502"],
        attack_techniques=["T1059", "T1190"],
        bucket="kev_override",
        suggested_action="Patch immediately.",
        exploit_status="exploit_db",
    )
    base.update(overrides)
    return EnrichedCve(**base)


def test_sigma_level_for_kev_is_critical():
    """A KEV-listed CVE always maps to Sigma level 'critical'."""
    from ramen_cve import _sigma_level_for

    assert _sigma_level_for(_kev_rec(cvss_score=4.0)) == "critical"


def test_sigma_level_for_high_cvss():
    """CVSS 9.0+ → critical, 7.0-8.9 → high, below 7 in patch_now → medium."""
    from ramen_cve import _sigma_level_for

    rec = _kev_rec(kev_listed=False, kev_due_date=None, bucket="patch_now", cvss_score=9.5)
    assert _sigma_level_for(rec) == "critical"
    rec.cvss_score = 7.5
    assert _sigma_level_for(rec) == "high"
    rec.cvss_score = 5.0
    assert _sigma_level_for(rec) == "medium"


def test_build_sigma_stub_contains_required_fields():
    """The emitted YAML carries title/id/status/level + ATT&CK + CVE tags."""
    from ramen_cve import _build_sigma_stub

    yaml = _build_sigma_stub(_kev_rec())
    assert "title:" in yaml
    assert "id: " in yaml
    assert "status: experimental" in yaml
    assert "level: critical" in yaml
    assert "cve.cve-2021-44228" in yaml
    assert "attack.t1059" in yaml
    assert "attack.t1190" in yaml
    assert "cisa.kev" in yaml
    assert "ransomware.known" in yaml
    # The block we want a detection engineer to fill in is clearly marked TODO
    assert "TODO" in yaml


def test_build_sigma_stub_has_stable_id_across_runs():
    """The same CVE always produces the same Sigma rule id (UUID-shaped)."""
    import re as _re

    from ramen_cve import _build_sigma_stub

    yaml1 = _build_sigma_stub(_kev_rec())
    yaml2 = _build_sigma_stub(_kev_rec())
    id1 = _re.search(r"^id:\s*(\S+)", yaml1, _re.MULTILINE)
    id2 = _re.search(r"^id:\s*(\S+)", yaml2, _re.MULTILINE)
    assert id1 is not None and id2 is not None
    assert id1.group(1) == id2.group(1)
    assert _re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}",
        id1.group(1),
    )


def test_write_sigma_stubs_filters_by_bucket(tmp_path):
    """Only kev_override / patch_now CVEs become Sigma stubs."""
    from ramen_cve import EnrichedCve, write_sigma_stubs

    kev = _kev_rec()
    patch_now = EnrichedCve(
        cve_id="CVE-2021-26855",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        bucket="patch_now",
    )
    watch_closely = EnrichedCve(
        cve_id="CVE-2024-1234",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=4.0,
        epss_score=0.5,
        bucket="watch_closely",
    )
    out_dir = tmp_path / "sigma"
    files = write_sigma_stubs([kev, patch_now, watch_closely], out_dir)
    names = sorted(p.name for p in files)
    assert names == ["CVE-2021-26855.yml", "CVE-2021-44228.yml"]
    assert not (out_dir / "CVE-2024-1234.yml").exists()


def test_write_sigma_stubs_creates_dir(tmp_path):
    """The output directory is created if it doesn't yet exist."""
    from ramen_cve import write_sigma_stubs

    out_dir = tmp_path / "nested" / "sigma"
    files = write_sigma_stubs([_kev_rec()], out_dir)
    assert out_dir.is_dir()
    assert len(files) == 1


def test_cli_format_sigma_choice_parses():
    """--format sigma is accepted."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["opml", "x.opml", "--format", "sigma"])
    assert args.format == "sigma"


# ---------------------------------------------------------------------------
# Slice 15 — Multi-source IOC enrichment
# ---------------------------------------------------------------------------


def _make_resp(status: int = 200, *, json_payload: dict | None = None, text: str = ""):
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.status_code = status
    if status >= 400 and status != 404:
        import requests as _req

        resp.raise_for_status.side_effect = _req.HTTPError(response=resp)
    else:
        resp.raise_for_status.return_value = None
    if json_payload is not None:
        resp.json.return_value = json_payload
    resp.text = text
    return resp


def test_virustotal_enricher_supports_only_with_key():
    """VirusTotal is gated on api_key; no key → supports() returns False."""
    from ramen_cve import VirusTotalEnricher

    no_key = VirusTotalEnricher(api_key=None)
    assert no_key.supports("md5") is False
    assert no_key.supports("ipv4") is False

    with_key = VirusTotalEnricher(api_key="vt-test")
    for t in ("ipv4", "domain", "url", "md5", "sha1", "sha256"):
        assert with_key.supports(t) is True
    assert with_key.supports("email") is False


def test_virustotal_enricher_returns_normalized_payload():
    """A 200 from VT is normalized to {found, malicious, suspicious, ...}."""
    from unittest.mock import patch

    from ramen_cve import VirusTotalEnricher

    cache = _mem_cache()
    e = VirusTotalEnricher(api_key="vt-test")
    payload = {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 80, "malicious": 3, "suspicious": 1, "undetected": 16,
                },
                "reputation": -5,
            },
        }
    }
    with patch("ramen_cve.requests.get", return_value=_make_resp(json_payload=payload)):
        result = e.enrich("ipv4", "8.8.8.8", cache)
    assert result["found"] is True
    assert result["malicious"] == 3
    assert result["suspicious"] == 1
    assert result["harmless"] == 80
    assert result["reputation"] == -5
    # Cache hit on second call
    with patch("ramen_cve.requests.get") as mock_get:
        cached = e.enrich("ipv4", "8.8.8.8", cache)
    assert cached == result
    mock_get.assert_not_called()


def test_virustotal_enricher_404_records_not_found():
    """A 404 is interpreted as 'found=False' and cached so we don't keep retrying."""
    from unittest.mock import patch

    from ramen_cve import VirusTotalEnricher

    cache = _mem_cache()
    e = VirusTotalEnricher(api_key="vt-test")
    with patch("ramen_cve.requests.get", return_value=_make_resp(status=404)):
        result = e.enrich("md5", "deadbeef" * 4, cache)
    assert result == {"found": False}


def test_virustotal_enricher_network_error_returns_none(caplog):
    """A network error logs a warning and returns None (and is NOT cached)."""
    import logging
    from unittest.mock import MagicMock, patch

    from ramen_cve import VirusTotalEnricher

    cache = _mem_cache()
    e = VirusTotalEnricher(api_key="vt-test")
    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("boom")
    with patch("ramen_cve.requests.get", return_value=bad), caplog.at_level(
        logging.WARNING, logger="ramen_cve"
    ):
        result = e.enrich("ipv4", "1.2.3.4", cache)
    assert result is None
    assert any("virustotal enrichment failed" in r.message for r in caplog.records)
    # Nothing should have been cached
    assert cache.get_enrichment("virustotal", "ipv4", "1.2.3.4") is None


def test_abuseipdb_enricher_only_supports_ipv4():
    """AbuseIPDB only enriches IPv4 and only with a key."""
    from ramen_cve import AbuseIPDBEnricher

    e = AbuseIPDBEnricher(api_key="abuse-test")
    assert e.supports("ipv4") is True
    for t in ("md5", "domain", "url", "email"):
        assert e.supports(t) is False


def test_abuseipdb_enricher_returns_normalized_payload():
    """AbuseIPDB response is normalized to abuse_confidence + total_reports."""
    from unittest.mock import patch

    from ramen_cve import AbuseIPDBEnricher

    cache = _mem_cache()
    e = AbuseIPDBEnricher(api_key="abuse-test")
    payload = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "countryCode": "RU",
        }
    }
    with patch("ramen_cve.requests.get", return_value=_make_resp(json_payload=payload)):
        result = e.enrich("ipv4", "1.2.3.4", cache)
    assert result["abuse_confidence"] == 87
    assert result["total_reports"] == 42
    assert result["country_code"] == "RU"


def test_otx_enricher_supported_types_and_url_encoding():
    """OTX maps each IOC type to an indicator endpoint and URL-encodes the value."""
    from unittest.mock import patch

    from ramen_cve import OtxEnricher

    cache = _mem_cache()
    e = OtxEnricher(api_key="otx-test")
    assert e.supports("ipv4") and e.supports("md5") and e.supports("url")
    assert not e.supports("email")
    payload = {"pulse_info": {"count": 7}, "reputation": 0}

    with patch(
        "ramen_cve.requests.get", return_value=_make_resp(json_payload=payload),
    ) as mock_get:
        result = e.enrich("url", "https://evil/?x=1", cache)
    assert result["pulse_count"] == 7
    # The URL value should be percent-encoded inside the request URL
    called = mock_get.call_args.args[0]
    assert "https%3A%2F%2Fevil%2F%3Fx%3D1" in called


def test_malwarebazaar_enricher_no_key_required():
    """MalwareBazaar supports hashes without a key."""
    from ramen_cve import MalwareBazaarEnricher

    e = MalwareBazaarEnricher()
    for t in ("md5", "sha1", "sha256"):
        assert e.supports(t) is True
    assert e.supports("ipv4") is False


def test_malwarebazaar_enricher_known_sample():
    """A 'query_status: ok' response yields found=True with file_name + signature."""
    from unittest.mock import patch

    from ramen_cve import MalwareBazaarEnricher

    cache = _mem_cache()
    e = MalwareBazaarEnricher()
    payload = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "ab" * 32,
                "file_name": "evil.exe",
                "file_type": "exe",
                "signature": "Emotet",
                "tags": ["banker", "trojan"],
            }
        ],
    }
    resp = _make_resp(json_payload=payload)
    with patch("ramen_cve.requests.post", return_value=resp):
        result = e.enrich("sha256", "ab" * 32, cache)
    assert result["found"] is True
    assert result["signature"] == "Emotet"
    assert "trojan" in result["tags"]


def test_malwarebazaar_enricher_unknown_sample():
    """A 'hash_not_found' response yields {found: False}."""
    from unittest.mock import patch

    from ramen_cve import MalwareBazaarEnricher

    cache = _mem_cache()
    e = MalwareBazaarEnricher()
    payload = {"query_status": "hash_not_found"}
    with patch("ramen_cve.requests.post", return_value=_make_resp(json_payload=payload)):
        result = e.enrich("sha256", "00" * 32, cache)
    assert result == {"found": False}


def test_enrich_iocs_runs_each_enricher_only_for_supported_types():
    """An IPv4 IOC is enriched by VT + AbuseIPDB but not MalwareBazaar."""
    from ramen_cve import (
        AbuseIPDBEnricher,
        IocRecord,
        MalwareBazaarEnricher,
        VirusTotalEnricher,
        enrich_iocs,
    )

    cache = _mem_cache()
    rec = IocRecord("ipv4", "8.8.8.8", "x", date(2024, 1, 1), "feed_pub")

    class CountingVT(VirusTotalEnricher):
        calls: int = 0

        def _fetch(self, ioc_type, value):
            type(self).calls += 1
            return {"found": True, "malicious": 0, "suspicious": 0, "harmless": 1, "reputation": 0}

    class CountingAbuse(AbuseIPDBEnricher):
        calls: int = 0

        def _fetch(self, ioc_type, value):
            type(self).calls += 1
            return {"found": True, "abuse_confidence": 0, "total_reports": 0,
                    "country_code": "US"}

    class CountingMB(MalwareBazaarEnricher):
        calls: int = 0

        def _fetch(self, ioc_type, value):
            type(self).calls += 1
            return None

    enrichers = [CountingVT("vt"), CountingAbuse("abuse"), CountingMB()]
    enrich_iocs([rec], cache, enrichers=enrichers)

    assert CountingVT.calls == 1
    assert CountingAbuse.calls == 1
    assert CountingMB.calls == 0
    assert "virustotal" in rec.enrichments
    assert "abuseipdb" in rec.enrichments
    assert "malwarebazaar" not in rec.enrichments


def test_enrich_iocs_uses_cache_on_second_call():
    """A second enrich pass over the same IOC list does NOT re-hit the network."""
    from ramen_cve import IocRecord, VirusTotalEnricher, enrich_iocs

    cache = _mem_cache()
    rec = IocRecord("md5", "d41d8cd98f00b204e9800998ecf8427e", "x",
                    date(2024, 1, 1), "feed_pub")

    class CountingVT(VirusTotalEnricher):
        calls: int = 0

        def _fetch(self, ioc_type, value):
            type(self).calls += 1
            return {"found": True, "malicious": 1, "suspicious": 0, "harmless": 0, "reputation": -1}

    enricher = CountingVT("vt-test")
    enrich_iocs([rec], cache, enrichers=[enricher])
    rec.enrichments = {}  # simulate fresh-load on second run
    enrich_iocs([rec], cache, enrichers=[enricher])
    assert CountingVT.calls == 1


def test_cache_get_enrichment_round_trip():
    """Cache.set_enrichment / get_enrichment round-trip."""
    c = _mem_cache()
    c.set_enrichment("vt", "md5", "ab" * 16, {"malicious": 1})
    assert c.get_enrichment("vt", "md5", "ab" * 16) == {"malicious": 1}
    # Different (enricher, type, value) tuples are independent rows
    assert c.get_enrichment("vt", "ipv4", "1.2.3.4") is None
    assert c.get_enrichment("abuseipdb", "md5", "ab" * 16) is None


def test_summarize_enrichment_handles_known_sources():
    """_summarize_enrichment renders concise per-source summaries."""
    from ramen_cve import _summarize_enrichment

    assert _summarize_enrichment("virustotal", {"found": True, "malicious": 5,
                                                "suspicious": 2, "reputation": -3}).startswith(
        "malicious=5"
    )
    assert "abuse_confidence=87" in _summarize_enrichment(
        "abuseipdb", {"found": True, "abuse_confidence": 87, "total_reports": 12}
    )
    assert "pulse_count=7" in _summarize_enrichment(
        "otx", {"found": True, "pulse_count": 7}
    )
    assert "Emotet" in _summarize_enrichment(
        "malwarebazaar", {"found": True, "signature": "Emotet"}
    )
    # not-found payloads collapse to empty
    assert _summarize_enrichment("virustotal", {"found": False}) == ""


def test_iocs_csv_includes_enrichments_column(tmp_path):
    """The new enrichments CSV column is JSON-serialized."""
    from ramen_cve import IOC_CSV_COLUMNS, IocRecord, write_iocs_csv

    rec = IocRecord(
        "ipv4", "8.8.8.8", "x", date(2024, 1, 1), "feed_pub",
        enrichments={"virustotal": {"malicious": 3}},
    )
    out = tmp_path / "iocs.csv"
    write_iocs_csv([rec], out)
    rows = list(csv.reader(out.open()))
    enr_idx = IOC_CSV_COLUMNS.index("enrichments")
    body = json.loads(rows[1][enr_idx])
    assert body == {"virustotal": {"malicious": 3}}


def test_markdown_iocs_section_renders_enrichment_summaries(tmp_path):
    """Markdown lists each enrichment as a sub-bullet under the IOC."""
    from ramen_cve import IocRecord, write_markdown

    iocs = [
        IocRecord(
            "ipv4", "8.8.8.8", "x", date(2024, 1, 1), "feed_pub",
            enrichments={
                "virustotal": {"found": True, "malicious": 4, "suspicious": 1,
                               "harmless": 60, "reputation": -2},
                "abuseipdb": {"found": True, "abuse_confidence": 75, "total_reports": 9},
            },
        )
    ]
    out = tmp_path / "report.md"
    write_markdown([], out, METADATA, iocs=iocs)
    text = out.read_text()
    assert "  - virustotal: malicious=4" in text
    assert "  - abuseipdb: abuse_confidence=75" in text


def test_cli_no_enrich_iocs_flag_parses():
    """--no-enrich-iocs is accepted on every subcommand."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["opml", "x.opml", "--no-enrich-iocs"])
    assert args.no_enrich_iocs is True


# ---------------------------------------------------------------------------
# Slice 16 — TLP + Admiralty source confidence
# ---------------------------------------------------------------------------


def test_normalize_tlp_default_clear():
    """Empty / None / unknown TLP collapses to CLEAR; legacy WHITE → CLEAR."""
    from ramen_cve import _normalize_tlp

    for v in (None, "", "rubbish", "white"):
        assert _normalize_tlp(v) == "CLEAR"
    assert _normalize_tlp("amber") == "AMBER"
    assert _normalize_tlp("RED") == "RED"


def test_worst_tlp_returns_more_restrictive():
    """RED > AMBER+STRICT > AMBER > GREEN > CLEAR."""
    from ramen_cve import _worst_tlp

    assert _worst_tlp("CLEAR", "GREEN") == "GREEN"
    assert _worst_tlp("AMBER", "GREEN") == "AMBER"
    assert _worst_tlp("AMBER+STRICT", "AMBER") == "AMBER+STRICT"
    assert _worst_tlp("RED", "AMBER+STRICT") == "RED"
    assert _worst_tlp("CLEAR", None) == "CLEAR"


def test_admiralty_score_handles_invalid_grade():
    """Invalid grades sort to the worst possible bucket."""
    from ramen_cve import _admiralty_score

    assert _admiralty_score("A1") == (0, 1)
    assert _admiralty_score("F6") == (5, 6)
    assert _admiralty_score("z9") == (99, 99)
    assert _admiralty_score("") == (99, 99)
    assert _admiralty_score(None) == (99, 99)
    assert _admiralty_score("A") == (99, 99)  # too short


def test_best_admiralty_returns_higher_confidence_grade():
    """Lower-tuple (more reliable) grade wins; 'X' loses to 'B2'."""
    from ramen_cve import _best_admiralty

    assert _best_admiralty("A1", "B2") == "A1"
    assert _best_admiralty("B2", "A1") == "A1"
    assert _best_admiralty("", "B2") == "B2"
    assert _best_admiralty("B2", "") == "B2"


def test_parse_opml_reads_data_tlp_and_admiralty(tmp_path):
    """parse_opml stamps each FeedEntry with the data-* attributes from the outline."""
    from ramen_cve import parse_opml

    opml = tmp_path / "feeds.opml"
    opml.write_text(textwrap.dedent("""
        <?xml version="1.0"?>
        <opml version="2.0"><body>
        <outline text="Trusted" data-tlp="GREEN" data-admiralty="A2">
            <outline type="rss" text="Feed-A" xmlUrl="https://a.example/feed"/>
        </outline>
        <outline type="rss" text="Feed-B" xmlUrl="https://b.example/feed"
                 data-tlp="amber" data-admiralty="C3"/>
        </body></opml>
    """).strip())

    entries = parse_opml(opml)
    by_url = {e.url: e for e in entries}
    a = by_url["https://a.example/feed"]
    b = by_url["https://b.example/feed"]
    # Inheritance: Feed-A has no data-* of its own, takes parent's GREEN/A2
    assert a.tlp == "GREEN"
    assert a.admiralty == "A2"
    # Override: Feed-B sets its own AMBER/C3
    assert b.tlp == "AMBER"
    assert b.admiralty == "C3"


def test_parse_opml_default_tlp_clear(tmp_path):
    """Outlines without data-tlp default to CLEAR and admiralty defaults to ''."""
    from ramen_cve import parse_opml

    opml = tmp_path / "feeds.opml"
    opml.write_text(
        '<?xml version="1.0"?><opml version="2.0"><body>'
        '<outline type="rss" text="X" xmlUrl="https://x.example/feed"/>'
        "</body></opml>"
    )
    e = parse_opml(opml)[0]
    assert e.tlp == "CLEAR"
    assert e.admiralty == ""


def test_extract_cves_stamps_tlp_and_admiralty():
    """extract_cves(tlp=..., admiralty=...) carries the tags onto each CveRecord."""
    from ramen_cve import extract_cves

    out = extract_cves(
        "see CVE-2021-44228", "src", TODAY, "feed_pub",
        tlp="amber", admiralty="B2",
    )
    assert out[0].tlp == "AMBER"
    assert out[0].admiralty == "B2"


def test_extract_iocs_stamps_tlp_and_admiralty():
    """extract_iocs(tlp=..., admiralty=...) carries the tags onto each IocRecord."""
    from ramen_cve import extract_iocs

    out = extract_iocs(
        "Beacon to 8.8.8.8", "src", TODAY, "feed_pub",
        tlp="green", admiralty="A1",
    )
    ips = [i for i in out if i.ioc_type == "ipv4"]
    assert ips[0].tlp == "GREEN"
    assert ips[0].admiralty == "A1"


def test_enrich_cves_propagates_worst_tlp_across_duplicates():
    """Two CveRecords for the same CVE merge to the more-restrictive TLP."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = _load_fixture("epss_batch.json")
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = _load_fixture("nvd_log4shell_v31.json")
        return resp

    records = [
        CveRecord("CVE-2021-44228", "feed-a", date(2024, 1, 1), "feed_pub",
                  tlp="GREEN", admiralty="C3"),
        CveRecord("CVE-2021-44228", "feed-b", date(2024, 1, 5), "feed_pub",
                  tlp="AMBER", admiralty="A1"),
    ]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None)
    assert len(result) == 1
    # Worst TLP wins
    assert result[0].tlp == "AMBER"
    # Best Admiralty wins
    assert result[0].admiralty == "A1"


def test_dedupe_iocs_propagates_worst_tlp_and_best_admiralty():
    """The same IOC across two feeds keeps worst-TLP and best-Admiralty."""
    from ramen_cve import IocRecord, _dedupe_iocs

    iocs = [
        IocRecord("ipv4", "8.8.8.8", "f-a", date(2024, 1, 1), "feed_pub",
                  tlp="CLEAR", admiralty="C3"),
        IocRecord("ipv4", "8.8.8.8", "f-b", date(2024, 1, 2), "feed_pub",
                  tlp="AMBER", admiralty="A1"),
    ]
    out = _dedupe_iocs(iocs)
    assert len(out) == 1
    assert out[0].tlp == "AMBER"
    assert out[0].admiralty == "A1"


def test_write_csv_includes_tlp_and_admiralty_columns(tmp_path):
    """CSV header and rows carry tlp + admiralty."""
    from ramen_cve import EnrichedCve, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="patch_now",
        tlp="AMBER", admiralty="B2",
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    assert "tlp" in header and "admiralty" in header
    row = dict(zip(header, rows[1], strict=True))
    assert row["tlp"] == "AMBER"
    assert row["admiralty"] == "B2"


def test_write_iocs_csv_includes_tlp_and_admiralty(tmp_path):
    """IOC CSV carries tlp + admiralty per record."""
    from ramen_cve import IOC_CSV_COLUMNS, IocRecord, write_iocs_csv

    rec = IocRecord(
        "ipv4", "8.8.8.8", "src", date(2024, 1, 1), "feed_pub",
        tlp="GREEN", admiralty="B2",
    )
    out = tmp_path / "iocs.csv"
    write_iocs_csv([rec], out)
    rows = list(csv.reader(out.open()))
    assert "tlp" in rows[0] and "admiralty" in rows[0]
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["tlp"] == "GREEN"
    assert row["admiralty"] == "B2"
    assert "tlp" in IOC_CSV_COLUMNS
    assert "admiralty" in IOC_CSV_COLUMNS


def test_write_markdown_renders_provenance_when_set(tmp_path):
    """Provenance line appears when tlp != CLEAR or admiralty is set."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="patch_now",
        tlp="AMBER", admiralty="B2",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "**Provenance:** TLP:AMBER · Admiralty B2" in text


def test_write_markdown_omits_provenance_for_clear_unrated(tmp_path):
    """No Provenance line when tlp=CLEAR and admiralty=''."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="patch_now",
        tlp="CLEAR", admiralty="",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "**Provenance:**" not in text


def test_output_strips_tlp_red_by_default(tmp_path, caplog):
    """TLP:RED records are excluded from output unless --allow-tlp-red was passed."""
    import argparse
    import logging

    from ramen_cve import EnrichedCve, IocRecord, _output

    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, allow_tlp_red=False,
    )
    red_cve = EnrichedCve(
        cve_id="CVE-2099-RED", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
        tlp="RED",
    )
    green_cve = EnrichedCve(
        cve_id="CVE-2099-GREEN", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
        tlp="GREEN",
    )
    red_ioc = IocRecord("ipv4", "1.2.3.4", "x", date(2024, 1, 1), "feed_pub", tlp="RED")
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        _output([red_cve, green_cve], args, {"version": "0.1"}, iocs=[red_ioc])

    csv_files = list(tmp_path.glob("ramen-cve-*.csv"))
    assert len(csv_files) == 1
    body = csv_files[0].read_text()
    assert "CVE-2099-GREEN" in body
    assert "CVE-2099-RED" not in body
    assert any("TLP:RED" in r.message for r in caplog.records)


def test_output_includes_tlp_red_when_flag_passed(tmp_path):
    """--allow-tlp-red preserves TLP:RED records in the output."""
    import argparse

    from ramen_cve import EnrichedCve, _output

    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, allow_tlp_red=True,
    )
    rec = EnrichedCve(
        cve_id="CVE-2099-RED", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
        tlp="RED",
    )
    _output([rec], args, {"version": "0.1"})
    csv_files = list(tmp_path.glob("ramen-cve-*.csv"))
    assert len(csv_files) == 1
    body = csv_files[0].read_text()
    assert "CVE-2099-RED" in body


def test_cli_allow_tlp_red_flag_parses():
    """--allow-tlp-red is accepted at the parser level."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["opml", "x.opml", "--allow-tlp-red"])
    assert args.allow_tlp_red is True
    args2 = build_parser().parse_args(["opml", "x.opml"])
    assert args2.allow_tlp_red is False


# ---------------------------------------------------------------------------
# Slice 17 — Threat hunting hypothesis workflow
# ---------------------------------------------------------------------------


def _hunt_payload(**overrides) -> dict:
    base = {
        "id": "test-hunt",
        "name": "Test hunt",
        "hypothesis": "We expect to see X.",
        "data_sources": ["proxy_logs"],
        "attack_techniques": ["T1190"],
        "linked_cves": ["CVE-2021-44228"],
        "status": "open",
        "created": "2024-01-01T00:00:00",
        "findings": [],
    }
    base.update(overrides)
    return base


def test_hunt_dataclass_round_trip():
    """Hunt.from_dict → Hunt.to_dict round-trips cleanly."""
    from ramen_cve import Hunt

    payload = _hunt_payload()
    hunt = Hunt.from_dict(payload)
    assert hunt.to_dict() == payload


def test_hunt_dataclass_from_dict_tolerates_missing_keys():
    """Missing optional keys default to sensible empty values."""
    from ramen_cve import Hunt

    hunt = Hunt.from_dict({"id": "x", "name": "n", "hypothesis": "h"})
    assert hunt.linked_cves == []
    assert hunt.findings == []
    assert hunt.status == "open"


def test_load_hunt_round_trip(tmp_path):
    """load_hunt + save_hunt round-trip preserves the payload."""
    from ramen_cve import Hunt, load_hunt, save_hunt

    p = tmp_path / "x.json"
    save_hunt(Hunt.from_dict(_hunt_payload()), p)
    re = load_hunt(p)
    assert re.id == "test-hunt"
    assert re.linked_cves == ["CVE-2021-44228"]


def test_load_hunt_missing_file_raises_friendly_error(tmp_path):
    """A missing hunt path raises OpmlError, not FileNotFoundError."""
    from ramen_cve import OpmlError, load_hunt

    with pytest.raises(OpmlError, match="not found"):
        load_hunt(tmp_path / "missing.json")


def test_load_hunt_invalid_json_raises_friendly_error(tmp_path):
    """A malformed JSON file raises OpmlError, not JSONDecodeError."""
    from ramen_cve import OpmlError, load_hunt

    p = tmp_path / "bad.json"
    p.write_text("{not: valid")
    with pytest.raises(OpmlError, match="parse"):
        load_hunt(p)


def test_load_all_hunts_returns_sorted_list(tmp_path):
    """load_all_hunts returns every well-formed *.json sorted by id."""
    from ramen_cve import Hunt, load_all_hunts, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="b-second")), tmp_path / "b.json")
    save_hunt(Hunt.from_dict(_hunt_payload(id="a-first")), tmp_path / "a.json")
    out = load_all_hunts(tmp_path)
    assert [h.id for h in out] == ["a-first", "b-second"]


def test_load_all_hunts_missing_dir_returns_empty(tmp_path):
    """A missing directory is non-fatal; load_all_hunts returns []."""
    from ramen_cve import load_all_hunts

    assert load_all_hunts(tmp_path / "no-such-dir") == []


def test_load_all_hunts_skips_malformed(tmp_path, caplog):
    """A malformed file is skipped (with WARNING) so other hunts still load."""
    import logging

    from ramen_cve import Hunt, load_all_hunts, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="ok")), tmp_path / "ok.json")
    (tmp_path / "broken.json").write_text("{not valid")
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        out = load_all_hunts(tmp_path)
    assert [h.id for h in out] == ["ok"]
    assert any("malformed hunt" in r.message.lower() for r in caplog.records)


def test_default_hunt_dir_loads_bundled_sample():
    """The bundled hunts/log4shell-evidence.json is well-formed and loads."""
    from ramen_cve import DEFAULT_HUNT_DIR, load_all_hunts

    assert DEFAULT_HUNT_DIR.exists()
    hunts = load_all_hunts(DEFAULT_HUNT_DIR)
    assert any(h.id == "log4shell-evidence" for h in hunts)


def test_cli_hunt_subcommand_parses():
    """`hunt` subcommand parses with action / hunt_id / value positions."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["hunt", "list"])
    assert args.subcommand == "hunt" and args.action == "list"
    args2 = build_parser().parse_args(
        ["hunt", "link", "log4shell-evidence", "CVE-2021-44228"]
    )
    assert args2.action == "link"
    assert args2.hunt_id == "log4shell-evidence"
    assert args2.value == "CVE-2021-44228"


def test_run_hunt_list(tmp_path, capsys):
    """`hunt list` prints one tab-delimited line per hunt."""
    import ramen_cve
    from ramen_cve import Hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1", name="First")), tmp_path / "h1.json")
    save_hunt(Hunt.from_dict(_hunt_payload(id="h2", name="Second")), tmp_path / "h2.json")
    rc = ramen_cve.main(["hunt", "list", "--hunt-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "h1" in out and "First" in out
    assert "h2" in out and "Second" in out


def test_run_hunt_show(tmp_path, capsys):
    """`hunt show <id>` prints the hunt as JSON."""
    import ramen_cve
    from ramen_cve import Hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1")), tmp_path / "h1.json")
    rc = ramen_cve.main(["hunt", "show", "h1", "--hunt-dir", str(tmp_path)])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body["id"] == "h1"


def test_run_hunt_link_appends_cve(tmp_path):
    """`hunt link <id> <cve>` appends to linked_cves and persists."""
    import ramen_cve
    from ramen_cve import Hunt, load_hunt, save_hunt

    save_hunt(
        Hunt.from_dict(_hunt_payload(id="h1", linked_cves=["CVE-2021-44228"])),
        tmp_path / "h1.json",
    )
    rc = ramen_cve.main([
        "hunt", "link", "h1", "CVE-2021-26855",
        "--hunt-dir", str(tmp_path),
    ])
    assert rc == 0
    hunt = load_hunt(tmp_path / "h1.json")
    assert "CVE-2021-26855" in hunt.linked_cves
    assert hunt.linked_cves.count("CVE-2021-26855") == 1


def test_run_hunt_link_dedupes(tmp_path):
    """Linking a CVE that's already present is a no-op success."""
    import ramen_cve
    from ramen_cve import Hunt, load_hunt, save_hunt

    save_hunt(
        Hunt.from_dict(_hunt_payload(id="h1", linked_cves=["CVE-2021-44228"])),
        tmp_path / "h1.json",
    )
    rc = ramen_cve.main([
        "hunt", "link", "h1", "CVE-2021-44228",
        "--hunt-dir", str(tmp_path),
    ])
    assert rc == 0
    hunt = load_hunt(tmp_path / "h1.json")
    assert hunt.linked_cves.count("CVE-2021-44228") == 1


def test_run_hunt_link_rejects_invalid_cve(tmp_path, caplog):
    """Linking a non-CVE-shaped value exits with code 1."""
    import logging

    import ramen_cve
    from ramen_cve import Hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1")), tmp_path / "h1.json")
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "hunt", "link", "h1", "NOT-A-CVE",
            "--hunt-dir", str(tmp_path),
        ])
    assert rc == 1
    assert any("not a valid CVE" in r.message for r in caplog.records)


def test_run_hunt_log_appends_finding_with_timestamp(tmp_path):
    """`hunt log <id> <text>` appends {timestamp, text} to findings."""
    import ramen_cve
    from ramen_cve import Hunt, load_hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1", findings=[])), tmp_path / "h1.json")
    rc = ramen_cve.main([
        "hunt", "log", "h1", "Saw nothing in proxy logs for the window.",
        "--hunt-dir", str(tmp_path),
    ])
    assert rc == 0
    hunt = load_hunt(tmp_path / "h1.json")
    assert len(hunt.findings) == 1
    assert hunt.findings[0]["text"].startswith("Saw nothing")
    # Timestamp should be ISO-8601-ish
    assert "T" in hunt.findings[0]["timestamp"]


def test_run_hunt_status_updates_value(tmp_path):
    """`hunt status <id> <new>` updates the status field."""
    import ramen_cve
    from ramen_cve import Hunt, load_hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1", status="open")), tmp_path / "h1.json")
    rc = ramen_cve.main([
        "hunt", "status", "h1", "closed_true_positive",
        "--hunt-dir", str(tmp_path),
    ])
    assert rc == 0
    hunt = load_hunt(tmp_path / "h1.json")
    assert hunt.status == "closed_true_positive"


def test_run_hunt_status_rejects_invalid_value(tmp_path, caplog):
    """An unknown status value errors out without modifying the file."""
    import logging

    import ramen_cve
    from ramen_cve import Hunt, load_hunt, save_hunt

    save_hunt(Hunt.from_dict(_hunt_payload(id="h1", status="open")), tmp_path / "h1.json")
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "hunt", "status", "h1", "invented",
            "--hunt-dir", str(tmp_path),
        ])
    assert rc == 1
    hunt = load_hunt(tmp_path / "h1.json")
    assert hunt.status == "open"
    assert any("not a valid status" in r.message for r in caplog.records)


def test_run_hunt_rejects_path_traversal(tmp_path, caplog):
    """A hunt_id with '/' or '..' is rejected before any file access."""
    import logging

    import ramen_cve

    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "hunt", "show", "../etc/passwd",
            "--hunt-dir", str(tmp_path),
        ])
    assert rc == 1
    assert any("invalid hunt id" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Slice 18 — Asset / Vulnerability exposure correlation
# ---------------------------------------------------------------------------


def test_parse_nvd_response_captures_cpes():
    """A configurations[].nodes[].cpeMatch[].criteria entry surfaces in cpes[]."""
    from ramen_cve import _parse_nvd_response

    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria":
                                                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        },
                                        {
                                            "criteria":
                                                "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        },
                                    ],
                                    "children": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "criteria":
                                                        "cpe:2.3:a:apache:log4j:2.16.0:"
                                                        "*:*:*:*:*:*:*",
                                                    "vulnerable": True,
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    out = _parse_nvd_response(payload)
    assert "cpes" in out
    assert any("apache:log4j:2.14.1" in c for c in out["cpes"])
    # Nested children CPEs are also captured
    assert any("apache:log4j:2.16.0" in c for c in out["cpes"])


def test_parse_nvd_response_no_configurations_yields_empty_cpes():
    """Old CVE fixtures with no configurations block return cpes=[]."""
    from ramen_cve import _parse_nvd_response

    data = _load_fixture("nvd_no_cvss.json")
    out = _parse_nvd_response(data)
    assert out["cpes"] == []


def test_cpe_matches_inventory_basic():
    """An exact product+version match (or '*' version) returns True."""
    from ramen_cve import _cpe_matches_inventory

    # CPE: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
    cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    assert _cpe_matches_inventory(cpe, "log4j", "2.14.1") is True
    assert _cpe_matches_inventory(cpe, "apache", "2.14.1") is True
    assert _cpe_matches_inventory(cpe, "log4j", "9.9.9") is False

    # Wildcard version on the CPE should match any inventory version
    cpe_wild = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert _cpe_matches_inventory(cpe_wild, "log4j", "2.14.1") is True
    assert _cpe_matches_inventory(cpe_wild, "log4j", "1.0.0") is True


def test_cpe_matches_inventory_rejects_wrong_product():
    """A non-matching product returns False."""
    from ramen_cve import _cpe_matches_inventory

    cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    assert _cpe_matches_inventory(cpe, "nginx", "1.0") is False


def test_cpe_matches_inventory_invalid_cpe_returns_false():
    """A malformed CPE returns False instead of raising."""
    from ramen_cve import _cpe_matches_inventory

    assert _cpe_matches_inventory("not-a-cpe", "log4j", "2.14.1") is False
    assert _cpe_matches_inventory("", "log4j", "2.14.1") is False


def test_load_inventory_round_trip(tmp_path):
    """A 3-row inventory CSV is parsed into 3 dicts with host/product/version/cpe."""
    from ramen_cve import load_inventory

    csv_text = (
        "host,product,version,cpe\n"
        "web-1,log4j,2.14.1,\n"
        "web-2,log4j,2.17.0,\n"
        "db-1,postgresql,14.5,cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*\n"
    )
    p = tmp_path / "inv.csv"
    p.write_text(csv_text)
    rows = load_inventory(p)
    assert len(rows) == 3
    assert rows[0]["host"] == "web-1"
    assert rows[2]["cpe"].startswith("cpe:2.3:a:postgresql")


def test_load_inventory_missing_file_raises_friendly():
    """A missing inventory file raises OpmlError."""
    from pathlib import Path

    from ramen_cve import OpmlError, load_inventory

    with pytest.raises(OpmlError, match="not found"):
        load_inventory(Path("/tmp/does-not-exist-ramen-inv.csv"))


def test_correlate_inventory_annotates_affected_hosts():
    """correlate_inventory populates affected_hosts on each EnrichedCve."""
    from ramen_cve import EnrichedCve, correlate_inventory

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        cpes=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
    )
    inventory = [
        {"host": "web-1", "product": "log4j", "version": "2.14.1", "cpe": ""},
        {"host": "web-2", "product": "log4j", "version": "2.17.0", "cpe": ""},  # version mismatch
        {"host": "db-1", "product": "postgres", "version": "14", "cpe": ""},   # product mismatch
    ]
    correlate_inventory([rec], inventory)
    assert rec.affected_hosts == ["web-1"]


def test_correlate_inventory_explicit_cpe_column_matches():
    """A row with an explicit cpe column matches via substring comparison."""
    from ramen_cve import EnrichedCve, correlate_inventory

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        cpes=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
    )
    inventory = [
        {"host": "h1", "product": "", "version": "",
         "cpe": "cpe:2.3:a:vendor:product:1.0"},
    ]
    correlate_inventory([rec], inventory)
    assert rec.affected_hosts == ["h1"]


def test_correlate_inventory_dedupes_same_host_across_cpes():
    """A host that matches multiple CPEs of the same CVE is added only once."""
    from ramen_cve import EnrichedCve, correlate_inventory

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        cpes=[
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        ],
    )
    inventory = [{"host": "web-1", "product": "log4j", "version": "2.14.1", "cpe": ""}]
    correlate_inventory([rec], inventory)
    assert rec.affected_hosts == ["web-1"]


def test_write_csv_includes_affected_hosts_column(tmp_path):
    """CSV adds an affected_hosts column joined with ';'."""
    from ramen_cve import EnrichedCve, write_csv

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        affected_hosts=["web-1", "web-2"],
    )
    out = tmp_path / "out.csv"
    write_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    assert "affected_hosts" in header
    row = dict(zip(header, rows[1], strict=True))
    assert row["affected_hosts"] == "web-1;web-2"


def test_write_markdown_renders_affected_hosts_and_cross_tab(tmp_path):
    """Per-CVE 'Affected in your environment' line + roll-up cross-tab table."""
    from ramen_cve import EnrichedCve, write_markdown

    recs = [
        EnrichedCve(
            cve_id="CVE-2021-44228",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=10.0,
            epss_score=0.97,
            bucket="patch_now",
            affected_hosts=["web-1", "web-2", "web-3"],
        ),
        EnrichedCve(
            cve_id="CVE-2021-26855",
            source="x",
            first_seen=date(2024, 1, 1),
            first_seen_type="feed_pub",
            cvss_score=9.8,
            epss_score=0.97,
            bucket="patch_now",
            affected_hosts=["web-1"],
        ),
    ]
    out = tmp_path / "report.md"
    write_markdown(recs, out, METADATA)
    text = out.read_text()
    assert "**Affected in your environment:** 3 host(s) — web-1, web-2, web-3" in text
    assert "## Affected in Your Environment" in text
    assert "| web-1 | 2 |" in text
    assert "| web-2 | 1 |" in text


def test_write_markdown_truncates_long_affected_lists(tmp_path):
    """A CVE with >8 affected hosts shows the first 8 and an '(and N more)' tail."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        affected_hosts=[f"host-{i:03d}" for i in range(15)],
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "(and 7 more)" in text


def test_cli_inventory_flag_parses(tmp_path):
    """--inventory accepts a path that survives parsing."""
    from ramen_cve import build_parser

    args = build_parser().parse_args([
        "opml", "x.opml",
        "--inventory", str(tmp_path / "inv.csv"),
    ])
    assert str(args.inventory).endswith("inv.csv")


def test_maybe_correlate_inventory_runs_only_when_flag_set(tmp_path, caplog):
    """If --inventory points at a real file, correlation runs and logs a summary."""
    import argparse
    import logging

    from ramen_cve import EnrichedCve, _maybe_correlate_inventory

    inv_path = tmp_path / "inv.csv"
    inv_path.write_text("host,product,version\nweb-1,log4j,2.14.1\n")

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
        cpes=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
    )
    args = argparse.Namespace(inventory=inv_path)
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        _maybe_correlate_inventory(args, [rec])
    assert rec.affected_hosts == ["web-1"]
    assert any("Inventory correlation" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Slice 19 — Dissemination dispatchers (Slack + generic webhook)
# ---------------------------------------------------------------------------


def _disp_rec(**overrides) -> "EnrichedCve":  # type: ignore[name-defined]
    """Convenience: build an EnrichedCve in the kev_override bucket for dispatch tests."""
    from ramen_cve import EnrichedCve, ThreatActor

    base = dict(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        kev_known_ransomware_use=True,
        attack_techniques=["T1059", "T1190"],
        bucket="kev_override",
        suggested_action="Patch immediately.",
        exploit_status="exploit_db",
        linked_actors=[ThreatActor("APT41")],
        affected_hosts=["web-1", "web-2"],
    )
    base.update(overrides)
    return EnrichedCve(**base)


def test_slack_dispatcher_disabled_without_webhook():
    """No SLACK_WEBHOOK_URL → enabled() is False, dispatch() is never called."""
    from ramen_cve import SlackWebhookDispatcher

    d = SlackWebhookDispatcher(webhook_url=None)
    assert d.enabled() is False


def test_slack_dispatcher_payload_contains_cve_and_metadata():
    """The Slack payload includes the CVE id, bucket, CVSS, KEV due date, ATT&CK list."""
    from ramen_cve import SlackWebhookDispatcher

    d = SlackWebhookDispatcher(webhook_url="https://hooks.slack.example/x")
    payload = d._build_payload(_disp_rec())
    assert payload["blocks"][0]["text"]["text"].startswith(":rotating_light: CVE-2021-44228")
    body_text = payload["blocks"][1]["text"]["text"]
    assert "Patch immediately." in body_text
    assert "CVSS:* 10.0 (CRITICAL)" in body_text
    assert "EPSS:* 0.9700" in body_text
    assert "CISA KEV:* listed (due 2021-12-24)" in body_text
    assert "known ransomware use" in body_text
    assert "ATT&CK:* T1059, T1190" in body_text
    assert "Exploit Status:*" in body_text and "exploit_db" in body_text
    assert "Linked Actors:* APT41" in body_text
    assert "Affected hosts:* 2" in body_text
    # Footer link to NVD
    ctx = payload["blocks"][2]["elements"][0]["text"]
    assert "CVE-2021-44228" in ctx and "nvd.nist.gov" in ctx


def test_slack_dispatcher_post_success():
    """A 200 response from Slack returns True."""
    from unittest.mock import patch

    from ramen_cve import SlackWebhookDispatcher

    d = SlackWebhookDispatcher(webhook_url="https://hooks.slack.example/x")
    with patch("ramen_cve.requests.post", return_value=_make_resp()):
        assert d.dispatch(_disp_rec()) is True


def test_slack_dispatcher_failure_returns_false(caplog):
    """A network error from Slack logs WARNING and returns False (no raise)."""
    import logging
    from unittest.mock import MagicMock, patch

    from ramen_cve import SlackWebhookDispatcher

    d = SlackWebhookDispatcher(webhook_url="https://hooks.slack.example/x")
    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("nope")
    with patch("ramen_cve.requests.post", return_value=bad), caplog.at_level(
        logging.WARNING, logger="ramen_cve"
    ):
        assert d.dispatch(_disp_rec()) is False
    assert any("Slack dispatch failed" in r.message for r in caplog.records)


def test_generic_webhook_dispatcher_payload_shape():
    """The generic webhook payload contains the expected EnrichedCve fields."""
    from ramen_cve import GenericWebhookDispatcher

    d = GenericWebhookDispatcher(webhook_url="https://x.example/hook")
    payload = d._build_payload(_disp_rec())
    assert payload["cve_id"] == "CVE-2021-44228"
    assert payload["bucket"] == "kev_override"
    assert payload["cvss_score"] == 10.0
    assert payload["epss_score"] == 0.97
    assert payload["kev_listed"] is True
    assert payload["kev_due_date"] == "2021-12-24"
    assert payload["attack_techniques"] == ["T1059", "T1190"]
    assert payload["linked_actors"] == ["APT41"]
    assert payload["affected_hosts"] == ["web-1", "web-2"]


def test_generic_webhook_dispatcher_disabled_without_url():
    from ramen_cve import GenericWebhookDispatcher

    assert GenericWebhookDispatcher(webhook_url=None).enabled() is False
    assert GenericWebhookDispatcher(webhook_url="").enabled() is False
    assert GenericWebhookDispatcher(webhook_url="https://x.example").enabled() is True


def test_dispatch_records_skips_low_priority_buckets():
    """A 'watch_closely' record is NOT dispatched even if a dispatcher is enabled."""
    from ramen_cve import dispatch_records

    class CountingDisp:
        name = "counting"
        calls: int = 0

        def enabled(self) -> bool:
            return True

        def dispatch(self, rec) -> bool:
            type(self).calls += 1
            return True

    low = _disp_rec(bucket="watch_closely")
    high = _disp_rec(bucket="patch_now")
    sent = dispatch_records([low, high], dispatchers=[CountingDisp()])
    assert sent == 1  # only 'high' triggered dispatch
    assert CountingDisp.calls == 1


def test_dispatch_records_no_enabled_dispatchers_logs_info(caplog):
    """If every dispatcher reports enabled=False, log INFO and return 0."""
    import logging

    from ramen_cve import dispatch_records

    class Disabled:
        name = "off"

        def enabled(self) -> bool:
            return False

        def dispatch(self, rec) -> bool:
            raise AssertionError("should not be called")

    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        n = dispatch_records([_disp_rec()], dispatchers=[Disabled()])
    assert n == 0
    assert any("no dispatchers configured" in r.message for r in caplog.records)


def test_dispatch_records_counts_only_successes():
    """Failed dispatch (returns False) is NOT counted toward the success total."""
    from ramen_cve import dispatch_records

    class Mixed:
        name = "mixed"

        def enabled(self) -> bool:
            return True

        def dispatch(self, rec) -> bool:
            return rec.cve_id != "CVE-2099-FAIL"

    rec_ok = _disp_rec(cve_id="CVE-2099-OK")
    rec_fail = _disp_rec(cve_id="CVE-2099-FAIL")
    n = dispatch_records([rec_ok, rec_fail], dispatchers=[Mixed()])
    assert n == 1


def test_cli_dispatch_flag_parses():
    """--dispatch is accepted on every analysis subcommand."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["opml", "x.opml", "--dispatch"])
    assert args.dispatch is True
    args2 = build_parser().parse_args(["opml", "x.opml"])
    assert args2.dispatch is False


# ---------------------------------------------------------------------------
# Slice 20 — Diamond Model + Cyber Kill Chain mapping
# ---------------------------------------------------------------------------


def test_map_cwes_to_kill_chain_default_exploitation():
    """An empty or unmapped CWE list defaults to 'exploitation'."""
    from ramen_cve import map_cwes_to_kill_chain

    assert map_cwes_to_kill_chain([]) == "exploitation"
    assert map_cwes_to_kill_chain(["CWE-99999"]) == "exploitation"


def test_map_cwes_to_kill_chain_overrides():
    """CWEs in CWE_TO_KILL_CHAIN return their override phase."""
    from ramen_cve import map_cwes_to_kill_chain

    assert map_cwes_to_kill_chain(["CWE-200"]) == "reconnaissance"
    assert map_cwes_to_kill_chain(["CWE-269"]) == "installation"
    assert map_cwes_to_kill_chain(["CWE-601"]) == "delivery"
    assert map_cwes_to_kill_chain(["CWE-552"]) == "actions_on_objectives"


def test_map_cwes_to_kill_chain_first_match_wins():
    """First CWE override wins so output is deterministic."""
    from ramen_cve import map_cwes_to_kill_chain

    assert map_cwes_to_kill_chain(["CWE-200", "CWE-269"]) == "reconnaissance"


def test_map_cwes_to_kill_chain_case_insensitive():
    """Lower-case CWE input is normalized."""
    from ramen_cve import map_cwes_to_kill_chain

    assert map_cwes_to_kill_chain(["cwe-269"]) == "installation"


def test_enrich_cves_populates_diamond_and_kill_chain():
    """End-to-end: a Log4Shell CVE gets Kill Chain + Diamond populated from CWE/actors."""
    from unittest.mock import MagicMock, patch

    from ramen_cve import CveRecord, ThreatActor, enrich_cves

    cache = _mem_cache()
    log4shell = _load_fixture("nvd_log4shell_v31.json")
    epss = _load_fixture("epss_batch.json")

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = log4shell
        return resp

    associations = {
        "CVE-2021-44228": {
            "actors": [ThreatActor(name="APT41")],
            "campaigns": [],
            "malware": [],
        }
    }
    records = [CveRecord("CVE-2021-44228", "f", date(2024, 1, 1), "feed_pub")]
    with patch("ramen_cve.requests.get", side_effect=_fake_get), patch("ramen_cve.time.sleep"):
        result = enrich_cves(records, cache, api_key=None, associations=associations)

    rec = result[0]
    # CWE-502 isn't an override, so default 'exploitation' wins.
    assert rec.kill_chain_phase == "exploitation"
    # Diamond adversary takes the first linked actor.
    assert rec.diamond_adversary == "APT41"
    # Capability is enriched with the primary CWE+technique.
    assert rec.diamond_capability.startswith("exploit (")
    assert "CWE-502" in rec.diamond_capability
    # Infrastructure / victim default to empty (filled by other features).
    assert rec.diamond_infrastructure == ""
    assert rec.diamond_victim == ""


def test_write_csv_includes_kill_chain_and_diamond_columns(tmp_path):
    """CSV header contains kill_chain_phase and the four diamond_* fields."""
    from ramen_cve import CSV_COLUMNS

    for col in (
        "kill_chain_phase", "diamond_capability", "diamond_adversary",
        "diamond_infrastructure", "diamond_victim",
    ):
        assert col in CSV_COLUMNS, f"missing CSV column {col}"


def test_write_markdown_diamond_line_for_high_priority(tmp_path):
    """The Diamond Model line is rendered for kev_override / patch_now."""
    from ramen_cve import EnrichedCve, write_markdown

    rec_kev = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
        diamond_adversary="APT41",
        diamond_capability="exploit (CWE-502, T1190)",
        diamond_infrastructure="",
        diamond_victim="3 inventory host(s)",
        kill_chain_phase="exploitation",
        affected_hosts=["a", "b", "c"],
    )
    out = tmp_path / "report.md"
    write_markdown([rec_kev], out, METADATA)
    text = out.read_text()
    assert "**Diamond Model:**" in text
    assert "Adversary=APT41" in text
    assert "Capability=exploit (CWE-502, T1190)" in text
    assert "Kill Chain=exploitation" in text


def test_write_markdown_diamond_line_skipped_for_low_priority(tmp_path):
    """No Diamond line for buckets below patch_now."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2024-9999", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=4.0, epss_score=0.05, bucket="deprioritize",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "Diamond Model" not in text


# ---------------------------------------------------------------------------
# Slice 21 — Historical trending & scheduled runs
# ---------------------------------------------------------------------------


def patch_cache_path(db_path):
    """Context manager that points ramen_cve.DEFAULT_CACHE_PATH at a test DB."""
    from unittest.mock import patch

    return patch("ramen_cve.DEFAULT_CACHE_PATH", str(db_path))


def test_cache_record_run_round_trip():
    """Cache.record_run + get_runs round-trip a sequence in chronological order."""
    import time as _time

    from ramen_cve import Cache

    c = Cache(":memory:")
    c.record_run("CVE-2021-44228", "patch_now", 10.0, 0.50)
    _time.sleep(0.01)  # ensure distinct ts_iso (record_run uses 1s resolution)
    c.record_run("CVE-2021-44228", "kev_override", 10.0, 0.97)
    runs = c.get_runs("CVE-2021-44228")
    # The second call may or may not produce a new ts_iso row depending on
    # second-level resolution; either way the latest bucket should be reflected.
    assert len(runs) >= 1
    assert runs[-1]["bucket"] == "kev_override"
    assert runs[-1]["epss_score"] == 0.97


def test_cache_get_runs_unknown_returns_empty():
    """Asking for runs on a CVE we've never seen returns []."""
    from ramen_cve import Cache

    c = Cache(":memory:")
    assert c.get_runs("CVE-2099-9999") == []


def test_sparkline_basic_mapping():
    """_sparkline maps low/high to the bottom/top characters of the ramp."""
    from ramen_cve import _sparkline

    out = _sparkline([0.0, 1.0])
    assert out[0] == "▁"  # low
    assert out[-1] == "█"  # high


def test_sparkline_handles_none_and_constant():
    """None values render as a space; constant values render as the lowest char."""
    from ramen_cve import _sparkline

    assert _sparkline([1.0, None, 2.0])[1] == " "
    # All-equal is a degenerate range; output should still produce 1 char per
    # input without crashing.
    out = _sparkline([0.5, 0.5, 0.5])
    assert len(out) == 3


def test_sparkline_empty_input():
    """An empty list returns an empty string."""
    from ramen_cve import _sparkline

    assert _sparkline([]) == ""
    assert _sparkline([None, None]) == ""


def test_record_runs_writes_one_row_per_enriched(tmp_path):
    """_record_runs walks the enriched list and inserts one row per CVE."""
    from ramen_cve import Cache, EnrichedCve, _record_runs

    c = Cache(":memory:")
    recs = [
        EnrichedCve(
            cve_id="CVE-2021-44228", source="x",
            first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
            cvss_score=10.0, epss_score=0.97, bucket="kev_override",
        ),
        EnrichedCve(
            cve_id="CVE-2021-26855", source="x",
            first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
            cvss_score=9.8, epss_score=0.97, bucket="patch_now",
        ),
    ]
    _record_runs(c, recs)
    assert len(c.get_runs("CVE-2021-44228")) == 1
    assert len(c.get_runs("CVE-2021-26855")) == 1


def test_run_trend_no_history_logs_info(tmp_path, caplog):
    """`trend` with no history logs an INFO and exits 0."""
    import logging

    import ramen_cve

    db = tmp_path / "cache.db"
    with (
        caplog.at_level(logging.INFO, logger="ramen_cve"),
        patch_cache_path(db),
    ):
        rc = ramen_cve.main(["trend", "CVE-2099-1234"])
    assert rc == 0
    assert any("No historical runs" in r.message for r in caplog.records)


def test_run_trend_prints_sparkline_and_table(tmp_path, capsys):
    """`trend` prints headers, sparklines, and a Markdown table after seeding history."""
    import ramen_cve
    from ramen_cve import Cache

    db = tmp_path / "cache.db"
    c = Cache(str(db))
    c.record_run("CVE-2021-44228", "watch_closely", 10.0, 0.05)
    c._conn.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
        ("CVE-2021-44228", "2024-06-01T12:00:00", "patch_now", 10.0, 0.50),
    )
    c._conn.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
        ("CVE-2021-44228", "2024-06-15T12:00:00", "kev_override", 10.0, 0.97),
    )
    c._conn.commit()

    with patch_cache_path(db):
        rc = ramen_cve.main(["trend", "CVE-2021-44228"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "CVE-2021-44228" in out
    assert "EPSS:" in out and "CVSS:" in out
    assert "| Run timestamp (UTC) | Bucket | CVSS | EPSS |" in out
    assert "patch_now" in out
    assert "kev_override" in out


def test_run_trend_invalid_cve_id_exits_1(tmp_path, caplog):
    """A bad CVE ID is rejected by the argparse type before the runner runs."""
    import subprocess

    result = subprocess.run(
        [".venv/bin/python", "threat_intel_hunter.py", "trend", "NOT-A-CVE"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_cli_trend_subcommand_parses():
    """`trend CVE-X` parses to subcommand=trend with cve_id set."""
    from ramen_cve import build_parser

    args = build_parser().parse_args(["trend", "CVE-2021-44228"])
    assert args.subcommand == "trend"
    assert args.cve_id == "CVE-2021-44228"


def test_write_markdown_diamond_uses_unknown_when_unset(tmp_path):
    """Missing adversary / infrastructure render as italic placeholders."""
    from ramen_cve import EnrichedCve, write_markdown

    rec = EnrichedCve(
        cve_id="CVE-2099-0001", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "*unknown actor*" in text
    assert "*unknown infrastructure*" in text


def test_maybe_dispatch_off_by_default(caplog):
    """_maybe_dispatch is a no-op unless --dispatch is set."""
    import argparse
    import logging

    from ramen_cve import _maybe_dispatch

    args = argparse.Namespace(dispatch=False)
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        _maybe_dispatch(args, [_disp_rec()])
    # No INFO log entry from dispatch_records since we never called it
    assert all("Dispatch complete" not in r.message for r in caplog.records)


def test_maybe_correlate_inventory_missing_path_logs_error(tmp_path, caplog):
    """A bogus --inventory path logs ERROR but does NOT abort."""
    import argparse
    import logging

    from ramen_cve import EnrichedCve, _maybe_correlate_inventory

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="patch_now",
    )
    args = argparse.Namespace(inventory=tmp_path / "nope.csv")
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        _maybe_correlate_inventory(args, [rec])
    assert rec.affected_hosts == []
    assert any("Inventory correlation skipped" in r.message for r in caplog.records)


def test_output_writes_sigma_dir_when_format_is_all(tmp_path):
    """--format all produces a *-sigma directory containing one YAML per qualifying CVE."""
    from unittest.mock import MagicMock, patch

    import ramen_cve

    bundle = tmp_path / "in.json"
    bundle.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "vulnerability",
                "id": "vulnerability--00000000-0000-4000-8000-000000000001",
                "name": "CVE-2021-44228",
            }
        ],
    }))

    nvd = _load_fixture("nvd_log4shell_v31.json")
    epss = _load_fixture("epss_batch.json")

    def _fake_get(url, params=None, headers=None, timeout=None, auth=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.text = ""
        if "epss" in url:
            resp.json.return_value = epss
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = nvd
        return resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
    ):
        rc = ramen_cve.main([
            "stix", str(bundle),
            "--no-cache", "--out-dir", str(tmp_path), "--format", "all",
            "--no-exploit-lookup",
        ])

    assert rc == 0
    sigma_dirs = list(tmp_path.glob("ramen-cve-*-sigma"))
    assert len(sigma_dirs) == 1
    yaml_files = list(sigma_dirs[0].glob("*.yml"))
    assert len(yaml_files) == 1
    yaml = yaml_files[0].read_text()
    assert "CVE-2021-44228" in yaml
    assert "level: critical" in yaml


def test_output_writes_stix_when_format_is_all(tmp_path):
    """--format all writes csv + md + stix, with stix containing the Vulnerability SDO."""
    from unittest.mock import MagicMock, patch

    import ramen_cve

    bundle = tmp_path / "in.json"
    bundle.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "vulnerability",
                "id": "vulnerability--00000000-0000-4000-8000-000000000001",
                "name": "CVE-2024-0001",
            }
        ],
    }))

    def _fake_get(url, params=None, headers=None, timeout=None, auth=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.text = ""
        resp.json.return_value = {"vulnerabilities": []}
        return resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
    ):
        rc = ramen_cve.main([
            "stix", str(bundle),
            "--no-cache", "--out-dir", str(tmp_path), "--format", "all",
            "--no-exploit-lookup",
        ])

    assert rc == 0
    stix_files = list(tmp_path.glob("ramen-cve-*.stix.json"))
    assert len(stix_files) == 1
    bundle_out = json.loads(stix_files[0].read_text())
    assert any(
        o.get("type") == "vulnerability" and o.get("name") == "CVE-2024-0001"
        for o in bundle_out["objects"]
    )


# ---------------------------------------------------------------------------
# Slice 22 — Audit logging
# ---------------------------------------------------------------------------


def test_cache_log_audit_round_trip():
    """log_audit + get_audit round-trip a row in chronological order."""
    from ramen_cve import Cache

    c = Cache(":memory:")
    c.log_audit("alice", "cve", '{"cves":["CVE-2021-44228"]}', "rc=0")
    c.log_audit("alice", "opml", '{"path":"feeds.opml"}', "rc=0")
    rows = c.get_audit(10)
    assert [r["command"] for r in rows] == ["cve", "opml"]
    assert rows[0]["actor"] == "alice"
    assert rows[0]["outcome"] == "rc=0"
    assert rows[0]["args_redacted"] == '{"cves":["CVE-2021-44228"]}'


def test_cache_audit_log_limit_keeps_most_recent():
    """get_audit(limit=N) returns the most recent N entries, oldest first."""
    from ramen_cve import Cache

    c = Cache(":memory:")
    for i in range(5):
        c.log_audit("alice", f"cmd-{i}", "{}", "rc=0")
    rows = c.get_audit(3)
    assert len(rows) == 3
    # Most recent 3 are cmd-2, cmd-3, cmd-4 (returned in chronological order)
    assert [r["command"] for r in rows] == ["cmd-2", "cmd-3", "cmd-4"]


def test_cache_audit_log_table_has_no_update_or_delete_helper():
    """Append-only contract: Cache exposes log_audit / get_audit but no setters
    that mutate or remove rows. This is the chain-of-custody requirement."""
    from ramen_cve import Cache

    audit_methods = {m for m in dir(Cache) if "audit" in m.lower()}
    # Allowed surface: log_audit, get_audit. Nothing else.
    assert audit_methods == {"log_audit", "get_audit"}


def test_audit_actor_returns_str():
    """`_audit_actor` returns a non-empty string under normal conditions."""
    import ramen_cve

    assert isinstance(ramen_cve._audit_actor(), str)
    assert ramen_cve._audit_actor() != ""


def test_audit_actor_falls_back_when_getuser_raises(monkeypatch):
    """If getpass.getuser() raises OSError (no user env), return 'unknown'."""
    import getpass

    import ramen_cve

    def _boom():
        raise OSError("no user")

    monkeypatch.setattr(getpass, "getuser", _boom)
    assert ramen_cve._audit_actor() == "unknown"


def test_redact_audit_args_masks_sensitive_fields():
    """Fields with 'key', 'pass', 'token', 'secret' in the name are replaced with '***'."""
    import argparse

    import ramen_cve

    ns = argparse.Namespace(
        cves=["CVE-2021-44228"],
        nvd_api_key="real-secret-key",
        taxii_pass="hunter2",
        github_token="ghp_real",
        slack_secret="real-webhook",
        cvss_threshold=7.0,
    )
    blob = ramen_cve._redact_audit_args(ns)
    data = json.loads(blob)
    assert data["cves"] == ["CVE-2021-44228"]
    assert data["nvd_api_key"] == "***"
    assert data["taxii_pass"] == "***"
    assert data["github_token"] == "***"
    assert data["slack_secret"] == "***"
    assert data["cvss_threshold"] == 7.0


def test_redact_audit_args_stringifies_path_and_date():
    """Path and date values become JSON-serializable strings."""
    import argparse
    from pathlib import Path

    import ramen_cve

    ns = argparse.Namespace(
        out_dir=Path("/tmp/reports"),
        start=date(2024, 6, 1),
        end=None,
    )
    blob = ramen_cve._redact_audit_args(ns)
    data = json.loads(blob)
    assert data["out_dir"] == "/tmp/reports"
    assert data["start"] == "2024-06-01"
    assert data["end"] is None


def test_redact_audit_args_blank_sensitive_field_serializes_as_null():
    """An unset sensitive arg (None / '') is recorded as null, not '***'."""
    import argparse

    import ramen_cve

    ns = argparse.Namespace(nvd_api_key=None, taxii_pass="")
    data = json.loads(ramen_cve._redact_audit_args(ns))
    assert data["nvd_api_key"] is None
    assert data["taxii_pass"] is None


def test_audit_dispatch_records_success_outcome():
    """A runner that returns 0 is logged with outcome='rc=0'."""
    import argparse

    import ramen_cve
    from ramen_cve import Cache

    cache = Cache(":memory:")
    args = argparse.Namespace(foo="bar")
    rc = ramen_cve._audit_dispatch(cache, "cve", args, lambda: 0)
    assert rc == 0
    rows = cache.get_audit(10)
    assert rows[-1]["command"] == "cve"
    assert rows[-1]["outcome"] == "rc=0"


def test_audit_dispatch_records_nonzero_outcome():
    """A runner that returns non-zero is logged with that rc."""
    import argparse

    import ramen_cve
    from ramen_cve import Cache

    cache = Cache(":memory:")
    rc = ramen_cve._audit_dispatch(cache, "cve", argparse.Namespace(), lambda: 2)
    assert rc == 2
    assert cache.get_audit(1)[0]["outcome"] == "rc=2"


def test_audit_dispatch_records_exception_and_reraises():
    """When the runner raises, the audit row records the exception type and we re-raise."""
    import argparse

    import pytest

    import ramen_cve
    from ramen_cve import Cache

    cache = Cache(":memory:")

    def _boom():
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError, match="kaboom"):
        ramen_cve._audit_dispatch(cache, "cve", argparse.Namespace(), _boom)
    rows = cache.get_audit(1)
    assert rows[0]["outcome"].startswith("error: RuntimeError")


def test_audit_dispatch_swallows_audit_write_failure(monkeypatch):
    """If log_audit itself blows up, the runner's result still surfaces."""
    import argparse

    import ramen_cve
    from ramen_cve import Cache

    cache = Cache(":memory:")

    def _broken_log(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(cache, "log_audit", _broken_log)
    rc = ramen_cve._audit_dispatch(cache, "cve", argparse.Namespace(), lambda: 0)
    assert rc == 0  # audit failure is non-fatal


def test_cli_audit_subcommand_parses():
    """The `audit` subcommand accepts --tail."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["audit", "--tail", "5"])
    assert args.subcommand == "audit"
    assert args.tail == 5


def test_audit_subcommand_prints_markdown_table(tmp_path, monkeypatch, capsys):
    """`ramen_cve audit` prints a Markdown header + table of recent entries."""
    import ramen_cve
    from ramen_cve import Cache

    db = tmp_path / "cache.db"
    c = Cache(str(db))
    c.log_audit("alice", "cve", '{"cves":["CVE-2021-44228"]}', "rc=0")
    c.log_audit("alice", "opml", '{"path":"feeds.opml"}', "rc=0")

    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(db))
    rc = ramen_cve.main(["audit", "--tail", "10"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Audit log" in out
    assert "| Timestamp (UTC) | Actor | Command | Outcome | Args |" in out
    assert "| alice | cve |" in out
    assert "| alice | opml |" in out


def test_audit_subcommand_empty_log_logs_info(tmp_path, monkeypatch, caplog):
    """An empty audit log produces an INFO message, not an empty table."""
    import logging

    import ramen_cve

    db = tmp_path / "cache.db"
    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(db))
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        rc = ramen_cve.main(["audit"])
    assert rc == 0
    assert any("Audit log is empty" in r.message for r in caplog.records)


def test_audit_subcommand_does_not_self_log(tmp_path, monkeypatch):
    """Reading the audit log must NOT append a new audit row."""
    import ramen_cve
    from ramen_cve import Cache

    db = tmp_path / "cache.db"
    c = Cache(str(db))
    c.log_audit("alice", "cve", "{}", "rc=0")
    before = len(c.get_audit(100))
    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(db))
    ramen_cve.main(["audit"])
    # Re-open to bypass connection-level caching, then count again.
    after = len(Cache(str(db)).get_audit(100))
    assert after == before


def test_audit_logs_after_cve_subcommand(tmp_path, monkeypatch):
    """End-to-end: running `cve` followed by `audit` shows the cve invocation."""
    from unittest.mock import MagicMock, patch

    import ramen_cve
    from ramen_cve import Cache

    db = tmp_path / "cache.db"
    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(db))
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    def _fake_get(url, params=None, headers=None, timeout=None, auth=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.status_code = 200
        if "epss" in url:
            resp.json.return_value = {"data": []}
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = {"vulnerabilities": []}
        resp.text = ""
        return resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.requests.post", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
    ):
        rc = ramen_cve.main([
            "cve", "CVE-2021-44228",
            "--out-dir", str(tmp_path),
            "--format", "csv",
            "--no-exploit-lookup",
            "--no-enrich-iocs",
        ])
    assert rc == 0
    rows = Cache(str(db)).get_audit(10)
    assert any(r["command"] == "cve" and r["outcome"] == "rc=0" for r in rows)


# ---------------------------------------------------------------------------
# Slice 23 — YARA rule generation
# ---------------------------------------------------------------------------


def test_yara_safe_name_handles_arbitrary_input():
    """The helper produces a valid YARA identifier from any input."""
    import ramen_cve

    assert ramen_cve._yara_safe_name("Cobalt Strike") == "Cobalt_Strike"
    assert ramen_cve._yara_safe_name("Ryuk!") == "Ryuk"
    assert ramen_cve._yara_safe_name("CVE-2021-44228") == "CVE_2021_44228"
    # Leading digit gets prefixed
    assert ramen_cve._yara_safe_name("404Frame").startswith("_")
    # Empty / None / whitespace collapses to a sentinel
    assert ramen_cve._yara_safe_name("") == "Unknown"
    assert ramen_cve._yara_safe_name("   ") == "Unknown"
    assert ramen_cve._yara_safe_name(None) == "Unknown"


def test_yara_string_escape_basic():
    """Backslashes and double quotes are escaped for YARA string literals."""
    import ramen_cve

    assert ramen_cve._yara_string_escape('say "hi"') == 'say \\"hi\\"'
    assert ramen_cve._yara_string_escape("C:\\evil\\bad.exe") == "C:\\\\evil\\\\bad.exe"
    assert ramen_cve._yara_string_escape("") == ""


def test_build_yara_stub_contains_required_metadata():
    """Emitted rule includes rule header, id, CVE, malware family, ATT&CK, TODO blocks."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, Malware

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        bucket="kev_override",
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        kev_known_ransomware_use=True,
        attack_techniques=["T1059", "T1190"],
    )
    mw = Malware(name="Cobalt Strike", url="https://attack.mitre.org/software/S0154/")
    out = ramen_cve._build_yara_stub(rec, mw)
    assert out.startswith("rule Ramen_Cobalt_Strike_CVE_2021_44228")
    assert 'cve = "CVE-2021-44228"' in out
    assert 'malware_family = "Cobalt Strike"' in out
    assert 'cvss = "10.0"' in out
    assert 'epss = "0.9700"' in out
    assert 'attack_techniques = "T1059, T1190"' in out
    assert 'cisa_kev = "listed (due 2021-12-24) - known ransomware use"' in out
    assert "mitre_software = \"https://attack.mitre.org/software/S0154/\"" in out
    assert "TODO_REPLACE_ME" in out
    assert "condition:" in out


def test_build_yara_stub_omits_kev_block_when_not_listed():
    """A non-KEV CVE produces a rule without the cisa_kev meta field."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, Malware

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        kev_listed=False,
        attack_techniques=[],
    )
    mw = Malware(name="UnknownTrojan")
    out = ramen_cve._build_yara_stub(rec, mw)
    assert "cisa_kev" not in out
    assert "mitre_software" not in out  # Malware.url is empty
    assert "Ramen_UnknownTrojan_CVE_2024_0001" in out


def test_build_yara_stub_uses_stable_id():
    """Same (CVE, malware) input produces the same rule id across two builds."""
    import re

    import ramen_cve
    from ramen_cve import EnrichedCve, Malware

    rec = EnrichedCve(
        cve_id="CVE-2099-1234", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        bucket="patch_now", cvss_score=8.0, epss_score=0.3,
    )
    mw = Malware(name="Acme")
    a = ramen_cve._build_yara_stub(rec, mw)
    b = ramen_cve._build_yara_stub(rec, mw)
    id_a = re.search(r'id = "([^"]+)"', a).group(1)
    id_b = re.search(r'id = "([^"]+)"', b).group(1)
    assert id_a == id_b
    # UUIDv4 shape
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}", id_a
    )


def test_write_yara_stubs_filters_by_bucket_and_malware(tmp_path):
    """Only kev_override / patch_now CVEs with linked malware become files."""
    from ramen_cve import EnrichedCve, Malware, write_yara_stubs

    high_with_mw = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
        linked_malware=[Malware("Cobalt Strike"), Malware("Ryuk")],
    )
    high_no_mw = EnrichedCve(
        cve_id="CVE-2021-26855", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.8, epss_score=0.97, bucket="patch_now",
        linked_malware=[],
    )
    low = EnrichedCve(
        cve_id="CVE-2024-9999", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=4.0, epss_score=0.05, bucket="deprioritize",
        linked_malware=[Malware("Whatever")],
    )
    out_dir = tmp_path / "yara"
    written = write_yara_stubs([high_with_mw, high_no_mw, low], out_dir)
    names = sorted(p.name for p in written)
    assert names == [
        "Cobalt_Strike_CVE_2021_44228.yar",
        "Ryuk_CVE_2021_44228.yar",
    ]
    # No file for the patch_now CVE without malware, none for the low bucket
    assert not (out_dir / "Whatever_CVE_2024_9999.yar").exists()


def test_write_yara_stubs_creates_output_dir(tmp_path):
    """Output dir is created if it doesn't already exist."""
    import ramen_cve
    from ramen_cve import EnrichedCve, Malware

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
        linked_malware=[Malware("X")],
    )
    nested = tmp_path / "deeply" / "nested" / "yara"
    files = ramen_cve.write_yara_stubs([rec], nested)
    assert nested.is_dir()
    assert len(files) == 1


def test_cli_format_yara_choice_parses():
    """--format yara is accepted on every analysis subcommand."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["opml", "x.opml", "--format", "yara"])
    assert args.format == "yara"


def test_output_writes_yara_dir_when_format_is_all(tmp_path):
    """End-to-end: --format all produces a *-yara directory with one stub per malware."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, Malware

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        bucket="kev_override",
        linked_malware=[Malware("Cobalt Strike")],
    )
    args = argparse.Namespace(
        format="all",
        out_dir=tmp_path,
        basename="run42",
        allow_tlp_red=False,
    )
    ramen_cve._output([rec], args, {"version": "0.1"})
    yara_dir = tmp_path / "run42-yara"
    assert yara_dir.is_dir()
    assert (yara_dir / "Cobalt_Strike_CVE_2021_44228.yar").exists()


# ---------------------------------------------------------------------------
# Slice 24 — IOC confidence decay
# ---------------------------------------------------------------------------


def test_ioc_confidence_no_decay_for_hashes():
    """Hash IOCs (md5/sha1/sha256) have half_life=0 → confidence stays at 1.0."""
    from datetime import date

    import ramen_cve

    # Even a year-old hash should still be 1.0
    old = date(2024, 1, 1)
    today = date(2025, 1, 1)
    for t in ("md5", "sha1", "sha256"):
        assert ramen_cve._ioc_confidence(t, old, today) == 1.0


def test_ioc_confidence_decays_for_ipv4_per_half_life():
    """At one half-life (30 days), an IPv4's confidence is 0.5."""
    from datetime import date

    import ramen_cve

    seen = date(2024, 6, 1)
    today = date(2024, 7, 1)  # exactly 30 days later
    conf = ramen_cve._ioc_confidence("ipv4", seen, today)
    assert abs(conf - 0.5) < 1e-6
    # Two half-lives → 0.25
    two_hl = ramen_cve._ioc_confidence("ipv4", seen, date(2024, 7, 31))
    assert abs(two_hl - 0.25) < 1e-6


def test_ioc_confidence_decays_for_domain_slower():
    """Domains use 90-day half-life — 30-day-old domain stays ~0.79."""
    from datetime import date

    import ramen_cve

    conf = ramen_cve._ioc_confidence("domain", date(2024, 6, 1), date(2024, 7, 1))
    assert 0.79 < conf < 0.80


def test_ioc_confidence_none_last_seen_returns_one():
    """A None last_seen short-circuits to 1.0 (the IOC was 'just observed')."""
    import ramen_cve

    assert ramen_cve._ioc_confidence("ipv4", None) == 1.0


def test_ioc_confidence_clamps_future_dates():
    """A future last_seen (clock skew) doesn't push confidence above 1.0."""
    from datetime import date

    import ramen_cve

    # last_seen tomorrow, today is yesterday → age = -1 day → clamped to 0
    assert ramen_cve._ioc_confidence("ipv4", date(2024, 6, 2), date(2024, 6, 1)) == 1.0


def test_apply_ioc_decay_mutates_in_place():
    """apply_ioc_decay updates each IocRecord.confidence using last_seen ?? first_seen."""
    from datetime import date

    import ramen_cve

    ip = ramen_cve.IocRecord(
        "ipv4", "1.2.3.4", "x", date(2024, 1, 1), "feed_pub",
        last_seen=date(2024, 1, 1),
    )
    domain = ramen_cve.IocRecord(
        "domain", "evil.example.com", "x", date(2024, 4, 1), "feed_pub",
        last_seen=date(2024, 4, 1),
    )
    today = date(2024, 4, 1)  # IP is 91 days old, domain is fresh
    ramen_cve.apply_ioc_decay([ip, domain], today=today)
    # IP is ~3 half-lives in (91 days / 30 ≈ 3.03), so confidence ≈ 0.123
    assert 0.1 < ip.confidence < 0.15
    assert abs(domain.confidence - 1.0) < 1e-6


def test_apply_ioc_decay_falls_back_to_first_seen_when_last_seen_unset():
    """When last_seen is None, decay uses first_seen as the anchor."""
    from datetime import date

    import ramen_cve

    rec = ramen_cve.IocRecord(
        "ipv4", "1.2.3.4", "x", date(2024, 6, 1), "feed_pub",
        last_seen=None,
    )
    ramen_cve.apply_ioc_decay([rec], today=date(2024, 7, 1))
    assert abs(rec.confidence - 0.5) < 1e-6


def test_filter_iocs_by_confidence_drops_sub_floor():
    """filter_iocs_by_confidence drops records strictly below the floor."""
    from datetime import date

    import ramen_cve

    high = ramen_cve.IocRecord("md5", "ab" * 16, "x", date.today(), "feed_pub")
    low = ramen_cve.IocRecord("ipv4", "1.2.3.4", "x", date(2020, 1, 1), "feed_pub")
    ramen_cve.apply_ioc_decay([high, low])
    kept = ramen_cve.filter_iocs_by_confidence([high, low], 0.5)
    assert high in kept
    assert low not in kept


def test_filter_iocs_floor_zero_keeps_everything():
    """A floor of 0.0 (the default) is a no-op."""
    from datetime import date

    import ramen_cve

    iocs = [
        ramen_cve.IocRecord("ipv4", "1.2.3.4", "x", date(2020, 1, 1), "feed_pub"),
    ]
    ramen_cve.apply_ioc_decay(iocs)
    assert ramen_cve.filter_iocs_by_confidence(iocs, 0.0) == iocs


def test_extract_iocs_sets_last_seen_to_first_seen():
    """Freshly-extracted IOCs use first_seen as their last_seen so decay anchors today."""
    from datetime import date

    import ramen_cve

    iocs = ramen_cve.extract_iocs(
        "Beacon to 8.8.8.8 hash d41d8cd98f00b204e9800998ecf8427e",
        "src", date(2024, 6, 1), "feed_pub",
    )
    assert all(i.last_seen == date(2024, 6, 1) for i in iocs)


def test_dedupe_iocs_propagates_most_recent_last_seen():
    """Two records for the same IOC: the merged record keeps the latest last_seen."""
    from datetime import date

    import ramen_cve
    from ramen_cve import _dedupe_iocs

    older = ramen_cve.IocRecord(
        "ipv4", "8.8.8.8", "feed-a", date(2024, 1, 1), "feed_pub",
        last_seen=date(2024, 1, 1),
    )
    newer = ramen_cve.IocRecord(
        "ipv4", "8.8.8.8", "feed-b", date(2024, 5, 1), "feed_pub",
        last_seen=date(2024, 5, 1),
    )
    out = _dedupe_iocs([older, newer])
    assert len(out) == 1
    assert out[0].last_seen == date(2024, 5, 1)
    # And first_seen still wins on the earliest
    assert out[0].first_seen == date(2024, 1, 1)


def test_write_iocs_csv_includes_confidence_and_last_seen(tmp_path):
    """CSV header carries the two new columns; freshly-decayed rows render 1.0000."""
    import csv
    from datetime import date

    import ramen_cve

    rec = ramen_cve.IocRecord(
        "ipv4", "8.8.8.8", "x", date(2024, 6, 1), "feed_pub",
        last_seen=date(2024, 6, 1),
    )
    ramen_cve.apply_ioc_decay([rec], today=date(2024, 6, 1))
    out = tmp_path / "iocs.csv"
    ramen_cve.write_iocs_csv([rec], out)
    rows = list(csv.reader(out.open()))
    header = rows[0]
    assert "confidence" in header and "last_seen" in header
    row = dict(zip(header, rows[1], strict=True))
    assert row["last_seen"] == "2024-06-01"
    assert row["confidence"] == "1.0000"


def test_write_markdown_shows_confidence_when_below_one(tmp_path):
    """Markdown IOC line shows '(confidence X.XX)' when decay has lowered the value."""
    from datetime import date

    import ramen_cve

    rec = ramen_cve.IocRecord(
        "ipv4", "1.2.3.4", "x", date(2024, 1, 1), "feed_pub",
        last_seen=date(2024, 1, 1),
    )
    ramen_cve.apply_ioc_decay([rec], today=date(2024, 7, 1))  # ~6 half-lives
    out = tmp_path / "report.md"
    ramen_cve.write_markdown([], out, METADATA, iocs=[rec])
    text = out.read_text()
    assert "(confidence" in text
    assert "1.2.3.4" in text


def test_write_markdown_omits_confidence_when_fresh(tmp_path):
    """A confidence at 1.0 should NOT clutter the Markdown line."""
    from datetime import date

    import ramen_cve

    rec = ramen_cve.IocRecord(
        "ipv4", "1.2.3.4", "x", date.today(), "feed_pub",
        last_seen=date.today(),
    )
    ramen_cve.apply_ioc_decay([rec])
    out = tmp_path / "report.md"
    ramen_cve.write_markdown([], out, METADATA, iocs=[rec])
    assert "confidence" not in out.read_text()


def test_cli_ioc_confidence_floor_flag_parses():
    """--ioc-confidence-floor is accepted and round-trips as a float."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--ioc-confidence-floor", "0.10"]
    )
    assert args.ioc_confidence_floor == 0.10


def test_decay_and_filter_iocs_drops_below_floor(caplog):
    """_decay_and_filter_iocs applies decay then enforces the floor."""
    import argparse
    import logging
    from datetime import date

    import ramen_cve

    fresh = ramen_cve.IocRecord(
        "md5", "ab" * 16, "x", date.today(), "feed_pub",
    )
    stale_ip = ramen_cve.IocRecord(
        "ipv4", "1.2.3.4", "x", date(2020, 1, 1), "feed_pub",
        last_seen=date(2020, 1, 1),
    )
    args = argparse.Namespace(ioc_confidence_floor=0.5)
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        out = ramen_cve._decay_and_filter_iocs(args, [fresh, stale_ip])
    assert fresh in out
    assert stale_ip not in out
    assert any("below the confidence floor" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Slice 25 — Sector / geopolitical context
# ---------------------------------------------------------------------------


def test_threat_actor_dataclass_carries_sectors():
    """ThreatActor includes sectors_targeted, defaulting to []."""
    from ramen_cve import ThreatActor

    a = ThreatActor(name="APT41", sectors_targeted=["financial", "technology"])
    assert a.sectors_targeted == ["financial", "technology"]
    b = ThreatActor(name="X")
    assert b.sectors_targeted == []


def test_build_actor_normalizes_sectors_to_lowercase():
    """JSON 'sectors_targeted' values are lowercased + stripped."""
    import ramen_cve

    a = ramen_cve._build_actor({
        "name": "X",
        "sectors_targeted": [" Financial ", "ENERGY", ""],
    })
    assert a.sectors_targeted == ["financial", "energy"]


def test_default_associations_carry_sectors_for_apt41():
    """The bundled associations file declares APT41 sectors after this feature."""
    import ramen_cve

    out = ramen_cve.load_associations(ramen_cve.DEFAULT_ASSOCIATIONS_PATH)
    apt41 = next(
        a for a in out["CVE-2021-44228"]["actors"] if a.name == "APT41"
    )
    # Lowercase tags from the JSON
    assert "financial" in apt41.sectors_targeted
    assert "technology" in apt41.sectors_targeted


def test_maybe_filter_by_sector_keeps_matching_actor():
    """A CVE with at least one actor targeting the chosen sector is kept."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, ThreatActor

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        linked_actors=[
            ThreatActor(name="Bank-Targeter", sectors_targeted=["financial"]),
        ],
    )
    args = argparse.Namespace(sector="financial")
    out = ramen_cve._maybe_filter_by_sector(args, [rec])
    assert out == [rec]


def test_maybe_filter_by_sector_drops_nonmatching_actor():
    """A CVE whose only actor targets a DIFFERENT sector is dropped."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, ThreatActor

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        linked_actors=[ThreatActor(name="Energy-Targeter", sectors_targeted=["energy"])],
    )
    args = argparse.Namespace(sector="financial")
    assert ramen_cve._maybe_filter_by_sector(args, [rec]) == []


def test_maybe_filter_by_sector_keeps_unattributed_records():
    """Safe-by-default: CVE without linked_actors stays in the report."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        linked_actors=[],
    )
    args = argparse.Namespace(sector="financial")
    out = ramen_cve._maybe_filter_by_sector(args, [rec])
    assert out == [rec]


def test_maybe_filter_by_sector_noop_when_unset():
    """Blank / None sector argument leaves the list untouched."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
    )
    assert ramen_cve._maybe_filter_by_sector(argparse.Namespace(sector=None), [rec]) == [rec]
    assert ramen_cve._maybe_filter_by_sector(argparse.Namespace(sector=""), [rec]) == [rec]


def test_maybe_filter_by_sector_case_insensitive():
    """'Financial' (mixed case) input matches 'financial' (lowercase) on the actor."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, ThreatActor

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        linked_actors=[ThreatActor(name="X", sectors_targeted=["financial"])],
    )
    args = argparse.Namespace(sector=" Financial ")
    assert ramen_cve._maybe_filter_by_sector(args, [rec]) == [rec]


def test_cli_sector_flag_parses():
    """--sector accepts a string and round-trips through build_parser."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--sector", "energy"]
    )
    assert args.sector == "energy"


def test_write_markdown_adversaries_cross_tab_includes_sectors(tmp_path):
    """The Linked Adversaries roll-up now has a 'Sectors Targeted' column."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, ThreatActor

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
        linked_actors=[
            ThreatActor(
                name="APT41",
                sectors_targeted=["financial", "technology"],
            )
        ],
    )
    out = tmp_path / "report.md"
    ramen_cve.write_markdown([rec], out, METADATA)
    text = out.read_text()
    assert "| Actor | CVEs | Sectors Targeted |" in text
    # Sectors are sorted in the row
    assert "| APT41 | 1 | financial, technology |" in text


def test_write_markdown_dash_when_no_sectors(tmp_path):
    """If an actor has no sectors_targeted, the column renders as '—'."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve, ThreatActor

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        linked_actors=[ThreatActor(name="Mystery")],
    )
    out = tmp_path / "report.md"
    ramen_cve.write_markdown([rec], out, METADATA)
    assert "| Mystery | 1 | — |" in out.read_text()


# ---------------------------------------------------------------------------
# Slice 26 — PIR (Priority Intelligence Requirements) tracking
# ---------------------------------------------------------------------------


def _pir_payload(**overrides) -> dict:
    base = {
        "id": "test-pir",
        "name": "Sample PIR",
        "question": "Are we exposed?",
        "owner": "cti-team",
        "status": "active",
        "created": "2024-01-01T00:00:00",
        "tagged_cves": ["CVE-2021-44228"],
        "tagged_iocs": [],
        "tagged_actors": ["APT41"],
    }
    base.update(overrides)
    return base


def test_pir_dataclass_round_trip():
    """Pir.from_dict / to_dict round-trip is value-preserving."""
    from ramen_cve import Pir

    payload = _pir_payload()
    assert Pir.from_dict(payload).to_dict() == payload


def test_pir_dataclass_tolerates_missing_keys():
    """Optional fields default to sensible empties / strings."""
    from ramen_cve import Pir

    p = Pir.from_dict({"id": "x", "name": "n", "question": "q?"})
    assert p.status == "active"
    assert p.owner == ""
    assert p.tagged_cves == []
    assert p.tagged_iocs == []
    assert p.tagged_actors == []


def test_load_pir_round_trip(tmp_path):
    """load_pir + save_pir round-trip preserves the payload."""
    from ramen_cve import Pir, load_pir, save_pir

    p = tmp_path / "x.json"
    save_pir(Pir.from_dict(_pir_payload()), p)
    out = load_pir(p)
    assert out.id == "test-pir"
    assert out.tagged_cves == ["CVE-2021-44228"]


def test_load_pir_missing_file_raises(tmp_path):
    """A missing PIR path raises OpmlError, not FileNotFoundError."""
    from ramen_cve import OpmlError, load_pir

    with pytest.raises(OpmlError, match="not found"):
        load_pir(tmp_path / "missing.json")


def test_load_pir_invalid_json_raises(tmp_path):
    """Malformed JSON raises OpmlError, not JSONDecodeError."""
    from ramen_cve import OpmlError, load_pir

    p = tmp_path / "bad.json"
    p.write_text("{not valid")
    with pytest.raises(OpmlError, match="parse"):
        load_pir(p)


def test_load_all_pirs_returns_sorted_list(tmp_path):
    """load_all_pirs returns every well-formed *.json sorted by id."""
    from ramen_cve import Pir, load_all_pirs, save_pir

    save_pir(Pir.from_dict(_pir_payload(id="zeta")), tmp_path / "zeta.json")
    save_pir(Pir.from_dict(_pir_payload(id="alpha")), tmp_path / "alpha.json")
    out = load_all_pirs(tmp_path)
    assert [p.id for p in out] == ["alpha", "zeta"]


def test_load_all_pirs_missing_dir_returns_empty(tmp_path):
    from ramen_cve import load_all_pirs

    assert load_all_pirs(tmp_path / "no-such-dir") == []


def test_load_all_pirs_skips_malformed(tmp_path, caplog):
    """A malformed PIR file is skipped with a WARNING; others still load."""
    import logging

    from ramen_cve import Pir, load_all_pirs, save_pir

    save_pir(Pir.from_dict(_pir_payload(id="ok")), tmp_path / "ok.json")
    (tmp_path / "broken.json").write_text("{not valid")
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        out = load_all_pirs(tmp_path)
    assert [p.id for p in out] == ["ok"]
    assert any("malformed pir" in r.message.lower() for r in caplog.records)


def test_default_pir_dir_loads_bundled_sample():
    """The bundled pirs/log4j-exposure.json is well-formed and loadable."""
    from ramen_cve import DEFAULT_PIR_DIR, load_all_pirs

    assert DEFAULT_PIR_DIR.exists()
    pirs = load_all_pirs(DEFAULT_PIR_DIR)
    assert any(p.id == "log4j-exposure" for p in pirs)


def test_cli_pir_subcommand_parses():
    """`pir list / show / link / coverage` round-trip through the parser."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["pir", "list"])
    assert args.subcommand == "pir" and args.action == "list"
    args2 = ramen_cve.build_parser().parse_args(
        ["pir", "link", "log4j-exposure", "CVE-2021-44228"]
    )
    assert args2.action == "link"
    assert args2.pir_id == "log4j-exposure"
    assert args2.value == "CVE-2021-44228"


def test_run_pir_list(tmp_path, capsys):
    """`pir list` prints one tab-delimited line per PIR with key counts."""
    import ramen_cve
    from ramen_cve import Pir, save_pir

    save_pir(Pir.from_dict(_pir_payload(id="p1", name="First")), tmp_path / "p1.json")
    save_pir(Pir.from_dict(_pir_payload(id="p2", name="Second")), tmp_path / "p2.json")
    rc = ramen_cve.main(["pir", "list", "--pir-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "p1" in out and "First" in out
    assert "p2" in out and "Second" in out
    assert "1 CVEs" in out


def test_run_pir_show(tmp_path, capsys):
    """`pir show <id>` prints the PIR as JSON."""
    import ramen_cve
    from ramen_cve import Pir, save_pir

    save_pir(Pir.from_dict(_pir_payload(id="p1")), tmp_path / "p1.json")
    rc = ramen_cve.main(["pir", "show", "p1", "--pir-dir", str(tmp_path)])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body["id"] == "p1"


def test_run_pir_link_appends_cve(tmp_path):
    """`pir link <id> <cve>` appends to tagged_cves and persists."""
    import ramen_cve
    from ramen_cve import Pir, load_pir, save_pir

    save_pir(
        Pir.from_dict(_pir_payload(id="p1", tagged_cves=["CVE-2021-44228"])),
        tmp_path / "p1.json",
    )
    rc = ramen_cve.main([
        "pir", "link", "p1", "CVE-2021-26855",
        "--pir-dir", str(tmp_path),
    ])
    assert rc == 0
    pir = load_pir(tmp_path / "p1.json")
    assert "CVE-2021-26855" in pir.tagged_cves


def test_run_pir_link_dedupes(tmp_path):
    """Linking a CVE that's already tagged is a no-op success."""
    import ramen_cve
    from ramen_cve import Pir, load_pir, save_pir

    save_pir(
        Pir.from_dict(_pir_payload(id="p1", tagged_cves=["CVE-2021-44228"])),
        tmp_path / "p1.json",
    )
    rc = ramen_cve.main([
        "pir", "link", "p1", "CVE-2021-44228",
        "--pir-dir", str(tmp_path),
    ])
    assert rc == 0
    pir = load_pir(tmp_path / "p1.json")
    assert pir.tagged_cves.count("CVE-2021-44228") == 1


def test_run_pir_link_rejects_invalid_cve(tmp_path, caplog):
    """A bad CVE id exits with code 1 and does not mutate the file."""
    import logging

    import ramen_cve
    from ramen_cve import Pir, load_pir, save_pir

    save_pir(Pir.from_dict(_pir_payload(id="p1")), tmp_path / "p1.json")
    before = load_pir(tmp_path / "p1.json").tagged_cves
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "pir", "link", "p1", "NOT-A-CVE",
            "--pir-dir", str(tmp_path),
        ])
    assert rc == 1
    assert load_pir(tmp_path / "p1.json").tagged_cves == before
    assert any("not a valid CVE" in r.message for r in caplog.records)


def test_run_pir_coverage_prints_markdown_table(tmp_path, capsys):
    """`pir coverage` prints a Markdown table of CVE / IOC / actor counts."""
    import ramen_cve
    from ramen_cve import Pir, save_pir

    save_pir(
        Pir.from_dict(_pir_payload(id="p1", tagged_cves=["CVE-X", "CVE-Y"], tagged_actors=["A"])),
        tmp_path / "p1.json",
    )
    rc = ramen_cve.main(["pir", "coverage", "--pir-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# PIR Coverage" in out
    assert "| PIR | Status | Tagged CVEs | Tagged IOCs | Tagged Actors |" in out
    assert "| p1 | active | 2 | 0 | 1 |" in out


def test_run_pir_rejects_path_traversal(tmp_path, caplog):
    """A pir_id with '/' or '..' is refused before any file access."""
    import logging

    import ramen_cve

    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve.main([
            "pir", "show", "../etc/passwd",
            "--pir-dir", str(tmp_path),
        ])
    assert rc == 1
    assert any("invalid pir id" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Slice 27 — Email / daily-digest dispatcher
# ---------------------------------------------------------------------------


def test_email_dispatcher_disabled_without_host_or_sender():
    """enabled() returns False when either SMTP host or From is missing."""
    from ramen_cve import EmailDispatcher

    assert EmailDispatcher(host=None, port=587, user=None, password=None,
                           sender="x@y", use_tls=True).enabled() is False
    assert EmailDispatcher(host="smtp.example", port=587, user=None, password=None,
                           sender=None, use_tls=True).enabled() is False
    assert EmailDispatcher(host="smtp.example", port=587, user=None, password=None,
                           sender="x@y", use_tls=True).enabled() is True


def test_email_dispatcher_from_env_reads_all_keys(monkeypatch):
    """EmailDispatcher.from_env parses every documented variable correctly."""
    import ramen_cve

    monkeypatch.setenv("RAMEN_SMTP_HOST", "smtp.example")
    monkeypatch.setenv("RAMEN_SMTP_PORT", "465")
    monkeypatch.setenv("RAMEN_SMTP_USER", "alice")
    monkeypatch.setenv("RAMEN_SMTP_PASS", "hunter2")
    monkeypatch.setenv("RAMEN_SMTP_FROM", "alice@example")
    monkeypatch.setenv("RAMEN_SMTP_USE_TLS", "0")
    monkeypatch.setenv("RAMEN_DIGEST_TO", "team@example")
    d = ramen_cve.EmailDispatcher.from_env()
    assert d.host == "smtp.example"
    assert d.port == 465
    assert d.user == "alice"
    assert d.password == "hunter2"
    assert d.sender == "alice@example"
    assert d.use_tls is False
    assert d.fallback_recipient == "team@example"


def test_email_dispatcher_from_env_defaults_when_unset(monkeypatch):
    """from_env defaults port=587 and use_tls=True when envs are absent."""
    import ramen_cve

    for k in ("RAMEN_SMTP_HOST", "RAMEN_SMTP_PORT", "RAMEN_SMTP_USER",
              "RAMEN_SMTP_PASS", "RAMEN_SMTP_FROM", "RAMEN_SMTP_USE_TLS",
              "RAMEN_DIGEST_TO"):
        monkeypatch.delenv(k, raising=False)
    d = ramen_cve.EmailDispatcher.from_env()
    assert d.port == 587
    assert d.use_tls is True
    assert d.host is None and d.sender is None
    assert d.enabled() is False


def test_email_dispatcher_build_message_includes_attachments(tmp_path):
    """The MIME message has the subject, body, and one attachment per readable file."""
    from ramen_cve import EmailDispatcher

    d = EmailDispatcher(
        host="smtp.example", port=587, user=None, password=None,
        sender="alice@example", use_tls=True,
    )
    csv = tmp_path / "report.csv"
    csv.write_text("cve_id,bucket\nCVE-2021-44228,kev_override\n")
    md = tmp_path / "report.md"
    md.write_text("# Ramen CVE Triage Report")
    missing = tmp_path / "ghost.bin"  # should be silently skipped
    msg = d._build_message(
        recipient="bob@example",
        subject="ramen-cve digest 1 actionable",
        body_markdown="# Body",
        attachments=[csv, md, missing],
    )
    raw = msg.as_string()
    assert "Subject: ramen-cve digest" in raw
    assert "To: bob@example" in raw
    assert "From: alice@example" in raw
    assert 'filename="report.csv"' in raw
    assert 'filename="report.md"' in raw
    # The missing path was skipped, not an exception
    assert 'filename="ghost.bin"' not in raw


def test_email_dispatcher_send_digest_success_calls_smtp(tmp_path, monkeypatch):
    """send_digest() does login + starttls + send_message + close on success."""
    from unittest.mock import MagicMock

    import ramen_cve

    d = ramen_cve.EmailDispatcher(
        host="smtp.example", port=587, user="alice", password="hunter2",
        sender="alice@example", use_tls=True,
    )
    smtp_instance = MagicMock()
    smtp_class = MagicMock(return_value=smtp_instance)
    smtp_instance.__enter__.return_value = smtp_instance
    smtp_instance.__exit__.return_value = False
    monkeypatch.setattr("smtplib.SMTP", smtp_class)

    ok = d.send_digest(
        recipient="bob@example",
        subject="ramen-cve digest",
        body_markdown="# Body",
        attachments=[],
    )
    assert ok is True
    smtp_class.assert_called_once()
    smtp_instance.starttls.assert_called_once()
    smtp_instance.login.assert_called_once_with("alice", "hunter2")
    smtp_instance.send_message.assert_called_once()


def test_email_dispatcher_send_digest_skips_login_without_credentials(monkeypatch):
    """No SMTP user/pass → skip login but still send."""
    from unittest.mock import MagicMock

    import ramen_cve

    d = ramen_cve.EmailDispatcher(
        host="smtp.example", port=587, user=None, password=None,
        sender="alice@example", use_tls=False,
    )
    smtp_instance = MagicMock()
    smtp_instance.__enter__.return_value = smtp_instance
    smtp_instance.__exit__.return_value = False
    smtp_class = MagicMock(return_value=smtp_instance)
    monkeypatch.setattr("smtplib.SMTP", smtp_class)

    assert d.send_digest("bob@example", "subj", "body") is True
    smtp_instance.login.assert_not_called()
    smtp_instance.starttls.assert_not_called()  # use_tls=False
    smtp_instance.send_message.assert_called_once()


def test_email_dispatcher_send_digest_failure_returns_false(monkeypatch, caplog):
    """A network exception from smtplib returns False with a WARNING."""
    import logging
    from unittest.mock import MagicMock

    import ramen_cve

    d = ramen_cve.EmailDispatcher(
        host="smtp.example", port=587, user=None, password=None,
        sender="alice@example", use_tls=True,
    )
    smtp_instance = MagicMock()
    smtp_instance.__enter__.return_value = smtp_instance
    smtp_instance.__exit__.return_value = False
    smtp_instance.send_message.side_effect = RuntimeError("connection refused")
    monkeypatch.setattr("smtplib.SMTP", MagicMock(return_value=smtp_instance))

    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        ok = d.send_digest("bob@example", "subj", "body")
    assert ok is False
    assert any("digest send to bob@example failed" in r.message for r in caplog.records)


def test_email_dispatcher_send_digest_not_enabled_warns(caplog, monkeypatch):
    """Calling send_digest without configuration WARNs and returns False."""
    import logging

    import ramen_cve

    d = ramen_cve.EmailDispatcher(
        host=None, port=587, user=None, password=None,
        sender=None, use_tls=True,
    )
    monkeypatch.setattr("smtplib.SMTP", lambda *a, **kw: pytest.fail("must not connect"))
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        ok = d.send_digest("bob@example", "subj", "body")
    assert ok is False
    assert any("RAMEN_SMTP_HOST" in r.message for r in caplog.records)


def test_load_inventory_captures_owner_column(tmp_path):
    """The optional `owner` column is preserved per inventory row."""
    from ramen_cve import load_inventory

    p = tmp_path / "inv.csv"
    p.write_text(
        "host,product,version,owner\n"
        "web-1,log4j,2.14.1,team-a@example\n"
        "web-2,log4j,2.14.1,\n"
    )
    rows = load_inventory(p)
    assert rows[0]["owner"] == "team-a@example"
    assert rows[1]["owner"] == ""


def test_group_records_by_owner_routes_per_host():
    """Records are routed to each owner of every affected host."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
        affected_hosts=["web-1", "web-2"],
    )
    inventory = [
        {"host": "web-1", "product": "", "version": "", "cpe": "", "owner": "alice@example"},
        {"host": "web-2", "product": "", "version": "", "cpe": "", "owner": "bob@example"},
    ]
    by_owner = ramen_cve._group_records_by_owner(
        [rec], inventory, fallback_recipient=None
    )
    assert set(by_owner) == {"alice@example", "bob@example"}
    assert rec in by_owner["alice@example"]
    assert rec in by_owner["bob@example"]


def test_group_records_by_owner_uses_fallback_when_no_match():
    """Records without inventory-matched owners go to the fallback recipient."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2099-1234",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="patch_now",
        affected_hosts=[],  # no inventory hits
    )
    by_owner = ramen_cve._group_records_by_owner(
        [rec], inventory_rows=[], fallback_recipient="team@example"
    )
    assert by_owner == {"team@example": [rec]}


def test_group_records_by_owner_skips_low_priority_buckets():
    """Only kev_override / patch_now records are eligible for the digest."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2024-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=3.0,
        epss_score=0.05,
        bucket="deprioritize",
    )
    by_owner = ramen_cve._group_records_by_owner(
        [rec], inventory_rows=[], fallback_recipient="x@y",
    )
    assert by_owner == {}


def test_build_digest_body_lists_owned_hosts():
    """The per-recipient body singles out THIS recipient's owned hosts."""
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        kev_listed=True,
        kev_due_date=date(2021, 12, 24),
        bucket="kev_override",
        suggested_action="Patch immediately.",
        affected_hosts=["web-1", "web-2", "web-3"],
    )
    inv = [
        {"host": "web-1", "owner": "alice@example", "product": "", "version": "", "cpe": ""},
        {"host": "web-3", "owner": "alice@example", "product": "", "version": "", "cpe": ""},
        {"host": "web-2", "owner": "bob@example", "product": "", "version": "", "cpe": ""},
    ]
    body = ramen_cve._build_digest_body("alice@example", [rec], inv)
    assert "Daily Patch Digest for alice@example" in body
    assert "CVE-2021-44228" in body
    assert "Patch immediately." in body
    assert "CISA KEV due date:** 2021-12-24" in body
    # Alice's hosts only — bob's web-2 is not listed under "Your hosts"
    assert "Your hosts (2):** web-1, web-3" in body
    assert "web-2" not in body.split("Your hosts")[1].split("\n")[0]


def test_cli_digest_flag_parses():
    """--digest is accepted and round-trips through build_parser."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["opml", "x.opml", "--digest"])
    assert args.digest is True
    assert ramen_cve.build_parser().parse_args(
        ["opml", "x.opml"]
    ).digest is False


def test_maybe_digest_short_circuits_when_flag_off():
    """Without --digest, _maybe_digest is a complete no-op."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2099-0001",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=9.0,
        epss_score=0.5,
        bucket="kev_override",
    )
    args = argparse.Namespace(digest=False)
    # Even with no SMTP env, this must not raise.
    ramen_cve._maybe_digest(args, [rec], output_paths={})


def test_maybe_digest_warns_when_smtp_missing(monkeypatch, caplog):
    """--digest with no RAMEN_SMTP_HOST / FROM logs a WARNING and returns."""
    import argparse
    import logging
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    for k in ("RAMEN_SMTP_HOST", "RAMEN_SMTP_FROM"):
        monkeypatch.delenv(k, raising=False)
    rec = EnrichedCve(
        cve_id="CVE-2099-0001", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="kev_override",
    )
    args = argparse.Namespace(digest=True, _inventory_rows=[])
    with caplog.at_level(logging.WARNING, logger="ramen_cve"):
        ramen_cve._maybe_digest(args, [rec], output_paths={})
    assert any("RAMEN_SMTP_HOST" in r.message for r in caplog.records)


def test_maybe_digest_sends_one_email_per_recipient(monkeypatch, tmp_path):
    """End-to-end with mocked SMTP: one email per owner, with CSV/MD attached."""
    import argparse
    from datetime import date
    from unittest.mock import MagicMock

    import ramen_cve
    from ramen_cve import EnrichedCve

    # Configure the dispatcher via env
    monkeypatch.setenv("RAMEN_SMTP_HOST", "smtp.example")
    monkeypatch.setenv("RAMEN_SMTP_FROM", "alice@example")
    monkeypatch.delenv("RAMEN_DIGEST_TO", raising=False)

    smtp_instance = MagicMock()
    smtp_instance.__enter__.return_value = smtp_instance
    smtp_instance.__exit__.return_value = False
    smtp_class = MagicMock(return_value=smtp_instance)
    monkeypatch.setattr("smtplib.SMTP", smtp_class)

    csv_path = tmp_path / "out.csv"
    csv_path.write_text("cve_id,bucket\nCVE-2021-44228,kev_override\n")
    md_path = tmp_path / "out.md"
    md_path.write_text("# Report")

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
        affected_hosts=["web-1", "db-1"],
    )
    args = argparse.Namespace(
        digest=True,
        _inventory_rows=[
            {"host": "web-1", "owner": "alice@example",
             "product": "", "version": "", "cpe": ""},
            {"host": "db-1", "owner": "bob@example",
             "product": "", "version": "", "cpe": ""},
        ],
    )
    ramen_cve._maybe_digest(args, [rec], output_paths={"csv": csv_path, "md": md_path})
    # send_message is called once per recipient
    assert smtp_instance.send_message.call_count == 2


def test_maybe_digest_no_recipients_logs_info(monkeypatch, caplog):
    """If nothing maps to a recipient, log INFO and don't connect."""
    import argparse
    import logging
    from datetime import date
    from unittest.mock import MagicMock

    import ramen_cve
    from ramen_cve import EnrichedCve

    monkeypatch.setenv("RAMEN_SMTP_HOST", "smtp.example")
    monkeypatch.setenv("RAMEN_SMTP_FROM", "alice@example")
    monkeypatch.delenv("RAMEN_DIGEST_TO", raising=False)
    smtp_class = MagicMock()
    monkeypatch.setattr("smtplib.SMTP", smtp_class)

    rec = EnrichedCve(
        cve_id="CVE-2099-0001", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
        affected_hosts=[],  # nothing routable
    )
    args = argparse.Namespace(digest=True, _inventory_rows=[])
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        ramen_cve._maybe_digest(args, [rec], output_paths={})
    smtp_class.assert_not_called()
    assert any("nothing sent" in r.message for r in caplog.records)


def test_output_returns_paths_dict(tmp_path):
    """_output now returns a dict mapping output kind → Path (or None)."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
    )
    args = argparse.Namespace(format="both", out_dir=tmp_path,
                              basename="run42", allow_tlp_red=False)
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    assert isinstance(paths, dict)
    assert paths["csv"].name == "run42.csv"
    assert paths["md"].name == "run42.md"
    assert paths["stix"] is None  # not requested


# ---------------------------------------------------------------------------
# Slice 28 — Phase 1 housekeeping: dir-OPML, path normalization, CVE validator,
# basename extension stripping, pre-write log confirmation
# ---------------------------------------------------------------------------


def test_path_arg_expands_tilde(monkeypatch):
    """_path_arg expands a leading ~ to the user's home directory."""
    import os

    import ramen_cve

    monkeypatch.setenv("HOME", "/tmp/fake-home")
    out = ramen_cve._path_arg("~/feeds")
    assert str(out) == os.path.join("/tmp/fake-home", "feeds")


def test_path_arg_strips_quotes_and_expands_tilde_together(monkeypatch):
    """A quoted ~-path round-trips cleanly through _path_arg."""
    import os

    import ramen_cve

    monkeypatch.setenv("HOME", "/tmp/fake-home")
    out = ramen_cve._path_arg('"~/Reports"')
    assert str(out) == os.path.join("/tmp/fake-home", "Reports")


def test_resolve_out_dir_handles_none_and_dot(tmp_path, monkeypatch):
    """_resolve_out_dir collapses None / '' / '.' to Path.cwd(); honors a real path."""
    import ramen_cve

    monkeypatch.chdir(tmp_path)
    assert ramen_cve._resolve_out_dir(None) == tmp_path
    from pathlib import Path

    assert ramen_cve._resolve_out_dir(Path("")) == tmp_path
    assert ramen_cve._resolve_out_dir(Path(".")) == tmp_path
    real = tmp_path / "reports"
    assert ramen_cve._resolve_out_dir(real) == real


def test_validate_opml_input_file(tmp_path):
    """A real .opml file passes the wizard validator."""
    import ramen_cve

    p = tmp_path / "feeds.opml"
    p.write_text('<?xml version="1.0"?><opml version="2.0"><body></body></opml>')
    assert ramen_cve._validate_opml_input(str(p)) is True


def test_validate_opml_input_directory_with_files(tmp_path):
    """A directory containing at least one .opml file passes."""
    import ramen_cve

    (tmp_path / "a.opml").write_text(
        '<?xml version="1.0"?><opml version="2.0"><body></body></opml>'
    )
    assert ramen_cve._validate_opml_input(str(tmp_path)) is True


def test_validate_opml_input_directory_empty_returns_error(tmp_path):
    """An empty directory fails validation with a helpful message."""
    import ramen_cve

    msg = ramen_cve._validate_opml_input(str(tmp_path))
    assert isinstance(msg, str)
    assert "no .opml files" in msg


def test_validate_opml_input_missing_path():
    """A non-existent path fails validation with a 'not found' message."""
    import ramen_cve

    msg = ramen_cve._validate_opml_input("/tmp/this-does-not-exist-ramen-test/x.opml")
    assert isinstance(msg, str)
    assert "not found" in msg.lower()


def test_validate_opml_input_empty_string():
    """Blank input fails the validator (no placeholder example in the message)."""
    import ramen_cve

    msg = ramen_cve._validate_opml_input("")
    assert isinstance(msg, str)
    # Critically, the error message must NOT contain a sample placeholder path.
    assert "examples/sample.opml" not in msg


def test_validate_opml_input_strips_quotes(tmp_path):
    """A quoted path (Windows Explorer paste) is accepted."""
    import ramen_cve

    (tmp_path / "feed.opml").write_text(
        '<?xml version="1.0"?><opml version="2.0"><body></body></opml>'
    )
    assert ramen_cve._validate_opml_input(f'"{tmp_path}"') is True


def test_collect_opml_files_single_file(tmp_path):
    """_collect_opml_files returns [path] when given a single .opml."""
    import ramen_cve

    p = tmp_path / "feeds.opml"
    p.write_text('<?xml version="1.0"?><opml version="2.0"><body></body></opml>')
    assert ramen_cve._collect_opml_files(p) == [p]


def test_collect_opml_files_directory(tmp_path):
    """A directory yields every top-level *.opml, sorted."""
    import ramen_cve

    body = '<?xml version="1.0"?><opml version="2.0"><body></body></opml>'
    (tmp_path / "z.opml").write_text(body)
    (tmp_path / "a.opml").write_text(body)
    (tmp_path / "ignored.txt").write_text("not opml")
    files = ramen_cve._collect_opml_files(tmp_path)
    assert [f.name for f in files] == ["a.opml", "z.opml"]


def test_collect_opml_files_empty_directory_raises(tmp_path):
    """An empty directory raises OpmlError with a clear message."""
    import ramen_cve
    from ramen_cve import OpmlError

    with pytest.raises(OpmlError, match="no .opml"):
        ramen_cve._collect_opml_files(tmp_path)


def test_collect_opml_files_missing_path_raises(tmp_path):
    """A non-existent path raises OpmlError."""
    import ramen_cve
    from ramen_cve import OpmlError

    with pytest.raises(OpmlError, match="not found"):
        ramen_cve._collect_opml_files(tmp_path / "no-such-file.opml")


def test_run_opml_handles_directory(tmp_path, monkeypatch):
    """End-to-end: `opml <dir>` loads every .opml file in the directory."""
    from unittest.mock import MagicMock, patch

    import ramen_cve

    opml_dir = tmp_path / "feeds"
    opml_dir.mkdir()
    (opml_dir / "a.opml").write_text(
        '<?xml version="1.0"?><opml version="2.0"><body>'
        '<outline type="rss" text="A" xmlUrl="https://a.example/feed"/>'
        "</body></opml>"
    )
    (opml_dir / "b.opml").write_text(
        '<?xml version="1.0"?><opml version="2.0"><body>'
        '<outline type="rss" text="B" xmlUrl="https://b.example/feed"/>'
        "</body></opml>"
    )

    parse_calls: list = []

    class _FakeFeed:
        bozo = 0
        entries: list = []

    def _fake_parse(url):
        parse_calls.append(url)
        return _FakeFeed()

    def _fake_get(url, params=None, headers=None, timeout=None, auth=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.text = ""
        if "epss" in url:
            resp.json.return_value = {"data": []}
        elif "known_exploited_vulnerabilities" in url:
            resp.json.return_value = {"vulnerabilities": []}
        else:
            resp.json.return_value = {"vulnerabilities": []}
        return resp

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.requests.post", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", side_effect=_fake_parse),
    ):
        rc = ramen_cve.main([
            "opml", str(opml_dir),
            "--no-cache", "--no-exploit-lookup", "--no-enrich-iocs",
            "--format", "csv", "--out-dir", str(tmp_path),
        ])
    assert rc == 0
    # Both feed URLs were processed
    assert "https://a.example/feed" in parse_calls
    assert "https://b.example/feed" in parse_calls


def test_run_opml_empty_directory_exits_nonzero(tmp_path):
    """`opml <empty-dir>` exits with code 1 and a clear log message."""
    import ramen_cve

    empty = tmp_path / "feeds"
    empty.mkdir()
    rc = ramen_cve.main([
        "opml", str(empty),
        "--no-cache", "--no-exploit-lookup", "--no-enrich-iocs",
        "--format", "csv", "--out-dir", str(tmp_path),
    ])
    assert rc == 1


def test_safe_basename_strips_known_extensions():
    """_safe_basename trims one trailing known output extension."""
    import ramen_cve

    assert ramen_cve._safe_basename("my-report.csv") == "my-report"
    assert ramen_cve._safe_basename("my-report.md") == "my-report"
    assert ramen_cve._safe_basename("findings.json") == "findings"
    assert ramen_cve._safe_basename("rule.yar") == "rule"
    assert ramen_cve._safe_basename("rule.YAR") == "rule"  # case-insensitive
    # Only ONE extension is stripped (so a doubled .tar.gz is left intact)
    assert ramen_cve._safe_basename("my-report") == "my-report"


def test_output_smart_extension_no_double_csv(tmp_path):
    """_output('--basename my-report.csv') writes my-report.csv, NOT my-report.csv.csv."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
    )
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="my-report.csv",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    assert paths["csv"].name == "my-report.csv"
    assert not (tmp_path / "my-report.csv.csv").exists()


def test_output_smart_extension_md_basename(tmp_path):
    """`--basename report.md` with --format md produces report.md, not report.md.md."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2024-0001", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=9.0, epss_score=0.5, bucket="patch_now",
    )
    args = argparse.Namespace(
        format="md", out_dir=tmp_path, basename="report.md",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    assert paths["md"].name == "report.md"


def test_output_logs_writing_before_each_write(tmp_path, caplog):
    """Each output write is announced via an INFO 'Writing X → /path/...' log."""
    import argparse
    import logging
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
    )
    args = argparse.Namespace(
        format="both", out_dir=tmp_path, basename="confirmation-test",
        allow_tlp_red=False,
    )
    with caplog.at_level(logging.INFO, logger="ramen_cve"):
        ramen_cve._output([rec], args, {"version": "0.1"})
    msgs = [r.message for r in caplog.records]
    assert any("Writing CVE CSV report" in m for m in msgs)
    assert any("Writing Markdown report" in m for m in msgs)


def test_output_default_out_dir_resolves_to_cwd(tmp_path, monkeypatch):
    """A None --out-dir resolves to Path.cwd() (no leading-period surprise)."""
    import argparse
    from datetime import date

    import ramen_cve
    from ramen_cve import EnrichedCve

    monkeypatch.chdir(tmp_path)
    rec = EnrichedCve(
        cve_id="CVE-2021-44228", source="x",
        first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=10.0, epss_score=0.97, bucket="kev_override",
    )
    args = argparse.Namespace(
        format="csv", out_dir=None, basename="run-x", allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    # File landed under cwd, not under "./"
    assert paths["csv"].parent == tmp_path


def test_wizard_validate_cve_list_accepts_valid_input():
    """Valid CVE IDs (comma- or whitespace-separated) pass the validator."""
    import ramen_cve

    assert ramen_cve._wizard_validate_cve_list("CVE-2021-44228, CVE-2021-26855") is True
    assert ramen_cve._wizard_validate_cve_list("CVE-2021-44228 CVE-2021-26855") is True
    # Case-insensitive
    assert ramen_cve._wizard_validate_cve_list("cve-2021-44228") is True


def test_wizard_validate_cve_list_rejects_empty():
    """Blank input gets a clear error (no echoed placeholder)."""
    import ramen_cve

    msg = ramen_cve._wizard_validate_cve_list("")
    assert isinstance(msg, str)
    # The error must not contain a literal CVE-YYYY-NNNNN sample placeholder.
    assert "CVE-2021-44228" not in msg


def test_wizard_validate_cve_list_rejects_invalid_tokens():
    """An invalid token surfaces a format-shape error message."""
    import ramen_cve

    msg = ramen_cve._wizard_validate_cve_list("CVE-2021-44228, not-a-cve, foo")
    assert isinstance(msg, str)
    assert "Expected CVE-YYYY-NNNN" in msg
    # The error references the OFFENDING tokens, but does not include extra
    # placeholder examples — the abstract format string is the only sample.
    assert "not-a-cve" in msg


# ---------------------------------------------------------------------------
# Slice 29 — YAML configuration presets
# ---------------------------------------------------------------------------


def test_default_config_template_ships_and_parses():
    """The bundled template at src/ramen_cve/config/config.yaml loads as a dict."""
    import ramen_cve

    assert ramen_cve.DEFAULT_CONFIG_TEMPLATE.exists()
    data = ramen_cve.load_yaml_config(str(ramen_cve.DEFAULT_CONFIG_TEMPLATE))
    assert isinstance(data, dict)
    # Sanity checks against the documented shape
    assert "output" in data
    assert "filters" in data


def test_resolve_config_path_bare_name(monkeypatch, tmp_path):
    """A bare name resolves under DEFAULT_PRESETS_DIR with .yaml appended."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    out = ramen_cve._resolve_config_path("daily-hunt")
    assert out == tmp_path / "daily-hunt.yaml"


def test_resolve_config_path_explicit_file(tmp_path):
    """A path containing a separator or .yaml is treated as a file path."""
    import ramen_cve

    p = tmp_path / "custom.yaml"
    assert ramen_cve._resolve_config_path(str(p)) == p
    # With path separator
    assert ramen_cve._resolve_config_path(f"./{p}") == Path(f"./{p}").expanduser()


def test_save_then_load_yaml_round_trip(tmp_path, monkeypatch):
    """save_yaml_config -> load_yaml_config preserves the payload structure."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    payload = {"subcommand": "opml", "opml_path": "/feeds",
               "output": {"format": "csv", "basename": "q2"}}
    written = ramen_cve.save_yaml_config("test", payload)
    assert written == tmp_path / "test.yaml"
    loaded = ramen_cve.load_yaml_config("test")
    assert loaded == payload


def test_load_yaml_config_missing_file(tmp_path, monkeypatch):
    """A missing preset raises FileNotFoundError so the CLI can return rc=1."""
    import pytest

    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        ramen_cve.load_yaml_config("nope")


def test_load_yaml_config_invalid_yaml_raises_value_error(tmp_path):
    """Malformed YAML surfaces a ValueError (not a YAMLError leak)."""
    import pytest

    import ramen_cve

    bad = tmp_path / "bad.yaml"
    bad.write_text(":\n  - this: [is\nbroken")
    with pytest.raises(ValueError):
        ramen_cve.load_yaml_config(str(bad))


def test_list_yaml_presets_returns_sorted(tmp_path, monkeypatch):
    """list_yaml_presets returns sorted *.yaml files (and nothing else)."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    (tmp_path / "zebra.yaml").write_text("subcommand: opml")
    (tmp_path / "alpha.yaml").write_text("subcommand: cve")
    (tmp_path / "ignored.txt").write_text("nope")
    out = ramen_cve.list_yaml_presets()
    assert [p.name for p in out] == ["alpha.yaml", "zebra.yaml"]


def test_apply_yaml_config_overlays_values():
    """YAML values fill argparse defaults; CLI-set values are not overwritten."""
    import argparse

    import ramen_cve

    args = argparse.Namespace(
        subcommand=None,        # unset → take YAML
        out_dir=None,           # unset → take YAML
        basename="cli-wins",    # already set → preserved
        format=None,
        cvss_threshold=None,
        epss_threshold=None,
        no_cache=False,
        quiet=False, verbose=False,
        dispatch=False, digest=False,
        no_exploit_lookup=False, no_enrich_iocs=False,
        sector=None, ioc_confidence_floor=None,
        start=None, end=None, date_mode=None,
        path=None, url=None, cves=None,
        taxii_url=None, taxii_collection=None,
        inventory=None, allow_tlp_red=False,
    )
    cfg = {
        "subcommand": "opml",
        "opml_path": "/tmp/feeds",
        "output": {"out_dir": "/tmp/reports", "basename": "yaml-loses",
                   "format": "csv"},
        "filters": {"cvss_threshold": 8.5, "epss_threshold": 0.25},
        "cache": {"no_cache": True},
        "logging": {"level": "verbose"},
    }
    ramen_cve.apply_yaml_config(args, cfg)
    assert args.subcommand == "opml"
    assert str(args.path) == "/tmp/feeds"
    assert str(args.out_dir) == "/tmp/reports"
    assert args.basename == "cli-wins"        # CLI preserved
    assert args.format == "csv"
    assert args.cvss_threshold == 8.5
    assert args.epss_threshold == 0.25
    assert args.no_cache is True
    assert args.verbose is True


def test_apply_yaml_config_email_block_populates_env(monkeypatch):
    """A YAML email block with enabled=true populates RAMEN_SMTP_* env vars."""
    import argparse

    import ramen_cve

    for k in ("RAMEN_SMTP_HOST", "RAMEN_SMTP_FROM", "RAMEN_SMTP_USER",
              "RAMEN_SMTP_PASS", "RAMEN_DIGEST_TO"):
        monkeypatch.delenv(k, raising=False)
    args = argparse.Namespace(digest=False, quiet=False, verbose=False)
    cfg = {
        "email": {
            "enabled": True,
            "smtp_host": "smtp.example",
            "smtp_from": "alice@example",
            "smtp_user": "alice",
            "smtp_pass": "hunter2",
            "fallback_recipient": "team@example",
        }
    }
    ramen_cve.apply_yaml_config(args, cfg)
    import os
    assert os.environ.get("RAMEN_SMTP_HOST") == "smtp.example"
    assert os.environ.get("RAMEN_SMTP_FROM") == "alice@example"
    assert os.environ.get("RAMEN_DIGEST_TO") == "team@example"
    # Email enabled implicitly turns on --digest mode
    assert args.digest is True


def test_args_to_yaml_payload_round_trip_through_apply():
    """A round-trip args → payload → apply_yaml_config reproduces the same args."""
    import argparse
    from datetime import date

    import ramen_cve

    original = argparse.Namespace(
        subcommand="opml",
        path=Path("/feeds"),
        url=None, cves=None,
        taxii_url=None, taxii_collection=None,
        inventory=Path("/inv.csv"),
        out_dir=Path("/reports"),
        basename="q2",
        format="csv",
        allow_tlp_red=False,
        cvss_threshold=7.0,
        epss_threshold=0.10,
        ioc_confidence_floor=0.0,
        start=date(2024, 1, 1),
        end=date(2024, 12, 31),
        date_mode="feed",
        sector="financial",
        no_exploit_lookup=True,
        no_enrich_iocs=False,
        no_cache=False,
        dispatch=False,
        quiet=False, verbose=True,
    )
    payload = ramen_cve.args_to_yaml_payload(original)
    # Sanity: subcommand survives
    assert payload["subcommand"] == "opml"
    assert payload["output"]["basename"] == "q2"

    # Build a blank args and apply
    target = argparse.Namespace(
        subcommand=None,
        path=None, url=None, cves=None,
        taxii_url=None, taxii_collection=None,
        inventory=None,
        out_dir=None, basename=None, format=None, allow_tlp_red=False,
        cvss_threshold=None, epss_threshold=None, ioc_confidence_floor=None,
        start=None, end=None, date_mode=None, sector=None,
        no_exploit_lookup=False, no_enrich_iocs=False,
        no_cache=False, dispatch=False,
        quiet=False, verbose=False,
    )
    ramen_cve.apply_yaml_config(target, payload)
    assert target.subcommand == "opml"
    assert str(target.path) == "/feeds"
    assert target.basename == "q2"
    assert target.format == "csv"
    assert target.cvss_threshold == 7.0
    assert target.epss_threshold == 0.10
    assert target.no_exploit_lookup is True
    assert target.verbose is True


def test_cli_list_configs_subcommand_prints_empty(tmp_path, monkeypatch, capsys):
    """`python threat_intel_hunter.py --list-configs` with no presets is a no-op rc=0."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    rc = ramen_cve.main(["--list-configs"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no saved presets" in out


def test_cli_list_configs_shows_existing_presets(tmp_path, monkeypatch, capsys):
    """`--list-configs` prints `<stem>\\t<path>` per preset."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    (tmp_path / "daily-hunt.yaml").write_text("subcommand: opml")
    rc = ramen_cve.main(["--list-configs"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "daily-hunt" in out


def test_cli_config_missing_returns_friendly_error(tmp_path, monkeypatch, capsys):
    """`--config noname` exits rc=1 with a "Config file not found" message on stderr."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    rc = ramen_cve.main(["--config", "noname"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Config file not found" in err


# ---------------------------------------------------------------------------
# Slice 30 — Scheduled-task generation (Windows Task Scheduler XML / cron)
# ---------------------------------------------------------------------------


def test_parse_schedule_time_valid_and_invalid():
    """_parse_schedule_time accepts HH:MM in range and rejects bad shapes."""
    import pytest

    import ramen_cve

    assert ramen_cve._parse_schedule_time("06:15") == (6, 15)
    assert ramen_cve._parse_schedule_time("23:59") == (23, 59)
    assert ramen_cve._parse_schedule_time("0:0") == (0, 0)
    for bad in ("6", "6:15:00", "ab:cd", "24:00", "12:60", ""):
        with pytest.raises(ValueError):
            ramen_cve._parse_schedule_time(bad)


def test_quote_for_task_scheduler():
    """Tokens with whitespace/quotes get wrapped; clean tokens are untouched."""
    import ramen_cve

    assert ramen_cve._quote_for_task_scheduler("--config") == "--config"
    assert ramen_cve._quote_for_task_scheduler("daily-hunt") == "daily-hunt"
    assert ramen_cve._quote_for_task_scheduler("C:\\Program Files\\x.py") == (
        '"C:\\Program Files\\x.py"'
    )
    assert ramen_cve._quote_for_task_scheduler("") == '""'


def test_emit_windows_task_xml_is_wellformed_and_has_trigger():
    """The generated XML parses, carries a daily trigger and the Exec action."""
    import argparse
    import xml.etree.ElementTree as ET

    import ramen_cve

    args = argparse.Namespace(
        action="windows-task", for_config="daily-hunt", time="06:15",
        task_name="ramen-cve-daily", python="/usr/bin/python3", output=None,
    )
    xml = ramen_cve._emit_windows_task_xml(args)
    # Must parse as valid XML
    root = ET.fromstring(xml)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.find(".//t:CalendarTrigger", ns) is not None
    assert root.find(".//t:ScheduleByDay/t:DaysInterval", ns).text == "1"
    cmd = root.find(".//t:Exec/t:Command", ns).text
    arguments = root.find(".//t:Exec/t:Arguments", ns).text
    assert cmd == "/usr/bin/python3"
    assert "--config" in arguments and "daily-hunt" in arguments
    # Trigger start time reflects --time
    sb = root.find(".//t:CalendarTrigger/t:StartBoundary", ns).text
    assert sb.endswith("T06:15:00")


def test_emit_cron_line_format():
    """The cron line is `MM HH * * * <python> <script> --config <name>`."""
    import argparse

    import ramen_cve

    args = argparse.Namespace(
        action="cron", for_config="daily-hunt", time="06:15",
        task_name="x", python="/usr/bin/python3", output=None,
    )
    line = ramen_cve._emit_cron_line(args)
    assert line.startswith("15 6 * * * /usr/bin/python3 ")
    assert "--config daily-hunt" in line
    assert line.endswith("\n")


def test_emit_cron_line_without_config():
    """Omitting --for-config produces a valid line with no --config token."""
    import argparse

    import ramen_cve

    args = argparse.Namespace(
        action="cron", for_config=None, time="09:30",
        task_name="x", python="/usr/bin/python3", output=None,
    )
    line = ramen_cve._emit_cron_line(args)
    assert line.startswith("30 9 * * * ")
    assert "--config" not in line


def test_run_schedule_writes_to_output_file(tmp_path):
    """`schedule windows-task --output FILE` writes the XML to the file, rc=0."""
    import argparse

    import ramen_cve

    out = tmp_path / "task.xml"
    args = argparse.Namespace(
        subcommand="schedule", action="windows-task", for_config="daily-hunt",
        time="06:15", task_name="ramen-cve-daily", python="/usr/bin/python3",
        output=out, quiet=False, verbose=False,
    )
    rc = ramen_cve._run_schedule(args, cache=None, api_key=None)
    assert rc == 0
    assert out.is_file()
    assert "<Task" in out.read_text()


def test_run_schedule_bad_time_returns_1(tmp_path, caplog):
    """An out-of-range --time exits rc=1 with a clear error, no file written."""
    import argparse
    import logging

    import ramen_cve

    out = tmp_path / "task.xml"
    args = argparse.Namespace(
        subcommand="schedule", action="cron", for_config=None,
        time="99:99", task_name="x", python=None, output=out,
        quiet=False, verbose=False,
    )
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve._run_schedule(args, cache=None, api_key=None)
    assert rc == 1
    assert not out.exists()
    assert any("out of range" in r.message for r in caplog.records)


def test_cli_schedule_cron_stdout(capsys):
    """End-to-end: `schedule cron --for-config x` prints a crontab line, rc=0."""
    import ramen_cve

    rc = ramen_cve.main([
        "schedule", "cron", "--for-config", "daily-hunt",
        "--time", "07:45", "--python", "/usr/bin/python3",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("45 7 * * * /usr/bin/python3 ")
    assert "--config daily-hunt" in out


def test_cli_schedule_subcommand_parses():
    """The schedule subcommand + its flags round-trip through build_parser."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args([
        "schedule", "windows-task",
        "--for-config", "weekly", "--time", "23:30",
        "--task-name", "tih-weekly",
    ])
    assert args.subcommand == "schedule"
    assert args.action == "windows-task"
    assert args.for_config == "weekly"
    assert args.time == "23:30"
    assert args.task_name == "tih-weekly"


# ---------------------------------------------------------------------------
# Slice 31 — OPML persistence + preset/opml reset
# ---------------------------------------------------------------------------


def test_save_and_load_remembered_opml_round_trip(tmp_path, monkeypatch):
    """_save_remembered_opml then _load_remembered_opml returns the same path."""
    import ramen_cve

    state = tmp_path / "last_opml.json"
    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", state)
    src = tmp_path / "feeds"
    ramen_cve._save_remembered_opml(src)
    assert state.is_file()
    assert ramen_cve._load_remembered_opml() == src


def test_load_remembered_opml_missing_returns_none(tmp_path, monkeypatch):
    """No state file → None (no exception)."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", tmp_path / "nope.json")
    assert ramen_cve._load_remembered_opml() is None


def test_load_remembered_opml_corrupt_returns_none(tmp_path, monkeypatch):
    """A corrupt state file is treated as 'nothing remembered'."""
    import ramen_cve

    state = tmp_path / "last_opml.json"
    state.write_text("{not valid json")
    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", state)
    assert ramen_cve._load_remembered_opml() is None


def test_reset_remembered_opml(tmp_path, monkeypatch):
    """_reset_remembered_opml deletes the state file and reports it."""
    import ramen_cve

    state = tmp_path / "last_opml.json"
    state.write_text('{"opml_path": "/x"}')
    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", state)
    assert ramen_cve._reset_remembered_opml() is True
    assert not state.exists()
    assert ramen_cve._reset_remembered_opml() is False  # already gone


def test_cli_opml_path_now_optional():
    """`opml` parses with no positional path (path defaults to None)."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["opml"])
    assert args.subcommand == "opml"
    assert args.path is None
    assert args.remember_opml is False
    args2 = ramen_cve.build_parser().parse_args(["opml", "x.opml", "--remember-opml"])
    assert str(args2.path) == "x.opml"
    assert args2.remember_opml is True


def test_run_opml_no_path_no_memory_errors(tmp_path, monkeypatch, caplog):
    """`opml` with no path and nothing remembered exits rc=1 with guidance."""
    import argparse
    import logging

    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", tmp_path / "none.json")
    args = argparse.Namespace(
        subcommand="opml", path=None, remember_opml=False,
        no_exploit_lookup=True, no_enrich_iocs=True, no_cache=True,
        date_mode=None, start=None, end=None,
        cvss_threshold=7.0, epss_threshold=0.10,
        format="csv", out_dir=tmp_path, basename=None, allow_tlp_red=False,
        associations_file=None, inventory=None, sector=None,
        ioc_confidence_floor=0.0, dispatch=False, digest=False,
    )
    with caplog.at_level(logging.ERROR, logger="ramen_cve"):
        rc = ramen_cve._run_opml(args, cache=ramen_cve.Cache(":memory:"), api_key=None)
    assert rc == 1
    assert any("nothing remembered" in r.message for r in caplog.records)


def test_run_opml_remembers_and_reuses(tmp_path, monkeypatch):
    """A run with --remember-opml persists the source; a later bare run reuses it."""
    from unittest.mock import MagicMock, patch

    import ramen_cve

    state = tmp_path / "last_opml.json"
    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", state)
    opml = tmp_path / "feeds.opml"
    opml.write_text(
        '<?xml version="1.0"?><opml version="2.0"><body>'
        '<outline type="rss" text="A" xmlUrl="https://a.example/feed"/>'
        "</body></opml>"
    )

    class _Feed:
        bozo = 0
        entries: list = []

    def _fake_get(url, params=None, headers=None, timeout=None, auth=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.text = ""
        resp.json.return_value = {"vulnerabilities": []}
        return resp

    common = dict(
        no_exploit_lookup=True, no_enrich_iocs=True, no_cache=True,
        date_mode=None, start=None, end=None,
        cvss_threshold=7.0, epss_threshold=0.10,
        format="csv", out_dir=tmp_path, basename=None, allow_tlp_red=False,
        associations_file=None, inventory=None, sector=None,
        ioc_confidence_floor=0.0, dispatch=False, digest=False,
    )
    import argparse

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.requests.post", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", return_value=_Feed()),
    ):
        # First run: explicit path + --remember-opml
        a1 = argparse.Namespace(subcommand="opml", path=opml,
                                remember_opml=True, **common)
        assert ramen_cve._run_opml(a1, ramen_cve.Cache(":memory:"), None) == 0
        assert state.is_file()
        # Second run: NO path — must reuse the remembered source
        a2 = argparse.Namespace(subcommand="opml", path=None,
                                remember_opml=False, **common)
        assert ramen_cve._run_opml(a2, ramen_cve.Cache(":memory:"), None) == 0


def test_delete_yaml_preset(tmp_path, monkeypatch):
    """delete_yaml_preset removes an existing preset and returns its path."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    (tmp_path / "gone.yaml").write_text("subcommand: opml")
    removed = ramen_cve.delete_yaml_preset("gone")
    assert removed == tmp_path / "gone.yaml"
    assert not (tmp_path / "gone.yaml").exists()
    assert ramen_cve.delete_yaml_preset("gone") is None  # already absent


def test_cli_reset_config(tmp_path, monkeypatch, capsys):
    """`--reset-config NAME` deletes the preset (rc=0) or errors rc=1 if absent."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "DEFAULT_PRESETS_DIR", tmp_path)
    (tmp_path / "daily.yaml").write_text("subcommand: opml")
    rc = ramen_cve.main(["--reset-config", "daily"])
    assert rc == 0
    assert "Deleted preset" in capsys.readouterr().out
    rc2 = ramen_cve.main(["--reset-config", "daily"])
    assert rc2 == 1
    assert "no such preset" in capsys.readouterr().err


def test_cli_reset_opml(tmp_path, monkeypatch, capsys):
    """`--reset-opml` clears the remembered source (rc=0 either way)."""
    import ramen_cve

    state = tmp_path / "last_opml.json"
    monkeypatch.setattr(ramen_cve, "DEFAULT_LAST_OPML_PATH", state)
    state.write_text('{"opml_path": "/x"}')
    rc = ramen_cve.main(["--reset-opml"])
    assert rc == 0
    assert "Forgot the remembered OPML" in capsys.readouterr().out
    assert not state.exists()
    rc2 = ramen_cve.main(["--reset-opml"])
    assert rc2 == 0
    assert "No remembered OPML" in capsys.readouterr().out


def test_apply_yaml_config_maps_remember_opml():
    """remember_opml: true in YAML flips args.remember_opml when CLI didn't."""
    import argparse

    import ramen_cve

    args = argparse.Namespace(remember_opml=False, quiet=False, verbose=False)
    ramen_cve.apply_yaml_config(args, {"remember_opml": True})
    assert args.remember_opml is True


def test_args_to_yaml_payload_includes_remember_opml():
    """The saved payload records remember_opml so a preset round-trips it."""
    import argparse

    import ramen_cve

    args = argparse.Namespace(
        subcommand="opml", path=Path("/feeds"), url=None, cves=None,
        taxii_url=None, taxii_collection=None, inventory=None,
        out_dir=None, basename=None, format="csv", allow_tlp_red=False,
        cvss_threshold=7.0, epss_threshold=0.10, ioc_confidence_floor=0.0,
        start=None, end=None, date_mode=None, sector=None,
        no_exploit_lookup=False, no_enrich_iocs=False, no_cache=False,
        dispatch=False, quiet=False, verbose=False, remember_opml=True,
    )
    payload = ramen_cve.args_to_yaml_payload(args)
    assert payload["remember_opml"] is True
