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


def test_cli_invalid_cve_id_rejected():
    """A CVE ID that doesn't match the regex is rejected before any work runs."""
    import subprocess

    result = subprocess.run(
        [".venv/bin/python", "ramen_cve.py", "cve", "NOT-A-CVE"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
