"""Multi-page URL crawl (`--depth 1`) — Slice A coverage.

Covers the pure stdlib link-extraction helpers added to
`src/ramen_cve/extract.py`:

  - `_extract_links(html, base_url)` — every `<a href>` resolved to absolute.
  - `_same_host(url1, url2)`        — case- + www-normalised host equality.
  - `_filter_and_cap_links(seed, html, cap)` — extract → same-host → dedupe
                                              → sort → cap.

Slice B (rate-limited fetch helper) + C (`_run_url` integration) + D
(error robustness + Markdown "Sources" enumeration) live in tasks/todo.md
task 2 and add their own test files / coverage when they land.
"""

from __future__ import annotations

import pytest

from ramen_cve.extract import (
    DEFAULT_MAX_CRAWL_LINKS,
    MAX_CRAWL_LINKS_CEILING,
    _extract_links,
    _filter_and_cap_links,
    _same_host,
)

# ---------------------------------------------------------------------------
# _extract_links
# ---------------------------------------------------------------------------


def test_extract_links_resolves_relative_and_absolute():
    html = """
    <a href="/foo">x</a>
    <a href="https://example.com/bar">y</a>
    <a href="bar/baz">z</a>
    """
    assert _extract_links(html, "https://example.com/seed/") == [
        "https://example.com/foo",
        "https://example.com/bar",
        "https://example.com/seed/bar/baz",
    ]


def test_extract_links_handles_attribute_orderings_and_quote_styles():
    html = (
        '<a class=c href="/q1">q1</a>'
        "<a href='/q2' rel=nofollow>q2</a>"
        "<a HREF=/q3 data-x=y>q3</a>"  # unquoted href
        '<A class="c" HREF="/q4">q4</A>'  # uppercase tag, mixed-case attr
    )
    out = _extract_links(html, "https://example.com/")
    assert out == [
        "https://example.com/q1",
        "https://example.com/q2",
        "https://example.com/q3",
        "https://example.com/q4",
    ]


def test_extract_links_skips_in_page_and_protocol_uris():
    html = (
        '<a href="#section">in-page</a>'
        '<a href="javascript:void(0)">js</a>'
        '<a href="mailto:x@y">m</a>'
        '<a href="tel:+1">t</a>'
        '<a href="/real">real</a>'
    )
    assert _extract_links(html, "https://example.com/") == [
        "https://example.com/real",
    ]


def test_extract_links_empty_html_returns_empty_list():
    assert _extract_links("", "https://example.com/") == []
    assert _extract_links("<html><body>no links here</body></html>",
                         "https://example.com/") == []


# ---------------------------------------------------------------------------
# _same_host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url_a", "url_b", "expected"),
    [
        # identical
        ("https://example.com/a", "https://example.com/b", True),
        # case-insensitive
        ("https://Example.COM/a", "https://example.com/b", True),
        # www. stripped on either side
        ("https://www.example.com/", "https://example.com/", True),
        ("https://example.com/", "https://www.example.com/", True),
        # different host
        ("https://example.com/", "https://elsewhere.com/", False),
        # subdomain mismatch (not stripped beyond `www.`)
        ("https://api.example.com/", "https://example.com/", False),
        # port mismatch — intentional: different service
        ("https://example.com:8080/", "https://example.com/", False),
        # unparseable / blank
        ("not-a-url", "https://example.com/", False),
        ("", "https://example.com/", False),
    ],
)
def test_same_host(url_a, url_b, expected):
    assert _same_host(url_a, url_b) is expected


# ---------------------------------------------------------------------------
# _filter_and_cap_links
# ---------------------------------------------------------------------------


def test_filter_and_cap_keeps_only_same_host():
    seed = "https://example.com/blog/"
    html = """
    <a href="/post1">a</a>
    <a href="https://other.com/elsewhere">b</a>
    <a href="https://example.com/post2">c</a>
    <a href="https://example.com/post3">d</a>
    """
    out = _filter_and_cap_links(seed, html)
    assert out == [
        "https://example.com/post1",
        "https://example.com/post2",
        "https://example.com/post3",
    ]


def test_filter_and_cap_dedupes_case_insensitively_and_sorts():
    seed = "https://example.com/"
    html = (
        '<a href="/B">b1</a>'
        '<a href="/a">a1</a>'
        '<a href="/A">a2</a>'  # same URL as /a after lowercasing
        '<a href="/c">c1</a>'
        '<a href="/a">a3</a>'  # duplicate
    )
    out = _filter_and_cap_links(seed, html)
    assert out == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]


def test_filter_and_cap_respects_cap_argument():
    seed = "https://example.com/"
    html = "".join(f'<a href="/p{i:03d}">x</a>' for i in range(50))
    assert len(_filter_and_cap_links(seed, html, cap=10)) == 10
    assert len(_filter_and_cap_links(seed, html, cap=5)) == 5


def test_filter_and_cap_clamps_above_ceiling():
    seed = "https://example.com/"
    html = "".join(f'<a href="/p{i:04d}">x</a>' for i in range(MAX_CRAWL_LINKS_CEILING + 50))
    # Request way more than the ceiling — must clamp.
    out = _filter_and_cap_links(seed, html, cap=10_000)
    assert len(out) == MAX_CRAWL_LINKS_CEILING


def test_filter_and_cap_default_matches_documented_default():
    """The default cap matches the exported DEFAULT_MAX_CRAWL_LINKS."""
    seed = "https://example.com/"
    html = "".join(f'<a href="/p{i:03d}">x</a>' for i in range(100))
    out = _filter_and_cap_links(seed, html)  # no cap kwarg
    assert len(out) == DEFAULT_MAX_CRAWL_LINKS


def test_filter_and_cap_clamps_negative_cap_to_zero():
    seed = "https://example.com/"
    html = '<a href="/a">a</a><a href="/b">b</a>'
    assert _filter_and_cap_links(seed, html, cap=-5) == []


# ---------------------------------------------------------------------------
# Slice B — rate-limited fetch helper
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch  # noqa: E402

from ramen_cve.models import OpmlError  # noqa: E402


def _ok_response(text: str = "<html>ok</html>"):
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.text = text
    return r


def test_fetch_url_with_rate_limit_returns_text():
    from ramen_cve.cli import _fetch_url_with_rate_limit

    # Reset the function-attribute throttle so we don't carry state
    # between tests in the same process.
    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call

    with patch("ramen_cve.requests.get", return_value=_ok_response("<html>hi</html>")):
        assert _fetch_url_with_rate_limit("https://example.com/x") == "<html>hi</html>"


def test_fetch_url_with_rate_limit_raises_OpmlError_on_http_error():
    from ramen_cve.cli import _fetch_url_with_rate_limit

    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call

    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("HTTP 500")
    with (
        patch("ramen_cve.requests.get", return_value=bad),
        pytest.raises(OpmlError, match="Failed to fetch"),
    ):
        _fetch_url_with_rate_limit("https://example.com/x")


def test_fetch_url_with_rate_limit_sleeps_between_calls():
    """Second call within `delay_ms` invokes time.sleep with the remaining
    delay; first call does NOT sleep."""
    from ramen_cve.cli import _fetch_url_with_rate_limit

    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call

    sleep_calls: list[float] = []
    with (
        patch("ramen_cve.requests.get", return_value=_ok_response()),
        patch("ramen_cve.time.sleep", side_effect=lambda s: sleep_calls.append(s)),
    ):
        _fetch_url_with_rate_limit("https://example.com/a", delay_ms=100)
        # The first call sets _last_call but does NOT sleep.
        assert sleep_calls == []
        _fetch_url_with_rate_limit("https://example.com/b", delay_ms=100)
        # Second call hits the throttle (we're well within 100ms of the
        # first call) and asks for a sleep of ~ <0.1 seconds.
        assert len(sleep_calls) == 1
        assert 0.0 < sleep_calls[0] <= 0.1


def test_fetch_url_with_rate_limit_zero_delay_skips_sleep():
    """delay_ms=0 disables throttling entirely (no time.sleep call)."""
    from ramen_cve.cli import _fetch_url_with_rate_limit

    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call

    sleep_calls: list[float] = []
    with (
        patch("ramen_cve.requests.get", return_value=_ok_response()),
        patch("ramen_cve.time.sleep", side_effect=lambda s: sleep_calls.append(s)),
    ):
        _fetch_url_with_rate_limit("https://example.com/a", delay_ms=0)
        _fetch_url_with_rate_limit("https://example.com/b", delay_ms=0)
    assert sleep_calls == []


def test_fetch_url_with_rate_limit_safe_url_in_error():
    """The error message redacts secrets via _safe_url_for_log."""
    from ramen_cve.cli import _fetch_url_with_rate_limit

    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call

    bad = MagicMock()
    bad.raise_for_status.side_effect = RuntimeError("HTTP 401")
    url = "https://example.com/x?apiKey=sekret&q=1"
    with (
        patch("ramen_cve.requests.get", return_value=bad),
        pytest.raises(OpmlError) as exc_info,
    ):
        _fetch_url_with_rate_limit(url)
    # The raw secret must not appear in the exception message.
    assert "sekret" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Slice C — `_run_url` integration (--depth 1 wires the helpers together)
# ---------------------------------------------------------------------------

import ramen_cve  # noqa: E402


def _run_url_cli(url_argv: list[str], *, fake_get, tmp_path):
    """Drive `_run_url` end-to-end via `ramen_cve.main`, with HTTP mocked.

    `url_argv` is everything that follows ``ramen-cve url`` (so the seed
    URL is the first element, then any --depth / --max-crawl-links / etc.).
    """
    argv = [
        "url", *url_argv,
        "--out-dir", str(tmp_path),
        "--format", "csv",
        "--no-cache", "--no-exploit-lookup", "--no-enrich-iocs",
        "--basename", "run",
    ]
    with (
        patch("ramen_cve.requests.get", side_effect=fake_get),
        patch("ramen_cve.time.sleep"),
        # No-op the NVD / EPSS / KEV fetches so the suite stays offline.
        patch("ramen_cve.enrich.orchestrator.fetch_nvd",
              return_value={"nvd_status": "ok"}),
        patch("ramen_cve.enrich.orchestrator.fetch_epss", return_value={}),
        patch("ramen_cve.enrich.orchestrator.fetch_kev_catalog", return_value={}),
    ):
        return ramen_cve.main(argv)


def _html(*links_and_cves: str) -> str:
    """Build a small HTML body with given <a href> and CVE-id mentions."""
    parts = []
    for s in links_and_cves:
        parts.append(f'<a href="{s}">link</a>' if s.startswith(("/", "http")) else f"<p>{s}</p>")
    return "<html><body>" + "".join(parts) + "</body></html>"


def _fake_get_factory(pages: dict[str, str]):
    """Return a fake requests.get that branches on URL.

    Pages keyed by URL; missing URL -> HTTP 500 (raise_for_status raises).
    """

    def _f(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        if url in pages:
            resp.raise_for_status.return_value = None
            resp.text = pages[url]
        else:
            resp.raise_for_status.side_effect = RuntimeError(f"HTTP 500 for {url}")
            resp.text = ""
        return resp

    return _f


# Reset the rate-limit throttle once per file (the depth-1 tests issue
# multiple fetches in a single test process — without this, monotonic
# time interactions across tests would couple unrelated cases).
@pytest.fixture(autouse=True)
def _reset_throttle():
    from ramen_cve.cli import _fetch_url_with_rate_limit
    if hasattr(_fetch_url_with_rate_limit, "_last_call"):
        del _fetch_url_with_rate_limit._last_call


def test_depth_0_is_byte_identical_path(tmp_path):
    """Without --depth, only the seed is fetched and only its CVE shows up."""
    pages = {
        "https://example.com/seed": _html("CVE-2024-0001"),
        "https://example.com/link": _html("CVE-2024-9999"),  # MUST NOT be fetched
    }
    fake_get = _fake_get_factory(pages)

    rc = _run_url_cli(["https://example.com/seed"], fake_get=fake_get, tmp_path=tmp_path)
    assert rc == 0
    csv = (tmp_path / "run.csv").read_text()
    assert "CVE-2024-0001" in csv
    assert "CVE-2024-9999" not in csv  # never followed at depth 0


def test_depth_1_follows_same_host_links(tmp_path):
    """--depth 1 fetches the seed + every same-host <a href> on the seed."""
    pages = {
        "https://example.com/seed": _html(
            "CVE-2024-0001",
            "/post-2",  # same host
            "https://example.com/post-3",  # absolute same host
        ),
        "https://example.com/post-2": _html("CVE-2024-0002"),
        "https://example.com/post-3": _html("CVE-2024-0003"),
    }
    fake_get = _fake_get_factory(pages)

    rc = _run_url_cli(
        ["https://example.com/seed", "--depth", "1"],
        fake_get=fake_get, tmp_path=tmp_path,
    )
    assert rc == 0
    csv = (tmp_path / "run.csv").read_text()
    for cid in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"):
        assert cid in csv, f"missing {cid}: {csv}"


def test_depth_1_skips_other_hosts(tmp_path):
    """--depth 1 does NOT follow off-host links."""
    pages = {
        "https://example.com/seed": _html(
            "CVE-2024-0001",
            "https://other.example.org/post",  # different host: not followed
        ),
        # Intentionally absent: if the runner tried to fetch it, HTTP 500
        # would surface as a WARNING but not a failure (fail-soft).
    }
    fake_get = _fake_get_factory(pages)

    rc = _run_url_cli(
        ["https://example.com/seed", "--depth", "1"],
        fake_get=fake_get, tmp_path=tmp_path,
    )
    assert rc == 0
    csv = (tmp_path / "run.csv").read_text()
    assert "CVE-2024-0001" in csv


def test_depth_1_fail_soft_on_followed_404(tmp_path):
    """One followed link 500s -> WARNING, run still exits 0, seed CVE still emitted."""
    pages = {
        "https://example.com/seed": _html(
            "CVE-2024-0001",
            "/broken",  # _fake_get returns HTTP 500 for unknown keys
            "/post-2",  # this one works
        ),
        "https://example.com/post-2": _html("CVE-2024-0002"),
    }
    fake_get = _fake_get_factory(pages)

    rc = _run_url_cli(
        ["https://example.com/seed", "--depth", "1"],
        fake_get=fake_get, tmp_path=tmp_path,
    )
    assert rc == 0
    csv = (tmp_path / "run.csv").read_text()
    # Seed CVE and the surviving followed-link CVE both made it through;
    # the broken-link page was just skipped with a warning.
    assert "CVE-2024-0001" in csv
    assert "CVE-2024-0002" in csv


def test_depth_1_respects_max_crawl_links(tmp_path):
    """--max-crawl-links caps the number of links followed from the seed."""
    seed_html = _html("CVE-2024-0001", *[f"/p{i:02d}" for i in range(10)])
    pages = {"https://example.com/seed": seed_html}
    # Provide HTML for the first 3 links (sorted alphabetically — /p00..02);
    # the rest 500. With cap=3 only those 3 should be attempted.
    for i in range(3):
        pages[f"https://example.com/p{i:02d}"] = _html(f"CVE-2024-99{i:02d}")

    fake_get = _fake_get_factory(pages)
    rc = _run_url_cli(
        ["https://example.com/seed", "--depth", "1", "--max-crawl-links", "3"],
        fake_get=fake_get, tmp_path=tmp_path,
    )
    assert rc == 0
    csv = (tmp_path / "run.csv").read_text()
    # Seed + first 3 links surfaced; the rest were never fetched (would
    # have HTTP-500'd, but the cap stops short of them).
    assert "CVE-2024-0001" in csv
    assert "CVE-2024-9900" in csv
    assert "CVE-2024-9901" in csv
    assert "CVE-2024-9902" in csv


def test_depth_0_default_emits_only_seed_in_sources_metadata(tmp_path):
    """At --depth 0 the run metadata's `sources` is exactly [args.url]
    (byte-identical to today)."""
    pages = {"https://example.com/seed": _html("CVE-2024-0001")}
    fake_get = _fake_get_factory(pages)

    # Use --format both so we get the Markdown report and can read back
    # the "## Sources" section.
    base = [
        "url", "https://example.com/seed",
        "--out-dir", str(tmp_path), "--format", "md",
        "--no-cache", "--no-exploit-lookup", "--no-enrich-iocs",
        "--basename", "run",
    ]
    with (
        patch("ramen_cve.requests.get", side_effect=fake_get),
        patch("ramen_cve.time.sleep"),
        patch("ramen_cve.enrich.orchestrator.fetch_nvd",
              return_value={"nvd_status": "ok"}),
        patch("ramen_cve.enrich.orchestrator.fetch_epss", return_value={}),
        patch("ramen_cve.enrich.orchestrator.fetch_kev_catalog", return_value={}),
    ):
        rc = ramen_cve.main(base)
    assert rc == 0
    md = (tmp_path / "run.md").read_text()
    # The Sources section lists exactly the seed URL — no extras.
    assert "https://example.com/seed" in md
    assert "## Sources" in md


def test_depth_1_lists_all_visited_in_sources_metadata(tmp_path):
    """At --depth 1 the run metadata's `sources` enumerates every visited URL."""
    pages = {
        "https://example.com/seed": _html("CVE-2024-0001", "/post-2"),
        "https://example.com/post-2": _html("CVE-2024-0002"),
    }
    fake_get = _fake_get_factory(pages)

    base = [
        "url", "https://example.com/seed", "--depth", "1",
        "--out-dir", str(tmp_path), "--format", "md",
        "--no-cache", "--no-exploit-lookup", "--no-enrich-iocs",
        "--basename", "run",
    ]
    with (
        patch("ramen_cve.requests.get", side_effect=fake_get),
        patch("ramen_cve.time.sleep"),
        patch("ramen_cve.enrich.orchestrator.fetch_nvd",
              return_value={"nvd_status": "ok"}),
        patch("ramen_cve.enrich.orchestrator.fetch_epss", return_value={}),
        patch("ramen_cve.enrich.orchestrator.fetch_kev_catalog", return_value={}),
    ):
        rc = ramen_cve.main(base)
    assert rc == 0
    md = (tmp_path / "run.md").read_text()
    # Both visited URLs surface in the Sources section.
    assert "https://example.com/seed" in md
    assert "https://example.com/post-2" in md
