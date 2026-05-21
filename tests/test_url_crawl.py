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
