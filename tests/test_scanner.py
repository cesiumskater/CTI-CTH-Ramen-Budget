"""Vulnerability-scanner import (src/ramen_cve/scanner.py + the `import`
subcommand).

Invariants under test:
  * _cpe_product_version parses CPE 2.2 and 2.3, blanks wildcard/NA versions,
    and returns ("","") for non-CPE input.
  * import_nessus: host label prefers FQDN > rdns > name attr; CPEs collected
    from both HostProperties cpe* tags and ReportItem/cpe; (host,cpe) pairs
    de-duped; rows sorted; product/version derived; owner/criticality blank.
  * Degradation: missing file and malformed XML raise OpmlError; an empty
    report yields [] .
  * import_scan dispatches nessus and rejects an unknown format.
  * Output round-trips: written CSV loads back through load_inventory, and an
    imported row correlates a CVE by CPE end-to-end.
  * CLI: import → stdout / --out file / bad file rc=1 / parser wiring.
  * Facade re-exports the public surface.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import ramen_cve
from ramen_cve.enrich.inventory import correlate_inventory, load_inventory
from ramen_cve.models import OpmlError
from ramen_cve.scanner import (
    INVENTORY_COLUMNS,
    SCANNER_FORMATS,
    _cpe_product_version,
    import_nessus,
    import_scan,
)

_NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2><Report name="scan">
  <ReportHost name="10.0.0.5">
    <HostProperties>
      <tag name="host-fqdn">web01.example.com</tag>
      <tag name="cpe">cpe:/a:apache:http_server:2.4.49</tag>
      <tag name="cpe-0">cpe:/o:linux:linux_kernel</tag>
    </HostProperties>
    <ReportItem port="443" pluginID="12345" pluginName="x">
      <cve>CVE-2021-41773</cve>
      <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
    </ReportItem>
    <ReportItem port="0" pluginID="45590" pluginName="CPE">
      <cpe>cpe:/a:openssl:openssl:1.1.1</cpe>
    </ReportItem>
  </ReportHost>
  <ReportHost name="10.0.0.6">
    <HostProperties>
      <tag name="cpe">cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*</tag>
    </HostProperties>
  </ReportHost>
</Report></NessusClientData_v2>
"""


def _write(tmp_path: Path, text: str, name: str = "s.nessus") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _cpe_product_version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:/a:apache:http_server:2.4.49", ("http_server", "2.4.49")),
    ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", ("http_server", "2.4.49")),
    ("cpe:/o:linux:linux_kernel", ("linux_kernel", "")),           # no version slot
    ("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*", ("openssh", "8.2")),
    ("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", ("p", "")),                  # wildcard version → ""
    ("cpe:2.3:a:v:p:-:*:*:*:*:*:*:*", ("p", "")),                  # NA version → ""
    ("not-a-cpe", ("", "")),
])
def test_cpe_product_version(cpe, expected):
    assert _cpe_product_version(cpe) == expected


# ---------------------------------------------------------------------------
# import_nessus
# ---------------------------------------------------------------------------


def test_import_nessus_extracts_hosts_and_cpes(tmp_path):
    rows = import_nessus(_write(tmp_path, _NESSUS))
    # 3 CPEs on web01 (fqdn preferred over the 10.0.0.5 name attr) + 1 on 10.0.0.6
    assert len(rows) == 4
    by_host: dict[str, list[str]] = {}
    for r in rows:
        by_host.setdefault(r["host"], []).append(r["cpe"])
    assert "web01.example.com" in by_host          # FQDN beat the IP name attr
    assert "10.0.0.5" not in by_host
    assert "10.0.0.6" in by_host
    assert len(by_host["web01.example.com"]) == 3  # 2 tags + 1 ReportItem cpe


def test_import_nessus_rows_sorted_and_have_all_columns(tmp_path):
    rows = import_nessus(_write(tmp_path, _NESSUS))
    keys = [(r["host"], r["cpe"]) for r in rows]
    assert keys == sorted(keys)
    for r in rows:
        assert set(r.keys()) == set(INVENTORY_COLUMNS)
        assert r["owner"] == "" and r["criticality"] == ""


def test_import_nessus_dedupes_host_cpe_pairs(tmp_path):
    """The apache CPE appears in both a HostProperties tag and a ReportItem —
    it must collapse to one row for the host."""
    rows = import_nessus(_write(tmp_path, _NESSUS))
    apache = [r for r in rows if "http_server" in r["cpe"]]
    assert len(apache) == 1


def test_import_nessus_prefers_rdns_when_no_fqdn(tmp_path):
    xml = """<NessusClientData_v2><Report name="s"><ReportHost name="1.2.3.4">
      <HostProperties>
        <tag name="host-rdns">box.local</tag>
        <tag name="cpe">cpe:/a:x:y:1</tag>
      </HostProperties></ReportHost></Report></NessusClientData_v2>"""
    rows = import_nessus(_write(tmp_path, xml))
    assert rows[0]["host"] == "box.local"


def test_import_nessus_falls_back_to_name_attr(tmp_path):
    xml = """<NessusClientData_v2><Report name="s"><ReportHost name="9.9.9.9">
      <HostProperties><tag name="cpe">cpe:/a:x:y:1</tag></HostProperties>
      </ReportHost></Report></NessusClientData_v2>"""
    rows = import_nessus(_write(tmp_path, xml))
    assert rows[0]["host"] == "9.9.9.9"


def test_import_nessus_empty_report_returns_empty(tmp_path):
    xml = "<NessusClientData_v2><Report name='s'></Report></NessusClientData_v2>"
    assert import_nessus(_write(tmp_path, xml)) == []


def test_import_nessus_missing_file_raises(tmp_path):
    with pytest.raises(OpmlError, match="not found"):
        import_nessus(tmp_path / "nope.nessus")


def test_import_nessus_malformed_xml_raises(tmp_path):
    with pytest.raises(OpmlError, match="parse"):
        import_nessus(_write(tmp_path, "<NessusClientData_v2><Report</bad>"))


def test_import_nessus_ignores_non_cpe_tags(tmp_path):
    """A host with only non-CPE properties yields no rows."""
    xml = """<NessusClientData_v2><Report name="s"><ReportHost name="h">
      <HostProperties><tag name="operating-system">Linux</tag></HostProperties>
      </ReportHost></Report></NessusClientData_v2>"""
    assert import_nessus(_write(tmp_path, xml)) == []


# ---------------------------------------------------------------------------
# import_scan dispatch
# ---------------------------------------------------------------------------


def test_import_scan_dispatches_nessus(tmp_path):
    assert len(import_scan(_write(tmp_path, _NESSUS), "nessus")) == 4


def test_import_scan_rejects_unknown_format(tmp_path):
    with pytest.raises(OpmlError, match="Unknown scanner format"):
        import_scan(_write(tmp_path, _NESSUS), "qualys")


def test_nessus_is_a_supported_format():
    assert "nessus" in SCANNER_FORMATS


# ---------------------------------------------------------------------------
# Round-trip + correlation
# ---------------------------------------------------------------------------


def test_written_csv_round_trips_through_load_inventory(tmp_path):
    rows = import_nessus(_write(tmp_path, _NESSUS))
    out = tmp_path / "inv.csv"
    ramen_cve.write_inventory_csv(rows, out)
    loaded = load_inventory(out)
    assert [r["cpe"] for r in loaded] == [r["cpe"] for r in rows]


def test_imported_inventory_correlates_a_cve_by_cpe(tmp_path):
    """End-to-end value: an imported host is attributed to a matching CVE."""
    rows = import_nessus(_write(tmp_path, _NESSUS))
    out = tmp_path / "inv.csv"
    ramen_cve.write_inventory_csv(rows, out)
    inv = load_inventory(out)
    rec = ramen_cve.EnrichedCve(
        cve_id="CVE-2021-41773", source="x", first_seen=__import__("datetime").date(2024, 1, 1),
        first_seen_type="feed_pub",
        cpes=["cpe:/a:apache:http_server:2.4.49"],
    )
    correlate_inventory([rec], inv)
    assert "web01.example.com" in rec.affected_hosts


# ---------------------------------------------------------------------------
# CLI wiring (cache pinned to tmp so no real-DB side effects)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _pin_cache(tmp_path, monkeypatch):
    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(tmp_path / "cache.db"))


def test_parser_wires_import_subcommand():
    args = ramen_cve.build_parser().parse_args(["import", "scan.nessus", "--scanner", "nessus"])
    assert args.subcommand == "import"
    assert args.scanner == "nessus"


def test_cli_import_to_stdout(_pin_cache, tmp_path, capsys):
    rc = ramen_cve.main(["import", str(_write(tmp_path, _NESSUS))])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.splitlines()[0] == "host,product,version,cpe,owner,criticality"
    assert "web01.example.com" in out


def test_cli_import_to_out_file(_pin_cache, tmp_path):
    out = tmp_path / "inv.csv"
    rc = ramen_cve.main(["import", str(_write(tmp_path, _NESSUS)), "--out", str(out)])
    assert rc == 0
    assert load_inventory(out)          # non-empty, parseable


def test_cli_import_missing_file_returns_1(_pin_cache, tmp_path):
    rc = ramen_cve.main(["import", str(tmp_path / "ghost.nessus")])
    assert rc == 1


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


def test_facade_reexports_scanner_surface():
    assert ramen_cve.import_nessus is import_nessus
    assert ramen_cve.import_scan is import_scan
    assert ramen_cve._cpe_product_version is _cpe_product_version
    assert ramen_cve.SCANNER_FORMATS == SCANNER_FORMATS
    assert ramen_cve.INVENTORY_COLUMNS == INVENTORY_COLUMNS
