"""Tests for the NVD API key bootstrap prompt and expired-key handling."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# _save_api_key_to_env
# ---------------------------------------------------------------------------


def test_save_api_key_creates_new_env(tmp_path):
    """If .env does not exist, it is created with NVD_API_KEY=<key>."""
    import ramen_cve

    env = tmp_path / ".env"
    ramen_cve._save_api_key_to_env("3c488890-269e-4cf6-a21e-e7618cbf5533", env_path=env)

    assert env.exists()
    assert env.read_text() == "NVD_API_KEY=3c488890-269e-4cf6-a21e-e7618cbf5533\n"


def test_save_api_key_replaces_existing_line(tmp_path):
    """An existing NVD_API_KEY= line is replaced, not duplicated."""
    import ramen_cve

    env = tmp_path / ".env"
    env.write_text("OTHER_VAR=keep-me\nNVD_API_KEY=old-key\nANOTHER=also-keep\n")

    ramen_cve._save_api_key_to_env("3c488890-269e-4cf6-a21e-e7618cbf5533", env_path=env)

    text = env.read_text()
    assert "OTHER_VAR=keep-me" in text
    assert "ANOTHER=also-keep" in text
    assert "NVD_API_KEY=3c488890-269e-4cf6-a21e-e7618cbf5533" in text
    assert "old-key" not in text
    # exactly one NVD_API_KEY line
    assert text.count("NVD_API_KEY=") == 1


def test_save_api_key_appends_when_missing(tmp_path):
    """If .env exists but has no NVD_API_KEY line, the line is appended."""
    import ramen_cve

    env = tmp_path / ".env"
    env.write_text("OTHER_VAR=keep-me\n")

    ramen_cve._save_api_key_to_env("3c488890-269e-4cf6-a21e-e7618cbf5533", env_path=env)

    text = env.read_text()
    assert "OTHER_VAR=keep-me" in text
    assert text.endswith("NVD_API_KEY=3c488890-269e-4cf6-a21e-e7618cbf5533\n")


def test_save_api_key_handles_no_trailing_newline(tmp_path):
    """If existing .env doesn't end with newline, the appended line still parses cleanly."""
    import ramen_cve

    env = tmp_path / ".env"
    env.write_text("OTHER_VAR=keep-me")  # no trailing \n

    ramen_cve._save_api_key_to_env("3c488890-269e-4cf6-a21e-e7618cbf5533", env_path=env)

    lines = env.read_text().splitlines()
    assert "OTHER_VAR=keep-me" in lines
    assert "NVD_API_KEY=3c488890-269e-4cf6-a21e-e7618cbf5533" in lines


# ---------------------------------------------------------------------------
# _prompt_for_api_key — non-interactive should bail out
# ---------------------------------------------------------------------------


def test_prompt_returns_none_when_non_interactive():
    """In a non-TTY context (CI, piped input), the prompt should return None."""
    import ramen_cve

    with patch("ramen_cve._is_interactive", return_value=False):
        assert ramen_cve._prompt_for_api_key() is None
        assert ramen_cve._prompt_for_api_key(reason="expired") is None


# ---------------------------------------------------------------------------
# _prompt_for_api_key — interactive happy path with mocked questionary
# ---------------------------------------------------------------------------


def test_prompt_enter_key_saves_to_env(tmp_path, monkeypatch):
    """User picks 'enter', pastes a valid key → key is saved to .env and returned."""
    import ramen_cve

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ramen_cve, "ENV_FILE_PATH", tmp_path / ".env")

    fake_q = MagicMock()
    enter_choice = MagicMock()
    enter_choice.unsafe_ask.return_value = "enter"
    fake_q.select.return_value = enter_choice
    pw_prompt = MagicMock()
    pw_prompt.unsafe_ask.return_value = "3c488890-269e-4cf6-a21e-e7618cbf5533"
    fake_q.password.return_value = pw_prompt
    fake_q.Choice.side_effect = lambda label, value=None: value if value is not None else label

    with (
        patch("ramen_cve._is_interactive", return_value=True),
        patch.dict("sys.modules", {"questionary": fake_q}),
    ):
        key = ramen_cve._prompt_for_api_key(reason="missing")

    assert key == "3c488890-269e-4cf6-a21e-e7618cbf5533"
    saved = (tmp_path / ".env").read_text()
    assert "NVD_API_KEY=3c488890-269e-4cf6-a21e-e7618cbf5533" in saved


def test_prompt_skip_returns_none(tmp_path, monkeypatch):
    """User picks 'skip' → no key saved, returns None."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "ENV_FILE_PATH", tmp_path / ".env")

    fake_q = MagicMock()
    skip_choice = MagicMock()
    skip_choice.unsafe_ask.return_value = "skip"
    fake_q.select.return_value = skip_choice
    fake_q.Choice.side_effect = lambda label, value=None: value if value is not None else label

    with (
        patch("ramen_cve._is_interactive", return_value=True),
        patch.dict("sys.modules", {"questionary": fake_q}),
    ):
        key = ramen_cve._prompt_for_api_key(reason="missing")

    assert key is None
    assert not (tmp_path / ".env").exists()


def test_prompt_keyboard_interrupt_returns_none(tmp_path, monkeypatch):
    """Ctrl-C during the prompt returns None instead of bubbling the exception."""
    import ramen_cve

    monkeypatch.setattr(ramen_cve, "ENV_FILE_PATH", tmp_path / ".env")

    fake_q = MagicMock()
    fake_q.select.side_effect = KeyboardInterrupt()
    fake_q.Choice.side_effect = lambda label, value=None: value if value is not None else label

    with (
        patch("ramen_cve._is_interactive", return_value=True),
        patch.dict("sys.modules", {"questionary": fake_q}),
    ):
        assert ramen_cve._prompt_for_api_key() is None


# ---------------------------------------------------------------------------
# fetch_nvd — auth_error surfaced on 401/403 and NOT cached
# ---------------------------------------------------------------------------


def _mem_cache():
    import ramen_cve

    return ramen_cve.Cache(":memory:")


def test_fetch_nvd_returns_auth_error_on_403(caplog):
    """A 403 response sets nvd_status='auth_error' and is not cached."""
    import ramen_cve

    cache = _mem_cache()
    if hasattr(ramen_cve.fetch_nvd, "_last_call"):
        del ramen_cve.fetch_nvd._last_call

    resp = MagicMock()
    resp.status_code = 403
    resp.raise_for_status.return_value = None

    with (
        patch("ramen_cve.requests.get", return_value=resp),
        patch("ramen_cve.time.sleep"),
        caplog.at_level(logging.WARNING, logger="ramen_cve"),
    ):
        result = ramen_cve.fetch_nvd("CVE-2021-44228", cache, api_key="bogus-key")

    assert result["nvd_status"] == "auth_error"
    # Confirm no cache entry was written
    assert cache.get_nvd("CVE-2021-44228") is None
    assert any("rejected the API key" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# enrich_cves — re-prompts once on first auth_error
# ---------------------------------------------------------------------------


def test_enrich_cves_reprompts_on_auth_error(tmp_path):
    """First NVD call returns 403 → _prompt_for_api_key is called once and the new key is used."""
    from datetime import date as _date

    import ramen_cve
    from ramen_cve import CveRecord, enrich_cves

    cache = _mem_cache()
    if hasattr(ramen_cve.fetch_nvd, "_last_call"):
        del ramen_cve.fetch_nvd._last_call

    log4shell = json_load("nvd_log4shell_v31.json")
    epss = json_load("epss_batch.json")

    call_count = {"n": 0}

    def _fake_get(url, params=None, headers=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "epss" in url:
            resp.status_code = 200
            resp.json.return_value = epss
            return resp
        # NVD: first call returns 403, subsequent calls return data
        call_count["n"] += 1
        if call_count["n"] == 1:
            resp.status_code = 403
        else:
            resp.status_code = 200
            resp.json.return_value = log4shell
        return resp

    records = [CveRecord("CVE-2021-44228", "test", _date(2024, 1, 1), "feed_pub")]

    new_key = "11111111-2222-3333-4444-555555555555"
    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("ramen_cve._prompt_for_api_key", return_value=new_key) as prompt_mock,
    ):
        result = enrich_cves(records, cache, api_key="bogus-key")

    prompt_mock.assert_called_once()
    assert prompt_mock.call_args.kwargs == {"reason": "expired"}
    assert len(result) == 1
    # After the re-prompt + retry, the CVSS score from the fixture should appear
    assert result[0].cvss_score == 10.0


def json_load(name: str):
    """Load a fixture JSON file (relative to tests/fixtures/)."""
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "fixtures" / name).read_text())
