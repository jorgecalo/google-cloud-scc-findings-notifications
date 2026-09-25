"""Unit tests for the SCC to Slack Cloud Run function.

Run from the repository root:
    python -m venv .venv && . .venv/bin/activate
    pip install -r app/scc-finding-slack-notifications/requirements.txt pytest
    pytest
"""

import base64
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app" / "scc-finding-slack-notifications"))
sys.dont_write_bytecode = True

import main  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def sha():
    return load("sha_private_google_access.json")


@pytest.fixture
def etd():
    return load("etd_v2_malware_bad_ip.json")


def block_texts(blocks):
    return [b["text"]["text"] for b in blocks if "text" in b]


def all_text(blocks):
    return "\n".join(block_texts(blocks))


# --- Formatting -------------------------------------------------------------

def test_sha_finding_renders_all_sections(sha):
    blocks = main.build_blocks(sha)
    text = all_text(blocks)
    assert "PRIVATE_GOOGLE_ACCESS_DISABLED" in text
    assert "*Project*: example-project-01" in text
    assert ":warning:" in text
    assert "*Explanation:*" in text and "*Recommendation:*" in text
    assert "`allow_private_google_access_disabled`" in text
    # eventTime is preferred over createTime.
    assert "2021-02-13T23:00:06.039628Z" in text
    assert blocks[-1] == {"type": "divider"}


def test_no_placeholders_left(sha, etd):
    for payload in (sha, etd):
        dumped = json.dumps(main.build_blocks(payload))
        for key in main.PLACEHOLDER_KEYS:
            assert f"<{key}>" not in dumped


def test_threat_finding_uses_description_and_next_steps(etd):
    blocks = main.build_blocks(etd)
    text = all_text(blocks)
    assert "null" not in text
    assert "known to be associated with malware" in text
    assert "isolate it" in text
    assert "*Instructions:*" not in text  # no ExceptionInstructions: block dropped
    assert ":rotating_light:" in text
    assert "*Resource*: web-frontend-1" in text


def test_slack_control_characters_are_escaped(etd):
    text = all_text(main.build_blocks(etd))
    assert "malware &amp; botnets &lt;C2&gt;" in text


def test_missing_source_properties_does_not_crash(sha):
    del sha["finding"]["sourceProperties"]
    text = all_text(main.build_blocks(sha))
    assert "*Explanation:*" not in text
    assert "PRIVATE_GOOGLE_ACCESS_DISABLED" in text


def test_missing_resource_and_category(sha):
    del sha["resource"]
    del sha["finding"]["category"]
    text = all_text(main.build_blocks(sha))
    assert "Unknown category" in text
    assert "*Project*: n/a" in text


def test_non_string_source_property(sha):
    sha["finding"]["sourceProperties"]["Explanation"] = {"a": 1}
    assert '{"a": 1}' in all_text(main.build_blocks(sha))


def test_long_sections_are_truncated(sha):
    sha["finding"]["sourceProperties"]["Recommendation"] = "x" * 5000
    for text in block_texts(main.build_blocks(sha)):
        assert len(text) <= main.SLACK_SECTION_TEXT_LIMIT


def test_template_is_not_mutated_between_calls(sha, etd):
    main.build_blocks(sha)
    second = all_text(main.build_blocks(etd))
    assert "PRIVATE_GOOGLE_ACCESS_DISABLED" not in second


# --- Console links ----------------------------------------------------------

@pytest.mark.parametrize("name, expected", [
    ("organizations/1/sources/2/findings/3", "organizationId=1"),
    ("organizations/1/sources/2/locations/global/findings/3", "organizationId=1"),
    ("projects/9/sources/2/findings/3", "project=9"),
    ("folders/7/sources/2/locations/global/findings/3", "folder=7"),
])
def test_console_url_scopes(name, expected):
    url = main.console_url(name)
    assert expected in url
    assert f"resourceId={name}" in url


def test_console_url_handles_missing_name():
    assert main.console_url(None) == main.CONSOLE_FINDINGS_URL


# --- Project allowlist & CVE filtering -------------------------------------

@pytest.fixture(autouse=True)
def clear_cve_dedup_cache():
    main._recent_cve_alerts_cache.clear()


def make_cve_finding(
    cve_id="CVE-2021-44228",
    exploitability="WIDE",
    impact="CRITICAL",
    severity="CRITICAL",
    project="example-project-01",
):
    return {
        "finding": {
            "name": f"organizations/111111111111/sources/222/findings/{cve_id}",
            "state": "ACTIVE",
            "severity": severity,
            "findingClass": "VULNERABILITY",
            "category": "SOFTWARE_VULNERABILITY",
            "vulnerability": {
                "cve": {
                    "id": cve_id,
                    "exploitationActivity": exploitability,
                    "impact": impact,
                    "upstreamFixAvailable": True,
                    "cvssv3": {"baseScore": 9.8},
                },
                "offendingPackage": {"packageName": "openssl", "version": "3.0.0"},
                "fixedPackage": {"packageName": "openssl", "version": "3.0.7"},
            },
        },
        "resource": {"projectDisplayName": project},
    }


def test_allowlist_empty_allows_all(sha, monkeypatch):
    monkeypatch.delenv("ALLOWED_PROJECTS", raising=False)
    assert main.should_notify(sha)


@pytest.mark.parametrize("value, allowed", [
    ("example-project-01", True),
    ("other, 222222222222", True),
    ("other-project", False),
])
def test_allowlist(sha, monkeypatch, value, allowed):
    monkeypatch.setenv("ALLOWED_PROJECTS", value)
    assert main.should_notify(sha) is allowed


@pytest.mark.parametrize("cve_id, exploitability, impact, expected", [
    ("CVE-2021-44228", "WIDE", "CRITICAL", True),
    ("CVE-2025-15467", "AVAILABLE", "HIGH", True),
    ("CVE-2026-45447", "NO_KNOWN", "HIGH", False),
    ("CVE-2022-23307", "ANTICIPATED", "CRITICAL", False),
    ("CVE-2023-0001", "AVAILABLE", "MEDIUM", False),
])
def test_cve_exploitability_and_impact_filtering(cve_id, exploitability, impact, expected):
    payload = make_cve_finding(cve_id=cve_id, exploitability=exploitability, impact=impact)
    assert main.should_notify(payload) is expected


def test_cve_organization_wide_deduplication():
    first = make_cve_finding("CVE-2025-15467", "AVAILABLE", "HIGH", project="proj-1")
    second_diff_proj = make_cve_finding("CVE-2025-15467", "AVAILABLE", "HIGH", project="proj-2")
    assert main.should_notify(first) is True
    assert main.should_notify(second_diff_proj) is False


def test_cve_blocks_include_exploitability_and_impact():
    payload = make_cve_finding("CVE-2021-44228", "WIDE", "CRITICAL")
    text = all_text(main.build_blocks(payload))
    assert "[WIDE EXPLOIT | CRITICAL IMPACT] CVE-2021-44228" in text
    assert "*Exploitability*: *WIDE* | *Impact*: *CRITICAL*" in text
    assert "Upgrade package openssl to 3.0.7." in text


# --- Slack API handling -----------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, body=None, json_error=False):
        self.status_code = status
        self._body = body if body is not None else {"ok": True}
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.calls = response, exc, []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.exc:
            raise self.exc
        return self.response


def test_post_success_sends_expected_payload(sha):
    session = FakeSession(FakeResponse())
    main.handle_notification(sha, token="xoxb-test\n", channel="C123", session=session)
    url, kwargs = session.calls[0]
    body = json.loads(kwargs["data"])
    assert url == main.SLACK_API_URL
    assert kwargs["headers"]["Authorization"] == "Bearer xoxb-test"
    assert kwargs["timeout"] == main.SLACK_TIMEOUT_SECONDS
    assert body["channel"] == "C123"
    assert body["unfurl_links"] is False
    assert "PRIVATE_GOOGLE_ACCESS_DISABLED" in body["text"]


@pytest.mark.parametrize("error", ["invalid_auth", "channel_not_found", "invalid_blocks", "not_in_channel"])
def test_slack_ok_false_is_permanent(sha, error):
    session = FakeSession(FakeResponse(200, {"ok": False, "error": error}))
    with pytest.raises(main.PermanentError, match=error):
        main.handle_notification(sha, token="t", channel="c", session=session)


@pytest.mark.parametrize("response, exc", [
    (FakeResponse(429), None),
    (FakeResponse(503), None),
    (FakeResponse(200, {"ok": False, "error": "ratelimited"}), None),
    (FakeResponse(200, json_error=True), None),
    (None, requests.ConnectionError("boom")),
])
def test_transient_errors_raise(sha, response, exc):
    with pytest.raises(main.TransientError):
        main.handle_notification(sha, token="t", channel="c",
                                 session=FakeSession(response, exc))


def test_missing_configuration_is_permanent(sha, monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("SLACK_CHANNEL", raising=False)
    with pytest.raises(main.PermanentError):
        main.handle_notification(sha, session=FakeSession(FakeResponse()))


def test_skipped_project_does_not_call_slack(sha, monkeypatch):
    monkeypatch.setenv("ALLOWED_PROJECTS", "other")
    session = FakeSession(FakeResponse())
    assert main.handle_notification(sha, token="t", channel="c", session=session) is False
    assert session.calls == []


# --- Entry point ------------------------------------------------------------

class FakeCloudEvent(dict):
    def __init__(self, data, time):
        super().__init__(id="evt-1", time=time)
        self.data = data


def make_event(payload, age=timedelta(seconds=5)):
    time = (datetime.now(timezone.utc) - age).isoformat().replace("+00:00", "Z")
    data = {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode()}}
    return FakeCloudEvent(data, time)


@pytest.fixture
def entry(monkeypatch):
    fn = main._entry_point
    monkeypatch.setenv("SLACK_BOT_TOKEN", "t")
    monkeypatch.setenv("SLACK_CHANNEL", "c")
    monkeypatch.delenv("ALLOWED_PROJECTS", raising=False)
    return fn


def test_entry_point_posts(entry, sha, monkeypatch):
    calls = []
    monkeypatch.setattr(main, "post_to_slack", lambda *a, **k: calls.append(a))
    entry(make_event(sha))
    assert len(calls) == 1


def test_entry_point_reraises_transient(entry, sha, monkeypatch):
    def fail(*a, **k):
        raise main.TransientError("try again")
    monkeypatch.setattr(main, "post_to_slack", fail)
    with pytest.raises(main.TransientError):
        entry(make_event(sha))


def test_entry_point_swallows_permanent(entry, sha, monkeypatch, capsys):
    def fail(*a, **k):
        raise main.PermanentError("bad token")
    monkeypatch.setattr(main, "post_to_slack", fail)
    entry(make_event(sha))
    assert '"severity": "ERROR"' in capsys.readouterr().out


def test_entry_point_drops_old_events(entry, sha, monkeypatch):
    calls = []
    monkeypatch.setattr(main, "post_to_slack", lambda *a, **k: calls.append(a))
    entry(make_event(sha, age=timedelta(hours=2)))
    assert calls == []


def test_entry_point_bad_payload_is_not_retried(entry, capsys):
    entry(FakeCloudEvent({"message": {"data": "not-base64!!"}}, datetime.now(timezone.utc).isoformat()))
    assert "Permanent failure" in capsys.readouterr().out


def test_functions_framework_entry_point_is_registered():
    pytest.importorskip("functions_framework")
    assert callable(main.send_slack_chat_notification)
