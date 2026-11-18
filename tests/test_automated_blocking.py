"""Blocking: the guard rails first, then each target.

A fake session records every request, so the tests can prove what would have
been sent and that a dry run sends nothing at all.
"""

import io
import json

import pytest
import requests

import automated_blocking
from automated_blocking import Indicator, NeverBlock, normalize

IP = "45.33.32.156"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
WAZUH_ENV = {"WAZUH_API_URL": "https://wazuh.lab:55000", "WAZUH_API_USER": "wazuh-wui", "WAZUH_API_PASSWORD": "pw"}


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


class FakeSession:
    """Answers requests from a list of (method, url fragment, response or exception)."""

    def __init__(self, *routes):
        self.routes = list(routes)
        self.calls = []

    def request(self, method, url, **options):
        self.calls.append({"method": method, "url": url, **options})
        for route_method, fragment, answer in self.routes:
            if route_method == method and fragment in url:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise AssertionError(f"unexpected request: {method} {url}")


def run_cli(args, tmp_path, environment=None, session=None, capsys=None):
    session = session or FakeSession()
    code = automated_blocking.main([*args, "--blocklist-dir", str(tmp_path / "lists")],
                                   environment=environment or {}, session=session)
    captured = capsys.readouterr() if capsys else None
    results = json.loads(captured.out) if captured and captured.out.strip().startswith("[") else []
    return code, results, session, captured


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


# -------------------------------------------------------------------- dry run

def test_nothing_happens_without_execute(tmp_path, capsys):
    session = FakeSession()
    code, results, session, captured = run_cli(
        ["--type", "ip", "--value", IP, "--target", "blocklist", "wazuh", "--agents", "001"],
        tmp_path, WAZUH_ENV, session, capsys)
    assert code == 0
    assert [(r["target"], r["status"]) for r in results] == [("blocklist", "planned"), ("wazuh", "planned")]
    assert "firewall-drop on agents 001" in results[1]["message"]
    assert session.calls == []
    assert not (tmp_path / "lists").exists()
    assert "Dry run: nothing was changed" in captured.err


def test_execute_and_dry_run_together_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as error:
        automated_blocking.main(["--type", "ip", "--value", IP, "--execute", "--dry-run"], environment={})
    assert error.value.code == 2


# ------------------------------------------------------------------ blocklist

def test_block_and_unblock_keep_the_list_sorted_and_unique(tmp_path, capsys):
    for value in ("9.9.9.9", IP, "9.9.9.9"):
        code, results, _, _ = run_cli(["--type", "ip", "--value", value, "--execute"], tmp_path, capsys=capsys)
        assert code == 0
    assert results[0]["message"] == "already listed"
    target = tmp_path / "lists" / "blocked_ips.txt"
    assert lines(target) == ["45.33.32.156", "9.9.9.9"]

    code, results, _, _ = run_cli(["--action", "unblock", "--type", "ip", "--value", "9.9.9.9", "--execute"],
                                  tmp_path, capsys=capsys)
    assert code == 0 and results[0]["message"] == "removed from blocked_ips.txt"
    assert lines(target) == ["45.33.32.156"]

    code, results, _, _ = run_cli(["--action", "unblock", "--type", "ip", "--value", "9.9.9.9", "--execute"],
                                  tmp_path, capsys=capsys)
    assert code == 0 and results[0]["message"] == "was not listed"
    assert sorted(path.name for path in (tmp_path / "lists").iterdir()) == ["audit.jsonl", "blocked_ips.txt"]


def test_each_type_goes_to_its_own_file_and_values_are_normalized(tmp_path, capsys):
    source = tmp_path / "iocs.json"
    source.write_text(json.dumps({
        "ipv4": [IP], "ipv6": ["2001:4860:4860:0:0:0:0:8888"], "domains": ["Evil.Example.COM."],
        "sha256_hashes": [SHA256.upper()], "md5_hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "urls": ["https://evil.example.com/a"], "emails": ["a@evil.example.com"],
    }), encoding="utf-8")
    code, results, _, captured = run_cli(["--input", str(source), "--execute", "--comment", "INC-1042"], tmp_path,
                                         capsys=capsys)
    assert code == 0 and {r["status"] for r in results} == {"done"}
    folder = tmp_path / "lists"
    assert lines(folder / "blocked_ips.txt") == ["2001:4860:4860::8888", "45.33.32.156"]
    assert lines(folder / "blocked_domains.txt") == ["evil.example.com"]
    assert lines(folder / "blocked_hashes.txt") == ["d41d8cd98f00b204e9800998ecf8427e", SHA256]
    assert captured.err.count("skipped: this type cannot be blocked") == 2
    audit = [json.loads(line) for line in lines(folder / "audit.jsonl")]
    assert len(audit) == 5 and {entry["comment"] for entry in audit} == {"INC-1042"}
    assert {entry["action"] for entry in audit} == {"block"} and all(entry["timestamp"].endswith("Z") for entry in audit)


def test_a_blocklist_that_cannot_be_written_is_a_failure(tmp_path, capsys):
    (tmp_path / "lists").write_text("this is a file, not a folder", encoding="utf-8")
    code, results, _, captured = run_cli(["--type", "ip", "--value", IP, "--execute"], tmp_path, capsys=capsys)
    assert code == 1
    assert results[0]["status"] == "failed" and "cannot update" in results[0]["message"]
    assert "the audit log could not be written" in captured.err
    assert (tmp_path / "lists").read_text(encoding="utf-8") == "this is a file, not a folder"


def test_no_temporary_files_are_left_behind(tmp_path, capsys):
    for value in (IP, "9.9.9.9", "8.8.8.8"):
        run_cli(["--type", "ip", "--value", value, "--execute"], tmp_path, capsys=capsys)
    assert sorted(path.name for path in (tmp_path / "lists").iterdir()) == ["audit.jsonl", "blocked_ips.txt"]


# ---------------------------------------------------------------- guard rails

@pytest.mark.parametrize("kind, value, reason", [
    ("ip", "999.1.1.1", "not an IP address"),
    ("ip", "45.33.32.0/24", "ranges are not accepted"),
    ("ip", "evil.example.com", "not an IP address"),
    ("domain", "not a domain", "not a valid domain"),
    ("domain", "45.33.32.156", "not a valid domain"),
    ("domain", "invoice.pdf", "not a valid domain"),
    ("hash", "abc123", "not an MD5"),
    ("hash", "z" * 64, "not an MD5"),
])
def test_values_that_are_not_what_they_claim_are_refused(kind, value, reason, tmp_path, capsys):
    indicator, problem = normalize(kind, value)
    assert indicator is None and reason in problem
    code, results, _, _ = run_cli(["--type", kind, "--value", value, "--execute"], tmp_path, capsys=capsys)
    assert code == 1 and results[0]["status"] == "refused"
    assert not (tmp_path / "lists").exists()


@pytest.mark.parametrize("value", ["10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1", "169.254.1.1", "0.0.0.0",
                                   "224.0.0.1", "100.64.0.1", "::1", "fe80::1", "fd00::1"])
def test_internal_addresses_are_never_blocked(value, tmp_path, capsys):
    code, results, _, _ = run_cli(["--type", "ip", "--value", value, "--execute"], tmp_path, capsys=capsys)
    assert code == 1
    assert results[0]["status"] == "refused" and "private, loopback or reserved" in results[0]["message"]
    assert not (tmp_path / "lists").exists()


@pytest.mark.parametrize("value", ["microsoft.com", "login.microsoft.com", "www.google.com", "github.com"])
def test_common_service_domains_are_never_blocked(value, tmp_path, capsys):
    code, results, _, _ = run_cli(["--type", "domain", "--value", value, "--execute"], tmp_path, capsys=capsys)
    assert code == 1 and "built-in allowlist" in results[0]["message"]


def test_a_lookalike_of_an_allowlisted_domain_can_be_blocked(tmp_path, capsys):
    code, results, _, _ = run_cli(["--type", "domain", "--value", "evilmicrosoft.com", "--execute"], tmp_path,
                                  capsys=capsys)
    assert code == 0 and results[0]["status"] == "done"


def test_never_block_file_covers_addresses_ranges_and_domains(tmp_path, capsys):
    never = tmp_path / "never.txt"
    never.write_text("# our own things\n198.18.0.0/15\n45.33.32.156   # scanner we run\npartner.example.com\n",
                     encoding="utf-8")
    protected = NeverBlock.from_file(never)
    assert "never-block list" in protected.reason(Indicator("ip", IP))
    assert "never-block list" in protected.reason(Indicator("domain", "api.partner.example.com"))
    assert protected.reason(Indicator("domain", "notpartner.example.com")) == ""
    assert protected.reason(Indicator("ip", "9.9.9.9")) == ""
    assert protected.reason(Indicator("hash", SHA256)) == ""

    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--execute", "--never-block", str(never)],
                                  tmp_path, capsys=capsys)
    assert code == 1 and results[0]["status"] == "refused"


def test_a_broken_never_block_file_stops_the_run(tmp_path, capsys):
    never = tmp_path / "never.txt"
    never.write_text("10.0.0.0/8\nthis is not valid\n", encoding="utf-8")
    code, _, _, captured = run_cli(["--type", "ip", "--value", IP, "--execute", "--never-block", str(never)],
                                   tmp_path, capsys=capsys)
    assert code == 2 and "never.txt:2" in captured.err


def test_guard_rails_do_not_stop_an_unblock(tmp_path, capsys):
    folder = tmp_path / "lists"
    folder.mkdir()
    (folder / "blocked_ips.txt").write_text("10.0.0.1\n", encoding="utf-8")
    code, results, _, _ = run_cli(["--action", "unblock", "--type", "ip", "--value", "10.0.0.1", "--execute"],
                                  tmp_path, capsys=capsys)
    assert code == 0 and results[0]["message"] == "removed from blocked_ips.txt"


def test_one_bad_entry_does_not_stop_the_good_ones(tmp_path, capsys):
    source = tmp_path / "list.json"
    source.write_text(json.dumps([{"type": "ip", "value": IP}, {"type": "ip", "value": "10.0.0.1"},
                                  {"type": "ip", "value": IP}, {"type": "url", "value": "http://x"}, "junk"]),
                      encoding="utf-8")
    code, results, _, captured = run_cli(["--input", str(source), "--execute"], tmp_path, capsys=capsys)
    assert code == 1
    assert [(r["ioc_value"], r["status"]) for r in results] == [("10.0.0.1", "refused"), (IP, "done")]
    assert captured.err.count("entry skipped") == 2


# ---------------------------------------------------------------------- Wazuh

def wazuh_session(put_response):
    return FakeSession(("POST", "/security/user/authenticate", FakeResponse(200, {"data": {"token": "jwt-token"}})),
                       ("PUT", "/active-response", put_response))


def test_wazuh_sends_firewall_drop_to_the_named_agents(tmp_path, capsys):
    session = wazuh_session(FakeResponse(200, {"data": {"affected_items": ["001", "002"], "total_affected_items": 2,
                                                         "total_failed_items": 0, "failed_items": []}}))
    code, results, session, _ = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", "--agents", "001", "002",
                                         "--execute"], tmp_path, WAZUH_ENV, session, capsys)
    assert code == 0 and results[0]["message"] == "firewall-drop sent to 2 agents"
    login, put = session.calls
    assert login["url"] == "https://wazuh.lab:55000/security/user/authenticate" and login["auth"] == ("wazuh-wui", "pw")
    assert put["params"] == {"agents_list": "001,002"}
    assert put["headers"] == {"Authorization": "Bearer jwt-token"}
    assert put["json"] == {"command": "!firewall-drop", "arguments": [], "alert": {"data": {"srcip": IP}}}
    assert login["verify"] is True and put["verify"] is True


def test_wazuh_all_agents_and_a_ca_bundle(tmp_path, capsys):
    session = wazuh_session(FakeResponse(200, {"data": {"total_affected_items": 3, "total_failed_items": 0}}))
    environment = {**WAZUH_ENV, "WAZUH_CA_BUNDLE": "/etc/ssl/lab-ca.pem"}
    code, _, session, _ = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", "--agents", "all", "--execute"],
                                  tmp_path, environment, session, capsys)
    assert code == 0
    assert session.calls[1]["params"] == {} and session.calls[1]["verify"] == "/etc/ssl/lab-ca.pem"


def test_insecure_turns_verification_off_and_says_so(tmp_path, capsys):
    session = wazuh_session(FakeResponse(200, {"data": {"total_affected_items": 1, "total_failed_items": 0}}))
    code, _, session, captured = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", "--agents", "001",
                                          "--execute", "--insecure"], tmp_path, WAZUH_ENV, session, capsys)
    assert code == 0 and session.calls[0]["verify"] is False
    assert "TLS certificates are not verified" in captured.err


@pytest.mark.parametrize("response, message", [
    (FakeResponse(200, {"data": {"total_affected_items": 0, "total_failed_items": 1,
                                 "failed_items": [{"error": {"code": 1707, "message": "Agent is not active"},
                                                   "id": ["001"]}]}}),
     "no agent accepted the command: Agent is not active"),
    (FakeResponse(200, {"data": {"total_affected_items": 1, "total_failed_items": 1}}),
     "firewall-drop sent to 1 agents, 1 agents failed"),
    (FakeResponse(400, {"title": "Bad Request", "detail": "Invalid command"}), "HTTP 400: Invalid command"),
    (FakeResponse(500), "HTTP 500"),
    (requests.exceptions.SSLError("certificate verify failed"), "TLS certificate could not be verified"),
    (requests.exceptions.ConnectionError("refused"), "connection failed"),
    (requests.exceptions.Timeout("slow"), "timed out"),
])
def test_wazuh_reports_what_really_happened(response, message, tmp_path, capsys):
    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", "--agents", "001", "--execute"],
                                  tmp_path, WAZUH_ENV, wazuh_session(response), capsys)
    assert code == 1 and results[0]["status"] == "failed"
    assert message in results[0]["message"]


def test_wazuh_login_failure_is_reported_without_the_password(tmp_path, capsys):
    session = FakeSession(("POST", "/security/user/authenticate", FakeResponse(401, {"title": "Unauthorized"})))
    code, results, _, captured = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", "--agents", "001",
                                          "--execute"], tmp_path, WAZUH_ENV, session, capsys)
    assert code == 1 and results[0]["message"] == "login failed: HTTP 401"
    assert "pw" not in captured.out.replace("pwd", "")


def test_wazuh_only_blocks_addresses_and_cannot_unblock(tmp_path, capsys):
    session = FakeSession()
    code, results, session, _ = run_cli(["--type", "domain", "--value", "evil.example.com", "--target", "wazuh",
                                         "--agents", "001", "--execute"], tmp_path, WAZUH_ENV, session, capsys)
    assert code == 1 and results[0]["status"] == "unsupported" and session.calls == []
    code, results, session, _ = run_cli(["--action", "unblock", "--type", "ip", "--value", IP, "--target", "wazuh",
                                         "--agents", "001", "--execute"], tmp_path, WAZUH_ENV, FakeSession(), capsys)
    assert code == 1 and "cannot lift a firewall-drop" in results[0]["message"] and session.calls == []


@pytest.mark.parametrize("environment, agents, message", [
    ({}, ["--agents", "001"], "set WAZUH_API_PASSWORD"),
    (WAZUH_ENV, [], "name the agents"),
])
def test_wazuh_without_configuration_is_a_configuration_error(environment, agents, message, tmp_path, capsys):
    code, _, session, captured = run_cli(["--type", "ip", "--value", IP, "--target", "wazuh", *agents, "--execute"],
                                         tmp_path, environment, capsys=capsys)
    assert code == 2 and message in captured.err and session.calls == []


# ----------------------------------------------------------------------- MISP

MISP_ENV = {"MISP_URL": "https://misp.lab/", "MISP_API_KEY": "misp-key"}


def test_misp_gets_one_event_with_every_indicator(tmp_path, capsys):
    source = tmp_path / "iocs.json"
    source.write_text(json.dumps({"ipv4": [IP], "domains": ["evil.example.com"], "sha256_hashes": [SHA256],
                                  "md5_hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}), encoding="utf-8")
    session = FakeSession(("POST", "/events/add", FakeResponse(200, {"Event": {"id": "42"}})))
    code, results, session, _ = run_cli(["--input", str(source), "--target", "misp", "--execute", "--comment", "INC-7"],
                                        tmp_path, MISP_ENV, session, capsys)
    assert code == 0 and {r["message"] for r in results} == {"added to MISP event 42"}
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["url"] == "https://misp.lab/events/add" and call["headers"]["Authorization"] == "misp-key"
    event = call["json"]["Event"]
    assert event["distribution"] == 0 and "INC-7" in event["info"]
    assert [(a["type"], a["category"], a["to_ids"]) for a in event["Attribute"]] == [
        ("ip-dst", "Network activity", True), ("domain", "Network activity", True),
        ("sha256", "Payload delivery", True), ("md5", "Payload delivery", True)]


def test_misp_failures_and_unblock(tmp_path, capsys):
    session = FakeSession(("POST", "/events/add", FakeResponse(403, {"message": "denied"})))
    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--target", "misp", "--execute"], tmp_path, MISP_ENV,
                                  session, capsys)
    assert code == 1 and results[0]["message"] == "HTTP 403"
    session = FakeSession(("POST", "/events/add", FakeResponse(200, {"unexpected": True})))
    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--target", "misp", "--execute"], tmp_path, MISP_ENV,
                                  session, capsys)
    assert code == 1 and results[0]["message"] == "MISP answered without an event"
    code, results, session, _ = run_cli(["--action", "unblock", "--type", "ip", "--value", IP, "--target", "misp",
                                         "--execute"], tmp_path, MISP_ENV, FakeSession(), capsys)
    assert code == 1 and results[0]["status"] == "unsupported" and session.calls == []


def test_misp_without_configuration(tmp_path, capsys):
    code, _, _, captured = run_cli(["--type", "ip", "--value", IP, "--target", "misp", "--execute"], tmp_path, {},
                                   capsys=capsys)
    assert code == 2 and "set MISP_URL and MISP_API_KEY" in captured.err


# -------------------------------------------------------------------- webhook

HOOK_ENV = {"BLOCK_WEBHOOK_URL": "http://127.0.0.1:3001/api/v1/hooks/webhook_abc", "BLOCK_WEBHOOK_TOKEN": "tok"}


@pytest.mark.parametrize("action", ["block", "unblock"])
def test_webhook_receives_the_action_and_the_indicators(action, tmp_path, capsys):
    session = FakeSession(("POST", "/hooks/webhook_abc", FakeResponse(202)))
    code, results, session, _ = run_cli(["--action", action, "--type", "domain", "--value", "evil.example.com",
                                         "--target", "webhook", "--execute", "--comment", "INC-9"], tmp_path, HOOK_ENV,
                                        session, capsys)
    assert code == 0 and results[0]["message"] == "webhook accepted the request (HTTP 202)"
    call = session.calls[0]
    assert call["headers"] == {"Content-Type": "application/json", "Authorization": "Bearer tok"}
    assert call["json"]["action"] == action and call["json"]["comment"] == "INC-9"
    assert call["json"]["indicators"] == [{"type": "domain", "value": "evil.example.com"}]


def test_webhook_failure_and_missing_url(tmp_path, capsys):
    session = FakeSession(("POST", "/hooks/", FakeResponse(500)))
    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--target", "webhook", "--execute"], tmp_path,
                                  HOOK_ENV, session, capsys)
    assert code == 1 and results[0]["message"] == "HTTP 500"
    code, _, _, captured = run_cli(["--type", "ip", "--value", IP, "--target", "webhook", "--execute"], tmp_path, {},
                                   capsys=capsys)
    assert code == 2 and "set BLOCK_WEBHOOK_URL" in captured.err


# ------------------------------------------------------------ several targets

def test_several_targets_and_the_audit_log(tmp_path, capsys):
    session = FakeSession(("POST", "/security/user/authenticate", FakeResponse(200, {"data": {"token": "t"}})),
                          ("PUT", "/active-response", FakeResponse(500)),
                          ("POST", "/hooks/", FakeResponse(200)))
    code, results, _, _ = run_cli(["--type", "ip", "--value", IP, "--target", "blocklist", "wazuh", "webhook",
                                   "--agents", "001", "--execute"], tmp_path, {**WAZUH_ENV, **HOOK_ENV}, session, capsys)
    assert code == 1
    assert [(r["target"], r["status"]) for r in results] == [("blocklist", "done"), ("wazuh", "failed"),
                                                             ("webhook", "done")]
    audit = [json.loads(line) for line in lines(tmp_path / "lists" / "audit.jsonl")]
    assert [(entry["target"], entry["status"]) for entry in audit] == [("blocklist", "done"), ("wazuh", "failed"),
                                                                        ("webhook", "done")]


def test_output_file_and_standard_input(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"ipv4": [IP]})))
    target = tmp_path / "result.json"
    code = automated_blocking.main(["--input", "-", "--blocklist-dir", str(tmp_path / "lists"), "--output", str(target)],
                                   environment={}, session=FakeSession())
    assert code == 0 and capsys.readouterr().out == ""
    assert json.loads(target.read_text(encoding="utf-8"))[0]["status"] == "planned"


def test_unreadable_input_is_a_usage_error(tmp_path, capsys):
    code, _, _, captured = run_cli(["--input", str(tmp_path / "missing.json")], tmp_path, capsys=capsys)
    assert code == 2 and "cannot read" in captured.err
