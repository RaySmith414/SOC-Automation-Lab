"""Enrichment: every way a service can fail to answer, and what the score does with the answers.

The HTTP layer is replaced, so these tests need no API keys and no network.
They prove the handling of each response. They do not prove that a provider
still returns the recorded shape.
"""

import io
import json

import pytest
import requests
import responses

import threat_enrichment
from threat_enrichment import (
    BASE_URLS,
    RateLimiter,
    SourceResult,
    ThreatEnricher,
    format_summary,
    load_api_keys,
    load_iocs,
    validate,
)

KEYS = {"virustotal": "vt-key", "abuseipdb": "abuse-key", "greynoise": "gn-key", "shodan": "SHODAN-SECRET-KEY",
        "otx": "otx-key"}
IP = "45.33.32.156"
VT_IP = f"{BASE_URLS['virustotal']}/ip_addresses/{IP}"
ABUSE = f"{BASE_URLS['abuseipdb']}/check"
GREYNOISE = f"{BASE_URLS['greynoise']}/community/{IP}"
SHODAN = f"{BASE_URLS['shodan']}/shodan/host/{IP}"
OTX_IP = f"{BASE_URLS['otx']}/indicators/IPv4/{IP}/general"


def enricher(services=None, keys=KEYS):
    sleeps = []
    instance = ThreatEnricher(keys, services, sleep=sleeps.append, clock=lambda: 0.0)
    for limiter in instance.limiters.values():
        limiter.interval = 0          # spacing is tested on its own below
    instance.sleeps = sleeps
    return instance


def vt_body(malicious=0, suspicious=0, **attributes):
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": 60, "undetected": 10}
    return {"data": {"attributes": {"last_analysis_stats": stats, **attributes}}}


def abuse_body(score=0, tor=False):
    return {"data": {"abuseConfidenceScore": score, "totalReports": 12, "countryCode": "US", "isp": "Example ISP",
                     "isTor": tor}}


def register_all_ip(vt=0, abuse=0, classification="unknown", pulses=0, vulns=()):
    responses.get(VT_IP, json=vt_body(vt, country="US", as_owner="Example AS"))
    responses.get(ABUSE, json=abuse_body(abuse))
    responses.get(GREYNOISE, json={"noise": True, "riot": False, "classification": classification, "name": "x"})
    responses.get(SHODAN, json={"ports": [443, 22], "org": "Example Org", "asn": "AS64500", "vulns": list(vulns)})
    responses.get(OTX_IP, json={"pulse_info": {"count": pulses, "pulses": [{"name": "Pulse A"}]}})


# ------------------------------------------------------- answers and scoring

@responses.activate
def test_all_services_answer_and_the_request_carries_the_right_credentials():
    register_all_ip(vt=12, abuse=90, classification="malicious", pulses=20)
    result = enricher().enrich(IP, "ip")
    assert result.verdict == "malicious" and result.malicious is True
    assert result.risk_score == 100            # 40 + 35 + 30 + 20, capped
    assert (result.answered, result.queried) == (5, 5)
    assert result.context == {"country": "US", "isp": "Example ISP", "org": "Example Org", "asn": "AS64500",
                              "as_owner": "Example AS"}
    assert "widely-detected" in result.tags and "internet-scanner" in result.tags
    sent = {call.request.url.split("?")[0]: call.request for call in responses.calls}
    assert sent[VT_IP].headers["x-apikey"] == "vt-key"
    assert sent[ABUSE].headers["Key"] == "abuse-key" and "ipAddress=45.33.32.156" in sent[ABUSE].url
    assert sent[GREYNOISE].headers["key"] == "gn-key"
    assert sent[OTX_IP].headers["X-OTX-API-KEY"] == "otx-key"
    assert "key=SHODAN-SECRET-KEY" in sent[SHODAN].url


@pytest.mark.parametrize("vt, abuse, classification, pulses, score, verdict", [
    (0, 0, "unknown", 0, 0, "not_flagged"),
    (1, 0, "unknown", 0, 10, "not_flagged"),
    (1, 25, "unknown", 0, 20, "suspicious"),
    (6, 60, "unknown", 0, 45, "suspicious"),
    (6, 60, "unknown", 1, 55, "malicious"),
    (11, 0, "unknown", 0, 40, "suspicious"),
    (11, 0, "benign", 0, 30, "suspicious"),
    (0, 0, "benign", 0, 0, "not_flagged"),       # the score never goes below zero
])
@responses.activate
def test_score_and_verdict_thresholds(vt, abuse, classification, pulses, score, verdict):
    register_all_ip(vt=vt, abuse=abuse, classification=classification, pulses=pulses)
    result = enricher().enrich(IP, "ip")
    assert (result.risk_score, result.verdict) == (score, verdict)


@responses.activate
def test_exposed_vulnerabilities_are_context_not_evidence_of_malice():
    register_all_ip(vulns=["CVE-2021-44228", "CVE-2019-0708"])
    result = enricher().enrich(IP, "ip")
    assert result.risk_score == 0 and "exposed-vulnerabilities" in result.tags


@responses.activate
def test_shodan_vulnerabilities_given_as_a_mapping_are_read():
    responses.get(SHODAN, json={"ports": [80], "vulns": {"CVE-2021-44228": {"cvss": 10}}})
    result = enricher(["shodan"]).enrich(IP, "ip")
    assert result.sources["shodan"]["data"]["vulns"] == ["CVE-2021-44228"]


# ------------------------------------------------ no answer is not "clean"

@pytest.mark.parametrize("status_code, status", [
    (404, "not_found"), (401, "unauthorized"), (403, "unauthorized"), (429, "rate_limited"), (400, "error"),
])
@responses.activate
def test_each_error_status_is_reported_and_never_crashes(status_code, status):
    for url in (VT_IP, ABUSE, GREYNOISE, SHODAN, OTX_IP):
        responses.get(url, status=status_code, json={"error": "x"})
    result = enricher().enrich(IP, "ip")
    assert {entry["status"] for entry in result.sources.values()} == {status}
    assert result.verdict == "unknown" and result.risk_score is None and result.malicious is False
    assert (result.answered, result.queried) == (0, 5)


@responses.activate
def test_one_answer_is_enough_for_a_score_and_the_rest_are_listed():
    responses.get(VT_IP, json=vt_body(7))
    for url in (ABUSE, GREYNOISE, SHODAN, OTX_IP):
        responses.get(url, status=404)
    result = enricher().enrich(IP, "ip")
    assert (result.risk_score, result.verdict, result.answered) == (25, "suspicious", 1)
    summary = format_summary([result])
    assert "[SUSPICIOUS] ip: 45.33.32.156 (score 25, 1 of 5 services answered)" in summary
    assert "abuseipdb not_found" in summary


@responses.activate
def test_unknown_is_shown_as_unknown_in_the_summary():
    for url in (VT_IP, ABUSE, GREYNOISE, SHODAN, OTX_IP):
        responses.get(url, status=404)
    summary = format_summary([enricher().enrich(IP, "ip")])
    assert summary.startswith("[UNKNOWN] ip: 45.33.32.156 (no score, 0 of 5 services answered)")
    assert "CLEAN" not in summary.upper()


@responses.activate
def test_an_answer_that_is_not_json_is_an_error():
    responses.get(VT_IP, body="<html>maintenance</html>", status=200)
    result = enricher(["virustotal"]).enrich(IP, "ip")
    assert result.sources["virustotal"] == {"status": "error", "data": {}, "detail": "the answer was not JSON"}


@responses.activate
def test_an_answer_with_missing_fields_is_read_as_zero_not_as_a_crash():
    responses.get(VT_IP, json={"data": None})
    responses.get(ABUSE, json={})
    responses.get(OTX_IP, json={"pulse_info": None})
    result = enricher(["virustotal", "abuseipdb", "otx"]).enrich(IP, "ip")
    assert result.answered == 3 and result.risk_score == 0


@responses.activate
def test_server_errors_are_retried_then_reported():
    responses.get(VT_IP, status=503)
    responses.get(VT_IP, status=502)
    responses.get(VT_IP, json=vt_body(3))
    instance = enricher(["virustotal"])
    result = instance.enrich(IP, "ip")
    assert result.sources["virustotal"]["status"] == "ok" and len(responses.calls) == 3
    assert instance.sleeps == [1, 2]

    responses.reset()
    responses.get(VT_IP, status=500)
    result = enricher(["virustotal"]).enrich(IP, "ip")
    assert result.sources["virustotal"] == {"status": "error", "data": {}, "detail": "HTTP 500"}
    assert len(responses.calls) == 3


@responses.activate
def test_a_network_failure_never_leaks_the_api_key():
    responses.get(SHODAN, body=requests.ConnectionError(f"Max retries exceeded with url: {SHODAN}?key=SHODAN-SECRET-KEY"))
    result = enricher(["shodan"]).enrich(IP, "ip")
    assert result.sources["shodan"] == {"status": "error", "data": {}, "detail": "ConnectionError"}
    assert "SHODAN-SECRET-KEY" not in json.dumps(result.to_dict())
    assert "SHODAN-SECRET-KEY" not in format_summary([result])


# ------------------------------------------------------------- what is sent

@pytest.mark.parametrize("address", ["10.0.0.5", "192.168.1.10", "127.0.0.1", "169.254.1.1", "fe80::1", "100.64.1.1"])
@responses.activate
def test_private_addresses_are_never_sent_to_a_service(address):
    result = enricher().enrich(address, "ip")
    assert result.verdict == "invalid" and "not sent" in result.context["reason"]
    assert len(responses.calls) == 0


@pytest.mark.parametrize("value, kind, reason", [
    ("999.1.1.1", "ip", "not an IP address"),
    ("not a domain", "domain", "not a valid domain"),
    ("abc123", "hash", "not an MD5"),
    ("ftp://evil.example.com/a", "url", "not an http"),
])
def test_values_that_are_not_what_they_claim_are_rejected(value, kind, reason):
    assert reason in validate(value, kind)


@responses.activate
def test_only_services_that_take_the_type_are_asked():
    responses.get(f"{BASE_URLS['virustotal']}/domains/evil.example.com", json=vt_body(2, registrar="Example Registrar"))
    responses.get(f"{BASE_URLS['otx']}/indicators/domain/evil.example.com/general", json={"pulse_info": {"count": 3}})
    result = enricher().enrich("evil.example.com", "domain")
    assert sorted(result.sources) == ["otx", "virustotal"]
    assert result.risk_score == 20 and result.context == {"registrar": "Example Registrar"}


@responses.activate
def test_hash_lookup_and_type_aliases():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    responses.get(f"{BASE_URLS['virustotal']}/files/{sha256}",
                  json=vt_body(30, type_description="Win32 EXE", names=["a.exe", "b.exe", "c", "d", "e", "f"]))
    responses.get(f"{BASE_URLS['otx']}/indicators/file/{sha256}/general", json={"pulse_info": {"count": 0}})
    result = enricher().enrich(sha256, "sha256")
    assert result.ioc_type == "hash" and result.risk_score == 40
    assert result.context == {"file_type": "Win32 EXE", "file_names": ["a.exe", "b.exe", "c", "d", "e"]}


@responses.activate
def test_url_lookup_uses_the_virustotal_url_identifier():
    url = "https://evil.example.com/gate?a=1"
    responses.get(f"{BASE_URLS['virustotal']}/urls/aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2dhdGU_YT0x", json=vt_body(1))
    result = enricher(["virustotal"]).enrich(url, "url")
    assert result.sources["virustotal"]["status"] == "ok" and result.risk_score == 10


@responses.activate
def test_ipv6_goes_to_the_ipv6_endpoints_and_skips_greynoise():
    address = "2001:4860:4860::8888"
    responses.get(f"{BASE_URLS['virustotal']}/ip_addresses/{address}", json=vt_body(0))
    responses.get(ABUSE, json=abuse_body(0))
    responses.get(f"{BASE_URLS['shodan']}/shodan/host/{address}", status=404)
    responses.get(f"{BASE_URLS['otx']}/indicators/IPv6/{address}/general", json={"pulse_info": {"count": 0}})
    result = enricher().enrich(address, "ip")
    assert "greynoise" not in result.sources and result.answered == 3


def test_services_without_a_key_are_not_asked():
    instance = ThreatEnricher({"otx": "k"}, ["virustotal", "otx"])
    assert instance.services == ["otx"]
    assert ThreatEnricher({}, None).services == []


def test_unsupported_type_is_an_error():
    with pytest.raises(ValueError, match="Unsupported IOC type"):
        enricher().enrich("x", "email")


# -------------------------------------------------------------- rate limiter

def test_rate_limiter_spaces_calls():
    now = [100.0]
    waits = []

    def sleep(seconds):
        waits.append(round(seconds, 3))
        now[0] += seconds

    limiter = RateLimiter(4, clock=lambda: now[0], sleep=sleep)   # four per minute: 15 seconds apart
    limiter.wait()
    assert waits == []                 # the first call goes straight through
    now[0] += 5
    limiter.wait()
    assert waits == [10.0]
    now[0] += 20
    limiter.wait()
    assert waits == [10.0]             # already far enough apart


# --------------------------------------------------------------------- input

def test_extractor_output_is_mapped_to_lookup_types(tmp_path):
    source = tmp_path / "iocs.json"
    source.write_text(json.dumps({
        "ipv4": ["45.33.32.156"], "ipv6": ["2001:4860:4860::8888"], "domains": ["evil.example.com"],
        "urls": ["https://evil.example.com/a"], "md5_hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "sha1_hashes": [], "sha256_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "emails": ["a@evil.example.com"], "cves": ["CVE-2024-3094"], "domains_or_file_names": ["update.zip"],
    }), encoding="utf-8")
    iocs, notes = load_iocs(str(source))
    assert iocs == [
        ("45.33.32.156", "ip"), ("2001:4860:4860::8888", "ip"), ("evil.example.com", "domain"),
        ("https://evil.example.com/a", "url"), ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),
    ]
    assert len(notes) == 3 and all("skipped" in note for note in notes)


def test_list_input_and_duplicates(tmp_path):
    source = tmp_path / "list.json"
    source.write_text(json.dumps([
        {"type": "ip", "value": "45.33.32.156"}, {"type": "IPv4", "value": "45.33.32.156"},
        {"type": "sha256", "value": "ab" * 32}, {"type": "email", "value": "a@b.com"}, "just a string",
    ]), encoding="utf-8")
    iocs, notes = load_iocs(str(source))
    assert iocs == [("45.33.32.156", "ip"), ("ab" * 32, "hash")]
    assert len(notes) == 2


def test_api_keys_come_from_the_environment():
    keys = load_api_keys({"VIRUSTOTAL_API_KEY": " vt ", "OTX_API_KEY": "", "UNRELATED": "x"})
    assert keys == {"virustotal": "vt"}


# ------------------------------------------------------------------------ CLI

@pytest.fixture
def no_keys(monkeypatch):
    for variable in threat_enrichment.ENV_KEYS.values():
        monkeypatch.delenv(variable, raising=False)


def test_cli_without_any_key_explains_and_exits_2(no_keys, capsys):
    assert threat_enrichment.main(["--ioc", IP, "--type", "ip"]) == 2
    assert "VIRUSTOTAL_API_KEY" in capsys.readouterr().err


def test_cli_with_a_key_for_another_service_only(no_keys, monkeypatch, capsys):
    monkeypatch.setenv("OTX_API_KEY", "k")
    assert threat_enrichment.main(["--ioc", IP, "--type", "ip", "--services", "virustotal"]) == 2
    assert "No API key is set for: virustotal" in capsys.readouterr().err


@responses.activate
def test_cli_single_ioc_json(no_keys, monkeypatch, capsys):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(threat_enrichment.RateLimiter, "wait", lambda self: None)
    responses.get(VT_IP, json=vt_body(12))
    assert threat_enrichment.main(["--ioc", IP, "--type", "ip"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "suspicious" and data[0]["sources"]["virustotal"]["data"]["malicious"] == 12


@responses.activate
def test_cli_reads_extractor_output_from_standard_input(no_keys, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(threat_enrichment.RateLimiter, "wait", lambda self: None)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"ipv4": [IP, "8.8.8.8"], "emails": ["a@b.com"]})))
    responses.get(VT_IP, json=vt_body(0))
    target = tmp_path / "out.txt"
    assert threat_enrichment.main(["--input", "-", "--format", "summary", "--limit", "1", "--output", str(target)]) == 0
    captured = capsys.readouterr()
    assert "skipped: no service takes this type" in captured.err and "over the limit of 1" in captured.err
    assert target.read_text(encoding="utf-8").startswith("[NOT_FLAGGED] ip: 45.33.32.156")
    assert len(responses.calls) == 1


def test_cli_unreadable_input_exits_1(no_keys, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert threat_enrichment.main(["--input", str(broken)]) == 1
    assert threat_enrichment.main(["--input", str(tmp_path / "missing.json")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_source_result_defaults():
    assert SourceResult("not_found").data == {} and SourceResult("not_found").detail == ""
