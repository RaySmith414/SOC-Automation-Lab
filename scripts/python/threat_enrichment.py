#!/usr/bin/env python3
"""Look up indicators in threat intelligence services and score the answers.

Supported services and the indicator types each one takes:

  VirusTotal   ip, domain, url, hash    VIRUSTOTAL_API_KEY
  AbuseIPDB    ip                       ABUSEIPDB_API_KEY
  GreyNoise    ip (IPv4)                GREYNOISE_API_KEY
  Shodan       ip                       SHODAN_API_KEY
  AlienVault   ip, domain, url, hash    OTX_API_KEY

API keys are read from the environment. A service without a key is skipped.

Each lookup ends in a status: ok, not_found, rate_limited, unauthorized, error
or skipped. The verdict is "unknown" when no service gave an answer. A missing
answer is never reported as clean.

Private and reserved IP addresses are never sent to a third party.

    threat_enrichment.py --ioc 45.33.32.156 --type ip
    threat_enrichment.py --input iocs.json --format summary
    ioc_extractor.py -i report.txt | threat_enrichment.py --input - --services virustotal otx
"""

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import requests

from ioc_extractor import is_routable, parse_ip, valid_domain

SERVICES = ("virustotal", "abuseipdb", "greynoise", "shodan", "otx")
ENV_KEYS = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "otx": "OTX_API_KEY",
}
BASE_URLS = {
    "virustotal": "https://www.virustotal.com/api/v3",
    "abuseipdb": "https://api.abuseipdb.com/api/v2",
    "greynoise": "https://api.greynoise.io/v3",
    "shodan": "https://api.shodan.io",
    "otx": "https://otx.alienvault.com/api/v1",
}
# Requests per minute. VirusTotal's public API allows four.
RATE_LIMITS = {"virustotal": 4, "abuseipdb": 60, "greynoise": 60, "shodan": 60, "otx": 60}

# Keys of the JSON written by ioc_extractor.py and the type each one is looked up as.
EXTRACTOR_KEYS = {
    "ipv4": "ip", "ipv6": "ip", "domains": "domain", "urls": "url",
    "md5_hashes": "hash", "sha1_hashes": "hash", "sha256_hashes": "hash",
}
TYPE_ALIASES = {"ip": "ip", "ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
                "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash"}
HASH_LENGTHS = (32, 40, 64)

MALICIOUS_SCORE = 50
SUSPICIOUS_SCORE = 20
TIMEOUT = 30
RETRIES = 2


@dataclass
class SourceResult:
    status: str                      # ok, not_found, rate_limited, unauthorized, error, skipped
    data: Dict[str, Any] = field(default_factory=dict)
    detail: str = ""


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    verdict: str                     # malicious, suspicious, not_flagged, unknown, invalid
    risk_score: Optional[int]        # None when no service answered
    malicious: bool
    answered: int                    # services that returned data
    queried: int                     # services that were asked
    tags: List[str]
    context: Dict[str, Any]
    sources: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RateLimiter:
    """Spaces calls so a service is not asked more often than its limit allows."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 60.0 / per_minute
        self.clock = clock
        self.sleep = sleep
        self.last: Optional[float] = None

    def wait(self) -> None:
        now = self.clock()
        if self.last is not None and now - self.last < self.interval:
            self.sleep(self.interval - (now - self.last))
        self.last = self.clock()


def load_api_keys(environment: Mapping[str, str] = os.environ) -> Dict[str, str]:
    return {name: environment[variable].strip() for name, variable in ENV_KEYS.items()
            if environment.get(variable, "").strip()}


def normalize_type(ioc_type: str) -> Optional[str]:
    return TYPE_ALIASES.get(ioc_type.lower().strip())


def validate(ioc: str, ioc_type: str) -> Optional[str]:
    """Reason the value cannot be looked up, or None when it can."""
    if ioc_type == "ip":
        address = parse_ip(ioc)
        if address is None:
            return "not an IP address"
        if not is_routable(address):
            return "private or reserved address, not sent to any service"
    elif ioc_type == "domain":
        if not valid_domain(ioc):
            return "not a valid domain"
    elif ioc_type == "hash":
        if len(ioc) not in HASH_LENGTHS or any(char not in "0123456789abcdefABCDEF" for char in ioc):
            return "not an MD5, SHA-1 or SHA-256 hash"
    elif ioc_type == "url":
        if not ioc.lower().startswith(("http://", "https://")):
            return "not an http or https URL"
    return None


class ThreatEnricher:
    def __init__(self, api_keys: Mapping[str, str], services: Optional[Sequence[str]] = None,
                 session: Optional[requests.Session] = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.api_keys = dict(api_keys)
        wanted = list(services) if services else list(SERVICES)
        self.services = [name for name in SERVICES if name in wanted and name in self.api_keys]
        self.session = session or requests.Session()
        self.sleep = sleep
        self.limiters = {name: RateLimiter(RATE_LIMITS[name], clock, sleep) for name in self.services}

    # ----------------------------------------------------------------- HTTP

    def _get(self, service: str, path: str, headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, Any]] = None) -> Tuple[SourceResult, Any]:
        """One GET with a short retry on server errors. Returns the result and the parsed JSON.

        Error details never include the URL or the parameters: Shodan takes its
        API key as a query parameter.
        """
        url = BASE_URLS[service] + path
        response = None
        failure = ""
        for attempt in range(RETRIES + 1):
            self.limiters[service].wait()
            try:
                response = self.session.get(url, headers=headers, params=params, timeout=TIMEOUT)
            except requests.RequestException as exc:
                response, failure = None, type(exc).__name__
            else:
                if response.status_code < 500:
                    break
                failure = f"HTTP {response.status_code}"
            if attempt < RETRIES:
                self.sleep(2 ** attempt)
        if response is None or response.status_code >= 500:
            return SourceResult("error", detail=failure), None
        if response.status_code == 404:
            return SourceResult("not_found"), None
        if response.status_code in (401, 403):
            return SourceResult("unauthorized", detail="the API key was rejected"), None
        if response.status_code == 429:
            return SourceResult("rate_limited", detail="request quota used up"), None
        if response.status_code != 200:
            return SourceResult("error", detail=f"HTTP {response.status_code}"), None
        try:
            return SourceResult("ok"), response.json()
        except ValueError:
            return SourceResult("error", detail="the answer was not JSON"), None

    # ------------------------------------------------------------- services

    def _virustotal(self, ioc: str, ioc_type: str) -> SourceResult:
        if ioc_type == "ip":
            path = f"/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            path = f"/domains/{ioc}"
        elif ioc_type == "hash":
            path = f"/files/{ioc}"
        else:
            identifier = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            path = f"/urls/{identifier}"
        result, body = self._get("virustotal", path, headers={"x-apikey": self.api_keys["virustotal"]})
        if result.status != "ok":
            return result
        attributes = ((body or {}).get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        result.data = {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
        }
        for key, source in (("country", "country"), ("as_owner", "as_owner"), ("registrar", "registrar"),
                            ("file_type", "type_description"), ("file_names", "names"),
                            ("reputation", "reputation")):
            if attributes.get(source) is not None:
                value = attributes[source]
                result.data[key] = value[:5] if isinstance(value, list) else value
        return result

    def _abuseipdb(self, ioc: str, ioc_type: str) -> SourceResult:
        result, body = self._get("abuseipdb", "/check",
                                 headers={"Key": self.api_keys["abuseipdb"], "Accept": "application/json"},
                                 params={"ipAddress": ioc, "maxAgeInDays": 90})
        if result.status != "ok":
            return result
        data = (body or {}).get("data") or {}
        result.data = {
            "abuse_confidence_score": int(data.get("abuseConfidenceScore") or 0),
            "total_reports": int(data.get("totalReports") or 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": bool(data.get("isTor")),
        }
        return result

    def _greynoise(self, ioc: str, ioc_type: str) -> SourceResult:
        result, body = self._get("greynoise", f"/community/{ioc}", headers={"key": self.api_keys["greynoise"]})
        if result.status != "ok":
            return result
        body = body or {}
        result.data = {
            "noise": bool(body.get("noise")),
            "riot": bool(body.get("riot")),
            "classification": body.get("classification"),
            "name": body.get("name"),
        }
        return result

    def _shodan(self, ioc: str, ioc_type: str) -> SourceResult:
        result, body = self._get("shodan", f"/shodan/host/{ioc}", params={"key": self.api_keys["shodan"]})
        if result.status != "ok":
            return result
        body = body or {}
        vulns = body.get("vulns") or []
        result.data = {
            "ports": sorted(body.get("ports") or []),
            "hostnames": body.get("hostnames") or [],
            "org": body.get("org"),
            "asn": body.get("asn"),
            "country": body.get("country_code"),
            "vulns": sorted(vulns),          # a list or a mapping keyed by CVE, depending on the plan
            "tags": body.get("tags") or [],
        }
        return result

    def _otx(self, ioc: str, ioc_type: str) -> SourceResult:
        if ioc_type == "ip":
            section = "IPv6" if ":" in ioc else "IPv4"
        else:
            section = {"domain": "domain", "url": "url", "hash": "file"}[ioc_type]
        value = requests.utils.quote(ioc, safe="") if ioc_type == "url" else ioc
        result, body = self._get("otx", f"/indicators/{section}/{value}/general",
                                 headers={"X-OTX-API-KEY": self.api_keys["otx"]})
        if result.status != "ok":
            return result
        pulses = ((body or {}).get("pulse_info") or {})
        result.data = {
            "pulse_count": int(pulses.get("count") or 0),
            "pulses": [pulse.get("name") for pulse in (pulses.get("pulses") or [])[:5]],
        }
        return result

    def _lookups(self, ioc: str, ioc_type: str) -> List[Tuple[str, Callable[[str, str], SourceResult]]]:
        plan: List[Tuple[str, Callable[[str, str], SourceResult]]] = [("virustotal", self._virustotal)]
        if ioc_type == "ip":
            plan.append(("abuseipdb", self._abuseipdb))
            if ":" not in ioc:
                plan.append(("greynoise", self._greynoise))
            plan.append(("shodan", self._shodan))
        plan.append(("otx", self._otx))
        return [(name, call) for name, call in plan if name in self.services]

    # --------------------------------------------------------------- scoring

    @staticmethod
    def score(sources: Mapping[str, SourceResult]) -> Tuple[int, List[str]]:
        """Risk score from 0 to 100 and tags, from the services that answered."""
        score = 0
        tags: List[str] = []

        def answer(name: str) -> Optional[Dict[str, Any]]:
            result = sources.get(name)
            return result.data if result is not None and result.status == "ok" else None

        virustotal = answer("virustotal")
        if virustotal is not None:
            flagged = virustotal["malicious"]
            score += 40 if flagged > 10 else 25 if flagged > 5 else 10 if flagged > 0 else 0
            if flagged > 10:
                tags.append("widely-detected")

        abuseipdb = answer("abuseipdb")
        if abuseipdb is not None:
            confidence = abuseipdb["abuse_confidence_score"]
            score += 35 if confidence > 80 else 20 if confidence > 50 else 10 if confidence > 20 else 0
            if abuseipdb["is_tor"]:
                score += 10
                tags.append("tor-exit-node")

        greynoise = answer("greynoise")
        if greynoise is not None:
            if greynoise["classification"] == "malicious":
                score += 30
            elif greynoise["classification"] == "benign":
                score -= 10
            if greynoise["riot"]:
                score -= 20
                tags.append("common-business-service")
            if greynoise["noise"]:
                tags.append("internet-scanner")

        otx = answer("otx")
        if otx is not None:
            pulses = otx["pulse_count"]
            score += 20 if pulses > 10 else 10 if pulses > 0 else 0

        shodan = answer("shodan")
        if shodan is not None and shodan["vulns"]:
            tags.append("exposed-vulnerabilities")    # context only: a vulnerable host is not a malicious one

        return min(max(score, 0), 100), tags

    # ------------------------------------------------------------------ run

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        kind = normalize_type(ioc_type)
        if kind is None:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        ioc = ioc.strip()
        problem = validate(ioc, kind)
        if problem:
            return EnrichmentResult(ioc, kind, "invalid", None, False, 0, 0, [], {"reason": problem}, {})

        sources: Dict[str, SourceResult] = {}
        for name, call in self._lookups(ioc, kind):
            try:
                sources[name] = call(ioc, kind)
            except Exception as exc:  # noqa: BLE001 - one broken answer must not stop the run
                sources[name] = SourceResult("error", detail=f"unexpected answer ({type(exc).__name__})")

        answered = sum(1 for result in sources.values() if result.status == "ok")
        context: Dict[str, Any] = {}
        for name in ("abuseipdb", "shodan", "virustotal"):
            result = sources.get(name)
            if result is not None and result.status == "ok":
                for key in ("country", "isp", "org", "asn", "as_owner", "registrar", "file_type", "file_names"):
                    if result.data.get(key) and key not in context:
                        context[key] = result.data[key]

        if answered == 0:
            verdict, score, tags = "unknown", None, []
        else:
            score, tags = self.score(sources)
            verdict = ("malicious" if score >= MALICIOUS_SCORE
                       else "suspicious" if score >= SUSPICIOUS_SCORE else "not_flagged")
        return EnrichmentResult(
            ioc=ioc, ioc_type=kind, verdict=verdict, risk_score=score, malicious=verdict == "malicious",
            answered=answered, queried=len(sources), tags=tags, context=context,
            sources={name: asdict(result) for name, result in sources.items()},
        )


# ------------------------------------------------------------------------ CLI

def load_iocs(source: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """IOCs to look up as (value, type), plus notes about entries that were left out."""
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    data = json.loads(text)
    iocs: List[Tuple[str, str]] = []
    notes: List[str] = []
    if isinstance(data, dict):
        for key, values in data.items():
            if not isinstance(values, list) or not values:
                continue
            kind = EXTRACTOR_KEYS.get(key) or normalize_type(key)
            if kind is None:
                notes.append(f"{len(values)} entries under '{key}' skipped: no service takes this type")
                continue
            iocs.extend((str(value), kind) for value in values)
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict) or "value" not in item or "type" not in item:
                notes.append(f"entry skipped: expected an object with 'type' and 'value', got {str(item)[:60]}")
                continue
            kind = normalize_type(str(item["type"]))
            if kind is None:
                notes.append(f"'{item['value']}' skipped: unsupported type {item['type']}")
                continue
            iocs.append((str(item["value"]), kind))
    else:
        raise ValueError("expected a JSON object or a JSON list")
    seen = set()
    unique = [entry for entry in iocs if not (entry in seen or seen.add(entry))]
    return unique, notes


def format_summary(results: Sequence[EnrichmentResult]) -> str:
    lines = []
    for result in results:
        if result.verdict == "invalid":
            lines.append(f"[INVALID] {result.ioc_type}: {result.ioc} ({result.context.get('reason')})")
            continue
        score = "no score" if result.risk_score is None else f"score {result.risk_score}"
        lines.append(f"[{result.verdict.upper()}] {result.ioc_type}: {result.ioc} "
                     f"({score}, {result.answered} of {result.queried} services answered)")
        if result.tags:
            lines.append(f"  Tags: {', '.join(result.tags)}")
        silent = [f"{name} {entry['status']}" for name, entry in result.sources.items() if entry["status"] != "ok"]
        if silent:
            lines.append(f"  No answer: {', '.join(silent)}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Look up IOCs in threat intelligence services.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="API keys are read from: " + ", ".join(ENV_KEYS.values()))
    parser.add_argument("--ioc", help="one IOC to look up")
    parser.add_argument("--type", choices=sorted(TYPE_ALIASES), help="type of --ioc")
    parser.add_argument("--input", "-i",
                        help='JSON from ioc_extractor.py, or a list of {"type", "value"} objects. '
                             '"-" reads standard input')
    parser.add_argument("--output", "-o", help="write the result to this file instead of standard output")
    parser.add_argument("--services", nargs="+", choices=SERVICES, help="ask only these services")
    parser.add_argument("--format", "-f", choices=["json", "summary"], default="json", help="output format")
    parser.add_argument("--limit", type=int, help="look up at most this many IOCs")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.ioc) == bool(args.input):
        parser.error("give either --ioc with --type, or --input")
    if args.ioc and not args.type:
        parser.error("--type is required with --ioc")

    api_keys = load_api_keys()
    enricher = ThreatEnricher(api_keys, args.services)
    if not enricher.services:
        wanted = args.services or list(SERVICES)
        print("No API key is set for: " + ", ".join(wanted), file=sys.stderr)
        print("Set one or more of: " + ", ".join(ENV_KEYS[name] for name in wanted), file=sys.stderr)
        return 2

    if args.ioc:
        iocs, notes = [(args.ioc, args.type)], []
    else:
        try:
            iocs, notes = load_iocs(args.input)
        except (OSError, ValueError) as exc:
            print(f"Error: cannot read {args.input}: {exc}", file=sys.stderr)
            return 1
    for note in notes:
        print(f"Note: {note}", file=sys.stderr)
    if args.limit is not None and len(iocs) > args.limit:
        print(f"Note: {len(iocs) - args.limit} IOCs over the limit of {args.limit} were not looked up",
              file=sys.stderr)
        iocs = iocs[:args.limit]

    results = []
    for value, kind in iocs:
        result = enricher.enrich(value, kind)
        results.append(result)
        if args.input:
            print(f"{result.verdict:12} {kind:7} {value}", file=sys.stderr)

    output = (json.dumps([result.to_dict() for result in results], indent=2) if args.format == "json"
              else format_summary(results))
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
