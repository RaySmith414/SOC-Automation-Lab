#!/usr/bin/env python3
"""Block or unblock indicators, with guard rails.

Nothing changes unless you add --execute. Without it the script prints what it
would do and makes no network call and no file change.

Targets:

  blocklist   Text files of blocked IPs, domains and hashes (one entry per line).
              Firewalls and proxies that read external lists can poll them:
              Palo Alto EDL, FortiGate threat feeds, pfSense URL aliases, Squid ACL files.
  wazuh       Wazuh active response "firewall-drop" on the chosen agents (IP addresses only).
  misp        One MISP event that holds the indicators as attributes flagged for detection.
  webhook     One JSON POST to a URL you choose, for example a Shuffle webhook that
              drives your own firewall or EDR.

Guard rails:

  - Every value is validated. A value that is not what its type says is refused.
  - Private, loopback and reserved addresses are never blocked.
  - Domains of common services (the extractor's allowlist) are never blocked.
  - Entries in a never-block file (IPs, CIDR ranges, domains) are never blocked.
  - TLS certificates are verified. Use a CA bundle for lab certificates, or --insecure.
  - Every executed action is appended to audit.jsonl next to the blocklists.

    automated_blocking.py --type ip --value 45.33.32.156
    automated_blocking.py --type ip --value 45.33.32.156 --target blocklist wazuh --agents 001 --execute
    automated_blocking.py --input iocs.json --target blocklist --execute --comment "INC-1042"
    automated_blocking.py --action unblock --type domain --value evil.example.com --execute

Exit codes: 0 everything requested was done (or planned, in a dry run), 1 one or
more actions failed, were refused or are not supported by the target, 2 usage or
configuration error.
"""

import argparse
import ipaddress
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import requests

from ioc_extractor import DEFAULT_ALLOWLIST, in_allowlist, is_routable, parse_ip, valid_domain

TARGETS = ("blocklist", "wazuh", "misp", "webhook")
ACTIONS = ("block", "unblock")
TYPES = ("ip", "domain", "hash")
EXTRACTOR_KEYS = {"ipv4": "ip", "ipv6": "ip", "domains": "domain",
                  "md5_hashes": "hash", "sha1_hashes": "hash", "sha256_hashes": "hash"}
TYPE_ALIASES = {"ip": "ip", "ipv4": "ip", "ipv6": "ip", "domain": "domain",
                "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash"}
BLOCKLIST_FILES = {"ip": "blocked_ips.txt", "domain": "blocked_domains.txt", "hash": "blocked_hashes.txt"}
HASH_NAMES = {32: "md5", 40: "sha1", 64: "sha256"}
TIMEOUT = 30


@dataclass(frozen=True)
class Indicator:
    kind: str     # ip, domain or hash
    value: str    # normalized


@dataclass
class Result:
    action: str
    target: str
    ioc_type: str
    ioc_value: str
    status: str       # done, planned, failed, refused, unsupported
    message: str
    timestamp: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def result(action: str, target: str, indicator: Indicator, status: str, message: str) -> Result:
    return Result(action, target, indicator.kind, indicator.value, status, message, now())


# ---------------------------------------------------------------- validation

def normalize(kind: str, value: str) -> Tuple[Optional[Indicator], str]:
    """A validated indicator, or None with the reason it was rejected."""
    value = value.strip()
    if kind == "ip":
        address = parse_ip(value)
        if address is None:
            return None, "not an IP address (ranges are not accepted)"
        return Indicator("ip", str(address)), ""
    if kind == "domain":
        name = value.lower().rstrip(".")
        if not valid_domain(name) or parse_ip(name) is not None:
            return None, "not a valid domain"
        return Indicator("domain", name), ""
    if kind == "hash":
        digest = value.lower()
        if len(digest) not in HASH_NAMES or any(char not in "0123456789abcdef" for char in digest):
            return None, "not an MD5, SHA-1 or SHA-256 hash"
        return Indicator("hash", digest), ""
    return None, f"unsupported type {kind}"


class NeverBlock:
    """Things that must not be blocked, whatever the input says."""

    def __init__(self, networks: Iterable[Any] = (), domains: Iterable[str] = ()):
        self.networks = list(networks)
        self.domains = {domain.lower() for domain in domains}

    @classmethod
    def from_file(cls, path: Optional[Path]) -> "NeverBlock":
        networks: List[Any] = []
        domains: List[str] = []
        if path is not None:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                entry = line.split("#", 1)[0].strip()
                if not entry:
                    continue
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                    continue
                except ValueError:
                    pass
                if not valid_domain(entry):
                    raise ValueError(f"{path}:{number}: '{entry}' is not an IP address, a CIDR range or a domain")
                domains.append(entry)
        return cls(networks, domains)

    def reason(self, indicator: Indicator) -> str:
        """Why this indicator must not be blocked, or an empty string."""
        if indicator.kind == "ip":
            address = ipaddress.ip_address(indicator.value)
            if not is_routable(address):
                return "private, loopback or reserved address"
            for network in self.networks:
                if address.version == network.version and address in network:
                    return f"inside {network} on the never-block list"
        elif indicator.kind == "domain":
            if in_allowlist(indicator.value, DEFAULT_ALLOWLIST):
                return "domain of a common service (built-in allowlist)"
            if in_allowlist(indicator.value, self.domains):
                return "on the never-block list"
        return ""


# -------------------------------------------------------------------- targets

class BlocklistTarget:
    name = "blocklist"

    def __init__(self, directory: Path):
        self.directory = directory

    def describe(self, action: str, indicator: Indicator) -> str:
        verb = "add to" if action == "block" else "remove from"
        return f"{verb} {self.directory / BLOCKLIST_FILES[indicator.kind]}"

    def _read(self, path: Path) -> List[str]:
        if not path.exists():
            return []
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]

    def _write(self, path: Path, entries: Iterable[str]) -> None:
        """Replace the file in one step so a reader never sees half a list."""
        self.directory.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=str(self.directory), prefix=".blocklist-")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write("".join(f"{entry}\n" for entry in entries))
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
        except BaseException:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise

    def apply(self, action: str, indicators: Sequence[Indicator], comment: str) -> List[Result]:
        results: List[Result] = []
        for kind in TYPES:
            wanted = [indicator for indicator in indicators if indicator.kind == kind]
            if not wanted:
                continue
            path = self.directory / BLOCKLIST_FILES[kind]
            try:
                entries = self._read(path)
                current = set(entries)
                for indicator in wanted:
                    if action == "block":
                        message = "already listed" if indicator.value in current else f"added to {path.name}"
                        current.add(indicator.value)
                    else:
                        message = f"removed from {path.name}" if indicator.value in current else "was not listed"
                        current.discard(indicator.value)
                    results.append(result(action, self.name, indicator, "done", message))
                if current != set(entries) or not path.exists():
                    self._write(path, sorted(current))
            except OSError as exc:
                results = [item for item in results if item.ioc_type != kind]
                results.extend(result(action, self.name, indicator, "failed", f"cannot update {path}: {exc.strerror}")
                               for indicator in wanted)
        return results


class HttpTarget:
    """Shared plumbing for the targets that call an API."""

    name = ""

    def __init__(self, verify: Any = True, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.verify = verify

    def _request(self, method: str, url: str, **options: Any) -> Tuple[Optional[requests.Response], str]:
        """The response, or None with a short reason. The reason never repeats credentials."""
        try:
            return self.session.request(method, url, timeout=TIMEOUT, verify=self.verify, **options), ""
        except requests.exceptions.SSLError:
            return None, "TLS certificate could not be verified (set a CA bundle, or use --insecure in a lab)"
        except requests.exceptions.ConnectionError:
            return None, "connection failed"
        except requests.exceptions.Timeout:
            return None, "timed out"
        except requests.RequestException as exc:
            return None, type(exc).__name__


class WazuhTarget(HttpTarget):
    name = "wazuh"

    def __init__(self, url: str, user: str, password: str, agents: Sequence[str], **options: Any):
        super().__init__(**options)
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.agents = list(agents)
        self._token: Optional[str] = None

    def describe(self, action: str, indicator: Indicator) -> str:
        if action == "unblock" or indicator.kind != "ip":
            return "nothing: Wazuh active response only blocks IP addresses"
        agents = "all agents" if self.agents == ["all"] else "agents " + ", ".join(self.agents)
        return f"PUT {self.url}/active-response (firewall-drop on {agents})"

    def _login(self) -> str:
        """Empty string on success, else the reason."""
        if self._token:
            return ""
        if not self.password:
            return "WAZUH_API_PASSWORD is not set"
        response, problem = self._request("POST", f"{self.url}/security/user/authenticate",
                                          auth=(self.user, self.password))
        if response is None:
            return f"login failed: {problem}"
        if response.status_code != 200:
            return f"login failed: HTTP {response.status_code}"
        try:
            self._token = response.json()["data"]["token"]
        except (ValueError, KeyError, TypeError):
            return "login failed: the answer held no token"
        return ""

    def apply(self, action: str, indicators: Sequence[Indicator], comment: str) -> List[Result]:
        results: List[Result] = []
        for indicator in indicators:
            if indicator.kind != "ip":
                results.append(result(action, self.name, indicator, "unsupported",
                                      "Wazuh active response only blocks IP addresses"))
                continue
            if action == "unblock":
                results.append(result(action, self.name, indicator, "unsupported",
                                      "the Wazuh API cannot lift a firewall-drop. It ends with the timeout set "
                                      "on the manager, or by removing the rule on the agent"))
                continue
            problem = self._login()
            if problem:
                results.append(result(action, self.name, indicator, "failed", problem))
                continue
            params = {} if self.agents == ["all"] else {"agents_list": ",".join(self.agents)}
            response, problem = self._request(
                "PUT", f"{self.url}/active-response", params=params,
                headers={"Authorization": f"Bearer {self._token}"},
                json={"command": "!firewall-drop", "arguments": [], "alert": {"data": {"srcip": indicator.value}}})
            results.append(result(action, self.name, indicator, *self._outcome(response, problem)))
        return results

    @staticmethod
    def _outcome(response: Optional[requests.Response], problem: str) -> Tuple[str, str]:
        if response is None:
            return "failed", problem
        try:
            body = response.json()
        except ValueError:
            body = {}
        data = body.get("data") or {} if isinstance(body, dict) else {}
        if response.status_code != 200:
            detail = body.get("detail") or body.get("title") or "" if isinstance(body, dict) else ""
            return "failed", f"HTTP {response.status_code}" + (f": {detail}" if detail else "")
        sent = int(data.get("total_affected_items") or 0)
        failed = int(data.get("total_failed_items") or 0)
        if sent == 0:
            reasons = "; ".join(str((item.get("error") or {}).get("message", ""))
                                for item in data.get("failed_items") or [])
            return "failed", "no agent accepted the command" + (f": {reasons}" if reasons else "")
        note = f", {failed} agents failed" if failed else ""
        # The API confirms delivery to the agent queue, not that the firewall rule exists.
        return ("failed" if failed else "done"), f"firewall-drop sent to {sent} agents{note}"


class MispTarget(HttpTarget):
    name = "misp"
    ATTRIBUTE_TYPES = {"ip": ("ip-dst", "Network activity"), "domain": ("domain", "Network activity")}

    def __init__(self, url: str, api_key: str, **options: Any):
        super().__init__(**options)
        self.url = url.rstrip("/")
        self.api_key = api_key

    def describe(self, action: str, indicator: Indicator) -> str:
        if action == "unblock":
            return "nothing: MISP is a sharing platform, withdraw the attribute there"
        return f"POST {self.url}/events/add (attribute flagged for detection)"

    def apply(self, action: str, indicators: Sequence[Indicator], comment: str) -> List[Result]:
        if action == "unblock":
            return [result(action, self.name, indicator, "unsupported",
                           "MISP is a sharing platform. Withdraw the attribute in MISP") for indicator in indicators]
        attributes = []
        for indicator in indicators:
            if indicator.kind == "hash":
                kind, category = HASH_NAMES[len(indicator.value)], "Payload delivery"
            else:
                kind, category = self.ATTRIBUTE_TYPES[indicator.kind]
            attributes.append({"type": kind, "category": category, "value": indicator.value, "to_ids": True,
                               "comment": comment})
        event = {"Event": {
            "info": f"SOC lab blocklist {now()}" + (f": {comment}" if comment else ""),
            "distribution": 0,        # this organization only
            "threat_level_id": 2,
            "analysis": 0,
            "Attribute": attributes,
        }}
        response, problem = self._request(
            "POST", f"{self.url}/events/add", json=event,
            headers={"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"})
        if response is None:
            status, message = "failed", problem
        elif response.status_code != 200:
            status, message = "failed", f"HTTP {response.status_code}"
        else:
            try:
                event_id = response.json()["Event"]["id"]
                status, message = "done", f"added to MISP event {event_id}"
            except (ValueError, KeyError, TypeError):
                status, message = "failed", "MISP answered without an event"
        return [result(action, self.name, indicator, status, message) for indicator in indicators]


class WebhookTarget(HttpTarget):
    name = "webhook"

    def __init__(self, url: str, token: str = "", **options: Any):
        super().__init__(**options)
        self.url = url
        self.token = token

    def describe(self, action: str, indicator: Indicator) -> str:
        return f"POST to the webhook (action: {action})"

    def apply(self, action: str, indicators: Sequence[Indicator], comment: str) -> List[Result]:
        payload = {
            "action": action,
            "comment": comment,
            "requested_at": now(),
            "indicators": [{"type": indicator.kind, "value": indicator.value} for indicator in indicators],
        }
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response, problem = self._request("POST", self.url, json=payload, headers=headers)
        if response is None:
            status, message = "failed", problem
        elif 200 <= response.status_code < 300:
            status, message = "done", f"webhook accepted the request (HTTP {response.status_code})"
        else:
            status, message = "failed", f"HTTP {response.status_code}"
        return [result(action, self.name, indicator, status, message) for indicator in indicators]


# ---------------------------------------------------------------- orchestration

def build_targets(names: Sequence[str], environment: Mapping[str, str], blocklist_dir: Path, agents: Sequence[str],
                  insecure: bool, session: Optional[requests.Session] = None) -> Tuple[List[Any], List[str]]:
    """Target objects for the chosen names, plus one message per target that is not configured."""
    targets: List[Any] = []
    problems: List[str] = []

    def verify(prefix: str) -> Any:
        if insecure:
            return False
        return environment.get(f"{prefix}_CA_BUNDLE") or True

    for name in names:
        if name == "blocklist":
            targets.append(BlocklistTarget(blocklist_dir))
        elif name == "wazuh":
            if not environment.get("WAZUH_API_PASSWORD"):
                problems.append("wazuh: set WAZUH_API_PASSWORD (and WAZUH_API_URL, WAZUH_API_USER if not the defaults)")
            elif not agents:
                problems.append("wazuh: name the agents with --agents 001 002, or --agents all")
            else:
                targets.append(WazuhTarget(environment.get("WAZUH_API_URL", "https://localhost:55000"),
                                           environment.get("WAZUH_API_USER", "wazuh-wui"),
                                           environment["WAZUH_API_PASSWORD"], agents,
                                           verify=verify("WAZUH"), session=session))
        elif name == "misp":
            if not environment.get("MISP_URL") or not environment.get("MISP_API_KEY"):
                problems.append("misp: set MISP_URL and MISP_API_KEY")
            else:
                targets.append(MispTarget(environment["MISP_URL"], environment["MISP_API_KEY"],
                                          verify=verify("MISP"), session=session))
        elif name == "webhook":
            if not environment.get("BLOCK_WEBHOOK_URL"):
                problems.append("webhook: set BLOCK_WEBHOOK_URL")
            else:
                targets.append(WebhookTarget(environment["BLOCK_WEBHOOK_URL"],
                                             environment.get("BLOCK_WEBHOOK_TOKEN", ""),
                                             verify=verify("BLOCK_WEBHOOK"), session=session))
    return targets, problems


def load_indicators(source: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """(type, value) pairs from extractor JSON or a list of {"type", "value"}, plus notes on skipped entries."""
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    data = json.loads(text)
    pairs: List[Tuple[str, str]] = []
    notes: List[str] = []
    if isinstance(data, dict):
        for key, values in data.items():
            if not isinstance(values, list) or not values:
                continue
            kind = EXTRACTOR_KEYS.get(key) or TYPE_ALIASES.get(key.lower())
            if kind is None:
                notes.append(f"{len(values)} entries under '{key}' skipped: this type cannot be blocked")
                continue
            pairs.extend((kind, str(value)) for value in values)
    elif isinstance(data, list):
        for item in data:
            kind = TYPE_ALIASES.get(str(item.get("type", "")).lower()) if isinstance(item, dict) else None
            value = (item.get("value") or item.get("ioc")) if isinstance(item, dict) else None
            if kind is None or not value:
                notes.append(f"entry skipped: needs a supported 'type' and a 'value': {str(item)[:60]}")
                continue
            pairs.append((kind, str(value)))
    else:
        raise ValueError("expected a JSON object or a JSON list")
    return pairs, notes


def run(action: str, pairs: Sequence[Tuple[str, str]], targets: Sequence[Any], never_block: NeverBlock,
        comment: str, execute: bool) -> List[Result]:
    """Validate, apply the guard rails, then plan or execute on each target."""
    results: List[Result] = []
    accepted: List[Indicator] = []
    seen = set()
    for kind, value in pairs:
        indicator, problem = normalize(kind, value)
        if indicator is None:
            results.append(Result(action, "validation", kind, value, "refused", problem, now()))
            continue
        if indicator in seen:
            continue
        seen.add(indicator)
        reason = never_block.reason(indicator) if action == "block" else ""
        if reason:
            results.append(result(action, "guard", indicator, "refused", f"never blocked: {reason}"))
            continue
        accepted.append(indicator)

    for target in targets:
        if not accepted:
            break
        if execute:
            results.extend(target.apply(action, accepted, comment))
        else:
            results.extend(result(action, target.name, indicator, "planned", target.describe(action, indicator))
                           for indicator in accepted)
    return results


def append_audit(directory: Path, results: Sequence[Result], comment: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / "audit.jsonl", "a", encoding="utf-8") as stream:
        for item in results:
            stream.write(json.dumps({**item.to_dict(), "comment": comment}, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--action", choices=ACTIONS, default="block", help="what to do (default: block)")
    parser.add_argument("--type", "-t", choices=sorted(TYPE_ALIASES), help="type of --value")
    parser.add_argument("--value", "-v", help="one indicator")
    parser.add_argument("--input", "-i",
                        help='JSON from ioc_extractor.py or a list of {"type", "value"}. "-" reads standard input')
    parser.add_argument("--target", nargs="+", choices=TARGETS, default=["blocklist"],
                        help="where to apply the action (default: blocklist)")
    parser.add_argument("--execute", action="store_true", help="apply the action. Without this flag nothing changes")
    parser.add_argument("--dry-run", action="store_true", help="plan only. This is the default and is kept for clarity")
    parser.add_argument("--comment", "-c", default="", help="reason or ticket number, stored with the action")
    parser.add_argument("--blocklist-dir", default=os.environ.get("BLOCKLIST_DIR", "blocklists"),
                        help="folder for the blocklist files and audit.jsonl (default: ./blocklists)")
    parser.add_argument("--never-block", default=os.environ.get("NEVER_BLOCK_FILE"),
                        help="file of IPs, CIDR ranges and domains that must never be blocked")
    parser.add_argument("--agents", nargs="+", default=[], help='Wazuh agent IDs, or "all"')
    parser.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (lab use only)")
    parser.add_argument("--output", "-o", help="write the JSON result to this file instead of standard output")
    return parser


def main(argv: Optional[List[str]] = None, environment: Mapping[str, str] = os.environ,
         session: Optional[requests.Session] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.value) == bool(args.input):
        parser.error("give either --value with --type, or --input")
    if args.value and not args.type:
        parser.error("--type is required with --value")
    if args.execute and args.dry_run:
        parser.error("--execute and --dry-run contradict each other")

    try:
        never_block = NeverBlock.from_file(Path(args.never_block) if args.never_block else None)
    except (OSError, ValueError) as exc:
        print(f"Error: never-block file: {exc}", file=sys.stderr)
        return 2

    if args.value:
        pairs, notes = [(TYPE_ALIASES[args.type], args.value)], []
    else:
        try:
            pairs, notes = load_indicators(args.input)
        except (OSError, ValueError) as exc:
            print(f"Error: cannot read {args.input}: {exc}", file=sys.stderr)
            return 2
    for note in notes:
        print(f"Note: {note}", file=sys.stderr)

    blocklist_dir = Path(args.blocklist_dir)
    targets, problems = build_targets(list(dict.fromkeys(args.target)), environment, blocklist_dir, args.agents,
                                      args.insecure, session)
    if problems:
        for problem in problems:
            print(f"Not configured: {problem}", file=sys.stderr)
        return 2
    if args.insecure:
        print("Warning: TLS certificates are not verified (--insecure).", file=sys.stderr)

    results = run(args.action, pairs, targets, never_block, args.comment, args.execute)
    audit_problem = ""
    if args.execute:
        executed = [item for item in results if item.status in ("done", "failed")]
        if executed:
            try:
                append_audit(blocklist_dir, executed, args.comment)
            except OSError as exc:
                audit_problem = f"the audit log could not be written: {exc.strerror or exc}"

    output = json.dumps([item.to_dict() for item in results], indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    counts: Dict[str, int] = {}
    for item in results:
        counts[item.status] = counts.get(item.status, 0) + 1
    summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items())) or "nothing to do"
    if not args.execute:
        summary += ". Dry run: nothing was changed. Add --execute to apply"
    print(f"{args.action}: {summary}.", file=sys.stderr)
    if audit_problem:
        print(f"Error: {audit_problem}", file=sys.stderr)
        return 1
    return 1 if any(item.status in ("failed", "refused", "unsupported") for item in results) else 0


if __name__ == "__main__":
    sys.exit(main())
