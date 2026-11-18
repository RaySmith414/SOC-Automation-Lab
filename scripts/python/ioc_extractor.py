#!/usr/bin/env python3
"""Extract indicators of compromise (IOCs) from text.

Finds IPv4 and IPv6 addresses, domains, URLs, file hashes, email addresses,
CVE IDs, Bitcoin and Ethereum addresses and MAC addresses. Defanged text such
as hxxp://evil[.]example[.]com is read as the real value.

Every candidate is validated before it is reported:

  IP addresses     parsed with the ipaddress module
  domains          must end in a real public suffix, so report.docx is not a domain
  URLs             must have a valid host
  Bitcoin          Base58Check or Bech32 checksum must be correct

    ioc_extractor.py --input report.txt
    ioc_extractor.py --text "C2 at 45.33.32.156 and evil[.]example[.]com" --format simple
    cat alert.json | ioc_extractor.py --input - --format stix
"""

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit

import tldextract

# Offline: use the public suffix list that ships with tldextract, never the network.
_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Domains that show up in almost every log and are almost never the indicator.
DEFAULT_ALLOWLIST = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "live.com", "outlook.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com", "icloud.com", "amazon.com",
    "amazonaws.com", "cloudflare.com", "akamai.com", "github.com", "githubusercontent.com",
})

# Real top level domains that are far more often a file extension in security text.
# A bare two-label name with one of these is reported as "domain or file name".
FILE_EXTENSION_TLDS = frozenset({"zip", "mov", "sh", "py", "md", "rs", "cab", "one"})

_HEX = "0-9A-Fa-f"
PATTERNS = {
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)"),
    "ipv6": re.compile(
        rf"(?<![{_HEX}:.])(?:[{_HEX}]{{0,4}}:){{2,7}}(?:(?:\d{{1,3}}\.){{3}}\d{{1,3}}|[{_HEX}]{{0,4}})(?![{_HEX}:])"),
    "domain": re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w-])"),
    "url": re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE),
    "md5": re.compile(rf"(?<![{_HEX}])[{_HEX}]{{32}}(?![{_HEX}])"),
    "sha1": re.compile(rf"(?<![{_HEX}])[{_HEX}]{{40}}(?![{_HEX}])"),
    "sha256": re.compile(rf"(?<![{_HEX}])[{_HEX}]{{64}}(?![{_HEX}])"),
    "email": re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![\w-])"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    "bitcoin_base58": re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])"),
    "bitcoin_bech32": re.compile(
        r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{11,71}|BC1[AC-HJ-NP-Z02-9]{11,71})(?![A-Za-z0-9])"),
    "ethereum": re.compile(rf"(?<![A-Za-z0-9])0x[{_HEX}]{{40}}(?![{_HEX}])"),
    "mac": re.compile(rf"(?<![{_HEX}:-])(?:[{_HEX}]{{2}}([:-]))(?:[{_HEX}]{{2}}\1){{4}}[{_HEX}]{{2}}(?![{_HEX}:-])"),
}

_REFANG = [
    (re.compile(r"h(?:xx|XX|\*\*)p(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\s?[\[({]\s*(?:\.|dot)\s*[\])}]\s?", re.IGNORECASE), "."),
    (re.compile(r"\s?[\[({]\s*(?:@|at)\s*[\])}]\s?", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    """Turn defanged indicators back into their real form."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------- validation

def parse_ip(value: str):
    """An ipaddress object, or None when the text is not a valid address."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_routable(address) -> bool:
    """True for addresses that can be a remote indicator.

    Private, loopback, link-local, carrier-grade NAT, documentation, multicast
    and reserved ranges are not.
    """
    return address.is_global and not (address.is_multicast or address.is_reserved or address.is_unspecified)


def valid_domain(name: str) -> bool:
    """True when the name has a registrable part under a real public suffix."""
    name = name.lower().rstrip(".")
    if len(name) > 253 or ".." in name:
        return False
    parts = _SUFFIXES(name)
    return bool(parts.suffix and parts.domain)


def in_allowlist(name: str, allowlist: Iterable[str]) -> bool:
    """True when the name is an allowlisted domain or one of its subdomains."""
    name = name.lower().rstrip(".")
    return any(name == entry or name.endswith("." + entry) for entry in allowlist)


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def valid_base58check(address: str) -> bool:
    """Bitcoin legacy address: 25 bytes whose last four are a double SHA-256 checksum."""
    number = 0
    for char in address:
        index = _BASE58.find(char)
        if index < 0:
            return False
        number = number * 58 + index
    leading_zeros = len(address) - len(address.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * leading_zeros + body
    if len(raw) != 25:
        return False
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return raw[21:] == checksum and raw[0] in (0x00, 0x05)


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def valid_bech32(address: str) -> bool:
    """Bitcoin SegWit address. Witness version 0 uses Bech32, later versions Bech32m."""
    if address != address.lower() and address != address.upper():
        return False
    address = address.lower()
    prefix, separator, data = address.rpartition("1")
    if prefix != "bc" or not separator or len(data) < 7:
        return False
    try:
        values = [_BECH32.index(char) for char in data]
    except ValueError:
        return False
    expanded = [ord(char) >> 5 for char in prefix] + [0] + [ord(char) & 31 for char in prefix]
    constant = 1 if values[0] == 0 else 0x2BC830A3
    return values[0] <= 16 and _bech32_polymod(expanded + values) == constant


def _looks_like_hash(value: str) -> bool:
    """Drop runs such as 0000...0000 that match the length of a hash."""
    return len(set(value.lower())) > 4


def _strip_url(url: str) -> str:
    """Remove punctuation that belongs to the sentence, not the URL."""
    while url and url[-1] in ".,;:!?'\"":
        url = url[:-1]
    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while url.endswith(closing) and url.count(closing) > url.count(opening):
            url = url[:-1]
    return url


# ------------------------------------------------------------------- results

@dataclass
class IOCResults:
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    domains_or_file_names: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    md5_hashes: List[str] = field(default_factory=list)
    sha1_hashes: List[str] = field(default_factory=list)
    sha256_hashes: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    bitcoin_addresses: List[str] = field(default_factory=list)
    ethereum_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[str]]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def total_count(self) -> int:
        return sum(len(values) for values in self.to_dict().values())


class IOCExtractor:
    def __init__(self, include_private: bool = False, include_allowlisted: bool = False,
                 allowlist: Optional[Iterable[str]] = None):
        self.include_private = include_private
        self.include_allowlisted = include_allowlisted
        self.allowlist = frozenset(entry.lower() for entry in (DEFAULT_ALLOWLIST if allowlist is None else allowlist))

    def _keep_host(self, host: str) -> bool:
        """Apply the private address and allowlist filters to a URL host."""
        address = parse_ip(host)
        if address is not None:
            return self.include_private or is_routable(address)
        return self.include_allowlisted or not in_allowlist(host, self.allowlist)

    def extract(self, text: str) -> IOCResults:
        text = refang(text)
        ipv4: Set[str] = set()
        ipv6: Set[str] = set()
        domains: Set[str] = set()
        ambiguous: Set[str] = set()
        urls: Set[str] = set()

        # URLs first. A host that appears in a URL is a domain even when it could be a file name.
        confirmed_hosts: Set[str] = set()
        for match in PATTERNS["url"].finditer(text):
            url = _strip_url(match.group(0))
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if not host:
                continue
            host = host.lower()
            if parse_ip(host) is None and not valid_domain(host):
                continue
            if not self._keep_host(host):
                continue
            urls.add(url)
            if parse_ip(host) is None:
                confirmed_hosts.add(host)

        emails: Set[str] = set()
        for match in PATTERNS["email"].finditer(text):
            address = match.group(0).lower()
            host = address.rsplit("@", 1)[1]
            if valid_domain(host):
                emails.add(address)

        for match in PATTERNS["ipv4"].finditer(text):
            address = parse_ip(match.group(0))
            if address is not None and address.version == 4 and (self.include_private or is_routable(address)):
                ipv4.add(str(address))

        for match in PATTERNS["ipv6"].finditer(text):
            candidate = match.group(0)
            if "::" not in candidate and candidate.count(":") != 7:
                continue   # times and MAC addresses have colons too
            address = parse_ip(candidate)
            if address is not None and address.version == 6 and (self.include_private or is_routable(address)):
                ipv6.add(str(address))

        for match in PATTERNS["domain"].finditer(text):
            name = match.group(0).lower()
            if not valid_domain(name):
                continue
            if not self.include_allowlisted and in_allowlist(name, self.allowlist):
                continue
            labels = name.split(".")
            if len(labels) == 2 and labels[1] in FILE_EXTENSION_TLDS and name not in confirmed_hosts:
                ambiguous.add(name)
            else:
                domains.add(name)
        domains.update(confirmed_hosts)
        ambiguous -= domains

        sha256 = {m.group(0).lower() for m in PATTERNS["sha256"].finditer(text) if _looks_like_hash(m.group(0))}
        sha1 = {m.group(0).lower() for m in PATTERNS["sha1"].finditer(text) if _looks_like_hash(m.group(0))}
        md5 = {m.group(0).lower() for m in PATTERNS["md5"].finditer(text) if _looks_like_hash(m.group(0))}

        ethereum = {m.group(0) for m in PATTERNS["ethereum"].finditer(text)}
        # "0x" plus 40 hex characters is an Ethereum address, not a SHA-1.
        sha1 -= {address[2:].lower() for address in ethereum}

        bitcoin = {m.group(0) for m in PATTERNS["bitcoin_base58"].finditer(text) if valid_base58check(m.group(0))}
        bitcoin |= {m.group(0).lower() for m in PATTERNS["bitcoin_bech32"].finditer(text) if valid_bech32(m.group(0))}

        macs = {m.group(0).lower().replace("-", ":") for m in PATTERNS["mac"].finditer(text)}
        cves = {m.group(0).upper() for m in PATTERNS["cve"].finditer(text)}

        return IOCResults(
            ipv4=sorted(ipv4, key=ipaddress.ip_address),
            ipv6=sorted(ipv6, key=ipaddress.ip_address),
            domains=sorted(domains),
            domains_or_file_names=sorted(ambiguous),
            urls=sorted(urls),
            md5_hashes=sorted(md5),
            sha1_hashes=sorted(sha1),
            sha256_hashes=sorted(sha256),
            emails=sorted(emails),
            cves=sorted(cves),
            bitcoin_addresses=sorted(bitcoin),
            ethereum_addresses=sorted(ethereum),
            mac_addresses=sorted(macs),
        )

    def extract_from_file(self, filepath: str) -> IOCResults:
        return self.extract(read_input(filepath))


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def read_input(filepath: str) -> str:
    """Text of a file, or of standard input for "-". JSON is flattened to its strings."""
    if filepath == "-":
        text = sys.stdin.read()
        is_json = text.lstrip()[:1] in ("{", "[")
    else:
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")
        text = path.read_text(encoding="utf-8", errors="replace")
        is_json = path.suffix.lower() == ".json"
    if is_json:
        try:
            # JSON escapes such as \/ would otherwise break URLs.
            return "\n".join(_strings(json.loads(text)))
        except ValueError:
            pass
    return text


# ----------------------------------------------------------------------- STIX

def _stix_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _stix_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_bundle(results: IOCResults, indicator_type: str = "unknown", now: Optional[datetime] = None) -> Dict[str, Any]:
    """STIX 2.1 bundle with one indicator per IOC and one vulnerability per CVE.

    The extractor does not judge what it finds, so indicators are typed
    "unknown" unless the caller says otherwise. Cryptocurrency addresses have
    no standard STIX 2.1 object and are left out.
    """
    stamp = _stix_time(now or datetime.now(timezone.utc))
    groups = [
        ("IPv4 address", results.ipv4, "[ipv4-addr:value = '{}']"),
        ("IPv6 address", results.ipv6, "[ipv6-addr:value = '{}']"),
        ("Domain", results.domains, "[domain-name:value = '{}']"),
        ("URL", results.urls, "[url:value = '{}']"),
        ("MD5", results.md5_hashes, "[file:hashes.MD5 = '{}']"),
        ("SHA-1", results.sha1_hashes, "[file:hashes.'SHA-1' = '{}']"),
        ("SHA-256", results.sha256_hashes, "[file:hashes.'SHA-256' = '{}']"),
        ("Email address", results.emails, "[email-addr:value = '{}']"),
        ("MAC address", results.mac_addresses, "[mac-addr:value = '{}']"),
    ]
    objects: List[Dict[str, Any]] = []
    for label, values, pattern in groups:
        for value in values:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": f"{label}: {value}",
                "indicator_types": [indicator_type],
                "pattern": pattern.format(_stix_literal(value)),
                "pattern_type": "stix",
                "valid_from": stamp,
            })
    for cve in results.cves:
        objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": stamp,
            "modified": stamp,
            "name": cve,
            "external_references": [{"source_name": "cve", "external_id": cve}],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ------------------------------------------------------------------------ CLI

def format_csv(results: IOCResults) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value"])
    for ioc_type, values in results.to_dict().items():
        for value in values:
            writer.writerow([ioc_type, value])
    return buffer.getvalue().rstrip("\n")


def format_simple(results: IOCResults) -> str:
    lines: List[str] = []
    for ioc_type, values in results.to_dict().items():
        if values:
            lines.append(f"[{ioc_type.upper()}]")
            lines.extend(f"  {value}" for value in values)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract indicators of compromise from text or a file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --input malware_report.txt
  %(prog)s --text "Beacon to 45.33.32.156 and evil[.]example[.]com" --format simple
  %(prog)s --input alert.json --format stix --output iocs.stix.json
  cat mail.eml | %(prog)s --input -
""")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", "-i", help='input file, or "-" for standard input')
    source.add_argument("--text", "-t", help="text to scan")
    parser.add_argument("--output", "-o", help="write the result to this file instead of standard output")
    parser.add_argument("--format", "-f", choices=["json", "stix", "csv", "simple"], default="json",
                        help="output format (default: json)")
    parser.add_argument("--include-private", "--no-filter-private", action="store_true",
                        help="keep private, loopback, link-local and reserved IP addresses")
    parser.add_argument("--include-allowlisted", "--no-filter-whitelist", action="store_true",
                        help="keep domains on the built-in allowlist of common services")
    parser.add_argument("--stix-indicator-type", default="unknown",
                        choices=["unknown", "malicious-activity", "anomalous-activity", "compromised", "benign"],
                        help="indicator type written to STIX output (default: unknown)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    extractor = IOCExtractor(include_private=args.include_private, include_allowlisted=args.include_allowlisted)
    try:
        results = extractor.extract(args.text) if args.text is not None else extractor.extract_from_file(args.input)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        output = results.to_json()
    elif args.format == "stix":
        output = json.dumps(stix_bundle(results, args.stix_indicator_type), indent=2)
    elif args.format == "csv":
        output = format_csv(results)
    else:
        output = format_simple(results)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"{results.total_count} IOCs written to {args.output}", file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
