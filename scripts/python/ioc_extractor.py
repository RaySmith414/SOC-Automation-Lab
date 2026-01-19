#!/usr/bin/env python3
"""
IOC Extractor - Extract Indicators of Compromise from various sources
SOC Automation Lab

Extracts: IPs, domains, URLs, hashes, emails, CVEs, cryptocurrency addresses
"""

import re
import json
import argparse
import sys
from typing import Dict, List, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

# IOC Regex Patterns
PATTERNS = {
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
    'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'url': r'https?://[^\s<>"\']+',
    'md5': r'\b[a-fA-F0-9]{32}\b',
    'sha1': r'\b[a-fA-F0-9]{40}\b',
    'sha256': r'\b[a-fA-F0-9]{64}\b',
    'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'cve': r'CVE-\d{4}-\d{4,}',
    'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
    'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
}

# Common false positives to filter
WHITELIST_DOMAINS = {
    'microsoft.com', 'google.com', 'googleapis.com', 'gstatic.com',
    'windows.com', 'office.com', 'live.com', 'outlook.com',
    'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com',
    'cloudflare.com', 'akamai.com', 'github.com', 'githubusercontent.com'
}

PRIVATE_IP_RANGES = [
    r'^10\.',
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    r'^192\.168\.',
    r'^127\.',
    r'^0\.',
    r'^169\.254\.',
]


@dataclass
class IOCResults:
    """Container for extracted IOCs"""
    ipv4: List[str]
    ipv6: List[str]
    domains: List[str]
    urls: List[str]
    md5_hashes: List[str]
    sha1_hashes: List[str]
    sha256_hashes: List[str]
    emails: List[str]
    cves: List[str]
    bitcoin_addresses: List[str]
    ethereum_addresses: List[str]
    mac_addresses: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def total_count(self) -> int:
        return sum(len(v) for v in asdict(self).values())


class IOCExtractor:
    """Extract IOCs from text content"""

    def __init__(self, filter_private_ips: bool = True, filter_whitelist: bool = True):
        self.filter_private_ips = filter_private_ips
        self.filter_whitelist = filter_whitelist
        self.compiled_patterns = {k: re.compile(v) for k, v in PATTERNS.items()}
        self.private_ip_patterns = [re.compile(p) for p in PRIVATE_IP_RANGES]

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        return any(pattern.match(ip) for pattern in self.private_ip_patterns)

    def _is_whitelisted_domain(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        domain_lower = domain.lower()
        return any(domain_lower.endswith(w) for w in WHITELIST_DOMAINS)

    def _defang(self, text: str) -> str:
        """Convert defanged IOCs back to normal format"""
        text = text.replace('[.]', '.')
        text = text.replace('hxxp', 'http')
        text = text.replace('hXXp', 'http')
        text = re.sub(r'\[:\]', ':', text)
        text = re.sub(r'\[at\]', '@', text, flags=re.IGNORECASE)
        return text

    def extract(self, text: str) -> IOCResults:
        """Extract all IOC types from text"""
        # Defang text first
        text = self._defang(text)

        # Extract each IOC type
        ipv4_raw = set(self.compiled_patterns['ipv4'].findall(text))
        ipv6 = list(set(self.compiled_patterns['ipv6'].findall(text)))
        domains_raw = set(self.compiled_patterns['domain'].findall(text))
        urls = list(set(self.compiled_patterns['url'].findall(text)))
        md5_hashes = list(set(self.compiled_patterns['md5'].findall(text)))
        sha1_hashes = list(set(self.compiled_patterns['sha1'].findall(text)))
        sha256_hashes = list(set(self.compiled_patterns['sha256'].findall(text)))
        emails = list(set(self.compiled_patterns['email'].findall(text)))
        cves = list(set(self.compiled_patterns['cve'].findall(text)))
        bitcoin = list(set(self.compiled_patterns['bitcoin'].findall(text)))
        ethereum = list(set(self.compiled_patterns['ethereum'].findall(text)))
        mac_addresses = list(set(self.compiled_patterns['mac_address'].findall(text)))

        # Filter IPv4 addresses
        if self.filter_private_ips:
            ipv4 = [ip for ip in ipv4_raw if not self._is_private_ip(ip)]
        else:
            ipv4 = list(ipv4_raw)

        # Filter domains
        if self.filter_whitelist:
            domains = [d for d in domains_raw if not self._is_whitelisted_domain(d)]
        else:
            domains = list(domains_raw)

        # Remove hash false positives (hashes that are too uniform)
        def is_valid_hash(h: str) -> bool:
            unique_chars = len(set(h.lower()))
            return unique_chars > 4  # Real hashes have more variety

        md5_hashes = [h for h in md5_hashes if is_valid_hash(h)]
        sha1_hashes = [h for h in sha1_hashes if is_valid_hash(h)]
        sha256_hashes = [h for h in sha256_hashes if is_valid_hash(h)]

        # Remove SHA1 and MD5 if they're substrings of SHA256
        sha256_set = set(h.lower() for h in sha256_hashes)
        md5_hashes = [h for h in md5_hashes if not any(h.lower() in s for s in sha256_set)]
        sha1_hashes = [h for h in sha1_hashes if not any(h.lower() in s for s in sha256_set)]

        return IOCResults(
            ipv4=sorted(ipv4),
            ipv6=sorted(ipv6),
            domains=sorted(domains),
            urls=sorted(urls),
            md5_hashes=sorted(md5_hashes),
            sha1_hashes=sorted(sha1_hashes),
            sha256_hashes=sorted(sha256_hashes),
            emails=sorted(emails),
            cves=sorted(cves),
            bitcoin_addresses=sorted(bitcoin),
            ethereum_addresses=sorted(ethereum),
            mac_addresses=sorted(mac_addresses)
        )

    def extract_from_file(self, filepath: str) -> IOCResults:
        """Extract IOCs from a file"""
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Handle different file types
        if path.suffix.lower() == '.json':
            with open(path, 'r') as f:
                data = json.load(f)
                text = json.dumps(data)
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()

        return self.extract(text)


def stix_output(results: IOCResults) -> Dict:
    """Convert results to STIX 2.1 format"""
    stix_objects = []

    # Add IPv4 indicators
    for ip in results.ipv4:
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5(ip.encode()).hexdigest()}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "labels": ["malicious-activity"]
        })

    # Add domain indicators
    for domain in results.domains:
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5(domain.encode()).hexdigest()}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "labels": ["malicious-activity"]
        })

    # Add file hash indicators
    for sha256 in results.sha256_hashes:
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5(sha256.encode()).hexdigest()}",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "labels": ["malicious-activity"]
        })

    return {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(str(results.total_count).encode()).hexdigest()}",
        "objects": stix_objects
    }


def main():
    parser = argparse.ArgumentParser(
        description='Extract IOCs from text, files, or URLs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --input malware_report.txt
  %(prog)s --text "Found malicious IP 192.168.1.1 and domain evil.com"
  %(prog)s --input email.eml --output iocs.json
  %(prog)s --input report.txt --format stix
        '''
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input', '-i', help='Input file path')
    input_group.add_argument('--text', '-t', help='Direct text input')

    parser.add_argument('--output', '-o', help='Output file path (default: stdout)')
    parser.add_argument('--format', '-f', choices=['json', 'stix', 'csv', 'simple'],
                        default='json', help='Output format')
    parser.add_argument('--no-filter-private', action='store_true',
                        help='Include private IP addresses')
    parser.add_argument('--no-filter-whitelist', action='store_true',
                        help='Include whitelisted domains')

    args = parser.parse_args()

    # Initialize extractor
    extractor = IOCExtractor(
        filter_private_ips=not args.no_filter_private,
        filter_whitelist=not args.no_filter_whitelist
    )

    # Extract IOCs
    try:
        if args.text:
            results = extractor.extract(args.text)
        else:
            results = extractor.extract_from_file(args.input)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Format output
    if args.format == 'json':
        output = results.to_json()
    elif args.format == 'stix':
        output = json.dumps(stix_output(results), indent=2)
    elif args.format == 'csv':
        lines = ['type,value']
        for ioc_type, values in results.to_dict().items():
            for value in values:
                lines.append(f'{ioc_type},{value}')
        output = '\n'.join(lines)
    else:  # simple
        lines = []
        for ioc_type, values in results.to_dict().items():
            if values:
                lines.append(f"\n[{ioc_type.upper()}]")
                for value in values:
                    lines.append(f"  {value}")
        output = '\n'.join(lines)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}")
        print(f"Total IOCs extracted: {results.total_count}")
    else:
        print(output)


if __name__ == '__main__':
    main()
