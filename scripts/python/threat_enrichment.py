#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Script
SOC Automation Lab

Enriches IOCs using multiple threat intelligence sources
"""

import os
import json
import argparse
import sys
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration from environment variables
CONFIG = {
    'virustotal': {
        'api_key': os.getenv('VIRUSTOTAL_API_KEY'),
        'base_url': 'https://www.virustotal.com/api/v3',
        'rate_limit': 4  # requests per minute for free API
    },
    'abuseipdb': {
        'api_key': os.getenv('ABUSEIPDB_API_KEY'),
        'base_url': 'https://api.abuseipdb.com/api/v2',
        'rate_limit': 60
    },
    'shodan': {
        'api_key': os.getenv('SHODAN_API_KEY'),
        'base_url': 'https://api.shodan.io',
        'rate_limit': 1
    },
    'greynoise': {
        'api_key': os.getenv('GREYNOISE_API_KEY'),
        'base_url': 'https://api.greynoise.io/v3',
        'rate_limit': 60
    },
    'urlscan': {
        'api_key': os.getenv('URLSCAN_API_KEY'),
        'base_url': 'https://urlscan.io/api/v1',
        'rate_limit': 60
    },
    'otx': {
        'api_key': os.getenv('OTX_API_KEY'),
        'base_url': 'https://otx.alienvault.com/api/v1',
        'rate_limit': 60
    }
}


@dataclass
class EnrichmentResult:
    """Container for enrichment results"""
    ioc: str
    ioc_type: str
    risk_score: int
    malicious: bool
    sources: Dict[str, Any]
    tags: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    context: Dict[str, Any]

    def to_dict(self) -> Dict:
        return asdict(self)


class RateLimiter:
    """Simple rate limiter"""

    def __init__(self, requests_per_minute: int):
        self.interval = 60.0 / requests_per_minute
        self.last_request = 0

    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_request = time.time()


class ThreatEnricher:
    """Enrich IOCs using multiple threat intelligence sources"""

    def __init__(self, services: Optional[List[str]] = None):
        self.services = services or list(CONFIG.keys())
        self.session = self._create_session()
        self.rate_limiters = {
            name: RateLimiter(cfg['rate_limit'])
            for name, cfg in CONFIG.items()
            if cfg.get('api_key')
        }

    def _create_session(self) -> requests.Session:
        """Create session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def _query_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal for IP information"""
        api_key = CONFIG['virustotal']['api_key']
        if not api_key:
            return None

        self.rate_limiters['virustotal'].wait()

        url = f"{CONFIG['virustotal']['base_url']}/ip_addresses/{ip}"
        headers = {'x-apikey': api_key}

        try:
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'country': data.get('data', {}).get('attributes', {}).get('country'),
                    'as_owner': data.get('data', {}).get('attributes', {}).get('as_owner')
                }
        except Exception as e:
            print(f"VirusTotal error for {ip}: {e}", file=sys.stderr)

        return None

    def _query_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Query VirusTotal for domain information"""
        api_key = CONFIG['virustotal']['api_key']
        if not api_key:
            return None

        self.rate_limiters['virustotal'].wait()

        url = f"{CONFIG['virustotal']['base_url']}/domains/{domain}"
        headers = {'x-apikey': api_key}

        try:
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'categories': data.get('data', {}).get('attributes', {}).get('categories', {}),
                    'registrar': data.get('data', {}).get('attributes', {}).get('registrar')
                }
        except Exception as e:
            print(f"VirusTotal error for {domain}: {e}", file=sys.stderr)

        return None

    def _query_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal for file hash information"""
        api_key = CONFIG['virustotal']['api_key']
        if not api_key:
            return None

        self.rate_limiters['virustotal'].wait()

        url = f"{CONFIG['virustotal']['base_url']}/files/{file_hash}"
        headers = {'x-apikey': api_key}

        try:
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'file_type': attrs.get('type_description'),
                    'file_size': attrs.get('size'),
                    'names': attrs.get('names', [])[:5],
                    'first_submission': attrs.get('first_submission_date'),
                    'last_analysis': attrs.get('last_analysis_date')
                }
        except Exception as e:
            print(f"VirusTotal error for {file_hash}: {e}", file=sys.stderr)

        return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB for IP information"""
        api_key = CONFIG['abuseipdb']['api_key']
        if not api_key:
            return None

        self.rate_limiters['abuseipdb'].wait()

        url = f"{CONFIG['abuseipdb']['base_url']}/check"
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}

        try:
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'is_tor': data.get('isTor', False),
                    'categories': data.get('reports', [{}])[0].get('categories', []) if data.get('reports') else []
                }
        except Exception as e:
            print(f"AbuseIPDB error for {ip}: {e}", file=sys.stderr)

        return None

    def _query_shodan(self, ip: str) -> Optional[Dict]:
        """Query Shodan for IP information"""
        api_key = CONFIG['shodan']['api_key']
        if not api_key:
            return None

        self.rate_limiters['shodan'].wait()

        url = f"{CONFIG['shodan']['base_url']}/shodan/host/{ip}"
        params = {'key': api_key}

        try:
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'country': data.get('country_code'),
                    'org': data.get('org'),
                    'asn': data.get('asn'),
                    'vulns': data.get('vulns', []),
                    'tags': data.get('tags', [])
                }
        except Exception as e:
            if 'No information available' not in str(e):
                print(f"Shodan error for {ip}: {e}", file=sys.stderr)

        return None

    def _query_greynoise(self, ip: str) -> Optional[Dict]:
        """Query GreyNoise for IP information"""
        api_key = CONFIG['greynoise']['api_key']
        if not api_key:
            return None

        self.rate_limiters['greynoise'].wait()

        url = f"{CONFIG['greynoise']['base_url']}/community/{ip}"
        headers = {'key': api_key}

        try:
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification'),
                    'name': data.get('name'),
                    'link': data.get('link')
                }
        except Exception as e:
            print(f"GreyNoise error for {ip}: {e}", file=sys.stderr)

        return None

    def _query_otx(self, ioc: str, ioc_type: str) -> Optional[Dict]:
        """Query AlienVault OTX"""
        api_key = CONFIG['otx']['api_key']
        if not api_key:
            return None

        self.rate_limiters['otx'].wait()

        type_map = {
            'ip': 'IPv4',
            'domain': 'domain',
            'url': 'url',
            'hash': 'file'
        }

        otx_type = type_map.get(ioc_type)
        if not otx_type:
            return None

        url = f"{CONFIG['otx']['base_url']}/indicators/{otx_type}/{ioc}/general"
        headers = {'X-OTX-API-KEY': api_key}

        try:
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])[:5]],
                    'validation': data.get('validation', [])
                }
        except Exception as e:
            print(f"OTX error for {ioc}: {e}", file=sys.stderr)

        return None

    def _calculate_risk_score(self, sources: Dict[str, Any], ioc_type: str) -> int:
        """Calculate overall risk score from enrichment results"""
        score = 0

        # VirusTotal scoring
        vt = sources.get('virustotal', {})
        if vt:
            malicious = vt.get('malicious', 0)
            if malicious > 10:
                score += 40
            elif malicious > 5:
                score += 25
            elif malicious > 0:
                score += 10

        # AbuseIPDB scoring
        abuse = sources.get('abuseipdb', {})
        if abuse:
            confidence = abuse.get('abuse_confidence_score', 0)
            if confidence > 80:
                score += 35
            elif confidence > 50:
                score += 20
            elif confidence > 20:
                score += 10

            if abuse.get('is_tor'):
                score += 10

        # GreyNoise scoring
        gn = sources.get('greynoise', {})
        if gn:
            if gn.get('classification') == 'malicious':
                score += 30
            elif gn.get('classification') == 'benign':
                score -= 10
            if gn.get('noise'):
                score += 5

        # Shodan scoring
        shodan = sources.get('shodan', {})
        if shodan:
            if shodan.get('vulns'):
                score += len(shodan['vulns']) * 5

        # OTX scoring
        otx = sources.get('otx', {})
        if otx:
            pulse_count = otx.get('pulse_count', 0)
            if pulse_count > 10:
                score += 20
            elif pulse_count > 0:
                score += 10

        return min(max(score, 0), 100)

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Enrich an IP address"""
        sources = {}
        tags = []

        if 'virustotal' in self.services:
            sources['virustotal'] = self._query_virustotal_ip(ip)

        if 'abuseipdb' in self.services:
            sources['abuseipdb'] = self._query_abuseipdb(ip)

        if 'shodan' in self.services:
            sources['shodan'] = self._query_shodan(ip)

        if 'greynoise' in self.services:
            sources['greynoise'] = self._query_greynoise(ip)

        if 'otx' in self.services:
            sources['otx'] = self._query_otx(ip, 'ip')

        # Generate tags
        if sources.get('abuseipdb', {}).get('is_tor'):
            tags.append('tor-exit-node')
        if sources.get('greynoise', {}).get('noise'):
            tags.append('internet-scanner')
        if sources.get('shodan', {}).get('vulns'):
            tags.append('vulnerable')

        risk_score = self._calculate_risk_score(sources, 'ip')

        return EnrichmentResult(
            ioc=ip,
            ioc_type='ip',
            risk_score=risk_score,
            malicious=risk_score >= 50,
            sources=sources,
            tags=tags,
            first_seen=None,
            last_seen=None,
            context={
                'country': sources.get('abuseipdb', {}).get('country') or sources.get('shodan', {}).get('country'),
                'asn': sources.get('shodan', {}).get('asn'),
                'org': sources.get('shodan', {}).get('org') or sources.get('abuseipdb', {}).get('isp')
            }
        )

    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Enrich a domain"""
        sources = {}

        if 'virustotal' in self.services:
            sources['virustotal'] = self._query_virustotal_domain(domain)

        if 'otx' in self.services:
            sources['otx'] = self._query_otx(domain, 'domain')

        risk_score = self._calculate_risk_score(sources, 'domain')

        return EnrichmentResult(
            ioc=domain,
            ioc_type='domain',
            risk_score=risk_score,
            malicious=risk_score >= 50,
            sources=sources,
            tags=[],
            first_seen=None,
            last_seen=None,
            context={
                'registrar': sources.get('virustotal', {}).get('registrar'),
                'categories': sources.get('virustotal', {}).get('categories')
            }
        )

    def enrich_hash(self, file_hash: str) -> EnrichmentResult:
        """Enrich a file hash"""
        sources = {}

        if 'virustotal' in self.services:
            sources['virustotal'] = self._query_virustotal_hash(file_hash)

        if 'otx' in self.services:
            sources['otx'] = self._query_otx(file_hash, 'hash')

        risk_score = self._calculate_risk_score(sources, 'hash')
        tags = []

        vt = sources.get('virustotal', {})
        if vt:
            if vt.get('malicious', 0) > 10:
                tags.append('malware')

        return EnrichmentResult(
            ioc=file_hash,
            ioc_type='hash',
            risk_score=risk_score,
            malicious=risk_score >= 50,
            sources=sources,
            tags=tags,
            first_seen=None,
            last_seen=None,
            context={
                'file_type': vt.get('file_type') if vt else None,
                'file_names': vt.get('names') if vt else None
            }
        )

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Enrich an IOC based on its type"""
        if ioc_type == 'ip':
            return self.enrich_ip(ioc)
        elif ioc_type == 'domain':
            return self.enrich_domain(ioc)
        elif ioc_type in ['hash', 'md5', 'sha1', 'sha256']:
            return self.enrich_hash(ioc)
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")


def main():
    parser = argparse.ArgumentParser(
        description='Enrich IOCs using threat intelligence sources'
    )

    parser.add_argument('--ioc', help='Single IOC to enrich')
    parser.add_argument('--type', choices=['ip', 'domain', 'hash', 'md5', 'sha1', 'sha256'],
                        help='IOC type (required with --ioc)')
    parser.add_argument('--input', '-i', help='Input JSON file with IOCs')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--services', nargs='+',
                        choices=['virustotal', 'abuseipdb', 'shodan', 'greynoise', 'urlscan', 'otx'],
                        help='Services to query (default: all available)')
    parser.add_argument('--format', '-f', choices=['json', 'summary'],
                        default='json', help='Output format')

    args = parser.parse_args()

    if args.ioc and not args.type:
        parser.error('--type is required when using --ioc')

    if not args.ioc and not args.input:
        parser.error('Either --ioc or --input is required')

    # Check for API keys
    available_services = [name for name, cfg in CONFIG.items() if cfg.get('api_key')]
    if not available_services:
        print("Warning: No API keys configured. Set environment variables:", file=sys.stderr)
        for name in CONFIG.keys():
            print(f"  {name.upper()}_API_KEY", file=sys.stderr)
        sys.exit(1)

    # Initialize enricher
    services = args.services or available_services
    enricher = ThreatEnricher(services=[s for s in services if s in available_services])

    results = []

    if args.ioc:
        # Single IOC
        result = enricher.enrich(args.ioc, args.type)
        results.append(result)
    else:
        # Batch from file
        with open(args.input, 'r') as f:
            data = json.load(f)

        # Process IOCs from file
        iocs_to_process = []
        if isinstance(data, dict):
            for ioc_type, values in data.items():
                for value in values:
                    iocs_to_process.append((value, ioc_type.replace('_hashes', '').replace('s', '')))
        elif isinstance(data, list):
            for item in data:
                iocs_to_process.append((item['value'], item['type']))

        for ioc, ioc_type in iocs_to_process:
            try:
                result = enricher.enrich(ioc, ioc_type)
                results.append(result)
                print(f"Enriched: {ioc} (score: {result.risk_score})", file=sys.stderr)
            except Exception as e:
                print(f"Error enriching {ioc}: {e}", file=sys.stderr)

    # Format output
    if args.format == 'json':
        output = json.dumps([r.to_dict() for r in results], indent=2)
    else:  # summary
        lines = []
        for r in results:
            status = "MALICIOUS" if r.malicious else "CLEAN"
            lines.append(f"[{status}] {r.ioc_type}: {r.ioc} (score: {r.risk_score})")
            if r.tags:
                lines.append(f"  Tags: {', '.join(r.tags)}")
        output = '\n'.join(lines)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
