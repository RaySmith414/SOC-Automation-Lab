#!/usr/bin/env python3
"""
Automated Blocking Script
SOC Automation Lab

Automates blocking of malicious indicators across security tools
"""

import os
import json
import argparse
import sys
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
CONFIG = {
    'wazuh': {
        'api_url': os.getenv('WAZUH_API_URL', 'https://localhost:55000'),
        'username': os.getenv('WAZUH_API_USER', 'wazuh'),
        'password': os.getenv('WAZUH_API_PASS', ''),
    },
    'firewall': {
        'api_url': os.getenv('FIREWALL_API_URL'),
        'api_key': os.getenv('FIREWALL_API_KEY'),
        'type': os.getenv('FIREWALL_TYPE', 'pfsense'),  # pfsense, fortigate, paloalto
    },
    'proxy': {
        'api_url': os.getenv('PROXY_API_URL'),
        'api_key': os.getenv('PROXY_API_KEY'),
        'type': os.getenv('PROXY_TYPE', 'squid'),
    },
    'edr': {
        'api_url': os.getenv('EDR_API_URL'),
        'api_key': os.getenv('EDR_API_KEY'),
        'type': os.getenv('EDR_TYPE', 'crowdstrike'),
    },
    'thehive': {
        'api_url': os.getenv('THEHIVE_URL', 'http://localhost:9000'),
        'api_key': os.getenv('THEHIVE_API_KEY'),
    },
    'misp': {
        'api_url': os.getenv('MISP_URL', 'https://localhost'),
        'api_key': os.getenv('MISP_API_KEY'),
    }
}


@dataclass
class BlockResult:
    """Result of a blocking action"""
    success: bool
    target: str
    ioc_type: str
    ioc_value: str
    message: str
    timestamp: str


class SecurityBlocker:
    """Unified interface for blocking across security tools"""

    def __init__(self, targets: Optional[List[str]] = None):
        self.targets = targets or ['wazuh', 'firewall', 'proxy', 'edr']
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for lab
        self._wazuh_token = None

    def _get_wazuh_token(self) -> str:
        """Get Wazuh API authentication token"""
        if self._wazuh_token:
            return self._wazuh_token

        url = f"{CONFIG['wazuh']['api_url']}/security/user/authenticate"
        auth = HTTPBasicAuth(
            CONFIG['wazuh']['username'],
            CONFIG['wazuh']['password']
        )

        try:
            response = self.session.post(url, auth=auth, timeout=30)
            if response.status_code == 200:
                self._wazuh_token = response.json()['data']['token']
                return self._wazuh_token
        except Exception as e:
            logger.error(f"Failed to get Wazuh token: {e}")

        raise Exception("Failed to authenticate with Wazuh")

    def _block_ip_wazuh(self, ip: str, comment: str = "") -> BlockResult:
        """Block IP using Wazuh active response"""
        try:
            token = self._get_wazuh_token()
            url = f"{CONFIG['wazuh']['api_url']}/active-response"
            headers = {'Authorization': f'Bearer {token}'}

            payload = {
                'command': 'firewall-drop',
                'custom': False,
                'alert': {
                    'data': {
                        'srcip': ip
                    }
                }
            }

            response = self.session.put(url, headers=headers, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                return BlockResult(
                    success=True,
                    target='wazuh',
                    ioc_type='ip',
                    ioc_value=ip,
                    message='IP blocked via Wazuh active response',
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                return BlockResult(
                    success=False,
                    target='wazuh',
                    ioc_type='ip',
                    ioc_value=ip,
                    message=f'Failed: {response.text}',
                    timestamp=datetime.utcnow().isoformat()
                )

        except Exception as e:
            return BlockResult(
                success=False,
                target='wazuh',
                ioc_type='ip',
                ioc_value=ip,
                message=str(e),
                timestamp=datetime.utcnow().isoformat()
            )

    def _block_ip_firewall(self, ip: str, comment: str = "") -> BlockResult:
        """Block IP on firewall"""
        fw_type = CONFIG['firewall']['type']
        api_url = CONFIG['firewall']['api_url']
        api_key = CONFIG['firewall']['api_key']

        if not api_url or not api_key:
            return BlockResult(
                success=False,
                target='firewall',
                ioc_type='ip',
                ioc_value=ip,
                message='Firewall not configured',
                timestamp=datetime.utcnow().isoformat()
            )

        try:
            if fw_type == 'pfsense':
                # pfSense API call
                url = f"{api_url}/api/v1/firewall/alias/entry"
                headers = {'Authorization': api_key}
                payload = {
                    'name': 'blocked_ips',
                    'address': ip,
                    'detail': comment or f'Blocked by SOC automation {datetime.utcnow().isoformat()}'
                }
                response = self.session.post(url, headers=headers, json=payload, timeout=30)

            elif fw_type == 'fortigate':
                # FortiGate API call
                url = f"{api_url}/api/v2/cmdb/firewall/address"
                headers = {'Authorization': f'Bearer {api_key}'}
                payload = {
                    'name': f'blocked_{ip.replace(".", "_")}',
                    'type': 'ipmask',
                    'subnet': f'{ip}/32',
                    'comment': comment
                }
                response = self.session.post(url, headers=headers, json=payload, timeout=30)

            elif fw_type == 'paloalto':
                # Palo Alto API call
                url = f"{api_url}/restapi/v10.0/Objects/Addresses"
                headers = {'X-PAN-KEY': api_key}
                payload = {
                    'entry': {
                        '@name': f'blocked_{ip.replace(".", "_")}',
                        'ip-netmask': f'{ip}/32',
                        'description': comment
                    }
                }
                response = self.session.post(url, headers=headers, json=payload, timeout=30)

            else:
                return BlockResult(
                    success=False,
                    target='firewall',
                    ioc_type='ip',
                    ioc_value=ip,
                    message=f'Unsupported firewall type: {fw_type}',
                    timestamp=datetime.utcnow().isoformat()
                )

            if response.status_code in [200, 201]:
                return BlockResult(
                    success=True,
                    target='firewall',
                    ioc_type='ip',
                    ioc_value=ip,
                    message=f'IP blocked on {fw_type} firewall',
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                return BlockResult(
                    success=False,
                    target='firewall',
                    ioc_type='ip',
                    ioc_value=ip,
                    message=f'Failed: {response.text}',
                    timestamp=datetime.utcnow().isoformat()
                )

        except Exception as e:
            return BlockResult(
                success=False,
                target='firewall',
                ioc_type='ip',
                ioc_value=ip,
                message=str(e),
                timestamp=datetime.utcnow().isoformat()
            )

    def _block_domain_proxy(self, domain: str, comment: str = "") -> BlockResult:
        """Block domain on web proxy"""
        api_url = CONFIG['proxy']['api_url']
        api_key = CONFIG['proxy']['api_key']

        if not api_url:
            return BlockResult(
                success=False,
                target='proxy',
                ioc_type='domain',
                ioc_value=domain,
                message='Proxy not configured',
                timestamp=datetime.utcnow().isoformat()
            )

        try:
            # Generic proxy blocklist API
            url = f"{api_url}/blocklist/domains"
            headers = {'Authorization': f'Bearer {api_key}'}
            payload = {
                'domain': domain,
                'comment': comment or f'Blocked by SOC automation',
                'timestamp': datetime.utcnow().isoformat()
            }

            response = self.session.post(url, headers=headers, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                return BlockResult(
                    success=True,
                    target='proxy',
                    ioc_type='domain',
                    ioc_value=domain,
                    message='Domain blocked on proxy',
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                return BlockResult(
                    success=False,
                    target='proxy',
                    ioc_type='domain',
                    ioc_value=domain,
                    message=f'Failed: {response.text}',
                    timestamp=datetime.utcnow().isoformat()
                )

        except Exception as e:
            return BlockResult(
                success=False,
                target='proxy',
                ioc_type='domain',
                ioc_value=domain,
                message=str(e),
                timestamp=datetime.utcnow().isoformat()
            )

    def _block_hash_edr(self, file_hash: str, comment: str = "") -> BlockResult:
        """Block file hash on EDR"""
        edr_type = CONFIG['edr']['type']
        api_url = CONFIG['edr']['api_url']
        api_key = CONFIG['edr']['api_key']

        if not api_url or not api_key:
            return BlockResult(
                success=False,
                target='edr',
                ioc_type='hash',
                ioc_value=file_hash,
                message='EDR not configured',
                timestamp=datetime.utcnow().isoformat()
            )

        try:
            if edr_type == 'crowdstrike':
                url = f"{api_url}/indicators/entities/iocs/v1"
                headers = {'Authorization': f'Bearer {api_key}'}
                payload = {
                    'indicators': [{
                        'type': 'sha256',
                        'value': file_hash,
                        'action': 'prevent',
                        'severity': 'high',
                        'description': comment,
                        'platforms': ['windows', 'mac', 'linux']
                    }]
                }

            elif edr_type == 'sentinelone':
                url = f"{api_url}/web/api/v2.1/threats/iocs"
                headers = {'Authorization': f'ApiToken {api_key}'}
                payload = {
                    'data': [{
                        'type': 'sha256',
                        'value': file_hash,
                        'source': 'SOC Automation',
                        'description': comment
                    }]
                }

            elif edr_type == 'carbonblack':
                url = f"{api_url}/appservices/v6/orgs/{os.getenv('CB_ORG_KEY')}/reputation_override/SHA256"
                headers = {
                    'X-Auth-Token': f'{api_key}',
                    'Content-Type': 'application/json'
                }
                payload = {
                    'sha256_hash': file_hash,
                    'description': comment,
                    'override_type': 'BLACK_LIST'
                }

            else:
                return BlockResult(
                    success=False,
                    target='edr',
                    ioc_type='hash',
                    ioc_value=file_hash,
                    message=f'Unsupported EDR type: {edr_type}',
                    timestamp=datetime.utcnow().isoformat()
                )

            response = self.session.post(url, headers=headers, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                return BlockResult(
                    success=True,
                    target='edr',
                    ioc_type='hash',
                    ioc_value=file_hash,
                    message=f'Hash blocked on {edr_type}',
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                return BlockResult(
                    success=False,
                    target='edr',
                    ioc_type='hash',
                    ioc_value=file_hash,
                    message=f'Failed: {response.text}',
                    timestamp=datetime.utcnow().isoformat()
                )

        except Exception as e:
            return BlockResult(
                success=False,
                target='edr',
                ioc_type='hash',
                ioc_value=file_hash,
                message=str(e),
                timestamp=datetime.utcnow().isoformat()
            )

    def _export_to_misp(self, ioc_type: str, ioc_value: str, comment: str = "") -> BlockResult:
        """Export IOC to MISP for threat intelligence sharing"""
        api_url = CONFIG['misp']['api_url']
        api_key = CONFIG['misp']['api_key']

        if not api_url or not api_key:
            return BlockResult(
                success=False,
                target='misp',
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                message='MISP not configured',
                timestamp=datetime.utcnow().isoformat()
            )

        # Map IOC types to MISP attribute types
        misp_type_map = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'hash': 'sha256',
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'email': 'email-src'
        }

        misp_type = misp_type_map.get(ioc_type)
        if not misp_type:
            return BlockResult(
                success=False,
                target='misp',
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                message=f'Unsupported IOC type for MISP: {ioc_type}',
                timestamp=datetime.utcnow().isoformat()
            )

        try:
            url = f"{api_url}/attributes/add/{{event_id}}"  # Needs event_id
            headers = {
                'Authorization': api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            payload = {
                'type': misp_type,
                'value': ioc_value,
                'category': 'Network activity' if ioc_type in ['ip', 'domain', 'url'] else 'Payload delivery',
                'to_ids': True,
                'comment': comment
            }

            # For this example, we'll create a new event
            event_url = f"{api_url}/events/add"
            event_payload = {
                'Event': {
                    'info': f'Automated blocking - {datetime.utcnow().strftime("%Y-%m-%d")}',
                    'distribution': 0,  # Organization only
                    'threat_level_id': 2,  # Medium
                    'analysis': 2,  # Completed
                    'Attribute': [payload]
                }
            }

            response = self.session.post(event_url, headers=headers, json=event_payload, timeout=30)

            if response.status_code in [200, 201]:
                return BlockResult(
                    success=True,
                    target='misp',
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    message='IOC exported to MISP',
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                return BlockResult(
                    success=False,
                    target='misp',
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    message=f'Failed: {response.text}',
                    timestamp=datetime.utcnow().isoformat()
                )

        except Exception as e:
            return BlockResult(
                success=False,
                target='misp',
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                message=str(e),
                timestamp=datetime.utcnow().isoformat()
            )

    def block_ip(self, ip: str, comment: str = "") -> List[BlockResult]:
        """Block IP across all configured targets"""
        results = []

        if 'wazuh' in self.targets:
            results.append(self._block_ip_wazuh(ip, comment))

        if 'firewall' in self.targets:
            results.append(self._block_ip_firewall(ip, comment))

        if 'misp' in self.targets:
            results.append(self._export_to_misp('ip', ip, comment))

        return results

    def block_domain(self, domain: str, comment: str = "") -> List[BlockResult]:
        """Block domain across all configured targets"""
        results = []

        if 'proxy' in self.targets:
            results.append(self._block_domain_proxy(domain, comment))

        if 'misp' in self.targets:
            results.append(self._export_to_misp('domain', domain, comment))

        return results

    def block_hash(self, file_hash: str, comment: str = "") -> List[BlockResult]:
        """Block file hash across all configured targets"""
        results = []

        if 'edr' in self.targets:
            results.append(self._block_hash_edr(file_hash, comment))

        if 'misp' in self.targets:
            hash_type = 'sha256' if len(file_hash) == 64 else 'md5' if len(file_hash) == 32 else 'sha1'
            results.append(self._export_to_misp(hash_type, file_hash, comment))

        return results

    def block(self, ioc_type: str, ioc_value: str, comment: str = "") -> List[BlockResult]:
        """Block an IOC based on its type"""
        if ioc_type == 'ip':
            return self.block_ip(ioc_value, comment)
        elif ioc_type == 'domain':
            return self.block_domain(ioc_value, comment)
        elif ioc_type in ['hash', 'md5', 'sha1', 'sha256']:
            return self.block_hash(ioc_value, comment)
        else:
            return [BlockResult(
                success=False,
                target='all',
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                message=f'Unsupported IOC type: {ioc_type}',
                timestamp=datetime.utcnow().isoformat()
            )]


def main():
    parser = argparse.ArgumentParser(
        description='Block malicious indicators across security tools'
    )

    parser.add_argument('--type', '-t', required=True,
                        choices=['ip', 'domain', 'hash', 'md5', 'sha1', 'sha256', 'url'],
                        help='IOC type')
    parser.add_argument('--value', '-v', help='IOC value to block')
    parser.add_argument('--input', '-i', help='Input file with IOCs (JSON)')
    parser.add_argument('--target', nargs='+',
                        choices=['wazuh', 'firewall', 'proxy', 'edr', 'misp', 'all'],
                        default=['all'],
                        help='Target systems to block on')
    parser.add_argument('--comment', '-c', default='',
                        help='Comment/reason for blocking')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be blocked without executing')

    args = parser.parse_args()

    if not args.value and not args.input:
        parser.error('Either --value or --input is required')

    # Determine targets
    if 'all' in args.target:
        targets = ['wazuh', 'firewall', 'proxy', 'edr', 'misp']
    else:
        targets = args.target

    # Initialize blocker
    blocker = SecurityBlocker(targets=targets)

    all_results = []

    if args.value:
        # Single IOC
        if args.dry_run:
            print(f"[DRY RUN] Would block {args.type}: {args.value} on {', '.join(targets)}")
        else:
            results = blocker.block(args.type, args.value, args.comment)
            all_results.extend(results)
    else:
        # Batch from file
        with open(args.input, 'r') as f:
            data = json.load(f)

        iocs = []
        if isinstance(data, list):
            iocs = data
        elif isinstance(data, dict):
            for ioc_type, values in data.items():
                for value in values:
                    iocs.append({'type': ioc_type, 'value': value})

        for ioc in iocs:
            ioc_type = ioc.get('type', args.type)
            ioc_value = ioc.get('value') or ioc.get('ioc')

            if args.dry_run:
                print(f"[DRY RUN] Would block {ioc_type}: {ioc_value} on {', '.join(targets)}")
            else:
                results = blocker.block(ioc_type, ioc_value, args.comment)
                all_results.extend(results)
                for r in results:
                    status = "SUCCESS" if r.success else "FAILED"
                    logger.info(f"[{status}] {r.target}: {r.ioc_value} - {r.message}")

    # Output results
    if not args.dry_run:
        output_data = [
            {
                'success': r.success,
                'target': r.target,
                'ioc_type': r.ioc_type,
                'ioc_value': r.ioc_value,
                'message': r.message,
                'timestamp': r.timestamp
            }
            for r in all_results
        ]

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"Results written to {args.output}")
        else:
            print(json.dumps(output_data, indent=2))

        # Summary
        success_count = sum(1 for r in all_results if r.success)
        total_count = len(all_results)
        print(f"\nSummary: {success_count}/{total_count} blocking actions successful")


if __name__ == '__main__':
    main()
