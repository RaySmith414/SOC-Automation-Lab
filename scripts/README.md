# Scripts

Two groups of scripts live here:

- [`setup/`](setup) brings the lab up: `init.sh`, `smoke_test.sh` and `provision.py`. The main [README](../README.md) shows how to use them.
- [`python/`](python) holds three tools that work on their own, with or without the lab running.

The tools need Python 3.9 or newer.

```bash
python3 -m pip install -r scripts/python/requirements.txt
```

## ioc_extractor.py

Pulls indicators of compromise out of text: IPv4 and IPv6 addresses, domains, URLs, MD5, SHA-1 and SHA-256 hashes, email addresses, CVE IDs, Bitcoin and Ethereum addresses and MAC addresses.

```bash
python3 ioc_extractor.py --input report.txt
python3 ioc_extractor.py --text "Beacon to 45[.]33[.]32[.]156 and hxxps://evil[.]example[.]com/gate" --format simple
python3 ioc_extractor.py --input alert.json --format stix --output iocs.stix.json
cat mail.eml | python3 ioc_extractor.py --input -
```

What it does to avoid false hits:

| Candidate | Check |
| --- | --- |
| IP address | Parsed with Python's `ipaddress` module. `256.1.1.1` and `1.2.3.4.5` are rejected. |
| Private and reserved addresses | Left out unless you pass `--include-private`. |
| Domain | Must end in a real public suffix, so `invoice.pdf` and `report.docx` are not domains. |
| Name that is both a top level domain and a file extension | `update.zip` or `setup.sh` on its own goes to `domains_or_file_names`. Seen inside a URL, it counts as a domain. |
| Common services | `microsoft.com`, `google.com` and similar are left out unless you pass `--include-allowlisted`. The match is on whole labels, so `evilmicrosoft.com` is kept. |
| URL | The host must be a valid domain or address. Trailing sentence punctuation is removed. |
| Hash | Exact length only. A run of one repeated character is not a hash. |
| Bitcoin address | The Base58Check or Bech32 checksum must be correct. |

Defanged forms are read as the real value: `hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`, `[at]` and `[@]`.

Output formats: `json` (default), `csv`, `simple` and `stix`. The STIX output is a STIX 2.1 bundle with one indicator per IOC and one vulnerability object per CVE. Indicators are typed `unknown` because extraction does not judge them. Change that with `--stix-indicator-type`. Cryptocurrency addresses have no standard STIX 2.1 object and are left out of the bundle.

Known limit: a name such as `System.IO` in source code ends in a real top level domain and is reported as a domain.

## threat_enrichment.py

Looks indicators up in threat intelligence services and turns the answers into a score.

| Service | Types | API key variable |
| --- | --- | --- |
| VirusTotal | ip, domain, url, hash | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | ip | `ABUSEIPDB_API_KEY` |
| GreyNoise (community API) | IPv4 | `GREYNOISE_API_KEY` |
| Shodan | ip | `SHODAN_API_KEY` |
| AlienVault OTX | ip, domain, url, hash | `OTX_API_KEY` |

```bash
export VIRUSTOTAL_API_KEY=...
python3 threat_enrichment.py --ioc 45.33.32.156 --type ip
python3 threat_enrichment.py --input iocs.json --format summary
python3 ioc_extractor.py -i report.txt | python3 threat_enrichment.py --input - --services virustotal otx --limit 20
```

`--input` takes the JSON that `ioc_extractor.py` writes. A list of `{"type": ..., "value": ...}` objects works too. Types no service takes (email, CVE, wallet, MAC) are skipped with a note.

How it behaves:

- **Every lookup has a status:** `ok`, `not_found`, `rate_limited`, `unauthorized`, `error` or `skipped`. One failed service never stops the run.
- **No answer is not a clean bill.** When no service answered, the verdict is `unknown` and the score is empty. The other verdicts are `malicious` (score 50 or more), `suspicious` (20 to 49) and `not_flagged`.
- **Private and reserved addresses stay home.** They are never sent to a third party.
- **Keys stay out of the output.** Error details never include a URL, because Shodan takes its key as a query parameter.
- **Rate limits are respected.** VirusTotal's public API allows four requests a minute, so a long list takes time. Use `--limit` to cap a run.

The score adds up what the services report:

| Signal | Points |
| --- | --- |
| VirusTotal engines flagging it: 1 to 5, 6 to 10, more than 10 | 10, 25, 40 |
| AbuseIPDB confidence: above 20, above 50, above 80 | 10, 20, 35 |
| AbuseIPDB marks it as a Tor exit node | 10 |
| GreyNoise classification `malicious` | 30 |
| GreyNoise classification `benign` | minus 10 |
| GreyNoise lists it as a common business service | minus 20 |
| OTX pulses: 1 to 10, more than 10 | 10, 20 |

Shodan adds context (ports, organization, exposed vulnerabilities) and no points. A vulnerable host is not a malicious one.

The tests replace the HTTP layer with recorded response shapes. They prove how each answer is handled. They cannot prove that a provider still returns that shape, so try a lookup with your own key before you rely on a service.

## automated_blocking.py

Blocks or unblocks IP addresses, domains and file hashes. Nothing changes unless you add `--execute`. Without it the script prints the plan and makes no network call and no file change.

```bash
python3 automated_blocking.py --type ip --value 45.33.32.156                       # plan only
python3 automated_blocking.py --type ip --value 45.33.32.156 --execute             # add to the blocklist
python3 automated_blocking.py --input iocs.json --execute --comment "INC-1042"
python3 automated_blocking.py --action unblock --type domain --value evil.example.com --execute
python3 automated_blocking.py --type ip --value 45.33.32.156 --target blocklist wazuh --agents 001 --execute
```

| Target | What it does | Configuration |
| --- | --- | --- |
| `blocklist` (default) | Keeps `blocked_ips.txt`, `blocked_domains.txt` and `blocked_hashes.txt`, one entry per line, sorted. Firewalls and proxies that read external lists can poll them. | `--blocklist-dir` or `BLOCKLIST_DIR` |
| `wazuh` | Sends the `firewall-drop` active response for an IP address to the agents you name. | `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `--agents` |
| `misp` | Creates one MISP event that holds the indicators as attributes flagged for detection. | `MISP_URL`, `MISP_API_KEY` |
| `webhook` | Sends one JSON POST with the action and the indicators, for example to a Shuffle webhook that drives your own firewall or EDR. | `BLOCK_WEBHOOK_URL`, `BLOCK_WEBHOOK_TOKEN` |

Guard rails:

- **Validation.** A value that is not what its type says is refused. Address ranges are refused too.
- **Never blocked.** Private, loopback and reserved addresses. Domains of common services. Anything in the file you pass with `--never-block` (IP addresses, CIDR ranges and domains, one per line).
- **TLS.** Certificates are verified. For a lab certificate, point `WAZUH_CA_BUNDLE` or `MISP_CA_BUNDLE` at the CA file. `--insecure` turns verification off and prints a warning.
- **Audit trail.** Every executed action is appended to `audit.jsonl` in the blocklist folder with its time, target, result and comment.
- **Honest results.** The Wazuh API confirms that a command reached the agent queue, not that the firewall rule exists. The message says so. An unblock through Wazuh or MISP is reported as unsupported.

Exit codes: 0 when everything requested was done or planned, 1 when an action failed, was refused or is not supported by the target, 2 for a usage or configuration error.

The file based blocklist is tested end to end. The Wazuh, MISP and webhook targets are tested against a recording session, not against live servers.
