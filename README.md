# SOC Automation Lab

[![CI](https://github.com/RaySmith414/SOC-Automation-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/RaySmith414/SOC-Automation-Lab/actions/workflows/ci.yml)

A Docker lab for security orchestration and case management. It runs Shuffle, TheHive and Cortex with pinned versions, sets them up through their APIs and ships Python tools for IOC extraction, threat intelligence lookups and guarded blocking. Incident response playbooks and TheHive case templates round it out.

## What is in the lab

| Part | Version | Role | Address |
| --- | --- | --- | --- |
| Shuffle | 2.3.0 | SOAR: workflows and automation | http://127.0.0.1:3001 |
| TheHive | 5.8.1 | Case management | http://127.0.0.1:9000 |
| Cortex | 4.1.0 | Observable analysis engine | http://127.0.0.1:9001 |
| Cassandra | 4.1.12 | TheHive database | not published |
| Elasticsearch | 8.19.23 | Index for TheHive and Cortex | not published |
| OpenSearch | 3.2.0 | Shuffle database | not published |

Around the stack:

- **Python tools** in [`scripts/python`](scripts/README.md): `ioc_extractor.py`, `threat_enrichment.py` and `automated_blocking.py`.
- **TheHive content** in [`thehive`](thehive/README.md): three case templates and two custom fields, loaded by a provisioning script.
- **Playbooks** in [`incident-response`](incident-response/README.md): malware infection, phishing and ransomware.
- **Workflow designs** in [`shuffle`](shuffle/README.md): four build sheets for Shuffle workflows. They are designs, not importable exports.

Wazuh and MISP are not part of the compose file. [`docs/OPTIONAL_COMPONENTS.md`](docs/OPTIONAL_COMPONENTS.md) explains how to run them next to the lab from their own official compose files.

## What is tested

Every push runs two jobs in GitHub Actions.

**Unit tests** on Python 3.9 through 3.13 cover the three tools without any network access: what the extractor accepts and rejects, how the enrichment handles every kind of failed lookup and every guard rail in the blocking script.

**The stack job** starts from a clean runner and:

1. generates secrets with `scripts/setup/init.sh`
2. starts all eight containers and waits until the health checks pass
3. checks that TheHive, Cortex and Shuffle answer
4. runs `scripts/setup/provision.py --self-test`, which sets up Cortex and TheHive through their APIs, creates a case from each template, checks its tasks and deletes it
5. has Shuffle run two workflows and waits for their results: Shuffle's own "Hello world" and one where the HTTP app fetches TheHive's status page by its name on the lab network
6. runs the provisioning a second time to prove that it changes nothing when the work is already done
7. stops the lab with `scripts/setup/stop.sh -v` and checks that no container, network or volume is left and that Docker is not in swarm mode

Not covered by CI: lookups against the live threat intelligence services (they need your API keys), Wazuh, MISP, Cortex analyzers and the workflow designs.

## Requirements

- Linux host with Docker Engine and the Docker Compose plugin. The stack job prints the versions it ran with. Older releases are untested.
- 16 GB of RAM, the size of the runner the stack is tested on. There the eight containers used about 7 GB after provisioning.
- About 10 GB of disk for the images
- `vm.max_map_count` of 262144 or more for Elasticsearch and OpenSearch
- Python 3.9 or newer for the tools and the provisioning script

## Quick start

```bash
git clone https://github.com/RaySmith414/SOC-Automation-Lab.git
cd SOC-Automation-Lab

sudo sysctl -w vm.max_map_count=262144
scripts/setup/init.sh                    # writes .env with a random value for every secret
docker compose up -d --wait              # the first start takes a few minutes
scripts/setup/smoke_test.sh              # checks that every service answers

python3 -m venv .venv
.venv/bin/pip install -r scripts/python/requirements.txt
.venv/bin/python scripts/setup/provision.py --self-test
```

The provisioning script prints where to log in. The passwords are in `.env`:

| Service | Login | Password variable |
| --- | --- | --- |
| TheHive | `admin@thehive.local` | `THEHIVE_ADMIN_PASSWORD` |
| TheHive | `analyst@soc.lab` (organisation `soc-lab`) | `THEHIVE_ANALYST_PASSWORD` |
| Cortex | `admin` | `CORTEX_ADMIN_PASSWORD` |
| Shuffle | `admin` | `SHUFFLE_DEFAULT_PASSWORD` |

To stop the lab, run `scripts/setup/stop.sh`. Add `-v` to delete the data as well. The script runs `docker compose down` and also removes worker containers that Shuffle started for workflow runs. They are not part of the compose project. One that is still running when the stack goes down would stay until it times out. Shuffle pulls and builds images for its apps while it runs. They stay on disk until you remove them.

TheHive 5 is commercial software with a free Community license. StrangeBee's licensing page lists what that license includes.

## Security notes

This is a lab. Run it on a machine you can throw away.

- **Docker socket.** Shuffle runs every workflow step in a container. Its backend and its Orborus service mount `/var/run/docker.sock` to start them. Anything that controls those two containers controls Docker on the host.
- **Ports.** Every published port is bound to `127.0.0.1`. To reach the lab from another machine, use an SSH tunnel instead of changing the binding.
- **No swarm mode.** Shuffle's own compose file runs its workers as Docker Swarm services. On a single host that made Docker a swarm node, published ports 33333 to 33337 on every interface and left services running after `docker compose down`. This lab runs workers and apps as plain containers that exist for one workflow run. Shuffle's pipelines are switched off too, because they start a Tenzir container that publishes ports 1514 and 5160.
- **Secrets.** `init.sh` creates a new random value for each secret and stores it in `.env` with file mode 600. `.env` is ignored by git. The configuration files in the repository hold no secret.
- **Databases.** Elasticsearch and OpenSearch require a password. Cassandra runs without authentication and is reachable only on the lab's Docker network. Traffic between the containers is not encrypted.
- **Default accounts.** The provisioning script replaces TheHive's default admin password. Cortex gets its first account from the script, with a generated password.

## Python tools

```bash
cd scripts/python

# 1. Pull indicators out of a report. Defanged text is understood.
python3 ioc_extractor.py --input report.txt --output iocs.json

# 2. Look them up. Services without an API key are skipped.
export VIRUSTOTAL_API_KEY=...
python3 threat_enrichment.py --input iocs.json --format summary

# 3. Plan a block. Nothing changes without --execute.
python3 automated_blocking.py --input iocs.json --target blocklist
python3 automated_blocking.py --input iocs.json --target blocklist --execute --comment "INC-1042"
```

[`scripts/README.md`](scripts/README.md) describes every option, the output formats and the guard rails.

## Project layout

```text
SOC-Automation-Lab/
  docker-compose.yml          # core stack with pinned versions
  .env.example                # every variable, documented (init.sh writes the real .env)
  scripts/
    setup/
      init.sh                 # generates secrets
      smoke_test.sh           # checks that every service answers
      provision.py            # sets up Cortex and TheHive through their APIs
      stop.sh                 # stops the lab and removes Shuffle's run containers
    python/
      ioc_extractor.py
      threat_enrichment.py
      automated_blocking.py
      requirements.txt
  thehive/
    config/application.conf
    templates/
      custom-fields.json
      case-templates/
  cortex/
    config/application.conf
  shuffle/
    workflow-designs/
  incident-response/
    playbooks/
  docs/
    OPTIONAL_COMPONENTS.md
  tests/
```

## Running the tests

```bash
python3 -m pip install -r requirements-dev.txt
ruff check .
python3 -m pytest
```

## License

MIT. See [LICENSE](LICENSE).

Shuffle, TheHive, Cortex, Cassandra, Elasticsearch and OpenSearch are the work of their own projects and companies and come under their own licenses. This repository only configures them.

## Author

Rayshaun Smith ([GitHub](https://github.com/RaySmith414))
