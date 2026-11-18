# TheHive and Cortex

[TheHive](https://strangebee.com/thehive/) 5.8.1 is the case management platform of the lab. [Cortex](https://github.com/TheHive-Project/Cortex) 4.1.0 is its analysis engine. Both come from StrangeBee.

| Container | Role | Address |
| --- | --- | --- |
| `thehive` | Cases, alerts, tasks and observables | http://127.0.0.1:9000 |
| `cortex` | Runs analyzers and responders on observables | http://127.0.0.1:9001 |
| `cassandra` | TheHive's database | not published |
| `elasticsearch` | Search index for TheHive and Cortex | not published |

## Configuration

[`config/application.conf`](config/application.conf) is TheHive's configuration and [`../cortex/config/application.conf`](../cortex/config/application.conf) is Cortex's. Neither file holds a secret. Values such as `${THEHIVE_SECRET}` and `${ELASTIC_PASSWORD}` are read from the container environment, which `docker-compose.yml` fills from `.env`.

TheHive and Cortex share one Elasticsearch here to keep the lab small. StrangeBee recommends separate instances for production.

## Provisioning

`scripts/setup/provision.py` sets both services up through their APIs:

| Step | Where |
| --- | --- |
| Create the index, a superadmin, the organization `soc-lab` and an org admin for TheHive | Cortex |
| Register the Cortex server with that org admin's API key | TheHive |
| Create the organisation `soc-lab` and the analyst account | TheHive |
| Create the custom fields in [`templates/custom-fields.json`](templates/custom-fields.json) | TheHive |
| Create the case templates in [`templates/case-templates/`](templates/case-templates) | TheHive |
| Replace the default admin password | TheHive |

Run it again at any time. Steps that are already done are reported as `exists`. With `--self-test` it also creates a case from each template, checks the title prefix, the severity and the number of tasks, then deletes the case. CI runs exactly that on every push. The same option also runs two Shuffle workflows, which the [Shuffle page](../shuffle/README.md) describes.

## Case templates

| Template | Display name | Severity | Tasks |
| --- | --- | --- | --- |
| `malware-incident` | Malware Incident Response | 3 (high) | 9 |
| `phishing-investigation` | Phishing Email Investigation | 2 (medium) | 8 |
| `ransomware-incident` | Ransomware Attack Response | 4 (critical) | 12 |

Each template sets a title prefix, TLP, PAP, tags, the custom fields `attack-vector` and `mitre-tactics` and an ordered task list grouped by response phase. The task text follows the playbooks in [`../incident-response`](../incident-response/README.md).

To add a template, drop a JSON file in the same format into `templates/case-templates/` and run the provisioning script. A custom field a template uses has to be listed in `custom-fields.json`. `tests/test_repository.py` checks that.

## Cortex analyzers

Cortex starts without access to Docker, so it can be configured but cannot run analyzers yet. [`../docs/OPTIONAL_COMPONENTS.md`](../docs/OPTIONAL_COMPONENTS.md) explains what turning that on involves.
