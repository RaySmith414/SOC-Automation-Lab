# Shuffle

[Shuffle](https://shuffler.io) is the automation engine of the lab. The compose file runs four containers for it, all at version 2.3.0:

| Container | Role |
| --- | --- |
| `shuffle-frontend` | Web interface on http://127.0.0.1:3001 |
| `shuffle-backend` | API on http://127.0.0.1:5001 |
| `shuffle-orborus` | Starts a worker container for every workflow run |
| `shuffle-opensearch` | Database |

## Logging in

`scripts/setup/init.sh` writes the first account to `.env`:

- user: `SHUFFLE_DEFAULT_USERNAME` (`admin`)
- password: `SHUFFLE_DEFAULT_PASSWORD`
- API key: `SHUFFLE_DEFAULT_APIKEY`

The backend creates that account on its first start. The API key has to be a UUID, which is why `init.sh` generates one.

```bash
source .env
curl -H "Authorization: Bearer $SHUFFLE_DEFAULT_APIKEY" http://127.0.0.1:5001/api/v1/workflows
```

The first start takes a few minutes because the backend downloads and builds its app catalog.

## How a workflow runs here

Orborus asks the backend for queued runs and starts a worker container for each one. The worker starts one container per step from the app's image. All of them share the network of the Orborus container and are removed when they finish.

Because these containers are not part of the compose project, stop the lab with `scripts/setup/stop.sh`. It removes any that are still running.

This differs from Shuffle's own compose file, which sets `SHUFFLE_SWARM_CONFIG=run` and keeps workers and apps running as Docker Swarm services. The lab leaves that setting out for the reasons given in the security notes of the main README. A run takes a few seconds longer because containers start on demand.

`scripts/setup/provision.py --self-test` proves the path on every CI run with two workflows:

1. Shuffle's own first workflow: the Shuffle Tools action `repeat_back_to_me` returns "Hello world".
2. The HTTP app requests `http://thehive:9000/api/v1/status/public` and gets HTTP 200.

## Workflow designs

[`workflow-designs/`](workflow-designs) holds four build sheets:

| File | What the workflow should do |
| --- | --- |
| `alert-triage.json` | Take a Wazuh alert, extract indicators, look them up, score the alert and open a TheHive alert |
| `phishing-response.json` | Parse a reported email, check URLs and attachments, open a case and notify the reporter |
| `malware-response.json` | Take an endpoint detection, gather context, contain the host and open a case |
| `threat-intel-enrichment.json` | Look indicators up in several services and write the result back |

**These files are designs, not Shuffle exports. They cannot be imported.** Each one lists triggers, steps, the app a step needs and how data flows from step to step. Use them as the build sheet when you create the workflow in the Shuffle editor. Step and app names in the designs are descriptive and do not always match the name of an app in Shuffle's catalog.

A test (`tests/test_repository.py`) keeps the designs consistent: every step has a unique ID and every reference between steps points at a step that exists.

## Connecting Shuffle to the rest of the lab

Inside the lab's Docker network the services reach each other by name. The self-test checks the TheHive address. The Cortex address follows the same pattern and is not tested from a workflow.

| Service | URL from a Shuffle app | Credential |
| --- | --- | --- |
| TheHive | `http://thehive:9000` | An API key you create for the analyst account in TheHive |
| Cortex | `http://cortex:9001` | An API key from Cortex |

A workflow can also call the Python tools. `automated_blocking.py` has a `webhook` target that posts a block request to a Shuffle webhook, so a workflow can decide what to do with it.
