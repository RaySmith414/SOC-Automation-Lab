# Optional components

The compose file in this repository runs Shuffle, TheHive and Cortex. That stack is started and checked by CI on every push. The parts below are not. They are described here so you know what each one needs, with a pointer to the project's own instructions. Follow those instructions for the exact commands, because they change from release to release.

## Cortex analyzers

Cortex runs each analyzer as a Docker container. For that it needs two things the lab does not give it by default:

1. access to the Docker socket of the host
2. a job directory that has the same path inside the Cortex container and on the host

The Docker socket gives Cortex control of Docker on the host, which is why it is left off. StrangeBee documents the setup in [Run Cortex with Docker](https://docs.strangebee.com/cortex/installation-and-configuration/run-cortex-with-docker). Once Cortex can start containers, log in as the `thehive` org admin (password `CORTEX_ORGADMIN_PASSWORD` in `.env`) and enable analyzers under Organization.

## Wazuh

Wazuh needs its own indexer, manager and dashboard with certificates between them. The Wazuh project ships a compose deployment for a single node that sets all of that up: see [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).

Things to know when you run it next to this lab:

- Wazuh publishes ports 443, 9200, 55000, 1514 and 1515. None of them collide with the lab, which publishes 3001, 3443, 5001, 9000 and 9001.
- Plan for several more gigabytes of RAM.
- `scripts/python/automated_blocking.py` can send the `firewall-drop` active response through the Wazuh API. Set `WAZUH_API_URL`, `WAZUH_API_USER` and `WAZUH_API_PASSWORD`. The Wazuh deployment uses a self-signed certificate, so point `WAZUH_CA_BUNDLE` at its root CA.

## MISP

The MISP project maintains [misp-docker](https://github.com/MISP/misp-docker). It brings its own database and cache.

Things to know:

- MISP publishes port 443 by default, the same port as the Wazuh dashboard. Change one of them if you run both.
- `scripts/python/automated_blocking.py` can publish indicators to MISP as an event. Set `MISP_URL` and `MISP_API_KEY`.
- TheHive can connect to MISP. Add the server under Platform Management in TheHive once MISP has an API key for it.
