#!/usr/bin/env python3
"""Provision the running lab through the TheHive, Cortex and Shuffle APIs.

Run it once after `docker compose up -d`:

    python3 scripts/setup/provision.py

What it does, in order:

  Cortex    creates the index, a superadmin, the organization "soc-lab" and an
            org admin whose API key TheHive uses
  TheHive   registers the Cortex server, creates the organization "soc-lab", an
            analyst account, the custom fields and the case templates under
            thehive/templates, then replaces the default admin password
  Shuffle   checks that the API answers with the generated API key

Every password comes from .env (scripts/setup/init.sh). The script can be run
again: steps that are already done are reported as "exists".

    python3 scripts/setup/provision.py --self-test

also creates a case from each template, counts its tasks and deletes it. Then
Shuffle runs two workflows: its own "Hello world" and one that fetches
TheHive's status page over the lab network.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
THEHIVE = "http://127.0.0.1:9000"
CORTEX = "http://127.0.0.1:9001"
SHUFFLE = "http://127.0.0.1:5001"
ORGANISATION = "soc-lab"
THEHIVE_DEFAULT_ADMIN = ("admin@thehive.local", "secret")
TIMEOUT = 60


class Step:
    """Collects one line per step so a single run shows everything that went wrong."""

    def __init__(self):
        self.failed = []

    def report(self, state, what, detail=""):
        print(f"{state:7} {what}" + (f"  ({detail})" if detail else ""), flush=True)
        if state == "FAILED":
            self.failed.append(what)


def load_env(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"{path} not found. Run scripts/setup/init.sh first.")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def describe(response) -> str:
    """Status code and a short body, for the log. Bodies of these calls hold no secret."""
    body = " ".join(response.text.split())
    return f"HTTP {response.status_code}" + (f": {body[:240]}" if body else "")


def wait_for(name, url, seconds=600):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=10).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(5)
    sys.exit(f"{name} did not answer at {url} within {seconds} seconds")


# --------------------------------------------------------------------- Cortex

def provision_cortex(env, step) -> str:
    """Initialize Cortex and return the API key TheHive will use ("" on failure)."""
    admin = ("admin", env["CORTEX_ADMIN_PASSWORD"])
    orgadmin = ("thehive", env["CORTEX_ORGADMIN_PASSWORD"])
    headers = {"Content-Type": "application/json"}

    if requests.get(f"{CORTEX}/api/user/current", auth=admin, timeout=TIMEOUT).status_code == 200:
        step.report("exists", "Cortex superadmin")
    else:
        response = requests.post(f"{CORTEX}/api/maintenance/migrate", timeout=TIMEOUT)
        step.report("ok" if response.status_code == 204 else "FAILED", "Cortex index", describe(response))
        response = requests.post(f"{CORTEX}/api/user", headers=headers, timeout=TIMEOUT, json={
            "login": admin[0], "name": "Lab administrator", "roles": ["superadmin"], "preferences": "{}",
            "password": admin[1], "organization": "cortex"})
        step.report("ok" if response.status_code == 201 else "FAILED", "Cortex superadmin", describe(response))

    response = requests.get(f"{CORTEX}/api/organization/{ORGANISATION}", auth=admin, timeout=TIMEOUT)
    if response.status_code == 200:
        step.report("exists", f"Cortex organization {ORGANISATION}")
    else:
        response = requests.post(f"{CORTEX}/api/organization", auth=admin, headers=headers, timeout=TIMEOUT, json={
            "name": ORGANISATION, "description": "SOC Automation Lab", "status": "Active"})
        step.report("ok" if response.status_code == 201 else "FAILED", f"Cortex organization {ORGANISATION}",
                    describe(response))

    response = requests.get(f"{CORTEX}/api/user/{orgadmin[0]}", auth=admin, timeout=TIMEOUT)
    if response.status_code == 200:
        step.report("exists", "Cortex org admin for TheHive")
    else:
        response = requests.post(f"{CORTEX}/api/user", auth=admin, headers=headers, timeout=TIMEOUT, json={
            "login": orgadmin[0], "name": "TheHive connector", "roles": ["read", "analyze", "orgadmin"],
            "password": orgadmin[1], "organization": ORGANISATION})
        step.report("ok" if response.status_code == 201 else "FAILED", "Cortex org admin for TheHive",
                    describe(response))

    response = requests.post(f"{CORTEX}/api/user/{orgadmin[0]}/key/renew", auth=admin, timeout=TIMEOUT)
    key = response.text.strip().strip('"') if response.status_code == 200 else ""
    check = requests.get(f"{CORTEX}/api/user/{orgadmin[0]}", headers={"Authorization": f"Bearer {key}"},
                         timeout=TIMEOUT) if key else None
    working = check is not None and check.status_code == 200
    step.report("ok" if working else "FAILED", "Cortex API key for TheHive",
                "key accepted" if working else describe(response))
    return key if working else ""


# -------------------------------------------------------------------- TheHive

def thehive_admin_auth(env):
    """The admin login with whichever password is current: the generated one or the default."""
    for password in (env["THEHIVE_ADMIN_PASSWORD"], THEHIVE_DEFAULT_ADMIN[1]):
        auth = (THEHIVE_DEFAULT_ADMIN[0], password)
        if requests.get(f"{THEHIVE}/api/v1/user/current", auth=auth, timeout=TIMEOUT).status_code == 200:
            return auth
    sys.exit("Cannot log in to TheHive as admin@thehive.local with the generated or the default password.")


def thehive_query(auth, query, organisation=None):
    headers = {"Content-Type": "application/json"}
    if organisation:
        headers["X-Organisation"] = organisation
    return requests.post(f"{THEHIVE}/api/v1/query", auth=auth, headers=headers, timeout=TIMEOUT,
                         json={"query": query})


def register_cortex(admin, key, step):
    payload = {
        "statusCheckInterval": "1 minute",
        "refreshDelay": "5 seconds",
        "maxRetryOnError": 3,
        "jobTimeout": "3 hours",
        "servers": [{
            "name": "Cortex",
            "url": "http://cortex:9001",
            "includedTheHiveOrganisations": ["*"],
            "excludedTheHiveOrganisations": [],
            "auth": {"type": "bearer", "key": key},
        }],
    }
    response = requests.put(f"{THEHIVE}/api/v1/admin/config/cortex", auth=admin, timeout=TIMEOUT,
                            headers={"Content-Type": "application/json", "X-Organisation": "admin"}, json=payload)
    step.report("ok" if response.status_code in (200, 204) else "FAILED", "TheHive: Cortex server registered",
                describe(response))


def provision_thehive(env, cortex_key, step):
    admin = thehive_admin_auth(env)
    analyst = (env["THEHIVE_ANALYST_LOGIN"], env["THEHIVE_ANALYST_PASSWORD"])
    headers = {"Content-Type": "application/json"}

    if cortex_key:
        register_cortex(admin, cortex_key, step)
    else:
        step.report("FAILED", "TheHive: Cortex server registered", "no Cortex API key")

    response = requests.get(f"{THEHIVE}/api/v1/organisation/{ORGANISATION}", auth=admin, timeout=TIMEOUT)
    if response.status_code == 200:
        step.report("exists", f"TheHive organisation {ORGANISATION}")
    else:
        response = requests.post(f"{THEHIVE}/api/v1/organisation", auth=admin, headers=headers, timeout=TIMEOUT,
                                 json={"name": ORGANISATION, "description": "SOC Automation Lab"})
        step.report("ok" if response.status_code == 201 else "FAILED", f"TheHive organisation {ORGANISATION}",
                    describe(response))

    if requests.get(f"{THEHIVE}/api/v1/user/current", auth=analyst, timeout=TIMEOUT).status_code == 200:
        step.report("exists", f"TheHive analyst {analyst[0]}")
    else:
        response = requests.post(f"{THEHIVE}/api/v1/user", auth=admin, headers=headers, timeout=TIMEOUT, json={
            "login": analyst[0], "name": "Lab analyst", "organisation": ORGANISATION, "profile": "org-admin",
            "password": analyst[1]})
        step.report("ok" if response.status_code == 201 else "FAILED", f"TheHive analyst {analyst[0]}",
                    describe(response))

    fields = json.loads((ROOT / "thehive/templates/custom-fields.json").read_text(encoding="utf-8"))
    existing = thehive_query(admin, [{"_name": "listCustomField"}])
    known = {item.get("name") for item in existing.json()} if existing.status_code == 200 else set()
    for field in fields:
        # "reference" is the name templates and cases use. "name" is the label shown in the interface.
        if field["reference"] in known:
            step.report("exists", f"TheHive custom field {field['reference']}")
            continue
        response = requests.post(f"{THEHIVE}/api/customField", auth=admin, headers=headers, timeout=TIMEOUT,
                                 json=field)
        step.report("ok" if response.status_code == 201 else "FAILED", f"TheHive custom field {field['reference']}",
                    describe(response))

    existing = thehive_query(analyst, [{"_name": "listCaseTemplate"}], ORGANISATION)
    known = {item.get("name") for item in existing.json()} if existing.status_code == 200 else set()
    templates = sorted((ROOT / "thehive/templates/case-templates").glob("*.json"))
    for path in templates:
        template = json.loads(path.read_text(encoding="utf-8"))
        if template["name"] in known:
            step.report("exists", f"TheHive case template {template['name']}")
            continue
        response = requests.post(f"{THEHIVE}/api/v1/caseTemplate", auth=analyst, timeout=TIMEOUT,
                                 headers={**headers, "X-Organisation": ORGANISATION}, json=template)
        step.report("ok" if response.status_code == 201 else "FAILED", f"TheHive case template {template['name']}",
                    describe(response))

    if admin[1] == THEHIVE_DEFAULT_ADMIN[1]:
        response = requests.post(f"{THEHIVE}/api/v1/user/{admin[0]}/password/change", auth=admin, headers=headers,
                                 timeout=TIMEOUT,
                                 json={"currentPassword": admin[1], "password": env["THEHIVE_ADMIN_PASSWORD"]})
        step.report("ok" if response.status_code in (200, 204) else "FAILED",
                    "TheHive default admin password replaced", describe(response))
    else:
        step.report("exists", "TheHive default admin password replaced")
    return analyst, templates


def self_test(analyst, templates, step):
    """Create a case from each template, compare the task count with the file and delete the case."""
    headers = {"Content-Type": "application/json", "X-Organisation": ORGANISATION}
    for path in templates:
        template = json.loads(path.read_text(encoding="utf-8"))
        what = f"self-test: case from template {template['name']}"
        response = requests.post(f"{THEHIVE}/api/v1/case", auth=analyst, headers=headers, timeout=TIMEOUT, json={
            "title": "Provisioning self-test", "description": "Created and deleted by provision.py --self-test",
            "caseTemplate": template["name"]})
        if response.status_code != 201:
            step.report("FAILED", what, describe(response))
            continue
        case = response.json()
        tasks = thehive_query(analyst, [{"_name": "getCase", "idOrName": case["_id"]}, {"_name": "tasks"}],
                              ORGANISATION)
        count = len(tasks.json()) if tasks.status_code == 200 else -1
        expected = len(template["tasks"])
        title_ok = case.get("title", "").startswith(template["titlePrefix"])
        good = count == expected and title_ok and case.get("severity") == template["severity"]
        step.report("ok" if good else "FAILED", what,
                    f"{count} of {expected} tasks, title {case.get('title')!r}, severity {case.get('severity')}")
        requests.delete(f"{THEHIVE}/api/v1/case/{case['_id']}", auth=analyst, headers=headers,
                        params={"force": "1"}, timeout=TIMEOUT)


# -------------------------------------------------------------------- Shuffle

def check_shuffle(env, step):
    response = requests.get(f"{SHUFFLE}/api/v1/workflows", timeout=TIMEOUT,
                            headers={"Authorization": f"Bearer {env['SHUFFLE_DEFAULT_APIKEY']}"})
    step.report("ok" if response.status_code == 200 else "FAILED", "Shuffle API accepts the generated API key",
                f"HTTP {response.status_code}")
    response = requests.get(f"{SHUFFLE}/api/v1/workflows", timeout=TIMEOUT,
                            headers={"Authorization": "Bearer not-the-key"})
    step.report("ok" if response.status_code in (401, 403) else "FAILED", "Shuffle API rejects a wrong API key",
                f"HTTP {response.status_code}")


def run_workflow(headers, workflow, deadline):
    """Create a workflow, run it, wait for the end and delete it. Returns (execution, error)."""
    response = requests.post(f"{SHUFFLE}/api/v1/workflows", headers=headers, timeout=TIMEOUT, json=workflow)
    created = response.json() if response.status_code == 200 else {}
    workflow_id = created.get("id")
    if not workflow_id or not created.get("actions"):
        return {}, f"could not create the workflow ({describe(response)})"
    try:
        response = requests.post(f"{SHUFFLE}/api/v1/workflows/{workflow_id}/execute", headers=headers,
                                 timeout=TIMEOUT, json={"execution_argument": "", "start": ""})
        started = response.json() if response.status_code == 200 else {}
        if not started.get("execution_id"):
            return {}, f"could not start the workflow ({describe(response)})"
        execution = {}
        while time.time() < deadline:
            response = requests.post(f"{SHUFFLE}/api/v1/streams/results", headers=headers, timeout=TIMEOUT, json={
                "execution_id": started["execution_id"], "authorization": started["authorization"]})
            execution = response.json() if response.status_code == 200 else {}
            if execution.get("status") in ("FINISHED", "ABORTED", "FAILURE"):
                break
            time.sleep(5)
        return execution, ""
    finally:
        requests.delete(f"{SHUFFLE}/api/v1/workflows/{workflow_id}", headers=headers, timeout=TIMEOUT)


def version_of(app):
    """Sort key for an app version such as 1.4.0."""
    return [int(part) for part in str(app.get("app_version", "0")).split(".") if part.isdigit()]


def shuffle_self_test(env, step, seconds=900):
    """Run two workflows end to end: backend, Orborus, a worker container and an app container.

    The first is Shuffle's own first node: a workflow created without actions gets
    the Shuffle Tools action "repeat_back_to_me" with the text "Hello world". The
    second has the HTTP app fetch TheHive's status page by its name on the lab
    network, which is how a workflow reaches the other services of the lab.
    """
    headers = {"Authorization": f"Bearer {env['SHUFFLE_DEFAULT_APIKEY']}"}
    deadline = time.time() + seconds
    note = "Created and deleted by provision.py --self-test"

    # The backend downloads its apps after the first start. Wait for the two the workflows use.
    while True:
        response = requests.get(f"{SHUFFLE}/api/v1/apps", headers=headers, timeout=TIMEOUT)
        apps = [app for app in (response.json() if response.status_code == 200 else []) if isinstance(app, dict)]
        tools = [app for app in apps if app.get("name") in ("Shuffle Tools", "Shuffle-Tools")
                 and app.get("app_version") == "1.2.0"]
        http = sorted((app for app in apps if str(app.get("name", "")).lower() == "http"), key=version_of)
        if tools and http:
            break
        if time.time() > deadline:
            for what in ("self-test: Shuffle runs a workflow", "self-test: a Shuffle app reaches TheHive"):
                step.report("FAILED", what, f"Shuffle did not load its apps ({describe(response)[:120]})")
            return
        time.sleep(10)

    what = "self-test: Shuffle runs a workflow"
    execution, error = run_workflow(headers, {"name": "Provisioning self-test", "description": note}, deadline)
    results = execution.get("results") or []
    output = " ".join(str(item.get("result", "")) for item in results)
    good = (execution.get("status") == "FINISHED" and bool(results)
            and all(item.get("status") == "SUCCESS" for item in results) and "Hello world" in output)
    step.report("ok" if good else "FAILED", what, error or (
        f"run {execution.get('execution_id', 'unknown')}, status {execution.get('status', 'no answer')}, "
        f"{len(results)} action result(s), output {' '.join(output.split())[:80]!r}"))

    what = "self-test: a Shuffle app reaches TheHive"
    app = http[-1]
    get = next((action for action in app.get("actions") or [] if action.get("name") == "GET"), None)
    if not get:
        step.report("FAILED", what, f"the HTTP app {app.get('app_version')} has no GET action")
        return
    node = "0f9d6c5e-1b7a-4c1e-9d55-6a1f0e3b7c21"
    parameters = [dict(parameter, value="http://thehive:9000/api/v1/status/public")
                  if parameter.get("name") == "url" else parameter for parameter in get.get("parameters") or []]
    execution, error = run_workflow(headers, {
        "name": "Provisioning self-test: TheHive status", "description": note, "start": node,
        "actions": [{
            "id": node, "label": "thehive_status", "name": "GET", "app_name": app["name"],
            "app_version": app["app_version"], "app_id": app["id"], "environment": "Shuffle",
            "is_valid": True, "isStartNode": True, "errors": [], "parameters": parameters,
            "position": {"x": 450, "y": 450}}],
    }, deadline)
    results = execution.get("results") or []
    output = str(results[0].get("result", "")) if results else ""
    try:
        status = json.loads(output).get("status")
    except (ValueError, AttributeError):
        status = None
    good = execution.get("status") == "FINISHED" and bool(results) and status == 200
    step.report("ok" if good else "FAILED", what, error or (
        f"run {execution.get('execution_id', 'unknown')}, status {execution.get('status', 'no answer')}, "
        f"HTTP status {status}, output {' '.join(output.split())[:120]!r}"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true",
                        help="also create a case from each template and run two Shuffle workflows")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="path of the .env file (default: ./.env)")
    args = parser.parse_args()

    env = load_env(Path(args.env_file))
    step = Step()
    wait_for("Cortex", f"{CORTEX}/api/status")
    wait_for("TheHive", f"{THEHIVE}/api/v1/status/public")

    cortex_key = provision_cortex(env, step)
    analyst, templates = provision_thehive(env, cortex_key, step)
    check_shuffle(env, step)
    if args.self_test:
        self_test(analyst, templates, step)
        shuffle_self_test(env, step)

    print()
    if step.failed:
        print(f"{len(step.failed)} step(s) failed:")
        for what in step.failed:
            print(f"  {what}")
        return 1
    print("Provisioning complete. Logins are in .env:")
    print(f"  TheHive  {THEHIVE}  admin@thehive.local (THEHIVE_ADMIN_PASSWORD), "
          f"{env['THEHIVE_ANALYST_LOGIN']} (THEHIVE_ANALYST_PASSWORD)")
    print(f"  Cortex   {CORTEX}  admin (CORTEX_ADMIN_PASSWORD)")
    print("  Shuffle  http://127.0.0.1:3001  SHUFFLE_DEFAULT_USERNAME (SHUFFLE_DEFAULT_PASSWORD)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
