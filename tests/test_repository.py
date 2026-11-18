"""The files in the repository agree with each other and with what the README says."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
MARKDOWN = sorted(path for path in ROOT.rglob("*.md")
                  if not any(part.startswith(".") for part in path.relative_to(ROOT).parts))


def env_names(path):
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if match:
            names.append(match.group(1))
    return names


# --------------------------------------------------------------------- compose

def test_every_image_is_pinned_to_a_version():
    images = re.findall(r"^\s+image:\s*(\S+)", COMPOSE, flags=re.M)
    assert len(images) == 8
    for image in images:
        tag = image.rsplit(":", 1)[1]
        assert tag != "latest" and re.search(r"\d", tag), image


def test_every_published_port_is_bound_to_localhost():
    ports = re.findall(r'^\s+- "([^"]+:\d+)"\s*$', COMPOSE, flags=re.M)
    assert len(ports) == 5
    assert all(port.startswith("127.0.0.1:") for port in ports), ports


def test_no_secret_has_a_default_value_in_the_compose_file():
    for name in ("ELASTIC_PASSWORD", "THEHIVE_SECRET", "CORTEX_SECRET", "SHUFFLE_OPENSEARCH_PASSWORD",
                 "SHUFFLE_DEFAULT_PASSWORD", "SHUFFLE_DEFAULT_APIKEY", "SHUFFLE_ENCRYPTION_MODIFIER"):
        uses = re.findall(r"(?<!\$)\$\{" + name + r"([^}]*)\}", COMPOSE)   # $${...} is read inside the container
        assert uses and all(use.startswith(":?") for use in uses), (name, uses)


def test_variables_used_by_compose_are_documented_and_generated():
    used = set(re.findall(r"(?<!\$)\$\{([A-Z][A-Z0-9_]*)", COMPOSE))
    documented = set(env_names(ROOT / ".env.example"))
    generated = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", (ROOT / "scripts/setup/init.sh").read_text(encoding="utf-8"),
                               flags=re.M))
    assert used <= documented, used - documented
    assert used <= generated, used - generated
    provision = (ROOT / "scripts/setup/provision.py").read_text(encoding="utf-8")
    assert set(re.findall(r'env\["([A-Z0-9_]+)"\]', provision)) <= generated


def test_the_example_file_holds_no_real_secret():
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            name, _, value = line.partition("=")
            if any(word in name for word in ("PASSWORD", "SECRET", "KEY", "TOKEN", "MODIFIER")):
                assert value in ("", "CHANGE_ME"), name


def test_configuration_files_hold_no_secret():
    for path in (ROOT / "thehive/config/application.conf", ROOT / "cortex/config/application.conf"):
        text = path.read_text(encoding="utf-8")
        assert re.search(r'play\.http\.secret\.key = \$\{[A-Z_]+\}', text)
        assert not re.search(r'(password|secret\.key)\s*=\s*"', text), path


# ------------------------------------------------------------ TheHive content

def test_case_templates_use_the_thehive_5_format_and_known_custom_fields():
    fields = json.loads((ROOT / "thehive/templates/custom-fields.json").read_text(encoding="utf-8"))
    references = {field["reference"] for field in fields}
    assert all({"name", "reference", "type", "mandatory", "options", "description"} <= set(field) for field in fields)
    templates = sorted((ROOT / "thehive/templates/case-templates").glob("*.json"))
    assert len(templates) == 3
    names = set()
    for path in templates:
        template = json.loads(path.read_text(encoding="utf-8"))
        assert {"name", "displayName", "titlePrefix", "description", "severity", "tlp", "pap", "tags", "tasks",
                "customFields"} <= set(template), path.name
        assert re.fullmatch(r"[a-z0-9-]+", template["name"])
        names.add(template["name"])
        assert 1 <= template["severity"] <= 4 and 0 <= template["tlp"] <= 4 and 0 <= template["pap"] <= 3
        assert [task["order"] for task in template["tasks"]] == list(range(len(template["tasks"])))
        assert all(task["title"] and task["group"] and task["description"] for task in template["tasks"])
        for field in template["customFields"]:
            assert field["name"] in references, (path.name, field["name"])
            options = next(item["options"] for item in fields if item["reference"] == field["name"])
            assert not options or field["value"] in options
    assert len(names) == 3


# ----------------------------------------------------------- workflow designs

@pytest.mark.parametrize("path", sorted((ROOT / "shuffle/workflow-designs").glob("*.json")), ids=lambda p: p.name)
def test_workflow_designs_are_labeled_and_consistent(path):
    design = json.loads(path.read_text(encoding="utf-8"))
    assert design["kind"] == "workflow-design" and "not a Shuffle export" in design["note"]
    identifiers = [item["id"] for item in design["actions"] + design["triggers"]]
    assert len(identifiers) == len(set(identifiers))
    referenced = set(re.findall(r"\$(action_\d+|trigger_\d+)", json.dumps(design)))
    assert referenced <= set(identifiers), referenced - set(identifiers)
    assert all(action["app_name"] and action["app_action"] for action in design["actions"])


# ------------------------------------------------------------------- documents

@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_point_at_files_that_exist(path):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        resolved = (path.parent / target.split("#")[0]).resolve()
        assert resolved.exists(), f"{path.relative_to(ROOT)} links to missing {target}"


def test_files_named_in_the_readme_tree_exist():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tree = re.search(r"```text\n(SOC-Automation-Lab/.*?)```", readme, flags=re.S)
    assert tree, "the README has no project layout block"
    stack = []
    for line in tree.group(1).splitlines()[1:]:
        entry = line.split("#")[0].rstrip()
        if not entry.strip():
            continue
        depth = (len(entry) - len(entry.lstrip())) // 2
        name = entry.strip()
        stack = stack[:depth - 1] + [name.rstrip("/")]
        assert (ROOT / Path(*stack)).exists(), "/".join(stack)


# ------------------------------------------------------------------ stop script

def test_stop_script_removes_only_the_containers_of_workflow_runs(tmp_path):
    """Run stop.sh against a stand-in for the docker command and look at what it would remove."""
    import os
    import subprocess

    run = "860f496a-0cbb-46f2-ac0a-260c6a54adf6"
    step = "0f9d6c5e-1b7a-4c1e-9d55-6a1f0e3b7c21"
    again = "11111111-2222-3333-4444-555555555555"
    listing = tmp_path / "ps.txt"
    listing.write_text("\n".join([
        f"aaaaaaaaaaa1 worker-{run}",
        f"aaaaaaaaaaa2 shuffle-tools_1.2.0_{step}_{run}",
        f"aaaaaaaaaaa3 worker-{run}-{again}",
        "bbbbbbbbbbb1 soc-lab-thehive-1",
        "bbbbbbbbbbb2 soc-lab-shuffle-orborus",
        "bbbbbbbbbbb3 worker-not-a-run-id",
        f"bbbbbbbbbbb4 my-worker-{run}",
        "bbbbbbbbbbb5 vigilant_driscoll",
    ]) + "\n", encoding="utf-8")
    calls = tmp_path / "calls.txt"
    stub = tmp_path / "bin" / "docker"
    stub.parent.mkdir()
    stub.write_text('#!/usr/bin/env bash\necho "$*" >> "$STUB_CALLS"\n'
                    'if [ "$1" = "ps" ]; then cat "$STUB_LISTING"; fi\n', encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub.parent}{os.pathsep}{os.environ['PATH']}",
               STUB_CALLS=str(calls), STUB_LISTING=str(listing))
    done = subprocess.run([str(ROOT / "scripts" / "setup" / "stop.sh"), "-v"], env=env, capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    recorded = calls.read_text(encoding="utf-8").splitlines()
    assert recorded[0] == "compose stop shuffle-orborus"
    assert recorded[2] == "rm -f aaaaaaaaaaa1 aaaaaaaaaaa2 aaaaaaaaaaa3"
    assert recorded[3] == "compose down -v"
    assert len(recorded) == 4
    assert f"worker-{run}" in done.stdout and "soc-lab-thehive-1" not in done.stdout


def test_stop_script_leaves_docker_alone_when_nothing_is_left(tmp_path):
    import os
    import subprocess

    listing = tmp_path / "ps.txt"
    listing.write_text("bbbbbbbbbbb1 soc-lab-thehive-1\n", encoding="utf-8")
    calls = tmp_path / "calls.txt"
    stub = tmp_path / "bin" / "docker"
    stub.parent.mkdir()
    stub.write_text('#!/usr/bin/env bash\necho "$*" >> "$STUB_CALLS"\n'
                    'if [ "$1" = "ps" ]; then cat "$STUB_LISTING"; fi\n', encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub.parent}{os.pathsep}{os.environ['PATH']}",
               STUB_CALLS=str(calls), STUB_LISTING=str(listing))
    done = subprocess.run([str(ROOT / "scripts" / "setup" / "stop.sh")], env=env, capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    recorded = calls.read_text(encoding="utf-8").splitlines()
    assert [call.split()[0] for call in recorded] == ["compose", "ps", "compose"]
    assert recorded[-1] == "compose down"
