"""IOC extraction: what is found, what is rejected and why."""

import io
import json

import pytest
import stix2
from stix2patterns.validator import run_validator

import ioc_extractor
from ioc_extractor import IOCExtractor, in_allowlist, refang, stix_bundle, valid_base58check, valid_bech32, valid_domain


def extract(text, **options):
    return IOCExtractor(**options).extract(text)


# ------------------------------------------------------------------ defanging

@pytest.mark.parametrize("defanged, real", [
    ("hxxp://evil[.]example[.]com/a", "http://evil.example.com/a"),
    ("hXXps://evil(.)example(.)com", "https://evil.example.com"),
    ("hxxps[://]evil{.}example{.}com", "https://evil.example.com"),
    ("evil[dot]example[dot]com", "evil.example.com"),
    ("evil [.] example [.] com", "evil.example.com"),
    ("45[.]33[.]32[.]156", "45.33.32.156"),
    ("user[at]evil.example.com", "user@evil.example.com"),
    ("user(at)evil.example.com", "user@evil.example.com"),
    ("user[@]evil.example.com", "user@evil.example.com"),
    ("http[:]//evil.example.com", "http://evil.example.com"),
])
def test_refang(defanged, real):
    assert refang(defanged) == real


def test_refang_leaves_ordinary_text_alone():
    text = "The array [0] and the call f(x) stay as they are. Meet at noon."
    assert refang(text) == text


def test_defanged_indicators_are_extracted():
    found = extract("Beacon to 45[.]33[.]32[.]156 and hxxps://evil[.]example[.]com/gate.php from bad[at]evil-mail[.]net")
    assert found.ipv4 == ["45.33.32.156"]
    assert found.urls == ["https://evil.example.com/gate.php"]
    assert found.emails == ["bad@evil-mail.net"]


# ----------------------------------------------------------------------- IPv4

def test_public_addresses_are_kept_and_sorted_by_value():
    assert extract("9.9.9.9 then 45.33.32.156 then 8.8.8.8").ipv4 == ["8.8.8.8", "9.9.9.9", "45.33.32.156"]


@pytest.mark.parametrize("address", [
    "10.0.0.5", "172.16.4.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "169.254.10.10", "0.0.0.0",
    "100.64.0.1", "224.0.0.1", "255.255.255.255", "192.0.2.10", "198.51.100.7", "203.0.113.9",
])
def test_non_routable_addresses_are_filtered_by_default(address):
    assert extract(f"seen {address} in the log").ipv4 == []
    assert extract(f"seen {address} in the log", include_private=True).ipv4 == [address]


@pytest.mark.parametrize("text", ["256.1.1.1", "1.2.3.999", "01.2.3.4", "1.2.3", "version 1.2.3.4.5", "1.2.3.4.5.6"])
def test_things_that_only_look_like_addresses_are_rejected(text):
    assert extract(text, include_private=True).ipv4 == []


def test_an_address_at_the_end_of_a_sentence_is_found():
    assert extract("The scanner was 45.33.32.156.").ipv4 == ["45.33.32.156"]


# ----------------------------------------------------------------------- IPv6

def test_ipv6_in_full_and_compressed_form():
    found = extract("resolvers 2001:4860:4860::8888 and 2606:4700:4700:0000:0000:0000:0000:1111")
    assert found.ipv6 == ["2001:4860:4860::8888", "2606:4700:4700::1111"]


def test_times_and_mac_addresses_are_not_ipv6():
    found = extract("at 12:34:56 from 00:1A:2B:3C:4D:5E, loopback ::1, link-local fe80::1")
    assert found.ipv6 == []
    assert found.mac_addresses == ["00:1a:2b:3c:4d:5e"]


def test_private_ipv6_is_kept_on_request():
    assert extract("fd12:3456:789a::1", include_private=True).ipv6 == ["fd12:3456:789a::1"]


# -------------------------------------------------------------------- domains

def test_file_names_are_not_domains():
    found = extract("Dropped invoice.pdf, report.docx, payload.exe, loader.dll, notes.txt and run.ps1")
    assert found.domains == [] and found.domains_or_file_names == []


def test_names_that_are_both_a_tld_and_a_file_extension_are_reported_separately():
    found = extract("Ran setup.sh then unpacked update.zip. Real domain: files.evil.zip")
    assert found.domains_or_file_names == ["setup.sh", "update.zip"]
    assert found.domains == ["files.evil.zip"]


def test_a_url_confirms_that_an_ambiguous_name_is_a_domain():
    found = extract("Victims were sent to https://update.zip/login and later saw update.zip in the proxy log")
    assert found.domains == ["update.zip"]
    assert found.domains_or_file_names == []


def test_allowlist_matches_whole_labels_only():
    found = extract("login.microsoft.com evilmicrosoft.com microsoft.com.evil.example.com notgoogle.com")
    assert found.domains == ["evilmicrosoft.com", "microsoft.com.evil.example.com", "notgoogle.com"]
    assert in_allowlist("a.b.github.com", ["github.com"]) and not in_allowlist("mygithub.com", ["github.com"])


def test_allowlisted_domains_are_kept_on_request():
    assert extract("login.microsoft.com", include_allowlisted=True).domains == ["login.microsoft.com"]


@pytest.mark.parametrize("name, expected", [
    ("evil.example.com", True), ("xn--80ak6aa92e.com", True), ("a.co.uk", True),
    ("localhost", False), ("example.invalidtld", False), ("co.uk", False), ("a..com", False),
])
def test_valid_domain(name, expected):
    assert valid_domain(name) is expected


def test_domains_are_lower_cased_and_deduplicated():
    assert extract("Evil.Example.COM evil.example.com EVIL.EXAMPLE.COM").domains == ["evil.example.com"]


# ----------------------------------------------------------------------- URLs

def test_sentence_punctuation_is_not_part_of_a_url():
    found = extract('See http://evil.example.com/a. Also (https://evil.example.com/b), "http://evil.example.com/c".')
    assert found.urls == ["http://evil.example.com/a", "http://evil.example.com/c", "https://evil.example.com/b"]


def test_balanced_brackets_inside_a_url_are_kept():
    assert extract("https://evil.example.com/wiki/Page_(draft)").urls == ["https://evil.example.com/wiki/Page_(draft)"]


def test_url_hosts_must_be_valid_and_pass_the_filters():
    found = extract("http://intranet/login http://10.1.2.3/a http://45.33.32.156:8080/a https://www.google.com/x")
    assert found.urls == ["http://45.33.32.156:8080/a"]
    assert found.domains == []


def test_url_host_is_listed_as_a_domain():
    assert extract("payload at ftp://files.evil.example.com/a.bin").domains == ["files.evil.example.com"]


# --------------------------------------------------------------------- hashes

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_each_hash_is_reported_once_under_its_own_type():
    found = extract(f"{MD5} {SHA1.upper()} {SHA256} {SHA256}")
    assert found.md5_hashes == [MD5] and found.sha1_hashes == [SHA1] and found.sha256_hashes == [SHA256]


def test_a_long_hash_does_not_also_yield_shorter_ones():
    found = extract(SHA256 + "ab")   # 66 hex characters: not a hash of any supported type
    assert found.total_count == 0


def test_runs_of_one_character_are_not_hashes():
    assert extract("0" * 32 + " " + "f" * 40 + " " + "ab" * 32).total_count == 0


def test_an_ethereum_address_is_not_a_sha1():
    address = "0x52908400098527886E0F7030069857D2E4169EE7"
    found = extract(f"wallet {address}")
    assert found.ethereum_addresses == [address] and found.sha1_hashes == []


# -------------------------------------------------------------- other types

def test_cves_are_normalized():
    assert extract("cve-2021-44228, CVE-2024-3094 and CVE-2024-3094 again, not CVE-24-1").cves == [
        "CVE-2021-44228", "CVE-2024-3094"]


def test_email_needs_a_real_domain():
    found = extract("ok@evil.example.com no@localhost no@file.docx")
    assert found.emails == ["ok@evil.example.com"]


def test_mac_addresses_are_normalized():
    assert extract("00-1A-2B-3C-4D-5E and 00:1a:2b:3c:4d:5e").mac_addresses == ["00:1a:2b:3c:4d:5e"]


@pytest.mark.parametrize("address", [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
])
def test_bitcoin_legacy_addresses_with_a_good_checksum(address):
    assert valid_base58check(address)
    assert extract(f"pay {address} now").bitcoin_addresses == [address]


@pytest.mark.parametrize("address", [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",    # last character changed
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz",
    "1111111111111111111111111111111111",
])
def test_bitcoin_legacy_addresses_with_a_bad_checksum_are_rejected(address):
    assert not valid_base58check(address)
    assert extract(f"pay {address} now").bitcoin_addresses == []


@pytest.mark.parametrize("address", [
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",                        # BIP 173
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",    # BIP 173
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",    # BIP 350 (Bech32m)
])
def test_bitcoin_segwit_addresses_from_the_bips(address):
    assert valid_bech32(address)
    assert extract(f"pay {address} now").bitcoin_addresses == [address.lower()]


@pytest.mark.parametrize("address", [
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",    # version 1 with a Bech32 checksum
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",    # version 16 with a Bech32 checksum
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",                        # version 0 with a Bech32m checksum
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                        # one character changed
    "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                        # mixed case
])
def test_bitcoin_segwit_addresses_with_a_bad_checksum_are_rejected(address):
    assert not valid_bech32(address)
    assert extract(f"pay {address} now").bitcoin_addresses == []


def test_empty_input_gives_an_empty_result():
    found = extract("")
    assert found.total_count == 0
    assert set(found.to_dict()) == {
        "ipv4", "ipv6", "domains", "domains_or_file_names", "urls", "md5_hashes", "sha1_hashes", "sha256_hashes",
        "emails", "cves", "bitcoin_addresses", "ethereum_addresses", "mac_addresses"}


# ----------------------------------------------------------------------- STIX

def sample_results():
    return extract(f"45.33.32.156 2001:4860:4860::8888 evil.example.com https://evil.example.com/gate?a=1 "
                   f"{MD5} {SHA1} {SHA256} bad@evil.example.com 00:1A:2B:3C:4D:5E CVE-2024-3094 "
                   f"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")


def test_stix_bundle_is_valid_stix_2_1():
    bundle = stix_bundle(sample_results())
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    assert parsed.type == "bundle"
    indicators = [item for item in bundle["objects"] if item["type"] == "indicator"]
    assert len(indicators) == 9
    for indicator in indicators:
        assert run_validator(indicator["pattern"], stix_version="2.1") == [], indicator["pattern"]
        assert indicator["spec_version"] == "2.1" and indicator["pattern_type"] == "stix"
        assert indicator["indicator_types"] == ["unknown"]
        assert indicator["created"] == indicator["modified"] == indicator["valid_from"]
    assert len({item["id"] for item in bundle["objects"]}) == len(bundle["objects"])


def test_stix_ids_are_random_uuids_not_hashes_of_the_value():
    first, second = stix_bundle(sample_results()), stix_bundle(sample_results())
    assert first["id"] != second["id"]
    assert first["objects"][0]["id"] != second["objects"][0]["id"]


def test_stix_cve_becomes_a_vulnerability_and_wallets_are_left_out():
    bundle = stix_bundle(sample_results())
    vulnerabilities = [item for item in bundle["objects"] if item["type"] == "vulnerability"]
    assert [item["name"] for item in vulnerabilities] == ["CVE-2024-3094"]
    assert vulnerabilities[0]["external_references"] == [{"source_name": "cve", "external_id": "CVE-2024-3094"}]
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" not in json.dumps(bundle)


def test_stix_pattern_escapes_quotes_and_backslashes():
    results = ioc_extractor.IOCResults(urls=["https://evil.example.com/it's\\here"])
    bundle = stix_bundle(results)
    pattern = bundle["objects"][0]["pattern"]
    assert pattern == "[url:value = 'https://evil.example.com/it\\'s\\\\here']"
    assert run_validator(pattern, stix_version="2.1") == []
    stix2.parse(json.dumps(bundle), allow_custom=False)


def test_stix_indicator_type_can_be_set():
    bundle = stix_bundle(extract("45.33.32.156"), indicator_type="malicious-activity")
    assert bundle["objects"][0]["indicator_types"] == ["malicious-activity"]


# ------------------------------------------------------------------------ CLI

def test_cli_json_output(capsys):
    assert ioc_extractor.main(["--text", "45.33.32.156 evil.example.com"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ipv4"] == ["45.33.32.156"] and data["domains"] == ["evil.example.com"]


def test_cli_csv_quotes_values_with_commas(capsys):
    assert ioc_extractor.main(["--text", "http://evil.example.com/a,b", "--format", "csv"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "type,value"
    assert 'urls,"http://evil.example.com/a,b"' in lines


def test_cli_simple_output(capsys):
    assert ioc_extractor.main(["--text", "CVE-2024-3094", "--format", "simple"]) == 0
    assert capsys.readouterr().out.strip() == "[CVES]\n  CVE-2024-3094"


def test_cli_writes_a_file(tmp_path, capsys):
    target = tmp_path / "out.stix.json"
    assert ioc_extractor.main(["--text", "45.33.32.156", "--format", "stix", "--output", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["type"] == "bundle"
    captured = capsys.readouterr()
    assert captured.out == "" and "1 IOCs written" in captured.err


def test_cli_reads_json_files_without_escape_damage(tmp_path, capsys):
    source = tmp_path / "alert.json"
    source.write_text('{"url": "https:\\/\\/evil.example.com\\/gate", "nested": [{"ip": "45.33.32.156"}]}', encoding="utf-8")
    assert ioc_extractor.main(["--input", str(source)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["urls"] == ["https://evil.example.com/gate"] and data["ipv4"] == ["45.33.32.156"]


def test_cli_reads_standard_input(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("seen 45.33.32.156"))
    assert ioc_extractor.main(["--input", "-"]) == 0
    assert json.loads(capsys.readouterr().out)["ipv4"] == ["45.33.32.156"]


def test_cli_missing_file_is_an_error(capsys):
    assert ioc_extractor.main(["--input", "/no/such/file.txt"]) == 1
    assert "File not found" in capsys.readouterr().err


def test_cli_keeps_the_old_option_names(capsys):
    assert ioc_extractor.main(["--text", "10.0.0.5 login.microsoft.com", "--no-filter-private",
                               "--no-filter-whitelist"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ipv4"] == ["10.0.0.5"] and data["domains"] == ["login.microsoft.com"]
