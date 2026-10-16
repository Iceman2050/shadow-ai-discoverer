"""Tests for shadow_ai_discoverer. Stdlib + pytest only."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shadow_ai_discoverer import (  # noqa: E402
    build_report,
    cmd_scan,
    load_db,
    load_domains_file,
    load_json_file,
    render_json,
    render_text,
    scan_domains,
    scan_extensions,
    scan_grants,
    sort_findings,
)

ROOT = os.path.join(os.path.dirname(__file__), "..")
FIX = os.path.join(ROOT, "fixtures")
DB = load_db(os.path.join(ROOT, "ai-tools.json"))


# ---------------------------------------------------------------- fixtures

def fixture_extensions():
    return load_json_file(os.path.join(FIX, "extensions.json"))


def fixture_grants():
    return load_json_file(os.path.join(FIX, "oauth-grants.json"))


def fixture_domains():
    return load_domains_file(os.path.join(FIX, "dns-hints.txt"))


# ------------------------------------------------- 1. extension scanning

def test_extensions_flags_known_ai_extensions():
    findings = scan_extensions(fixture_extensions(), DB["extensions"])
    tools = {f["tool"] for f in findings}
    assert "ChatGPT for Chrome" in tools
    assert "Perplexity AI" in tools
    assert "Grammarly AI writing" in tools
    assert "Otter.ai meeting recorder" in tools
    assert "Claude / Anthropic assistant" in tools
    assert len(findings) == 5


def test_extensions_ignores_benign_extensions():
    findings = scan_extensions(fixture_extensions(), DB["extensions"])
    evidence = " ".join(f["evidence"] for f in findings)
    assert "uBlock" not in evidence
    assert "LastPass" not in evidence
    assert "Dark Reader" not in evidence


def test_extension_matching_is_case_insensitive():
    installed = [{"id": "x", "name": "CHATGPT FOR CHROME"}]
    findings = scan_extensions(installed, DB["extensions"])
    assert len(findings) == 1
    assert findings[0]["tool"] == "ChatGPT for Chrome"


def test_extension_matches_on_exact_id():
    db = [{"name": "Example AI Ext", "match": [], "ids": ["deadbeef"],
           "category": "AI tool", "risk": "low", "note": "n"}]
    findings = scan_extensions([{"id": "DEADBEEF", "name": "Something Else"}], db)
    assert len(findings) == 1
    assert findings[0]["tool"] == "Example AI Ext"


def test_extension_one_finding_per_extension():
    installed = [{"id": "x", "name": "ChatGPT Claude Perplexity bundle"}]
    findings = scan_extensions(installed, DB["extensions"])
    assert len(findings) == 1


def test_extension_finding_shape():
    findings = scan_extensions(fixture_extensions(), DB["extensions"])
    chatgpt = next(f for f in findings if f["tool"] == "ChatGPT for Chrome")
    assert chatgpt["source"] == "browser_extensions"
    assert chatgpt["risk"] in ("high", "medium", "low")
    assert chatgpt["note"]
    assert "ChatGPT for Chrome" in chatgpt["evidence"]


# ------------------------------------------------------ 2. grant scanning

def test_grants_flags_ai_services():
    findings = scan_grants(fixture_grants(), DB["services"])
    tools = {f["tool"] for f in findings}
    assert "OpenAI / ChatGPT" in tools
    assert "Notion AI" in tools
    assert "ElevenLabs" in tools
    assert len(findings) == 3


def test_grants_ignores_benign_apps():
    findings = scan_grants(fixture_grants(), DB["services"])
    tools = {f["tool"] for f in findings}
    assert not any("Zoom" in t or "Teams" in t for t in tools)


def test_grant_evidence_includes_scopes_and_user():
    findings = scan_grants(fixture_grants(), DB["services"])
    chatgpt = next(f for f in findings if f["tool"] == "OpenAI / ChatGPT")
    assert "drive.readonly" in chatgpt["evidence"]
    assert "jdoe@example.com" in chatgpt["evidence"]


def test_grant_matches_on_domain_when_name_differs():
    grants = [{"app_name": "Acme Connector",
               "homepage_url": "https://app.elevenlabs.io/dashboard"}]
    findings = scan_grants(grants, DB["services"])
    assert len(findings) == 1
    assert findings[0]["tool"] == "ElevenLabs"


def test_grant_supports_alternate_field_names():
    grants = [{"client_name": "Claude Desktop", "scope": "openid email"}]
    findings = scan_grants(grants, DB["services"])
    assert len(findings) == 1
    assert findings[0]["tool"] == "Anthropic Claude"


# ----------------------------------------------------- 3. domain scanning

def test_domains_flags_known_ai_domains():
    findings = scan_domains(fixture_domains(), DB["domains"])
    tools = {f["tool"] for f in findings}
    assert "OpenAI ChatGPT" in tools
    assert "OpenAI API" in tools
    assert "Anthropic API" in tools
    assert "Perplexity" in tools
    assert "Hugging Face" in tools
    assert len(findings) == 5


def test_domains_ignores_benign_domains():
    findings = scan_domains(fixture_domains(), DB["domains"])
    evidence = " ".join(f["evidence"] for f in findings)
    assert "google.com" not in evidence
    assert "internal.example" not in evidence


def test_domain_matches_subdomains():
    findings = scan_domains(["eu.api.openai.com"], DB["domains"])
    assert len(findings) == 1
    assert findings[0]["tool"] == "OpenAI API"


def test_domain_rejects_lookalike_suffixes():
    findings = scan_domains(["notopenai.com", "openai.com.evil.example"], DB["domains"])
    assert findings == []


def test_domains_file_parsing():
    path = os.path.join(FIX, "dns-hints.txt")
    domains = load_domains_file(path)
    assert "chat.openai.com" in domains
    assert "www.google.com" in domains
    assert not any(d.startswith("#") for d in domains)
    assert len(domains) == len(set(domains))  # de-duplicated


# ------------------------------------------------------- 4. approved list

def test_approved_list_excludes_sanctioned_tools():
    approved = ["grammarly ai writing"]
    findings = scan_extensions(fixture_extensions(), DB["extensions"], approved)
    tools = {f["tool"] for f in findings}
    assert "Grammarly AI writing" not in tools
    assert "ChatGPT for Chrome" in tools
    assert len(findings) == 4


# ------------------------------------------------------- 5. report building

def test_findings_sorted_high_risk_first():
    findings = (scan_extensions(fixture_extensions(), DB["extensions"])
                + scan_grants(fixture_grants(), DB["services"])
                + scan_domains(fixture_domains(), DB["domains"]))
    ordered = sort_findings(findings)
    risks = [f["risk"] for f in ordered]
    order = {"high": 0, "medium": 1, "low": 2}
    assert risks == sorted(risks, key=lambda r: order[r])


def test_report_summary_counts():
    findings = (scan_extensions(fixture_extensions(), DB["extensions"])
                + scan_grants(fixture_grants(), DB["services"])
                + scan_domains(fixture_domains(), DB["domains"]))
    report = build_report(findings, inputs={"extensions": ["e"]})
    assert report["summary"]["total_findings"] == 13
    assert report["summary"]["by_source"] == {
        "browser_extensions": 5, "oauth_grants": 3, "dns_hints": 5}
    assert sum(report["summary"]["by_risk"].values()) == 13
    assert report["generated_by"] == "shadow-ai-discoverer"


def test_text_report_sections():
    findings = scan_extensions(fixture_extensions(), DB["extensions"])
    text = render_text(build_report(findings, inputs={}))
    assert "SHADOW AI DISCOVERY REPORT" in text
    assert "BROWSER EXTENSIONS" in text
    assert "[HIGH] ChatGPT for Chrome" in text
    assert "Risk note:" in text
    assert "Total findings: 5" in text


def test_text_report_empty_inputs():
    text = render_text(build_report([], inputs={}))
    assert "Total findings: 0" in text
    assert "not seen in these files" in text


def test_json_report_is_valid():
    findings = scan_domains(fixture_domains(), DB["domains"])
    parsed = json.loads(render_json(build_report(findings, inputs={})))
    assert parsed["summary"]["total_findings"] == 5
    assert all("tool" in f and "risk" in f and "note" in f for f in parsed["findings"])


# ------------------------------------------------------- 6. CLI end to end

class Args:
    def __init__(self, **kwargs):
        self.extensions = kwargs.get("extensions", [])
        self.grants = kwargs.get("grants", [])
        self.domains = kwargs.get("domains", [])
        self.db = kwargs.get("db", os.path.join(ROOT, "ai-tools.json"))
        self.approved = kwargs.get("approved", None)
        self.format = kwargs.get("format", "text")
        self.output = kwargs.get("output", None)


def test_cli_full_scan_text(capsys):
    rc = cmd_scan(Args(
        extensions=[os.path.join(FIX, "extensions.json")],
        grants=[os.path.join(FIX, "oauth-grants.json")],
        domains=[os.path.join(FIX, "dns-hints.txt")]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Total findings: 13" in out
    assert "ChatGPT for Chrome" in out
    assert "OpenAI / ChatGPT" in out
    assert "api.anthropic.com" in out


def test_cli_full_scan_json_to_file(tmp_path):
    out_path = str(tmp_path / "report.json")
    rc = cmd_scan(Args(
        extensions=[os.path.join(FIX, "extensions.json")],
        grants=[os.path.join(FIX, "oauth-grants.json")],
        domains=[os.path.join(FIX, "dns-hints.txt")],
        format="json", output=out_path))
    assert rc == 0
    with open(out_path, encoding="utf-8") as fh:
        report = json.load(fh)
    assert report["summary"]["total_findings"] == 13


def test_cli_with_approved_list(capsys):
    rc = cmd_scan(Args(
        extensions=[os.path.join(FIX, "extensions.json")],
        approved=os.path.join(FIX, "approved.example.json")))
    assert rc == 0
    out = capsys.readouterr().out
    assert "Total findings: 4" in out
    assert "Grammarly" not in out


def test_cli_requires_at_least_one_input(capsys):
    assert cmd_scan(Args()) == 2


def test_cli_missing_input_file(capsys):
    assert cmd_scan(Args(extensions=["/nonexistent/file.json"])) == 2


def test_cli_bad_db_path(capsys):
    assert cmd_scan(Args(extensions=[os.path.join(FIX, "extensions.json")],
                         db="/nonexistent/db.json")) == 2


# ------------------------------------------------------- 7. db sanity

def test_db_entries_all_have_risk_notes():
    for section in ("extensions", "services", "domains"):
        assert DB[section], "empty db section: %s" % section
        for entry in DB[section]:
            assert entry.get("risk") in ("high", "medium", "low"), entry
            assert entry.get("note"), entry
