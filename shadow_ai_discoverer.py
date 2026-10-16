#!/usr/bin/env python3
"""shadow-ai-discoverer: inventory unsanctioned AI usage from local sources.

Three local evidence sources, one report:

  1. Browser extension manifests  -- installed extensions matched against the
     curated known-AI-extension list (ai-tools.json).
  2. OAuth grant exports          -- third-party app authorizations matched
     against known AI services and their domains.
  3. Hosts/DNS hint lists         -- observed domains matched against known
     AI-service domains (exact or subdomain match).

Read-only: this tool never modifies the system, the browser, or the network.
It only reads the files you point it at. Stdlib only -- no dependencies.

Usage:
    python shadow_ai_discoverer.py scan --extensions ext.json \
        --grants grants.json --domains dns.txt --format text
    python shadow_ai_discoverer.py scan --extensions ext.json --format json -o report.json
"""

import argparse
import json
import os
import sys

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}
VALID_RISKS = set(RISK_ORDER)
DB_FILENAME = "ai-tools.json"

APP_FIELDS = ("app_name", "client_name", "name", "display_name")
URL_FIELDS = ("homepage_url", "website", "url", "client_id")


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def load_json_file(path):
    """Load JSON from path; tolerate a bare list or an object wrapping a list."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        for key in ("extensions", "grants", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("expected a JSON object or array in %s" % path)


def load_domains_file(path):
    """Read a plain-text domain list; blank lines and # comments are ignored."""
    domains = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # tolerate "host:port" or URL-ish lines in sloppy exports
            line = line.split("://")[-1].split("/")[0].split(":")[0].strip(".")
            if line:
                domains.append(line)
    # de-duplicate, preserve order
    return list(dict.fromkeys(domains))


def load_db(path=None):
    """Load the curated AI-tool database."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_FILENAME)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_approved(path):
    """Load an approved-tool list (JSON array of names or match strings)."""
    if not path:
        return []
    return [str(x).strip().lower() for x in load_json_file(path) if str(x).strip()]


# --------------------------------------------------------------------------
# matching helpers
# --------------------------------------------------------------------------

def _norm(value):
    return str(value or "").strip().lower()


def is_approved(tool_name, approved):
    name = _norm(tool_name)
    return any(a and (a == name or a in name) for a in approved)


def _make_finding(source, tool, category, risk, note, evidence):
    if risk not in VALID_RISKS:
        raise ValueError("unknown risk level: %r" % (risk,))
    return {
        "source": source,
        "tool": tool,
        "category": category,
        "risk": risk,
        "note": note,
        "evidence": evidence,
    }


def scan_extensions(installed, db_entries, approved=()):
    """Match installed browser extensions against known AI extensions."""
    findings = []
    for ext in installed or []:
        if not isinstance(ext, dict):
            continue
        name = str(ext.get("name", "") or "")
        ext_id = _norm(ext.get("id"))
        name_l = _norm(name)
        for entry in db_entries:
            hit = False
            if ext_id and any(ext_id == _norm(i) for i in entry.get("ids", [])):
                hit = True
            if not hit:
                for frag in entry.get("match", []):
                    if _norm(frag) and _norm(frag) in name_l:
                        hit = True
                        break
            if hit:
                if not is_approved(entry["name"], approved):
                    findings.append(_make_finding(
                        source="browser_extensions",
                        tool=entry["name"],
                        category=entry.get("category", "AI tool"),
                        risk=entry.get("risk", "medium"),
                        note=entry.get("note", ""),
                        evidence="extension name=%r id=%r" % (name, ext.get("id", "")),
                    ))
                break  # one finding per installed extension
    return findings


def _grant_app_name(grant):
    for field in APP_FIELDS:
        if grant.get(field):
            return str(grant[field])
    return ""


def _grant_urls(grant):
    urls = []
    for field in URL_FIELDS:
        if grant.get(field):
            urls.append(_norm(grant[field]))
    return " ".join(urls)


def scan_grants(grants, db_services, approved=()):
    """Match OAuth grant exports against known AI services."""
    findings = []
    for grant in grants or []:
        if not isinstance(grant, dict):
            continue
        app_name = _grant_app_name(grant)
        app_l = _norm(app_name)
        urls = _grant_urls(grant)
        for service in db_services:
            hit = False
            for frag in service.get("names", []):
                if _norm(frag) and _norm(frag) in app_l:
                    hit = True
                    break
            if not hit:
                for domain in service.get("domains", []):
                    if _norm(domain) and _norm(domain) in urls:
                        hit = True
                        break
            if hit:
                if not is_approved(service["name"], approved):
                    scopes = grant.get("scopes") or grant.get("scope") or ""
                    if isinstance(scopes, (list, tuple)):
                        scopes = ", ".join(str(s) for s in scopes)
                    user = grant.get("user") or grant.get("email") or ""
                    evidence = "app=%r" % app_name
                    if scopes:
                        evidence += " scopes=%r" % (scopes,)
                    if user:
                        evidence += " user=%r" % (user,)
                    findings.append(_make_finding(
                        source="oauth_grants",
                        tool=service["name"],
                        category=service.get("category", "AI service"),
                        risk=service.get("risk", "medium"),
                        note=service.get("note", ""),
                        evidence=evidence,
                    ))
                break
    return findings


def _domain_matches(domain, known):
    domain = _norm(domain)
    known = _norm(known)
    return bool(domain) and bool(known) and (domain == known or domain.endswith("." + known))


def scan_domains(domains, db_domains, approved=()):
    """Match observed domains against known AI-service domains."""
    findings = []
    for domain in domains or []:
        domain = _norm(domain)
        if not domain:
            continue
        for entry in db_domains:
            if _domain_matches(domain, entry.get("domain", "")):
                if not is_approved(entry.get("tool", ""), approved):
                    findings.append(_make_finding(
                        source="dns_hints",
                        tool=entry.get("tool", ""),
                        category="AI service domain",
                        risk=entry.get("risk", "medium"),
                        note=entry.get("note", ""),
                        evidence="domain=%r matched known=%r" % (domain, entry.get("domain")),
                    ))
                break
    return findings


def sort_findings(findings):
    return sorted(findings, key=lambda f: (RISK_ORDER.get(f["risk"], 99), f["tool"].lower()))


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def build_report(findings, inputs):
    findings = sort_findings(findings)
    by_risk = {}
    by_source = {}
    for f in findings:
        by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1
        by_source[f["source"]] = by_source.get(f["source"], 0) + 1
    return {
        "generated_by": "shadow-ai-discoverer",
        "inputs": inputs,
        "summary": {
            "total_findings": len(findings),
            "by_risk": by_risk,
            "by_source": by_source,
        },
        "findings": findings,
    }


def render_text(report):
    lines = []
    lines.append("=" * 64)
    lines.append("SHADOW AI DISCOVERY REPORT")
    lines.append("=" * 64)
    summary = report["summary"]
    lines.append("Total findings: %d" % summary["total_findings"])
    if summary["by_risk"]:
        lines.append("By risk: " + ", ".join(
            "%s=%d" % (r, summary["by_risk"][r])
            for r in sorted(summary["by_risk"], key=lambda r: RISK_ORDER.get(r, 99))))
    if summary["by_source"]:
        lines.append("By source: " + ", ".join(
            "%s=%d" % (s, summary["by_source"][s]) for s in sorted(summary["by_source"])))
    lines.append("")
    if not report["findings"]:
        lines.append("No unsanctioned AI usage detected in the provided inputs.")
        lines.append("Reminder: empty results mean 'not seen in these files', not 'clean'.")
        return "\n".join(lines) + "\n"
    current_source = None
    for f in report["findings"]:
        if f["source"] != current_source:
            current_source = f["source"]
            lines.append("-" * 64)
            lines.append("Source: %s" % current_source.replace("_", " ").upper())
            lines.append("-" * 64)
        lines.append("[%s] %s" % (f["risk"].upper(), f["tool"]))
        lines.append("  Category: %s" % f["category"])
        lines.append("  Risk note: %s" % f["note"])
        lines.append("  Evidence: %s" % f["evidence"])
        lines.append("")
    return "\n".join(lines)


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="shadow_ai_discoverer.py",
        description="Inventory unsanctioned AI usage from browser extensions, "
                    "OAuth grants, and DNS hint lists. Read-only, stdlib only.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run the discovery scan")
    scan.add_argument("--extensions", action="append", default=[],
                      help="JSON file of installed browser extensions (repeatable)")
    scan.add_argument("--grants", action="append", default=[],
                      help="JSON file of OAuth grant exports (repeatable)")
    scan.add_argument("--domains", action="append", default=[],
                      help="text file of observed domains, one per line (repeatable)")
    scan.add_argument("--db", default=None,
                      help="path to ai-tools.json (default: bundled copy)")
    scan.add_argument("--approved", default=None,
                      help="JSON list of sanctioned tool names to exclude")
    scan.add_argument("--format", choices=("text", "json"), default="text",
                      help="report format (default: text)")
    scan.add_argument("-o", "--output", default=None,
                      help="write the report to this file instead of stdout")
    return parser


def cmd_scan(args):
    if not (args.extensions or args.grants or args.domains):
        print("error: at least one of --extensions, --grants, --domains is required",
              file=sys.stderr)
        return 2
    try:
        db = load_db(args.db)
    except (OSError, ValueError) as exc:
        print("error: cannot load AI tool database: %s" % exc, file=sys.stderr)
        return 2
    try:
        approved = load_approved(args.approved)
    except (OSError, ValueError) as exc:
        print("error: cannot load approved list: %s" % exc, file=sys.stderr)
        return 2

    findings = []
    inputs = {"extensions": [], "grants": [], "domains": []}
    try:
        for path in args.extensions:
            installed = load_json_file(path)
            inputs["extensions"].append(path)
            findings += scan_extensions(installed, db.get("extensions", []), approved)
        for path in args.grants:
            grants = load_json_file(path)
            inputs["grants"].append(path)
            findings += scan_grants(grants, db.get("services", []), approved)
        for path in args.domains:
            domains = load_domains_file(path)
            inputs["domains"].append(path)
            findings += scan_domains(domains, db.get("domains", []), approved)
    except (OSError, ValueError) as exc:
        print("error: cannot read input: %s" % exc, file=sys.stderr)
        return 2

    report = build_report(findings, inputs)
    output = render_json(report) if args.format == "json" else render_text(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
