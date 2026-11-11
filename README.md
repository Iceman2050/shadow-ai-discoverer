# shadow-ai-discoverer

A zero-dependency Python CLI that inventories **unsanctioned AI usage** from
three local evidence sources — and tells you which AI tools are in use that IT
never approved, each with a risk note.

## Problem statement

Employees adopt AI tools faster than IT can track them: a ChatGPT browser
extension here, an OAuth grant to an AI notetaker there, ad-hoc API traffic to
a model provider. Every one of those is a data flow to a third party — and
most of them were never reviewed, never approved, and never logged. That is
**shadow AI**: the ungoverned surface where customer data, source code, and
credentials quietly leave the corporate boundary.

shadow-ai-discoverer gives security teams a fast, read-only starting point.
Point it at exports you already have — no agents, no network access, no
permissions changes — and get a risk-ranked inventory of the AI tools hiding
in your environment.

## Install

Python 3.8+ with no third-party packages. Clone and run:

```bash
git clone https://github.com/Iceman2050/shadow-ai-discoverer.git
cd shadow-ai-discoverer
python3 shadow_ai_discoverer.py scan --help
```

Tests need `pytest` (`pip install pytest`) — the tool itself needs nothing.

## Usage

The `scan` command takes any combination of the three evidence sources:

```bash
# All three sources, human-readable report
python3 shadow_ai_discoverer.py scan \
  --extensions exports/browser-extensions.json \
  --grants exports/oauth-grants.json \
  --domains exports/dns-hints.txt

# Machine-readable JSON report to a file
python3 shadow_ai_discoverer.py scan \
  --extensions exports/browser-extensions.json \
  --format json -o report.json

# Exclude tools your org has already sanctioned
python3 shadow_ai_discoverer.py scan \
  --extensions exports/browser-extensions.json \
  --approved my-org/approved-ai-tools.json
```

Input formats:

| Flag | Format |
|---|---|
| `--extensions` | JSON array of objects with `id` and `name` (e.g. a browser extension export). Repeatable. |
| `--grants` | JSON array of objects with `app_name` (also accepts `client_name`/`name`), plus optional `scopes`, `user`, `homepage_url`. Repeatable. |
| `--domains` | Plain-text file, one domain per line; `#` comments and blank lines ignored. Repeatable. |
| `--approved` | JSON array of sanctioned tool names or match strings — matching findings are excluded. |
| `--db` | Path to a custom `ai-tools.json` (default: the bundled curated database). |

The tool is **read-only**: it never modifies the system, the browser, or the
network, and it makes no outbound connections.

## Example output

Real output from the bundled fixtures:

```
================================================================
SHADOW AI DISCOVERY REPORT
================================================================
Total findings: 13
By risk: high=7, medium=6
By source: browser_extensions=5, dns_hints=5, oauth_grants=3

----------------------------------------------------------------
Source: BROWSER EXTENSIONS
----------------------------------------------------------------
[HIGH] ChatGPT for Chrome
  Category: AI chat assistant
  Risk note: Any text the user types or highlights can be sent to OpenAI's
  servers. Customer data, source code, or credentials pasted into prompts
  leave the corporate boundary with no local log.
  Evidence: extension name='ChatGPT for Chrome' id='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

[HIGH] Otter.ai meeting recorder
  Category: AI meeting transcription
  Risk note: Joins or records meetings and ships audio plus transcripts to
  Otter's cloud. Participants are rarely aware; check consent and
  data-residency requirements.
  Evidence: extension name='Otter.ai Meeting Recorder' id='ffffffffffffffffffffffffffffffff'

----------------------------------------------------------------
Source: OAUTH GRANTS
----------------------------------------------------------------
[HIGH] OpenAI / ChatGPT
  Category: AI chat / API
  Risk note: OAuth grants with broad scopes let ChatGPT pull data on its own
  schedule. Confirm scopes are minimal and the account is a business account
  under your DPA.
  Evidence: app='ChatGPT' scopes='openid, email, drive.readonly' user='jdoe@example.com'

----------------------------------------------------------------
Source: DNS HINTS
----------------------------------------------------------------
[HIGH] OpenAI API
  Category: AI service domain
  Risk note: Programmatic API traffic — likely scripts or tools sending data
  to OpenAI models.
  Evidence: domain='api.openai.com' matched known='api.openai.com'

[MEDIUM] Perplexity
  Category: AI service domain
  Risk note: AI search queries leaving the network.
  Evidence: domain='perplexity.ai' matched known='perplexity.ai'
```

## How matching works

- **Extensions** match on case-insensitive name fragments or exact extension
  IDs from `ai-tools.json`. Add `ids` entries to pin exact extensions.
- **OAuth grants** match on app-name fragments, with a fallback to vendor
  domains in the app's homepage/client URL.
- **Domains** match exactly or as subdomains (`eu.api.openai.com` matches
  `api.openai.com`), but never on partial suffixes (`notopenai.com` does not
  match `openai.com`).

## Extending the database

`ai-tools.json` is a plain JSON file with three sections — `extensions`,
`services`, `domains`. Every entry carries a `risk` (`high`/`medium`/`low`)
and a `note`. Fork it, add your org's entries, and point the CLI at it with
`--db`.

## Limitations

- The tool can only see what you feed it: exports must come from your own
  browser management, identity provider, and DNS logs.
- Name-fragment matching is deliberately broad; tune `ai-tools.json` and
  `--approved` for your org to cut noise.
- Empty results mean "not seen in these files", not "clean".

## Built by Ingenious AI

shadow-ai-discoverer is built and maintained by **Ingenious AI**.

Explore our security platform suite — request early access:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)

## License

MIT — see [LICENSE](LICENSE).


> Built by Ingenious AI
