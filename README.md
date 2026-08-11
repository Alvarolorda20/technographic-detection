# techdetect

A minimal, production-quality CLI that detects which technologies a company
uses from publicly observable signals — HTTP response headers, cookies,
`<script>` tags, raw HTML, meta tags and DNS records — matched against
Wappalyzer-format fingerprints. HTTP-client-only by design: no headless
browser, no paid APIs.

## Assignment checklist

| Requirement | Where it is met |
|---|---|
| Plain-text file of domains, one per line | `DOMAINS_FILE` arg; `#` comments, blanks and duplicates handled — [scanner.py](techdetect/scanner.py) |
| Homepage fetch handling redirects, timeouts, soft-blocks | candidate ladder, per-request + per-domain deadlines, block classifier — [fetcher.py](techdetect/fetcher.py) |
| Signals from ≥ 4 channels | **5 of the 6 the assignment lists** — headers, `<script src>`, cookies, DNS (MX/TXT/CNAME), meta — plus `html`, which the supplied `[html]` patterns need |
| `window.*` JavaScript globals (static analysis) | Implemented, **off by default** — a static read is not proof of runtime provisioning, see [The `js` channel](#the-js-channel) |
| Wappalyzer pattern format, extensible to the full DB without code changes | [engine.py](techdetect/engine.py); verified in CI against a vendored excerpt of the real database |
| `{ "domain": [...] }` JSON output | [output.json](output.json) — a real run against the 20 test domains |
| 20 domains in under 60 s | `Scanned 20 domain(s) in 6.1s (20 ok, 0 blocked, 0 no response, 0 partial)` |
| No headless browser, no paid API | two runtime dependencies: `httpx`, `dnspython` |
| Matching logic implemented, not imported | no Wappalyzer package is used; the database is only a format reference |

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/Alvarolorda20/technographic-detection.git
cd technographic-detection
pip install -e .          # add ".[dev]" for tests + lint
```

## Run

```bash
techdetect domains.txt -o output.json
python -m techdetect domains.txt -o output.json   # equivalent, no entry point needed
```

| Flag | Meaning |
|---|---|
| `DOMAINS_FILE` | one domain per line; `#` comments and blanks ignored, `-` reads stdin. Input is normalized: scheme/path/port stripped, lowercased, leading `www.` removed, de-duplicated |
| `-o/--output` | results JSON (default: stdout). Logs always go to stderr, so `techdetect domains.txt > output.json` stays clean |
| `--fingerprints` | load any Wappalyzer-format technology JSON instead of the bundled set |
| `--evidence` | per-domain match evidence, in a separate file. [evidence.example.json](evidence.example.json) is the committed run: 59 records behind 49 detections |
| `--min-confidence` | confidence total a technology must reach (default 100) |
| `--concurrency` | domains scanned at once (default 10). DNS concurrency is bounded separately |
| `--timeout` | per-HTTP-request timeout (default 8 s). Not a whole-scan budget: the 5 s connect timeout and 20 s per-domain deadline are fixed |
| `--enable-js-channel` | opt into the `js` channel — see below |
| `-v` / `-q` | debug logging (adds per-signal match detail) or errors only |

```json
{ "stripe.com": ["Google Workspace", "Stripe"], "loom.com": [] }
```

Exit codes: `0` = run completed (per-domain failures are expected operation,
never a crash), `1` = fatal setup or output error, `2` = usage error.

## Architecture

```
domains.txt → normalize → semaphore(10) → per domain, concurrently:
                 ├── HTTP fetch (redirects, ladder, body cap, cookies)
                 └── DNS lookups (MX, TXT, CNAME — shared cached resolver)
             → SignalSet → fingerprint match (precompiled) → output.json
```

| Module | Responsibility |
|---|---|
| `scanner.py` | input normalization, concurrency, per-domain deadline, assembly |
| `fetcher.py` | candidate ladder, streamed body cap, Set-Cookie chain walk, soft-block classifier |
| `dns_records.py` | shared cached resolver; MX/TXT/CNAME with retries; absence vs failure |
| `extract.py` | HTML parsing: script srcs, executable inline scripts, meta tags |
| `engine.py` | Wappalyzer-format loading, pattern compilation, matching, evidence |

The decisions behind that shape, and the cheaper alternative each one rejects:

| Decision | Why |
|---|---|
| `asyncio`, 10 domains in flight | The workload is I/O-bound, so asyncio lets HTTP and DNS waits overlap with low coordination overhead; the cap keeps concurrency bounded. The cap stops 20 domains becoming 20 connections plus 80 DNS queries at once; wall-clock lands near the slowest domain, not the sum |
| Signals collected into a `SignalSet`, matching a pure function of it | Separates what needs the network from what gets graded: the whole engine is testable offline |
| One channel per pattern, never a concatenated text blob | A blob is the main false-positive source — cookie rules firing on prose, script rules on blog posts |
| Patterns compiled once at load | 24 patterns hide the cost, ~7,500 do not; an invalid regex becomes a load-time warning instead of a mid-scan surprise |
| Per-domain failure is a result, not an exception | Blocks, timeouts and TLS refusals produce a row with a reason attached; the scan never aborts |
| Evidence written to a separate file | `output.json` keeps exactly the schema the assignment fixes |
| Two runtime dependencies | The two the assignment names; argument parsing, HTML parsing and logging are stdlib |

### Fetching

- **Ladder** `https://host` → `https://www.host` → `http://host` →
  `http://www.host`, advancing **only on transport failures**. Any valid HTTP
  response, 4xx/5xx included, ends the ladder: it is the domain's answer.
- **Timeouts**: 8 s per request (5 s connect), hard 20 s per domain — which also
  defuses trickling bodies.
- **Body capped at 4 MB** while streaming. The largest test homepage is ~1.5 MB,
  so the cap has real headroom; hitting it flags the domain partial.
- **Soft blocks** (401/403/429, 503-with-challenge, 200-with-challenge markers
  from Cloudflare/PerimeterX/DataDome) keep headers, cookies and DNS but drop
  every page-derived signal: that body belongs to the blocker, not the site. A
  Cloudflare challenge still yields Cloudflare — `cf-ray` is real evidence.
- Browser `User-Agent`, homepage only — no crawling, no external assets.

Run timings against the 60 s limit:

```text
INFO loom.com: 0 technologie(s) [HTTP 200, 0.4s]
INFO hubspot.com: 3 technologie(s) [HTTP 200, 4.3s]
INFO Scanned 20 domain(s) in 6.1s (20 ok, 0 blocked, 0 no response, 0 partial)
```

### DNS

DNS is the channel most likely to fail quietly, so it is treated as a
measurement that can fail, not a lookup that returns a list:

- **Absence ≠ failure.** `NXDOMAIN`/`NoAnswer` is a real answer; a timeout or
  SERVFAIL is retried and, if it still fails, recorded as unmeasured.
- **One cached resolver per scan**, so repeated lookups are cheap and consistent.
- In development, firing the baseline DNS lookups without a concurrency bound produced resolver timeouts, so DNS concurrency is capped at 12.

Together these are what make `output.json` reproducible across runs.

### Matching semantics

Patterns are preprocessed Wappalyzer-style — split on `\;`, `confidence:N`
honored (default 100), `version:` recognized and discarded — then compiled
case-insensitively. A rule contributes at most once no matter how often it
matches; distinct rules accumulate up to 100, so weak signals can corroborate.

| Key | Matched against | Name matching | Value matching |
|---|---|---|---|
| `headers` | final-response headers | regex, **fullmatch** | regex, search; empty = presence |
| `cookies` | Set-Cookie from every redirect hop | regex, **search** | regex, search |
| `scriptSrc` / `scripts` / `script` | `<script src>` / inline JS / both | — | search |
| `html` | raw document (capped) | — | search |
| `meta` | `<meta name/property>` content | exact, lowercased | search |
| `dns` | MX/TXT on the input host; CNAME also on `www.` and the final redirected host | record type | search |
| `js` *(opt-in)* | executable inline JS | read through the global object, **case-sensitive** | — |

`fullmatch` on header names keeps `cf-ray` from matching `cf-ray-id` while
`X-Stripe-.*` still covers the family; `search` on cookie names lets
`^intercom-` hit `intercom-id-abc`. Cookies come from every redirect hop, and
CNAME is queried on the host that actually serves the site.

The bundled [fingerprints.json](techdetect/data/fingerprints.json) is the
assignment's 24 patterns over 16 technologies in Wappalyzer schema — `[script]`
→ `script`, `[header]` → `headers`, `[cookie]` → `cookies`, `[html]` → `html`,
`[dns_*]` → `dns`. It is validated strictly at load (24 compiled, 0 skipped) and
ships as package data, so `pip install .` works without the checkout. External
files load leniently: unsupported patterns are skipped and counted, never fatal.

### Accuracy

The core requirement is detecting a technology only on strong evidence, so each
pattern sees only its own channel — a blog post *mentioning* `js.stripe.com/v3`
never reaches the script matcher. Three guards:

1. **Executable scripts only.** Inline bodies are read from executable
   JavaScript, not from `application/json`, `ld+json` or templates, which is
   exactly where page prose leaks into `<script>`.
2. **Serialized HTML is not usage.** A match preceded by an *escaped* script tag
   (`\u003cscript`, `&lt;script`) sits in HTML-as-data — a docs sample, an RSC
   payload — and is rejected. Raw `document.write` loaders and plain URL strings
   still count.
3. **Blocked bodies are untrusted** (see Fetching).

Two limits stated rather than hidden: the `html` channel keeps Wappalyzer's
raw-document semantics, and `gtag\(` is not GA4-specific — it is kept exactly as
supplied instead of being silently tightened, and `--evidence` makes both
auditable.

### The `js` channel

`js` fingerprints are global object paths and assume a runtime; this tool
executes no JavaScript. It is implemented as a static approximation, off by
default: a pattern matches only where inline JS **reads the path through the
global object** (`window.X`, `window["X"]`, `globalThis.X`, `self.X` — not
`top`/`parent`), not where the bare name happens to appear in the source,
case-sensitively and under the same serialized-HTML guard as every script rule.

It still ships off because observing a global read does not establish that the
global is actually provisioned at runtime; it may be a probe, feature check or
dead code. The approximation cannot reproduce browser-runtime semantics.

### Partial measurements

An empty result can mean two things, and conflating them is a silent false
negative. A domain is **partial** when a DNS lookup produced no answer or the
body hit the cap — logged as a warning and counted in the summary:

```text
WARNING figma.com: 1 DNS lookup(s) produced no answer (MX figma.com: LifetimeTimeout)
INFO    Scanned 20 domain(s) in 4.8s (20 ok, 0 blocked, 0 no response, 1 partial)
```

For a partial domain an absent technology means *unconfirmed*, not ruled out.
The committed run reports `0 partial`.

### Wappalyzer compatibility — the exact claim

**Format compatibility, not detection parity.** Valid Wappalyzer-format datasets
can be loaded without technology-specific code changes. Patterns in supported
channels are matched; unsupported channels are skipped and counted. Results may
therefore differ from Wappalyzer, or from a fuller dataset, when a detection
depends on a channel this tool does not implement. That is the intentional
boundary of the compatibility claim.

## Tests

```bash
pytest            # 147 tests, fully offline — no network access needed
ruff check . && ruff format --check .
```

CI runs the suite and both lint checks on Python 3.11, 3.12 and 3.13. Coverage
spans pattern parsing, every matching semantic (including `cf-ray` vs
`cf-ray-id`), the `js` channel's accepted and rejected forms, extraction, the
fetch ladder, body-cap truncation and block classification (`httpx.MockTransport`),
DNS behaviour (fake resolver, absence vs failure, concurrency bound) and an
offline end-to-end run. The release blocker is the adversarial fixture: a page
mentioning `js.stripe.com/v3` in prose, a `<pre>` block, JSON data and an escaped
docs sample must yield zero detections.

## Limitations

- Client-side-rendered signals are invisible without a browser — the
  HTTP-only constraint, and the largest source of missed detections. It is why a
  few vendor domains do not report their own product: the loader is not in the
  served HTML.
- The `js` channel does not follow aliased globals (`var w=window; w.Intercom=i`),
  so it misses Intercom's own snippet. Accepting short arbitrary roots would
  trade that for false positives; the real fix is scope analysis, i.e. a JS
  parser. A `scripts` pattern is the escape hatch.
- Wappalyzer's `implies` is read as metadata, not applied: a WordPress hit does
  not also report PHP. Every technology reported is one whose own pattern
  matched, so inferring others would report what the run never observed.
- No public-suffix handling: DNS uses the normalized host with `www.` stripped.
  Correct for these inputs; a PSL library is the production upgrade.
- Matching runs on the event loop and outside any deadline. With the assignment's
  24 patterns it is instant; loading the full ~7,600-pattern database makes it
  CPU-bound — concentrated in the `html` channel, the only one that sweeps the
  whole document — and the per-domain fetch and DNS deadlines then expire on
  starved CPU rather than on the network. Format compatibility is unaffected;
  throughput is not.
- Results are deterministic per response and repeated scans reproduce
  `output.json`, but sites change legitimately over time — so a later run
  differing is not by itself a defect, while a *partial* run is flagged as one.

## Implementation references

- **[WebAppAnalyzer fingerprint specification](https://github.com/enthec/webappanalyzer)**
  — fingerprint keys, regex metadata, confidence and version tags, and the
  entries vendored for the compatibility test.
- **[dnspython](https://dnspython.readthedocs.io/en/stable/async.html)** — async
  resolution and
  [resolver caching](https://dnspython.readthedocs.io/en/stable/resolver-caching.html).
