# log-redaction-spec

Declarative log redaction: declare sensitive fields in a JSON spec, validate the spec, apply mask/drop/hash strategies to log lines, and audit emitted logs for anything that still leaks. Pure standard library, no network, CLI included.

## Problem

Logs leak. Emails, bearer tokens, IPs, and phone numbers end up in log files that then flow into aggregators, ticket systems, and third-party SaaS. Point fixes (one-off `sed`, ad-hoc formatter hooks) drift: each service redacts different fields in different ways, and nobody can answer "what is our redaction policy?" from one file. Worse, nothing checks whether redaction actually worked after the fact.

## How it works

1. **Spec** — a JSON document listing fields: `{"field": "email", "pattern": "...", "strategy": "mask", "keep": 2}`. Strategies are `mask` (keep first N chars, star the rest), `drop` (replace with `[REDACTED:field]`), `hash` (12-hex sha256 prefix for correlation without exposure).
2. **Validator** — `load_spec` rejects invalid JSON, empty/duplicate field names, unknown strategies, bad regexes, and non-integer `keep` before anything runs.
3. **Redactor** — `redact_line` / `redact_text` apply every field pattern per line, preserving line endings, and return per-field hit counts.
4. **Leak audit** — `audit_leaks` samples output lines that *still* match any declared pattern; the CLI exits 1 when suspects are found, so it can gate a CI job.

## Quickstart

```bash
# Redact a log with the built-in spec (email/IPv4/bearer/phone). ~0.2s [estimated]
python log_redaction_spec.py redact --file app.log > app.redacted.log

# Use your own spec
python log_redaction_spec.py redact --spec my_spec.json --file app.log

# Audit a log for leaks; exit code 1 = suspects found
python log_redaction_spec.py audit --file app.log

# Full self-test, 50 checks. ~0.3s [estimated; repro: time python self_test.py]
python self_test.py
```

## How this differs (why-not-X)

| Alternative | Stars* | How this repo differs |
|---|---|---|
| [pinojs/pino-noir](https://github.com/pinojs/pino-noir) | 74 | Runtime redaction wired into one JS logger's internals; this is a language-neutral spec + batch line redactor with a post-hoc leak audit, usable on any log file. |
| [larsderidder/contextio](https://github.com/larsderidder/contextio) | 31 | A live proxy between AI tools and LLM APIs; this does zero proxying and zero network — it validates declarations and scrubs already-emitted lines. |
| [bitbonk/LogRedactionDemo](https://github.com/bitbonk/LogRedactionDemo) | 1 | A demo for Microsoft.Extensions logging in C#; this ships a validated spec schema plus a standalone audit command that samples for residual PII. |

\* Stars from the R13 precheck snapshot, as of 2026-10-11.

## Minimal Fallback

If you can't run Python on the log host: keep the spec JSON as documentation and apply the same patterns with `grep -E` + `sed`. The spec's `pattern` fields are standard regexes, e.g. `sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[REDACTED:email]/g'`. Fidelity is lower (no hit counts, no audit), so re-run the audit command later on a machine that has Python.

## Design Trade-offs

- **Regex over NLP** — deterministic, auditable, fast; misses non-pattern-shaped PII (free-text names). Accepted: false negatives are documented rather than guessed.
- **Line-oriented** — multi-line stack traces are treated line by line; a token split across lines is not caught.
- **`keep` masking leaks structure** — masked emails still reveal provider domain shape (`jo********`); that aids debugging but is a (small) disclosure.
- **Single-pass, ordered fields** — a later field can re-match an earlier field's replacement text; specs should use disjoint patterns.

## Limits & Second-order Effects

- The built-in phone pattern can match date-like strings (`2026-10-11`); per-deployment specs should drop or narrow it.
- Aggressive redaction degrades debuggability: on-call engineers may need access to raw logs for incidents, creating pressure to bypass the tool — plan a gated un-redaction path instead of ad-hoc ones.
- A clean audit is not proof of safety, only that declared patterns are absent; undeclared PII classes pass silently (second-order: false confidence).
- Regex denial-of-service: patterns from untrusted spec authors run against untrusted log lines; keep specs in review.

## FAQ

**Why JSON and not YAML or TOML?** Zero dependencies: `json` is stdlib and every editor highlights it.

**Does it modify my files?** No — it reads a file/stdin and writes redacted output to stdout. Redirect yourself.

**Is the audit a security guarantee?** No. It checks only the declared patterns; treat it as a tripwire, not a proof.

**When NOT to use this?** Do not use it as the only control for regulated PII (HIPAA/GDPR-grade obligations need reviewed, defense-in-depth handling); do not use it to redact binary logs; do not use it where structured field-level logging frameworks (with allow-lists at the source) are available — redacting at the source is strictly better.

## [Core Assumptions]

1. Logs are line-oriented text in a UTF-8-compatible encoding.
2. A small, reviewed set of field patterns covers the PII classes that matter for a given deployment.
3. Regex replacement is acceptable even though it is not semantically aware (no NER).
4. Callers can tolerate the CPU cost of re-scanning lines (O(patterns × line length)).

---

*Confidence: high — mechanism is small, deterministic, and covered by a 50-check self-test; star counts are from the R13 precheck snapshot. Content as of 2026-10-11.*

---

Part of the [zhengming-toolbox](https://github.com/chenhz01/zhengming-toolbox) — 55 purpose-built AI-engineering tools across neglected niches.

Related tools: [secret-rotation-check](https://github.com/chenhz01/secret-rotation-check) · [retention-policy-check](https://github.com/chenhz01/retention-policy-check) · [ai-commit-disclosure](https://github.com/chenhz01/ai-commit-disclosure)
