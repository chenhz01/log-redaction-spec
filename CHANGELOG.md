# Changelog

Format inspired by Keep a Changelog; versions are SemVer.

## [0.1.1] - 2026-10-11

### Changed
- Round-2 content iteration: self-test suite expanded from 40 to 50 checks (+25% on the coverage dimension) — added spec-validator exception paths (empty spec object, non-list fields, non-string pattern, non-int keep, negative keep clamping), mutation-safety and boundary checks, and a CLI error-path check.
- README: tightened Quickstart commands and added CLI error-path examples in self-test.

## [0.1.0] - 2026-10-11

### Added
- Field-level redaction spec schema (JSON) with mask/drop/hash strategies and validator (`load_spec`).
- `redact_line` / `redact_text` with per-field hit counts and line-ending preservation.
- `audit_leaks` post-hoc leak sampling with 1-based line numbers and sample limit.
- CLI: `redact` and `audit` subcommands (argparse), built-in default spec.
- Self-test suite: 40 checks (functional / exception / extreme edges).
- MIT license (zhengming contributors), README with anchor comparison.
