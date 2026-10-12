#!/usr/bin/env python3
"""log-redaction-spec: declarative, field-level log redaction with leak audit.

A JSON spec declares named sensitive fields (regex pattern + strategy:
mask / drop / hash). The validator enforces the schema, redact applies the
strategies to log lines, and audit samples emitted logs for residual PII.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

__version__ = "0.1.1"

STRATEGIES = ("mask", "drop", "hash")

DEFAULT_SPEC = {
    "version": "1.0",
    "fields": [
        {"field": "email", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
         "strategy": "mask", "keep": 2},
        {"field": "ipv4", "pattern": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
         "strategy": "mask", "keep": 1},
        {"field": "bearer_token", "pattern": "(?i)bearer\\s+[A-Za-z0-9._~+/=-]{8,}",
         "strategy": "drop"},
        {"field": "phone", "pattern": "\\+?\\d[\\d\\s-]{7,13}\\d",
         "strategy": "drop"},
    ],
}


class SpecError(ValueError):
    """Raised when a redaction spec violates the schema."""


def load_spec(data):
    """Load and validate a spec from a JSON string or an already-parsed dict."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SpecError("spec is not valid JSON: %s" % exc) from None
    if not isinstance(data, dict):
        raise SpecError("spec must be a JSON object, got %s" % type(data).__name__)
    fields = data.get("fields")
    if not isinstance(fields, list) or not fields:
        raise SpecError("spec.fields must be a non-empty list")
    compiled = []
    seen = set()
    for i, entry in enumerate(fields):
        if not isinstance(entry, dict):
            raise SpecError("field %d: entry must be an object" % i)
        name = entry.get("field")
        if not isinstance(name, str) or not name.strip():
            raise SpecError("field %d: missing non-empty 'field' name" % i)
        if name in seen:
            raise SpecError("duplicate field name: %s" % name)
        seen.add(name)
        strategy = entry.get("strategy")
        if strategy not in STRATEGIES:
            raise SpecError("field %s: strategy must be one of %s"
                            % (name, "/".join(STRATEGIES)))
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise SpecError("field %s: 'pattern' must be a non-empty string" % name)
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise SpecError("field %s: invalid pattern: %s" % (name, exc)) from None
        keep = entry.get("keep", 0)
        if isinstance(keep, bool) or not isinstance(keep, int):
            raise SpecError("field %s: 'keep' must be an integer" % name)
        compiled.append({"field": name, "rx": rx, "strategy": strategy, "keep": max(0, keep)})
    return {"version": str(data.get("version", "1")), "fields": compiled}


def _mask(value, keep):
    if keep <= 0 or len(value) <= keep:
        return "*" * max(1, len(value))
    return value[:keep] + "*" * (len(value) - keep)


def _apply(value, entry):
    if entry["strategy"] == "drop":
        return "[REDACTED:%s]" % entry["field"]
    if entry["strategy"] == "hash":
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
        return "sha256:%s" % digest
    return _mask(value, entry["keep"])


def redact_line(line, spec):
    """Redact one log line. Returns (redacted_line, hits) where hits maps
    field name -> number of matches replaced."""
    if not isinstance(line, str):
        raise TypeError("line must be str, got %s" % type(line).__name__)
    if not isinstance(spec, dict) or "fields" not in spec:
        raise SpecError("spec must be a loaded spec object")
    hits = {}
    out = line
    for entry in spec["fields"]:
        def _sub(match, _entry=entry):
            hits[_entry["field"]] = hits.get(_entry["field"], 0) + 1
            return _apply(match.group(0), _entry)
        out = entry["rx"].sub(_sub, out)
    return out, hits


def redact_text(text, spec):
    """Redact multi-line text, preserving line endings. Returns (text, hits)."""
    if not isinstance(text, str):
        raise TypeError("text must be str, got %s" % type(text).__name__)
    out_parts = []
    total = {}
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        eol = line[len(stripped):]
        new_line, hits = redact_line(stripped, spec)
        for key, value in hits.items():
            total[key] = total.get(key, 0) + value
        out_parts.append(new_line + eol)
    return "".join(out_parts), total


def audit_leaks(lines, spec, sample_limit=20):
    """Return leak suspects: lines that still contain a declared pattern."""
    if not isinstance(lines, (list, tuple)):
        raise TypeError("lines must be a list of strings")
    leaks = []
    for idx, line in enumerate(lines):
        if len(leaks) >= sample_limit:
            break
        if not isinstance(line, str):
            continue
        for entry in spec["fields"]:
            if entry["rx"].search(line):
                leaks.append({"line_no": idx + 1, "field": entry["field"],
                              "sample": line[:200]})
                break
    return leaks


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="log-redaction-spec", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_red = sub.add_parser("redact", help="redact a log file or stdin")
    p_red.add_argument("--spec", default=None, help="spec JSON path (default: built-in)")
    p_red.add_argument("--file", default="-", help="input file ('-' = stdin)")
    p_aud = sub.add_parser("audit", help="audit a log file for leaked PII")
    p_aud.add_argument("--spec", default=None, help="spec JSON path (default: built-in)")
    p_aud.add_argument("--file", required=True, help="log file to audit")
    p_aud.add_argument("--limit", type=int, default=20, help="max leak samples")
    args = parser.parse_args(argv)
    spec = load_spec(_read(args.spec)) if args.spec else load_spec(json.dumps(DEFAULT_SPEC))
    if args.command == "redact":
        text = _read(args.file)
        out, _hits = redact_text(text, spec)
        sys.stdout.write(out)
        return 0
    with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
        leaks = audit_leaks(fh.read().splitlines(), spec, args.limit)
    print(json.dumps({"leak_suspects": len(leaks), "samples": leaks}, indent=2))
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
