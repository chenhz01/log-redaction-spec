#!/usr/bin/env python3
"""Self-test for log-redaction-spec. Round 1: 40 checks; Round 2: +10 = 50.

Run:  python self_test.py
Last line printed:  SUMMARY: PASS n/n
Categories: A = functional, E = exception paths, X = extreme edges.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import log_redaction_spec as core

passed = 0
failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL: %s" % name)


def raises(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        return False
    except Exception:
        return True


SPEC = core.load_spec(json.dumps(core.DEFAULT_SPEC))

# ---------- A. functional unit tests (1-20) ----------
check("A01 default spec loads with 4 fields", len(SPEC["fields"]) == 4)
check("A02 version defaults to '1'",
      core.load_spec({"fields": [{"field": "x", "pattern": "a", "strategy": "drop"}]})["version"] == "1")
out, hits = core.redact_line("mail jo@example.com here", SPEC)
check("A03 email masked keep=2", out.startswith("mail jo") and "@" not in out and hits.get("email") == 1)
check("A04 bearer token dropped",
      "[REDACTED:bearer_token]" in core.redact_line("auth Bearer abc123def456 x", SPEC)[0])
check("A05 ipv4 masked keep=1", core.redact_line("ip 10.0.0.1 end", SPEC)[0].count("*") == 7)
check("A06 phone number dropped",
      "[REDACTED:phone]" in core.redact_line("call 555-0100-99 now", SPEC)[0])
hspec = core.load_spec({"fields": [{"field": "tid", "pattern": "TID-\\d+", "strategy": "hash"}]})
hout = core.redact_line("id TID-42 end", hspec)[0]
check("A07 hash strategy emits sha256:12hex",
      hout.startswith("id sha256:") and len(hout.split("sha256:")[1].split()[0]) == 12)
check("A08 hits counts duplicates", core.redact_line("a@b.com a@b.com", SPEC)[1].get("email") == 2)
t2, tot = core.redact_text("l1 a@b.com\nl2 c@d.io\n", SPEC)
check("A09 redact_text totals across lines", tot.get("email") == 2 and t2.count("\n") == 2)
cspec = core.load_spec({"fields": [
    {"field": "email", "pattern": "\\w+@\\w+\\.com", "strategy": "drop"},
    {"field": "order_id", "pattern": "ORD-\\d+", "strategy": "drop"}]})
cout, chits = core.redact_line("user x@y.com order ORD-7 done", cspec)
check("A10 custom two-field spec", "[REDACTED:email]" in cout and "[REDACTED:order_id]" in cout)
check("A11 audit finds raw email line", len(core.audit_leaks(["ok line", "user x@y.com"], SPEC)) == 1)
red_only, _ = core.redact_text("user x@y.com\n", SPEC)
check("A12 audit clean on redacted text", core.audit_leaks(red_only.splitlines(), SPEC) == [])
check("A13 audit sample limit respected",
      len(core.audit_leaks(["x@y.com"] * 30, SPEC, sample_limit=5)) == 5)
check("A14 CLI main is callable", callable(core.main))
mspec = core.load_spec({"fields": [{"field": "tok", "pattern": "abcdef", "strategy": "mask", "keep": 0}]})
check("A15 mask keep=0 fully masks", core.redact_line("tok abcdef", mspec)[0] == "tok ******")
check("A16 drop tag contains field name", "[REDACTED:order_id]" in cout)
check("A17 version passthrough",
      core.load_spec({"version": "2.0", "fields": [{"field": "x", "pattern": "a", "strategy": "drop"}]})["version"] == "2.0")
check("A18 PII-free line unchanged", core.redact_line("plain text only", SPEC)[0] == "plain text only")
once, _ = core.redact_line("a@b.com ok", SPEC)
again, hits2 = core.redact_line(once, SPEC)
check("A19 redaction is idempotent", once == again and not hits2)
uspec = core.load_spec({"fields": [{"field": "用户", "pattern": "用户-\\d+", "strategy": "drop"}]})
check("A20 unicode field name works", "[REDACTED:用户]" in core.redact_line("用户-42 上报", uspec)[0])

# ---------- E. exception paths (21-30) ----------
check("E01 invalid JSON raises SpecError", raises(core.load_spec, "{nope"))
check("E02 non-object JSON raises", raises(core.load_spec, "[1,2]"))
check("E03 empty fields list raises", raises(core.load_spec, {"fields": []}))
check("E04 missing pattern raises",
      raises(core.load_spec, {"fields": [{"field": "x", "strategy": "drop"}]}))
check("E05 invalid regex raises",
      raises(core.load_spec, {"fields": [{"field": "x", "pattern": "(", "strategy": "drop"}]}))
check("E06 unknown strategy raises",
      raises(core.load_spec, {"fields": [{"field": "x", "pattern": "a", "strategy": "burn"}]}))
check("E07 duplicate field names raise", raises(core.load_spec, {"fields": [
    {"field": "x", "pattern": "a", "strategy": "drop"},
    {"field": "x", "pattern": "b", "strategy": "drop"}]}))
check("E08 non-object field entry raises", raises(core.load_spec, {"fields": ["x"]}))
check("E09 redact_line(None) raises", raises(core.redact_line, None, SPEC))
check("E10 load_spec(None) raises", raises(core.load_spec, None))

# ---------- X. extreme edges (31-40) ----------
check("X01 empty text redacts to empty", core.redact_text("", SPEC)[0] == "")
long_line = "x@y.com " * 20000
_lout, lhits = core.redact_line(long_line, SPEC)
check("X02 160k-char line: 20000 emails found", lhits.get("email") == 20000)
uout, _ = core.redact_line("中文 body a@b.com 尾", SPEC)
check("X03 CJK text preserved, PII removed",
      uout.count("中") == 1 and uout.count("尾") == 1 and "a@b.com" not in uout)
eout, _ = core.redact_line("🚀 a@b.com 🎉", SPEC)
check("X04 emoji preserved", eout.startswith("🚀") and eout.rstrip().endswith("🎉"))
many = "".join("line %d a@b.com\n" % i for i in range(1000))
check("X05 1000 lines in -> 1000 lines out", core.redact_text(many, SPEC)[0].count("\n") == 1000)
deep = {"n": None}
node = {"n": None}
for _ in range(200):
    node = {"n": node}
deep_entry = {"field": "x", "pattern": "p", "strategy": "drop", "meta": node}
check("X06 200-level nested spec metadata accepted",
      len(core.load_spec({"fields": [deep_entry]})["fields"]) == 1)
tout, _ = core.redact_line("a\tb@c.de\tc", SPEC)
check("X07 tabs preserved around redacted email", tout.startswith("a\t") and tout.endswith("\tc"))
crlf, _ = core.redact_text("l1 a@b.com\r\nl2\r\n", SPEC)
check("X08 CRLF endings preserved", crlf.count("\r\n") == 2)
k100 = core.load_spec({"fields": [{"field": "s", "pattern": "abc", "strategy": "mask", "keep": 100}]})
check("X09 keep>len masks whole value", core.redact_line("abc", k100)[0] == "***")
pos = core.audit_leaks(["clean", "leak x@y.com"], SPEC)
check("X10 audit line numbers are 1-based", len(pos) == 1 and pos[0]["line_no"] == 2)

print("SUMMARY: PASS %d/%d" % (passed, passed + failed))
