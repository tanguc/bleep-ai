#!/usr/bin/env python3
"""
Find missed redactions in bleep-gateway request logs.

Reads /tmp/all_requests.jsonl (original bodies, pre-redaction),
re-runs every rule from combined.yaml, and reports matches that look
like they should have been caught but weren't.

Usage:
    python scripts/eval-missed-redactions.py [LOG_PATH] [options]

Requirements:
    pip install pyyaml
    Optional: pip install regex  (Rust-compatible regex engine, fallback to stdlib re)

Note: enable request logging first if not already running:
    BLEEP_LOG_REQUESTS=1 task run
    or:
    task eval:capture
"""

import sys
import json
import math
import argparse
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("Missing dependency: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# try the 'regex' package first (better Rust compat), fall back to stdlib re
try:
    import regex as re_module  # type: ignore
except ImportError:
    import re as re_module  # type: ignore

# ── ANSI colours ─────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"

def c(*codes: str) -> str:
    return "".join(codes)

def col(text: str, *codes: str) -> str:
    return c(*codes) + text + RESET

# ── helpers ───────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def luhn_valid(data: bytes) -> bool:
    digits = [b - 48 for b in data if 48 <= b <= 57]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def body_to_text(val) -> str | None:
    """Flatten a parsed JSON value to a plain text string for regex scanning."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val, ensure_ascii=False)


def keyword_hit(body: bytes, keywords: list[str]) -> bool:
    """
    Case-sensitive byte-substring check, mirroring the gateway:
      body.windows(k.len()).any(|w| w == k.as_bytes())
    """
    if not keywords:
        return True
    for kw in keywords:
        if kw.encode() in body:
            return True
    return False


def context_snippet(text: str, start: int, end: int, window: int = 55) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    pre  = "..." if s > 0 else ""
    suf  = "..." if e < len(text) else ""
    seg  = text[s:e]
    rs, re_ = start - s, end - s
    highlighted = seg[:rs] + col(seg[rs:re_], BOLD, RED) + seg[re_:]
    return pre + highlighted + suf


def truncate(s: str, n: int = 70) -> str:
    return s[:n - 3] + "..." if len(s) > n else s

# ── rule loading ──────────────────────────────────────────────────────────────

def load_rules(path: Path) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)

    rules = []
    skipped = 0
    for r in data.get("rules", []):
        pattern = r.get("regex")
        if not pattern:
            continue
        try:
            # compile against bytes so find_iter returns byte offsets
            compiled = re_module.compile(pattern.encode())
        except Exception:
            skipped += 1
            continue
        rules.append(
            {
                "id":          r["id"],
                "name":        r.get("name", r["id"]),
                "category":    r.get("category", ""),
                "subcategory": r.get("subcategory", ""),
                "severity":    r.get("severity", "medium"),
                "confidence":  r.get("confidence", "medium"),
                # keep keywords exactly as-is — gateway match is case-sensitive
                "keywords":    r.get("keywords") or [],
                "entropy":     r.get("entropy"),
                "checksum":    r.get("checksum_type"),
                "compiled":    compiled,
            }
        )
    if skipped:
        print(col(f"  [warn] {skipped} rule(s) failed to compile (skipped)", DIM),
              file=sys.stderr)
    return rules

# ── scanning ──────────────────────────────────────────────────────────────────

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def scan(body: bytes, rules: list[dict], use_keywords: bool) -> list[dict]:
    raw_matches: list[dict] = []

    for rule in rules:
        if use_keywords and not keyword_hit(body, rule["keywords"]):
            continue

        for m in rule["compiled"].finditer(body):
            chunk = body[m.start():m.end()]

            if rule["entropy"] is not None and shannon_entropy(chunk) < rule["entropy"]:
                continue
            if rule["checksum"] == "luhn" and not luhn_valid(chunk):
                continue
            if is_bleep_fake(rule["id"], chunk):
                # bleep's realistic mimicry produces values that match the same
                # rule again (an `hf_…` fake matches the HF rule, a fake email
                # matches the email rule). Reporting these would drown out real
                # misses, so we skip anything that looks like our own output.
                continue

            raw_matches.append(
                {
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "category":    rule["category"],
                    "subcategory": rule["subcategory"],
                    "severity":    rule["severity"],
                    "confidence":  rule["confidence"],
                    "start":       m.start(),
                    "end":         m.end(),
                    "text":        chunk.decode("utf-8", errors="replace"),
                }
            )

    # overlap resolution: longer span wins (same as gateway)
    raw_matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
    resolved: list[dict] = []
    for m in raw_matches:
        if any(m["start"] >= p["start"] and m["end"] <= p["end"] for p in resolved):
            continue
        resolved.append(m)

    return resolved


# ── known-fake patterns ──────────────────────────────────────────────────────
# bleep's realistic mimicry produces values that match the same rules that
# detected the original. Without filtering, the eval double-counts them as
# misses. We recognize each replacer's deterministic signature here.
#
# Sources of truth: src/replacement/replacers.rs (the *_realistic functions).

import re as _stdlib_re  # always available, doesn't depend on the optional 'regex' pkg

_FAKE_EMAIL_DOMAINS = _stdlib_re.compile(rb"@example\.(com|org|net)\b")
# fake_phone_visible / fake_phone_realistic both pick from a small set; visible
# format is "+1-555-010-NNNN", realistic preserves the input format with random
# digits — hard to fingerprint cheaply, so phone is left to the per-rule logic.
_FAKE_IPV4_TESTNET = _stdlib_re.compile(rb"^(198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3}|192\.0\.2\.\d{1,3})$")
_FAKE_SSN_VISIBLE = _stdlib_re.compile(rb"^000-(00|99)-\d{4}$")
_FAKE_JWT_HEADER = b"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # fake_jwt_realistic header


def is_bleep_fake(rule_id: str, chunk: bytes) -> bool:
    """Return True if `chunk` looks like a value the realistic mimicry replacer
    would have produced — so we should NOT flag it as a missed redaction."""
    # email rules — all fakes land on @example.{com,org,net}
    if "email" in rule_id:
        return bool(_FAKE_EMAIL_DOMAINS.search(chunk))
    # ipv4 rules — fakes use IANA TEST-NET ranges
    if "ipv4" in rule_id or rule_id.endswith(".ip"):
        return bool(_FAKE_IPV4_TESTNET.search(chunk))
    # ssn — visible marker uses 000-XX form
    if "ssn" in rule_id:
        return bool(_FAKE_SSN_VISIBLE.search(chunk))
    # jwt — fake header is a fixed value
    if "jwt" in rule_id or rule_id.endswith(".jwt"):
        return _FAKE_JWT_HEADER in chunk
    return False


# ── multi-line JSON entry iterator ───────────────────────────────────────────

def iter_entries(fh):
    """
    Yield parsed JSON objects from a file of concatenated pretty-printed objects.
    The request_logger writes serde_json::to_string_pretty entries back-to-back with
    no delimiter, so we use raw_decode to find each object boundary.
    """
    decoder = json.JSONDecoder()
    buf = ""
    for line in fh:
        buf += line
        # try to parse from the start whenever we see a closing brace at col 0
        while buf.lstrip():
            stripped = buf.lstrip()
            if not stripped.startswith("{"):
                # skip garbage / whitespace until next object
                buf = stripped
                break
            try:
                obj, idx = decoder.raw_decode(stripped)
                yield obj
                buf = stripped[idx:]
            except json.JSONDecodeError:
                break  # incomplete object — read more lines

# ── report helpers ────────────────────────────────────────────────────────────

def sev_col(sev: str) -> str:
    return {"critical": c(RED, BOLD), "high": RED, "medium": YELLOW, "low": DIM}.get(
        sev.lower(), RESET
    )


def bar(value: int, max_val: int, width: int = 18) -> str:
    filled = round(width * value / max_val) if max_val else 0
    return col("█" * filled + "░" * (width - filled), CYAN)

# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)
    project_root = Path(__file__).resolve().parent.parent

    ap = argparse.ArgumentParser(
        description="Evaluate bleep-gateway request logs for missed redactions"
    )
    ap.add_argument(
        "jsonl",
        nargs="?",
        default="/tmp/all_requests.jsonl",
        help="Path to all_requests.jsonl (default: /tmp/all_requests.jsonl)",
    )
    ap.add_argument(
        "--rules",
        default=str(project_root / "rules" / "combined.yaml"),
        help="Path to combined.yaml",
    )
    ap.add_argument(
        "--no-keywords",
        action="store_true",
        help="Disable keyword pre-filter — surfaces misses caused by the filter itself",
    )
    ap.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=20,
        help="Max missed-request details to print (default: 20)",
    )
    args = ap.parse_args()

    jsonl_path  = Path(args.jsonl)
    rules_path  = Path(args.rules)
    min_sev_ord = SEV_ORDER.get(args.min_severity, 0)

    # ── header ────────────────────────────────────────────────────────────────
    print()
    print(col("BLEEP  MISSED-REDACTION  EVAL", BOLD, CYAN))
    print(col("━" * 60, CYAN))

    # ── load rules ────────────────────────────────────────────────────────────
    if not rules_path.exists():
        print(col(f"[error] rules file not found: {rules_path}", RED))
        sys.exit(1)

    rules_label = rules_path.name
    print(f"Rules  : {rules_label}")
    rules = load_rules(rules_path)
    print(col(f"         {len(rules)} rules compiled", GREEN))

    if args.no_keywords:
        print(col("         keyword pre-filter DISABLED (--no-keywords)", YELLOW))

    print()

    if not jsonl_path.exists():
        print(col(f"[error] log not found: {jsonl_path}", RED))
        print()
        print("  Request logging is not enabled. Start the gateway with:")
        print(col("    BLEEP_LOG_REQUESTS=1 BLEEP_LOG_PATH=/tmp task run", BOLD))
        print()
        print("  Or use the Taskfile shortcut:")
        print(col("    task eval:capture", BOLD))
        print()
        sys.exit(1)

    file_size = jsonl_path.stat().st_size
    print(f"Log    : {jsonl_path}  ({file_size // 1024} KB)")
    print()

    # ── scan ──────────────────────────────────────────────────────────────────
    total_entries    = 0
    entries_w_body   = 0
    total_caught     = 0
    total_found      = 0
    entries_w_misses = 0
    miss_by_rule: dict[str, int] = defaultdict(int)
    missed_items: list[dict] = []

    with open(jsonl_path) as fh:
        for entry in iter_entries(fh):

            total_entries += 1
            caught = entry.get("redactions", 0)
            total_caught += caught

            body_text = body_to_text(entry.get("body"))
            if not body_text:
                continue
            entries_w_body += 1

            body_bytes = body_text.encode("utf-8")
            matches = scan(body_bytes, rules, use_keywords=not args.no_keywords)
            matches = [m for m in matches if SEV_ORDER.get(m["severity"], 0) >= min_sev_ord]

            total_found += len(matches)

            # flag if our scanner found more potential hits than bleep reported
            if len(matches) > caught:
                entries_w_misses += 1
                for m in matches:
                    miss_by_rule[m["rule_id"]] += 1
                missed_items.append(
                    {
                        "entry":   entry,
                        "text":    body_text,
                        "matches": matches,
                        "caught":  caught,
                    }
                )

    # ── summary ───────────────────────────────────────────────────────────────
    print(col("SUMMARY", BOLD))
    print(f"  Log entries scanned          : {total_entries}")
    print(f"  Entries with non-empty body  : {entries_w_body}")
    print(f"  Redactions bleep applied     : {col(str(total_caught), GREEN)}")
    print(f"  Rule matches found by eval   : {col(str(total_found), CYAN)}")

    miss_pct = (entries_w_misses / entries_w_body * 100) if entries_w_body else 0.0
    miss_color = RED if entries_w_misses else GREEN
    print(
        f"  Entries with potential misses : "
        f"{col(str(entries_w_misses), miss_color, BOLD)} "
        f"{col(f'({miss_pct:.1f}%)', miss_color)}"
    )
    print()

    if not missed_items:
        print(col("  No missed redactions found. Rules look solid.", GREEN, BOLD))
        print()
        return

    # ── top missed rules ──────────────────────────────────────────────────────
    rule_meta = {r["id"]: r for r in rules}
    sorted_rules = sorted(miss_by_rule.items(), key=lambda x: -x[1])
    max_count = sorted_rules[0][1] if sorted_rules else 1

    print(col("TOP MISSED RULES", BOLD))
    print(f"  {'#':<4} {'Rule ID':<46} {'Sev':<9} {'Hits':>5}  {'':18}")
    print(f"  {'─'*4} {'─'*46} {'─'*9} {'─'*5}  {'─'*18}")
    for rank, (rule_id, cnt) in enumerate(sorted_rules[:20], 1):
        info = rule_meta.get(rule_id, {})
        sev  = info.get("severity", "?")
        sev_s = col(f"{sev:<9}", sev_col(sev))
        print(
            f"  {rank:<4} {rule_id:<46} {sev_s} {cnt:>5}  {bar(cnt, max_count)}"
        )
    if len(sorted_rules) > 20:
        print(col(f"  ... and {len(sorted_rules) - 20} more", DIM))
    print()

    # ── per-request detail ────────────────────────────────────────────────────
    shown = min(args.top, len(missed_items))
    print(col("MISSED REQUESTS", BOLD))
    print(col(f"  (showing {shown} of {len(missed_items)})", DIM))
    print()

    for idx, item in enumerate(missed_items[:shown], 1):
        entry   = item["entry"]
        matches = item["matches"]
        caught  = item["caught"]
        text    = item["text"]

        etype = entry.get("type", "?")
        ts    = entry.get("ts", "")[:19]

        if etype == "request":
            label = f"{entry.get('method','?')} {entry.get('uri','?')}"
        else:
            label = f"RESPONSE {entry.get('status','?')}"

        print(col("  " + "─" * 58, DIM))
        print(
            f"  {col(f'[{idx:03d}]', BOLD, CYAN)} {col(truncate(label, 52), BOLD)}"
            f"  {col(ts, DIM)}"
        )
        print(f"       bleep caught : {col(str(caught), GREEN)} redaction(s)")
        print(f"       eval found   : {col(str(len(matches)), YELLOW)} potential match(es)")
        print()

        for m in matches:
            sev = m["severity"]
            print(
                f"    {col('✗', RED, BOLD)} {col(m['rule_id'], BOLD)}"
                f"  {col(f'[{sev}]', sev_col(sev))}"
                f"  conf={m['confidence']}"
            )
            print(f"      matched  : {col(truncate(repr(m['text']), 80), RED)}")
            snippet = " ".join(context_snippet(text, m["start"], m["end"]).split())
            print(f"      context  : {truncate(snippet, 120)}")
            print()

    print(col("━" * 60, CYAN))
    print(
        col(
            f"Done. {entries_w_misses} request(s) with potential missed redactions "
            f"out of {entries_w_body} with body.",
            BOLD,
        )
    )
    print()


if __name__ == "__main__":
    main()
