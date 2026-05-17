#!/usr/bin/env python3
"""
Live streaming eval: tails all_requests.jsonl and flags missed redactions in real-time.

Usage:
    python scripts/eval-stream.py [LOG_PATH] [options]
"""

import sys
import json
import math
import time
import argparse
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("Missing dependency: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

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

def col(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET

# ── reuse helpers from eval-missed-redactions ─────────────────────────────────

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
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val, ensure_ascii=False)


def keyword_hit(body: bytes, keywords: list[str]) -> bool:
    if not keywords:
        return True
    for kw in keywords:
        if kw.encode() in body:
            return True
    return False


def context_snippet(text: str, start: int, end: int, window: int = 50) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    pre = "..." if s > 0 else ""
    suf = "..." if e < len(text) else ""
    seg = text[s:e]
    rs, re_ = start - s, end - s
    highlighted = seg[:rs] + col(seg[rs:re_], BOLD, RED) + seg[re_:]
    return pre + highlighted + suf


def truncate(s: str, n: int = 80) -> str:
    return s[:n - 3] + "..." if len(s) > n else s


SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def sev_col(sev: str) -> str:
    return {
        "critical": BOLD + RED,
        "high": RED,
        "medium": YELLOW,
        "low": DIM,
    }.get(sev.lower(), RESET)


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
            compiled = re_module.compile(pattern.encode())
        except Exception:
            skipped += 1
            continue
        rules.append({
            "id":          r["id"],
            "name":        r.get("name", r["id"]),
            "category":    r.get("category", ""),
            "subcategory": r.get("subcategory", ""),
            "severity":    r.get("severity", "medium"),
            "confidence":  r.get("confidence", "medium"),
            "keywords":    r.get("keywords") or [],
            "entropy":     r.get("entropy"),
            "checksum":    r.get("checksum_type"),
            "compiled":    compiled,
        })
    if skipped:
        print(col(f"  [warn] {skipped} rules skipped (compile error)", DIM), file=sys.stderr)
    return rules


def scan(body: bytes, rules: list[dict], use_kw: bool) -> list[dict]:
    raw: list[dict] = []
    for rule in rules:
        if use_kw and not keyword_hit(body, rule["keywords"]):
            continue
        for m in rule["compiled"].finditer(body):
            chunk = body[m.start():m.end()]
            if rule["entropy"] is not None and shannon_entropy(chunk) < rule["entropy"]:
                continue
            if rule["checksum"] == "luhn" and not luhn_valid(chunk):
                continue
            raw.append({
                "rule_id":     rule["id"],
                "severity":    rule["severity"],
                "confidence":  rule["confidence"],
                "start":       m.start(),
                "end":         m.end(),
                "text":        chunk.decode("utf-8", errors="replace"),
            })
    # overlap resolution
    raw.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
    resolved: list[dict] = []
    for m in raw:
        if any(m["start"] >= p["start"] and m["end"] <= p["end"] for p in resolved):
            continue
        resolved.append(m)
    return resolved


# ── multi-line JSON parser ────────────────────────────────────────────────────

def iter_entries_from_text(text: str):
    """Parse all complete JSON objects out of accumulated text."""
    decoder = json.JSONDecoder()
    buf = text.lstrip()
    while buf:
        if not buf.startswith("{"):
            buf = buf.lstrip()
            if not buf or not buf.startswith("{"):
                break
        try:
            obj, idx = decoder.raw_decode(buf)
            yield obj
            buf = buf[idx:].lstrip()
        except json.JSONDecodeError:
            break  # incomplete object at end — caller will append more text

# ── live tail ────────────────────────────────────────────────────────────────

def tail_follow(path: Path):
    """
    Yield parsed JSON entry dicts as they are appended to path.
    Waits for the file to appear, then tails it from the current end.
    Handles multi-line pretty-printed JSON objects written by request_logger.
    """
    while not path.exists():
        print(col(f"  waiting for {path} ...", DIM), end="\r", flush=True)
        time.sleep(1)
    print()

    decoder = json.JSONDecoder()
    with open(path) as fh:
        fh.seek(0, 2)  # jump to current end — only new traffic
        buf = ""
        while True:
            chunk = fh.read(65536)
            if chunk:
                buf += chunk
            # parse as many complete objects as possible out of buf
            changed = True
            while changed:
                changed = False
                stripped = buf.lstrip()
                if not stripped.startswith("{"):
                    buf = stripped
                    break
                try:
                    obj, idx = decoder.raw_decode(stripped)
                    yield obj
                    buf = stripped[idx:]
                    changed = True
                except json.JSONDecodeError:
                    pass  # incomplete — wait for more data
            if not chunk:
                time.sleep(0.25)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)
    project_root = Path(__file__).resolve().parent.parent

    ap = argparse.ArgumentParser(
        description="Live eval: tail request log and flag missed redactions in real-time"
    )
    ap.add_argument("jsonl", nargs="?", default="/tmp/all_requests.jsonl")
    ap.add_argument("--rules", default=str(project_root / "rules" / "combined.yaml"))
    ap.add_argument("--no-keywords", action="store_true")
    ap.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to flag (default: medium)",
    )
    ap.add_argument(
        "--replay",
        action="store_true",
        help="Scan existing log from the beginning instead of tailing new entries",
    )
    args = ap.parse_args()

    jsonl_path  = Path(args.jsonl)
    rules_path  = Path(args.rules)
    min_sev_ord = SEV_ORDER.get(args.min_severity, 1)

    print()
    print(col("BLEEP  LIVE EVAL  —  missed redaction detector", BOLD, CYAN))
    print(col("━" * 60, CYAN))

    if not rules_path.exists():
        print(col(f"[error] rules not found: {rules_path}", RED))
        sys.exit(1)

    rules = load_rules(rules_path)
    print(f"  {col(str(len(rules)), GREEN)} rules loaded  ·  "
          f"min severity={col(args.min_severity, YELLOW)}  ·  "
          f"keywords={'off' if args.no_keywords else 'on'}")
    print(f"  watching {col(str(jsonl_path), CYAN)}")
    print(col("  Press Ctrl+C to stop and see totals.", DIM))
    print()

    # counters
    scanned = 0
    with_body = 0
    miss_count = 0
    miss_by_rule: dict[str, int] = defaultdict(int)

    def print_totals() -> None:
        print()
        print(col("━" * 60, CYAN))
        print(col("SESSION TOTALS", BOLD))
        print(f"  Entries scanned  : {scanned}")
        print(f"  With body        : {with_body}")
        print(f"  Missed entries   : {col(str(miss_count), RED if miss_count else GREEN)}")
        if miss_by_rule:
            print()
            print(col("  Top missed rules:", BOLD))
            for rule_id, cnt in sorted(miss_by_rule.items(), key=lambda x: -x[1])[:10]:
                print(f"    {rule_id:<48} {cnt}")
        print()

    def replay_entries(path: Path):
        decoder = json.JSONDecoder()
        with open(path) as fh:
            buf = fh.read()
        buf = buf.lstrip()
        while buf.startswith("{"):
            try:
                obj, idx = decoder.raw_decode(buf)
                yield obj
                buf = buf[idx:].lstrip()
            except json.JSONDecodeError:
                break

    try:
        if args.replay and jsonl_path.exists():
            source = replay_entries(jsonl_path)
        else:
            source = tail_follow(jsonl_path)

        for entry in source:

            scanned += 1
            caught = entry.get("redactions", 0)

            body_text = body_to_text(entry.get("body"))
            if not body_text:
                continue
            with_body += 1

            body_bytes = body_text.encode("utf-8")
            matches = scan(body_bytes, rules, use_kw=not args.no_keywords)
            matches = [m for m in matches if SEV_ORDER.get(m["severity"], 0) >= min_sev_ord]

            if len(matches) <= caught:
                # bleep caught everything (or no matches) — print a dot for heartbeat
                print(col(".", DIM), end="", flush=True)
                continue

            # ── MISS ─────────────────────────────────────────────────────────
            miss_count += 1
            for m in matches:
                miss_by_rule[m["rule_id"]] += 1

            etype = entry.get("type", "?")
            ts    = entry.get("ts", "")[:19]

            if etype == "request":
                label = f"{entry.get('method','?')} {truncate(entry.get('uri','?'), 55)}"
            else:
                label = f"RESPONSE {entry.get('status','?')}"

            print()  # end heartbeat dots line
            print(col("  ─" * 30, DIM))
            print(
                f"  {col('MISS', RED, BOLD)}  {col(label, BOLD)}  "
                f"{col(ts, DIM)}  "
                f"[bleep caught {caught}, eval found {len(matches)}]"
            )

            for m in matches:
                sev = m["severity"]
                print(
                    f"    {col('✗', RED, BOLD)} {col(m['rule_id'], BOLD)}"
                    f"  {col(f'[{sev}]', sev_col(sev))}"
                    f"  conf={m['confidence']}"
                )
                print(f"      matched : {col(truncate(repr(m['text']), 70), RED)}")
                snippet = " ".join(context_snippet(body_text, m["start"], m["end"]).split())
                print(f"      context : {truncate(snippet, 110)}")

            print(flush=True)

    except KeyboardInterrupt:
        print_totals()
        sys.exit(0)


if __name__ == "__main__":
    main()
