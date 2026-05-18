#!/usr/bin/env python3
"""
Autonomous bleep-gateway classifier daemon.

Tails all_requests.jsonl, detects missed redactions with the regex scanner,
classifies each miss via `claude -p` (Haiku by default).

Outputs:
  /tmp/eval-classify.log       — human-readable verdicts (ANSI)
  /tmp/eval-classify.jsonl     — machine-readable verdicts (one JSON per line)
  /tmp/eval-classify.pid       — PID file while running
  /tmp/eval-classify-state.json — persisted counters across restarts

Usage:
    python scripts/eval-classify.py [options] [LOG_PATH]
    python scripts/eval-classify.py --replay   # scan from beginning then tail
    python scripts/eval-classify.py --stop     # send SIGTERM to running daemon
    python scripts/eval-classify.py --status   # show running state + counters
"""

import sys
import io
import json
import math
import os
import signal
import time
import subprocess
import argparse
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)

try:
    import yaml
except ImportError:
    print("Missing dependency: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

try:
    import regex as re_module  # type: ignore
except ImportError:
    import re as re_module  # type: ignore

# ── paths ─────────────────────────────────────────────────────────────────────

PID_FILE    = Path("/tmp/eval-classify.pid")
STATE_FILE  = Path("/tmp/eval-classify-state.json")
VERDICT_LOG = Path("/tmp/eval-classify.jsonl")
HUMAN_LOG   = Path("/tmp/eval-classify.log")

# ── ansi ──────────────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"


def col(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET


# ── state persistence ─────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"scanned": 0, "with_body": 0, "true_miss": 0, "false_pos": 0, "ambiguous": 0, "started_at": ""}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except Exception:
        pass


# ── pid management ────────────────────────────────────────────────────────────

def write_pid() -> None:
    PID_FILE.write_text(str(os.getpid()))


def clear_pid() -> None:
    PID_FILE.unlink(missing_ok=True)


def read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ── detection ─────────────────────────────────────────────────────────────────

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
    return any(kw.encode() in body for kw in keywords)


def truncate(s: str, n: int = 80) -> str:
    return s[: n - 3] + "..." if len(s) > n else s


SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load_rules(path: Path) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)
    rules = []
    for r in data.get("rules", []):
        pattern = r.get("regex")
        if not pattern:
            continue
        try:
            compiled = re_module.compile(pattern.encode())
        except Exception:
            continue
        rules.append(
            {
                "id":         r["id"],
                "name":       r.get("name", r["id"]),
                "category":   r.get("category", ""),
                "severity":   r.get("severity", "medium"),
                "confidence": r.get("confidence", "medium"),
                "keywords":   r.get("keywords") or [],
                "entropy":    r.get("entropy"),
                "checksum":   r.get("checksum_type"),
                "compiled":   compiled,
            }
        )
    return rules


def scan(body: bytes, rules: list[dict], use_kw: bool) -> list[dict]:
    raw: list[dict] = []
    for rule in rules:
        if use_kw and not keyword_hit(body, rule["keywords"]):
            continue
        for m in rule["compiled"].finditer(body):
            chunk = body[m.start() : m.end()]
            if rule["entropy"] is not None and shannon_entropy(chunk) < rule["entropy"]:
                continue
            if rule["checksum"] == "luhn" and not luhn_valid(chunk):
                continue
            raw.append(
                {
                    "rule_id":    rule["id"],
                    "severity":   rule["severity"],
                    "confidence": rule["confidence"],
                    "start":      m.start(),
                    "end":        m.end(),
                    "text":       chunk.decode("utf-8", errors="replace"),
                }
            )
    raw.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
    resolved: list[dict] = []
    for m in raw:
        if any(m["start"] >= p["start"] and m["end"] <= p["end"] for p in resolved):
            continue
        resolved.append(m)
    return resolved


# ── classifier ────────────────────────────────────────────────────────────────

CLASSIFY_PROMPT = """\
You are a security data classifier for a privacy proxy called bleep-gateway.

A regex rule matched a string in an HTTP request/response body. Decide if this is:
- TRUE_MISS: genuinely sensitive data (PII, secrets, credentials) that the proxy SHOULD redact but didn't
- FALSE_POSITIVE: the rule matched something that looks sensitive but isn't (e.g. a memory byte count matched a tax ID pattern, a git hash matched a token pattern, a code placeholder like email@x.com)
- AMBIGUOUS: you can't tell without more context

Rule that fired: {rule_id}  (severity={severity}, confidence={confidence})
Matched text: {matched_text}
Surrounding context: {context}
Request URL: {url}

Respond with exactly one line in this format:
VERDICT: <TRUE_MISS|FALSE_POSITIVE|AMBIGUOUS>
REASON: <one short sentence>
"""


def classify_miss(match: dict, url: str, context: str, model: str) -> tuple[str, str]:
    prompt = CLASSIFY_PROMPT.format(
        rule_id=match["rule_id"],
        severity=match["severity"],
        confidence=match["confidence"],
        matched_text=repr(match["text"][:120]),
        context=truncate(context, 300),
        url=truncate(url, 100),
    )
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", model],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        verdict = "AMBIGUOUS"
        reason = output
        for line in output.splitlines():
            if line.startswith("VERDICT:"):
                verdict = line.split(":", 1)[1].strip()
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()
        return verdict, reason
    except subprocess.TimeoutExpired:
        return "AMBIGUOUS", "classifier timed out"
    except Exception as e:
        return "AMBIGUOUS", f"classifier error: {e}"


# ── log entry parsing ─────────────────────────────────────────────────────────

def iter_entries_from_file(path: Path):
    decoder = json.JSONDecoder()
    with open(path) as fh:
        buf = fh.read().lstrip()
    while buf.startswith("{"):
        try:
            obj, idx = decoder.raw_decode(buf)
            yield obj
            buf = buf[idx:].lstrip()
        except json.JSONDecodeError:
            break


def tail_follow(path: Path):
    """Yield new log entries as the gateway appends them. Waits for file to appear."""
    while not path.exists():
        print(col(f"  waiting for {path} ...", DIM), end="\r", flush=True)
        time.sleep(1)
    print()

    decoder = json.JSONDecoder()
    with open(path) as fh:
        fh.seek(0, 2)
        buf = ""
        while True:
            chunk = fh.read(65536)
            if chunk:
                buf += chunk
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
                    pass
            if not chunk:
                time.sleep(0.25)


def context_around(text: str, start: int, end: int, window: int = 80) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return ("..." if s > 0 else "") + text[s:e] + ("..." if e < len(text) else "")


def verdict_col(v: str) -> str:
    return {
        "TRUE_MISS":      col(v, RED, BOLD),
        "FALSE_POSITIVE": col(v, GREEN),
        "AMBIGUOUS":      col(v, YELLOW),
    }.get(v, col(v, DIM))


# ── output helpers ────────────────────────────────────────────────────────────

def emit(human_fh, line: str) -> None:
    """Write to stdout and human log."""
    print(line)
    human_fh.write(line + "\n")
    human_fh.flush()


def emit_verdict(verdict_fh, record: dict) -> None:
    verdict_fh.write(json.dumps(record) + "\n")
    verdict_fh.flush()


def print_totals(state: dict, emit_fn) -> None:
    emit_fn(col("━" * 60, CYAN))
    emit_fn(col("TOTALS (lifetime)", BOLD))
    emit_fn(f"  Scanned       : {state['scanned']}")
    emit_fn(f"  With body     : {state['with_body']}")
    emit_fn(f"  {col('TRUE_MISS', RED, BOLD)}     : {state['true_miss']}")
    emit_fn(f"  {col('FALSE_POSITIVE', GREEN)} : {state['false_pos']}")
    emit_fn(f"  {col('AMBIGUOUS', YELLOW)}     : {state['ambiguous']}")
    emit_fn("")


# ── subcommands ───────────────────────────────────────────────────────────────

def cmd_stop() -> None:
    pid = read_pid()
    if pid is None:
        print("no classifier running (no PID file)")
        return
    if not is_running(pid):
        print(f"stale PID {pid} — cleaning up")
        clear_pid()
        return
    os.kill(pid, signal.SIGTERM)
    print(f"sent SIGTERM to PID {pid}")


def cmd_status() -> None:
    pid = read_pid()
    if pid is None or not is_running(pid):
        print(col("classifier: NOT running", RED))
        clear_pid()
    else:
        print(col(f"classifier: running  (PID {pid})", GREEN))
    state = load_state()
    if state["started_at"]:
        print(f"  started     : {state['started_at']}")
    print(f"  scanned     : {state['scanned']}")
    print(f"  true_miss   : {col(str(state['true_miss']), RED if state['true_miss'] else DIM)}")
    print(f"  false_pos   : {state['false_pos']}")
    print(f"  ambiguous   : {state['ambiguous']}")
    print(f"  verdict log : {VERDICT_LOG}")
    print(f"  human log   : {HUMAN_LOG}")


# ── main loop ─────────────────────────────────────────────────────────────────

def run(args) -> None:
    # check for already-running instance
    pid = read_pid()
    if pid and is_running(pid):
        print(col(f"classifier already running (PID {pid}). Use --stop first.", YELLOW))
        sys.exit(1)

    write_pid()
    state = load_state()
    if not state["started_at"]:
        state["started_at"] = datetime.now(timezone.utc).isoformat()

    project_root = Path(__file__).resolve().parent.parent
    jsonl_path   = Path(args.jsonl)
    rules_path   = Path(args.rules)
    min_sev_ord  = SEV_ORDER.get(args.min_severity, 1)

    def _shutdown(signum, frame):
        with open(HUMAN_LOG, "a") as hfh:
            print_totals(state, lambda l: (print(l), hfh.write(l + "\n")))
        save_state(state)
        clear_pid()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    if not rules_path.exists():
        print(col(f"[error] rules not found: {rules_path}", RED))
        clear_pid()
        sys.exit(1)

    rules = load_rules(rules_path)

    with open(HUMAN_LOG, "a") as human_fh, open(VERDICT_LOG, "a") as verdict_fh:
        def out(line: str) -> None:
            emit(human_fh, line)

        out("")
        out(col("BLEEP  AUTONOMOUS CLASSIFIER", BOLD, CYAN))
        out(col("━" * 60, CYAN))
        out(
            f"  {col(str(len(rules)), GREEN)} rules  ·  "
            f"classifier={col(args.model, MAGENTA)}  ·  "
            f"min_severity={col(args.min_severity, YELLOW)}  ·  "
            f"keywords={'off' if args.no_keywords else 'on'}"
        )
        out(f"  watching {col(str(jsonl_path), CYAN)}")
        out(f"  pid={os.getpid()}  ·  verdicts → {VERDICT_LOG}")
        out(col("  send SIGTERM or run --stop to exit cleanly", DIM))
        out("")

        mode = "replay+tail" if args.replay else "tail"

        def process_stream(source):
            for entry in source:
                try:
                    state["scanned"] += 1
                    caught = entry.get("redactions", 0)

                    body_text = body_to_text(entry.get("body"))
                    if not body_text:
                        continue
                    state["with_body"] += 1

                    body_bytes = body_text.encode("utf-8")
                    matches = scan(body_bytes, rules, use_kw=not args.no_keywords)
                    matches = [m for m in matches if SEV_ORDER.get(m["severity"], 0) >= min_sev_ord]

                    if len(matches) <= caught:
                        print(col(".", DIM), end="", flush=True)
                        continue

                    etype = entry.get("type", "?")
                    ts    = entry.get("ts", "")[:19]
                    url   = entry.get("uri", entry.get("status", "?"))
                    label = (
                        f"{entry.get('method','?')} {truncate(str(url), 52)}"
                        if etype == "request"
                        else f"RESPONSE {url}"
                    )

                    out("")
                    out(col("  " + "─" * 58, DIM))
                    out(
                        f"  {col('MISS', RED, BOLD)}  {col(label, BOLD)}  "
                        f"{col(ts, DIM)}  "
                        f"[caught={caught} found={len(matches)}]"
                    )
                    out(col(f"  classifying {len(matches)} match(es) via {args.model}...", DIM))

                    for m in matches:
                        ctx = context_around(body_text, m["start"], m["end"])
                        verdict, reason = classify_miss(m, str(url), ctx, args.model)

                        if verdict == "TRUE_MISS":
                            state["true_miss"] += 1
                        elif verdict == "FALSE_POSITIVE":
                            state["false_pos"] += 1
                        else:
                            state["ambiguous"] += 1

                        out(f"    {verdict_col(verdict):<30}  rule={col(m['rule_id'], BOLD)}")
                        out(f"      matched : {col(truncate(repr(m['text']), 70), RED)}")
                        out(f"      reason  : {reason}")
                        out("")

                        emit_verdict(
                            verdict_fh,
                            {
                                "ts":       datetime.now(timezone.utc).isoformat(),
                                "verdict":  verdict,
                                "reason":   reason,
                                "rule_id":  m["rule_id"],
                                "severity": m["severity"],
                                "matched":  m["text"][:120],
                                "url":      str(url),
                            },
                        )

                    # persist state after every miss entry
                    save_state(state)

                except Exception as e:
                    # never crash on a bad entry
                    out(col(f"  [warn] skipped entry: {e}", YELLOW))
                    continue

        if args.replay:
            out(col("  [replay] scanning existing log...", DIM))
            process_stream(iter_entries_from_file(jsonl_path))
            out(col("  [replay] done — switching to tail mode", DIM))

        process_stream(tail_follow(jsonl_path))


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    ap = argparse.ArgumentParser(description="Autonomous bleep-gateway eval classifier")
    ap.add_argument("jsonl", nargs="?", default="/tmp/bleep-requests.jsonl")
    ap.add_argument("--rules", default=str(project_root / "rules" / "combined.yaml"))
    ap.add_argument("--no-keywords", action="store_true")
    ap.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="medium")
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    ap.add_argument("--replay", action="store_true", help="scan existing log first, then tail")
    ap.add_argument("--stop",   action="store_true", help="stop a running classifier daemon")
    ap.add_argument("--status", action="store_true", help="show running state and lifetime counters")
    args = ap.parse_args()

    if args.stop:
        cmd_stop()
        return
    if args.status:
        cmd_status()
        return

    run(args)


if __name__ == "__main__":
    main()
