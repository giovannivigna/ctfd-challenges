#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path


VULN_APP_PATH = Path("/home/challenge/ro/vuln_app.py")
RULE_PATH = Path("/home/challenge/rw/rule.yml")

# Stable line numbers in ro/vuln_app.py
EXPECTED = {
    "seminterp.sqli": 541,
    "seminterp.cmdi": 490,
    "seminterp.pickle": 509,
}

MAX_RULE_BYTES = 128 * 1024
SEMGREP_TIMEOUT_S = 8


def _w(s: str) -> None:
    sys.stdout.write(s)
    sys.stdout.flush()


def _read_rule_until_eof_marker() -> str:
    _w("Paste your Semgrep YAML now. End with a line containing only EOF.\n\n")
    buf: list[str] = []
    total = 0
    while True:
        line = sys.stdin.readline()
        if line == "":
            break
        if line.strip() == "EOF":
            break
        total += len(line.encode("utf-8", errors="ignore"))
        if total > MAX_RULE_BYTES:
            raise ValueError("rule too large")
        buf.append(line)
    return "".join(buf)


def _run_semgrep(rule_text: str) -> dict:
    RULE_PATH.write_text(rule_text, encoding="utf-8")

    env = dict(os.environ)
    env["SEMGREP_SEND_METRICS"] = "off"
    # Semgrep writes per-user state under $HOME/.semgrep by default.
    # /home/challenge is intentionally not writable, so point HOME to rw.
    env["HOME"] = "/home/challenge/rw"

    cmd = [
        "semgrep",
        "--config",
        str(RULE_PATH),
        "--json",
        "--disable-version-check",
        str(VULN_APP_PATH),
    ]
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=SEMGREP_TIMEOUT_S,
    )
    if p.returncode not in (0, 1):
        raise RuntimeError((p.stderr or p.stdout or "semgrep failed").strip())
    try:
        return json.loads(p.stdout or "{}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"failed to parse semgrep json output: {e}") from e


def _check_results(data: dict) -> tuple[bool, str]:
    results = data.get("results", []) or []
    seen: dict[str, set[int]] = {}
    for r in results:
        check_id = r.get("check_id")
        if not isinstance(check_id, str):
            continue
        normalized: str | None = None
        for rid in EXPECTED:
            if check_id == rid or check_id.endswith("." + rid):
                normalized = rid
                break
        start = (r.get("start") or {}).get("line")
        if isinstance(start, int):
            seen.setdefault(normalized or check_id, set()).add(start)

    missing: list[str] = []
    wrong_line: list[str] = []
    for rule_id, expected_line in EXPECTED.items():
        if rule_id not in seen:
            missing.append(rule_id)
            continue
        if expected_line not in seen[rule_id]:
            wrong_line.append(f"{rule_id} (expected line {expected_line}, got {sorted(seen[rule_id])})")

    if missing or wrong_line:
        parts: list[str] = []
        if missing:
            parts.append("Missing findings for: " + ", ".join(missing))
        if wrong_line:
            parts.append("Findings on unexpected lines for: " + "; ".join(wrong_line))
        return False, "\n".join(parts)
    return True, ""


def main() -> int:
    _w("== seminterp ==\n")
    _w("You are given a Python file. Submit a Semgrep config that finds ALL 3 vulnerabilities.\n\n")
    _w("Rules must include these IDs (exactly):\n")
    for rid in EXPECTED:
        _w(f"- {rid}\n")
    _w("\n--- vuln_app.py ---\n")
    _w(VULN_APP_PATH.read_text(encoding="utf-8"))
    _w("\n--- end ---\n\n")

    try:
        rule_text = _read_rule_until_eof_marker()
        data = _run_semgrep(rule_text)
        ok, reason = _check_results(data)
        if not ok:
            _w("\nNo flag for you.\n")
            _w(reason + "\n")
            _w("\nTip: match the exact vulnerable constructs and ensure each rule triggers on the intended line.\n")
            return 0

        flag = Path("/flag").read_text(encoding="utf-8").strip()
        _w("\nAll 3 findings detected.\n")
        _w(flag + "\n")
        return 0
    except subprocess.TimeoutExpired:
        _w("\nSemgrep timed out.\n")
        return 0
    except Exception as e:
        _w("\nError: " + str(e) + "\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
