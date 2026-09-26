#!/usr/bin/env python3
"""NetSentry agent - a local Ollama model reviews inventory + logs and writes recommendations.

The model only gets READ-ONLY tools (SQLite queries and named Loki queries).
It cannot run commands, change configuration, or touch devices.

  python agent.py --mode full   # after a scan: inventory diff + vulns + logs
  python agent.py --mode logs   # logs only (run hourly)
"""
import argparse
import collections
import datetime as dt
import json
import os
import re
import sqlite3
import time

import requests
import yaml

CFG = yaml.safe_load(open(os.environ.get("NETSENTRY_CONFIG", "/config/config.yaml")))
O = CFG["ollama"]
LOKI = CFG.get("loki") or {}
MAX_CHARS = CFG.get("max_tool_chars", 4000)
SEV_RANK = {"ok": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def log(msg):
    print(f"[agent] {msg}", flush=True)


def clip(obj):
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str, separators=(",", ":"))
    return s if len(s) <= MAX_CHARS else s[:MAX_CHARS] + f"...[truncated {len(s) - MAX_CHARS} chars]"


def iso(ts):
    return dt.datetime.fromtimestamp(ts).isoformat(timespec="minutes") if ts else None


def db():
    c = sqlite3.connect(CFG["db"])
    c.row_factory = sqlite3.Row
    return c


def rows(cur):
    return [dict(r) for r in cur]


def scan_times(c):
    ts = [r[0] for r in c.execute("SELECT ts FROM scans ORDER BY ts DESC LIMIT 2")]
    return (ts + [None, None])[:2]


# ---------------------------------------------------------------- read-only tools
def get_changes():
    c = db()
    cur, prev = scan_times(c)
    if cur is None:
        return {"error": "no scans yet - run scanner.py first"}
    out = {"scan_time": iso(cur), "previous_scan": iso(prev)}
    if prev is None:
        out["note"] = "First scan - this is the baseline, so nothing is 'new'. Review exposure instead."
        out["hosts_up"] = c.execute("SELECT count(*) FROM hosts WHERE last_seen=?", (cur,)).fetchone()[0]
        out["open_ports"] = c.execute("SELECT count(*) FROM ports WHERE last_seen=?", (cur,)).fetchone()[0]
        return out
    out["new_hosts"] = rows(c.execute(
        "SELECT id, ip, hostname, vendor, network, wired, source FROM hosts WHERE first_seen=?", (cur,)))
    out["hosts_missing_since_last_scan"] = rows(c.execute(
        "SELECT ip, hostname, vendor, wired FROM hosts WHERE last_seen=? LIMIT 30", (prev,)))
    out["new_open_ports"] = rows(c.execute(
        "SELECT ip, port, proto, service, product, version FROM ports WHERE first_seen=?", (cur,)))
    out["ports_closed_since_last_scan"] = rows(c.execute(
        "SELECT ip, port, proto, service FROM ports WHERE last_seen=?", (prev,)))
    out["new_cves"] = rows(c.execute(
        """SELECT ip, port, vuln_id, cvss, exploit FROM vulns
           WHERE first_seen=? AND vtype='cve' ORDER BY cvss DESC LIMIT 40""", (cur,)))
    return out


def get_vulnerabilities(min_cvss=7.0, exploit_only=False):
    c = db()
    cur, _ = scan_times(c)
    q = """SELECT v.ip,
                  (SELECT hostname FROM hosts h WHERE h.ip=v.ip ORDER BY last_seen DESC LIMIT 1) AS hostname,
                  v.port, p.service, p.product, p.version, v.vuln_id, v.cvss, v.exploit
           FROM vulns v LEFT JOIN ports p ON p.ip=v.ip AND p.port=v.port AND p.proto='tcp'
           WHERE v.last_seen=? AND v.vtype='cve' AND v.cvss>=?"""
    if exploit_only:
        q += " AND v.exploit=1"
    return rows(c.execute(q + " ORDER BY v.cvss DESC LIMIT 60", (cur, float(min_cvss))))


def get_host(ip):
    c = db()
    cur, _ = scan_times(c)
    return {
        "host": rows(c.execute("SELECT * FROM hosts WHERE ip=? ORDER BY last_seen DESC", (ip,))),
        "open_ports": rows(c.execute(
            "SELECT port, proto, service, product, version, first_seen FROM ports WHERE ip=? AND last_seen=?",
            (ip, cur))),
        "cves": rows(c.execute(
            """SELECT port, vuln_id, cvss, exploit FROM vulns
               WHERE ip=? AND last_seen=? AND vtype='cve' AND cvss>=4 ORDER BY cvss DESC LIMIT 30""",
            (ip, cur))),
    }


def list_inventory():
    c = db()
    cur, _ = scan_times(c)
    return rows(c.execute(
        """SELECT h.ip, h.hostname, h.vendor, h.network, h.wired,
                  (SELECT count(*) FROM ports p WHERE p.ip=h.ip AND p.last_seen=?) AS open_ports
           FROM hosts h WHERE h.last_seen=? ORDER BY h.ip""", (cur, cur)))


def run_log_query(name):
    q = (LOKI.get("queries") or {}).get(name)
    if not q:
        return {"error": f"unknown or unconfigured log query '{name}'"}
    now = time.time_ns()
    try:
        if q.get("type", "instant") == "instant":
            r = requests.get(f"{LOKI['url']}/loki/api/v1/query",
                             params={"query": q["logql"], "time": now}, timeout=60)
        else:
            start = now - int(q.get("hours", 24) * 3600 * 1e9)
            r = requests.get(f"{LOKI['url']}/loki/api/v1/query_range",
                             params={"query": q["logql"], "start": start, "end": now,
                                     "limit": q.get("limit", 200), "direction": "backward"}, timeout=60)
        r.raise_for_status()
        data = r.json()["data"]
    except Exception as e:
        return {"error": f"loki query failed: {e}"}

    kind, res = data["resultType"], data["result"]
    if kind == "vector":
        return {"query": name, "results": [{**s["metric"], "value": s["value"][1]} for s in res]}
    if kind == "matrix":
        return {"query": name, "results": [{**s["metric"], "latest": s["values"][-1][1]} for s in res if s["values"]]}
    # streams: collapse duplicate lines (numbers normalised) so repeats don't eat context
    counts = collections.Counter()
    example = {}
    for s in res:
        for _, line in s["values"]:
            key = re.sub(r"\d+", "N", line)[:300]
            counts[key] += 1
            example.setdefault(key, line[:400])
    return {"query": name, "total_lines": sum(counts.values()),
            "patterns": [{"count": n, "example": example[k]} for k, n in counts.most_common(30)]}


DISPATCH = {
    "get_changes": get_changes,
    "get_vulnerabilities": get_vulnerabilities,
    "get_host": get_host,
    "list_inventory": list_inventory,
    "run_log_query": run_log_query,
}


def fn(name, desc, props=None, required=None):
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
        "type": "object", "properties": props or {}, "required": required or []}}}


TOOLS = [
    fn("get_changes", "Differences between the latest and previous network scan."),
    fn("get_vulnerabilities", "CVE matches from the latest scan.",
       {"min_cvss": {"type": "number", "description": "Minimum CVSS, default 7"},
        "exploit_only": {"type": "boolean", "description": "Only CVEs with a known public exploit"}}),
    fn("get_host", "Details, open ports and CVEs for one IP.",
       {"ip": {"type": "string"}}, ["ip"]),
    fn("list_inventory", "All hosts seen in the latest scan with open-port counts."),
    fn("run_log_query", "Run a predefined log query against Loki.",
       {"name": {"type": "string", "enum": list((LOKI.get("queries") or {}).keys()) or ["none"]}}, ["name"]),
]

SYSTEM = """You are a defensive security analyst for a private home network. You review scan \
inventory and log summaries and write recommendations for the owner, who decides and acts. \
You cannot change anything and must never claim to have changed anything.

Rules:
- Base every finding on the provided context or tool results. Cite host/IP, port, CVE ID or log evidence.
- Never invent CVE IDs, versions, hosts or log lines. If data is missing or ambiguous, say so.
- nmap/vulners CVE matches are version-string matches and often false positives (backported \
patches, wrong version detection). Call them "possible" unless corroborated, and say how to verify.
- Priority: internet-exposed services > CVEs with public exploits > new unknown devices or new \
open ports > log anomalies > everything else.
- Be brief. If nothing needs attention, say so plainly.

Output Markdown in exactly this shape:
SEVERITY: <ok|low|medium|high|critical>
## Summary
2-4 sentences.
## Findings
One block per finding: **title** - evidence - recommended action - how to verify.
## Watch list
Minor items, one line each.

Network context from the owner:
"""


def chat(messages, use_tools=True):
    body = {"model": O["model"], "messages": messages, "stream": False, "think": O.get("think", False),
            "options": {"num_ctx": O.get("num_ctx", 16384), "temperature": 0.2}}
    if use_tools:
        body["tools"] = TOOLS
    r = requests.post(f"{O['url']}/api/chat", json=body, timeout=O.get("timeout_s", 900))
    r.raise_for_status()
    return r.json()["message"]


def run(mode):
    parts = []
    if mode == "full":
        parts.append("## Inventory changes since last scan\n" + clip(get_changes()))
        parts.append("## CVE matches with CVSS >= 7\n" + clip(get_vulnerabilities(7.0)))
    for name in LOKI.get("auto_queries", []):
        parts.append(f"## Log query: {name}\n" + clip(run_log_query(name)))

    messages = [
        {"role": "system", "content": SYSTEM + CFG.get("network_context", "(none provided)")},
        {"role": "user", "content": "\n\n".join(parts) +
         "\n\nUse the tools to look closer at anything that warrants it, then write the report."},
    ]
    for _ in range(CFG.get("max_rounds", 6)):
        msg = chat(messages)
        messages.append(msg)
        calls = msg.get("tool_calls") or []
        if not calls:
            break
        for call in calls:
            name = call["function"]["name"]
            args = call["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            log(f"tool call: {name}({args})")
            try:
                result = DISPATCH[name](**args) if name in DISPATCH else {"error": f"no tool {name}"}
            except Exception as e:
                result = {"error": str(e)}
            messages.append({"role": "tool", "tool_name": name, "content": clip(result)})
    else:
        messages.append({"role": "user", "content": "Stop using tools and write the final report now."})
        msg = chat(messages, use_tools=False)

    report = re.sub(r"<think>.*?</think>", "", msg.get("content") or "", flags=re.S).strip()
    m = re.search(r"SEVERITY:\s*(ok|low|medium|high|critical)", report, re.I)
    severity = m.group(1).lower() if m else "medium"   # unparseable -> make a human look
    return report, severity


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["full", "logs"], default="full")
    mode = ap.parse_args().mode

    report, severity = run(mode)
    os.makedirs(CFG["reports_dir"], exist_ok=True)
    path = os.path.join(CFG["reports_dir"], f"netsentry-{dt.datetime.now():%Y%m%d-%H%M}-{mode}.md")
    with open(path, "w") as f:
        f.write(report + "\n")
    log(f"severity={severity} report={path}")

    n = CFG.get("notify") or {}
    if n.get("webhook") and SEV_RANK[severity] >= SEV_RANK[n.get("min_severity", "low")]:
        try:
            requests.post(n["webhook"], json={
                "source": "netsentry", "mode": mode, "severity": severity,
                "title": f"NetSentry ({mode}): {severity.upper()}",
                "summary": report[:1500], "report_file": path}, timeout=15)
        except Exception as e:
            log(f"webhook failed: {e}")


if __name__ == "__main__":
    main()
