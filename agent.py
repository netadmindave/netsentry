#!/usr/bin/env python3
"""NetSentry agent - a local Ollama model reviews inventory + logs and writes recommendations.

The model only gets READ-ONLY tools (SQLite queries and named Loki queries).
It cannot run commands, change configuration, or touch devices.

The report has two parts: the model's findings, and an appendix generated directly from
the scan data (device map, services, CVE summary) so the tables are never AI-written.

  python agent.py --mode full   # after a scan: inventory, vulns, logs, appendix
  python agent.py --mode logs   # logs only (run hourly)
"""
import argparse
import collections
import datetime as dt
import ipaddress
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
MAX_CHARS = CFG.get("max_tool_chars", 6000)
SEV_RANK = {"ok": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_NOTES = {k.upper(): v for k, v in (CFG.get("cve_notes") or {}).items()}
SUPPRESS = {c.upper() for c in (CFG.get("suppress_cves") or [])}
# nmap often cannot fingerprint these precisely, so version-matched CVEs are unreliable.
LOW_CONFIDENCE_PRODUCTS = {"Samba smbd"}


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


def ip_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, str(ip))


# ---------------------------------------------------------------- reference data
_KEV = None


def kev():
    """CISA Known Exploited Vulnerabilities, cached next to the database and refreshed daily."""
    global _KEV
    if _KEV is not None:
        return _KEV
    k = CFG.get("kev") or {}
    _KEV = {}
    if k.get("enabled", True) is False:
        return _KEV
    path = os.path.join(os.path.dirname(CFG["db"]) or ".", "kev.json")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < k.get("max_age_h", 24) * 3600
    if not fresh:
        try:
            r = requests.get(k.get("url", KEV_URL), timeout=60)
            r.raise_for_status()
            r.json()                                  # validate before replacing the cache
            with open(path + ".tmp", "w") as f:
                f.write(r.text)
            os.replace(path + ".tmp", path)
        except Exception as e:
            log(f"KEV download failed ({e}); using cached copy if present")
    try:
        with open(path) as f:
            data = json.load(f)
        _KEV = {v["cveID"].upper(): {"added": v.get("dateAdded"),
                                     "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
                for v in data.get("vulnerabilities", [])}
    except Exception:
        log("no KEV data available; known-exploited checks disabled for this run")
    return _KEV


def known_device(ip, mac):
    for d in CFG.get("known_devices") or []:
        m = {str(x).lower() for x in d.get("match", [])}
        if (ip and ip.lower() in m) or (mac and mac.lower() in m):
            return d
    return None


def exposures(ip, port=None):
    return [e for e in CFG.get("internet_exposed") or []
            if e.get("ip") == ip and (port is None or e.get("port") in (None, port))]


def host_index(c, ts):
    """ip -> best host row for that IP in the given scan (UniFi-identified rows win)."""
    idx = {}
    for h in rows(c.execute("SELECT * FROM hosts WHERE last_seen=? "
                            "ORDER BY (unifi_name IS NULL), (mac IS NULL)", (ts,))):
        idx.setdefault(h["ip"], h)
    return idx


def label(h, ip=None):
    ip = ip or (h or {}).get("ip")
    k = known_device(ip, (h or {}).get("mac"))
    if k:
        return k["name"]
    if h:
        return h.get("unifi_name") or h.get("hostname") or h.get("vendor") or "unidentified"
    return "unidentified"


def version_confidence(product, version):
    if not version or "X" in version or re.fullmatch(r"\d+", version) or product in LOW_CONFIDENCE_PRODUCTS:
        return "low"
    return "normal"


def services(c, ts):
    """One entry per open port with its CVE matches grouped and ranked."""
    hosts = host_index(c, ts)
    by_port = collections.defaultdict(list)
    for ip, port, vid, cvss, ex in c.execute(
            "SELECT ip, port, vuln_id, cvss, exploit FROM vulns WHERE last_seen=? AND vtype='cve'", (ts,)):
        if vid.upper() not in SUPPRESS:
            by_port[(ip, port)].append((vid.upper(), cvss or 0.0, bool(ex)))
    K = kev()
    out = []
    for p in rows(c.execute("SELECT ip, port, proto, service, product, version FROM ports WHERE last_seen=?",
                            (ts,))):
        vs = by_port.get((p["ip"], p["port"]), [])
        ranked = sorted(vs, key=lambda v: (v[0] in K, v[2], v[1]), reverse=True)
        out.append({
            "host": label(hosts.get(p["ip"]), p["ip"]), "ip": p["ip"], "port": p["port"],
            "service": p["service"], "product": p["product"], "version": p["version"],
            "version_confidence": version_confidence(p["product"], p["version"]),
            "cve_count": len(vs),
            "max_cvss": max((v[1] for v in vs), default=0.0),
            "exploit_count": sum(v[2] for v in vs),
            "kev": [v[0] for v in ranked if v[0] in K],
            "top_cves": [{"id": v[0], "cvss": v[1], "exploit": v[2],
                          **({"note": CVE_NOTES[v[0]]} if v[0] in CVE_NOTES else {})} for v in ranked[:3]],
            "internet_exposed": [e.get("via", "yes") for e in exposures(p["ip"], p["port"])],
        })
    return out


def critical_allowed(svcs):
    """Critical is reserved for a known-exploited CVE on an internet-exposed service."""
    return any(s["kev"] and s["internet_exposed"] for s in svcs)


# ---------------------------------------------------------------- read-only tools
def get_changes():
    c = db()
    cur, prev = scan_times(c)
    if cur is None:
        return {"error": "no scans yet - run scanner.py first"}
    out = {"scan_time": iso(cur), "previous_scan": iso(prev)}
    if prev is None:
        out["note"] = "First scan - baseline, so nothing is 'new'. Review exposure instead."
        return out
    prev_row = c.execute("SELECT * FROM scans WHERE ts=?", (prev,)).fetchone()
    if prev_row is not None and "duration_s" in prev_row.keys() and prev_row["duration_s"] is None:
        out["note"] = ("The previous scan came from an older NetSentry version that scanned fewer ports and "
                       "did not list UniFi devices. New ports and UniFi devices in this diff are mostly "
                       "coverage changes, not new activity; judge them on their own merits.")
    hosts = host_index(c, cur)
    out["new_hosts"] = [{"ip": h["ip"], "name": label(h), "vendor": h["vendor"], "network": h["network"],
                         "conn": h["conn"], "uplink": h["uplink"]}
                        for h in rows(c.execute("SELECT * FROM hosts WHERE first_seen=?", (cur,)))]
    out["hosts_missing_since_last_scan"] = [
        {"ip": h["ip"], "name": label(h), "conn": h["conn"]}
        for h in rows(c.execute("SELECT * FROM hosts WHERE last_seen=? LIMIT 30", (prev,)))]
    out["new_open_ports"] = [{**p, "host": label(hosts.get(p["ip"]), p["ip"])} for p in rows(c.execute(
        "SELECT ip, port, service, product, version FROM ports WHERE first_seen=?", (cur,)))]
    out["ports_closed_since_last_scan"] = rows(c.execute(
        "SELECT ip, port, service FROM ports WHERE last_seen=?", (prev,)))
    K = kev()
    out["new_cves"] = [{**v, "kev": v["vuln_id"].upper() in K} for v in rows(c.execute(
        "SELECT ip, port, vuln_id, cvss, exploit FROM vulns WHERE first_seen=? AND vtype='cve' "
        "ORDER BY cvss DESC LIMIT 40", (cur,))) if v["vuln_id"].upper() not in SUPPRESS]
    return out


def get_vulnerabilities(min_cvss=7.0, kev_only=False):
    c = db()
    cur, _ = scan_times(c)
    svcs = [s for s in services(c, cur) if s["cve_count"] and (s["kev"] or s["max_cvss"] >= float(min_cvss))]
    if kev_only:
        svcs = [s for s in svcs if s["kev"]]
    svcs.sort(key=lambda s: (bool(s["kev"]), bool(s["internet_exposed"]), s["version_confidence"] == "normal",
                             s["exploit_count"] > 0, s["max_cvss"]), reverse=True)
    return svcs[:40]


def get_host(ip):
    c = db()
    cur, _ = scan_times(c)
    h = host_index(c, cur).get(ip)
    k = known_device(ip, (h or {}).get("mac"))
    return {"host": h, "known_as": k, "internet_exposed": exposures(ip),
            "services": [s for s in services(c, cur) if s["ip"] == ip]}


def list_inventory():
    c = db()
    cur, _ = scan_times(c)
    counts = collections.Counter(r[0] for r in c.execute("SELECT ip FROM ports WHERE last_seen=?", (cur,)))
    out = [{"ip": ip, "name": label(h), "vendor": h["vendor"], "network": h["network"], "conn": h["conn"],
            "uplink": h["uplink"], "open_ports": counts.get(ip, 0)}
           for ip, h in host_index(c, cur).items()]
    return sorted(out, key=lambda r: ip_key(r["ip"]))


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
    fn("get_vulnerabilities", "Services with CVE matches, grouped per host and port, ranked "
                              "(known-exploited and internet-exposed first).",
       {"min_cvss": {"type": "number", "description": "Minimum CVSS, default 7"},
        "kev_only": {"type": "boolean", "description": "Only services with CISA known-exploited CVEs"}}),
    fn("get_host", "Identity, connection, exposure and services for one IP.",
       {"ip": {"type": "string"}}, ["ip"]),
    fn("list_inventory", "All hosts in the latest scan with names, connection and open-port counts."),
    fn("run_log_query", "Run a predefined log query against Loki.",
       {"name": {"type": "string", "enum": list((LOKI.get("queries") or {}).keys()) or ["none"]}}, ["name"]),
]

SYSTEM = """You are a defensive security analyst for a private home network. You review scan \
inventory and log summaries and write recommendations for the owner, who decides and acts. \
You cannot change anything and must never claim to have changed anything.

Evidence rules:
- Base every finding on the provided context or tool results. Never invent CVE IDs, versions, hosts or log lines.
- Name each finding's host by its name AND IP, with port and detected product/version.
- CVE matches are version-string matches. When version_confidence is "low" (e.g. nmap reports \
Samba as "3.X - 4.X"), the CVEs are unreliable: recommend confirming the real version, not patching \
for specific CVEs.
- Respect CVE notes (e.g. client-side-only or configuration-specific CVEs do not threaten a server).
- Known devices and their expected services are listed; do not report expected behaviour as a finding.
- Accepted risks are the owner's decisions; do not report them as findings.

Severity rules (overall SEVERITY is the highest finding):
- critical: a CISA known-exploited (KEV) CVE on an internet-exposed service. Nothing else.
- high: a KEV CVE on a LAN service; or an internet-exposed admin interface (container manager, \
hypervisor, router, download client); or a new unidentified device offering admin services.
- medium: exploit-available CVEs on normal-confidence versions; unpatched or end-of-life software; \
unauthenticated services reachable from IoT networks.
- low: hygiene items. ok: nothing needs attention.

Priority: internet exposure > known-exploited > new unknown devices or new open ports > log anomalies > hygiene.
At most 8 findings, one per host+issue. Be concise.

Output Markdown in exactly this shape:
SEVERITY: <ok|low|medium|high|critical>
## Summary
2-4 sentences.
## Findings
One block per finding: **title (host name, IP)** - evidence - recommended action - how to verify.
## Watch list
Minor items, one line each.
"""


def owner_context():
    parts = ["Network context from the owner:\n" + (CFG.get("network_context") or "(none provided)").strip()]
    kd = CFG.get("known_devices") or []
    if kd:
        parts.append("Known devices:\n" + "\n".join(
            f"- {d['name']} ({', '.join(map(str, d.get('match', [])))}): {d.get('note', '')}" for d in kd))
    ar = CFG.get("accepted_risks") or []
    if ar:
        parts.append("Accepted risks:\n" + "\n".join(f"- {r}" for r in ar))
    ie = CFG.get("internet_exposed") or []
    if ie:
        parts.append("Internet-exposed services:\n" + "\n".join(
            f"- {e.get('ip')}:{e.get('port', 'any')} {e.get('name', '')} via {e.get('via', '?')}" for e in ie))
    return "\n\n".join(parts)


def chat(messages, use_tools=True):
    body = {"model": O["model"], "messages": messages, "stream": False, "think": O.get("think", False),
            "options": {"num_ctx": O.get("num_ctx", 16384), "temperature": 0.2}}
    if use_tools:
        body["tools"] = TOOLS
    r = requests.post(f"{O['url']}/api/chat", json=body, timeout=O.get("timeout_s", 900))
    r.raise_for_status()
    return r.json()["message"]


# ---------------------------------------------------------------- deterministic appendix
def md(v):
    return "" if v is None else str(v).replace("|", "/").replace("\n", " ")


def appendix():
    c = db()
    cur, prev = scan_times(c)
    if cur is None:
        return ""
    scan = dict(c.execute("SELECT * FROM scans WHERE ts=?", (cur,)).fetchone())
    hosts = host_index(c, cur)
    svcs = services(c, cur)
    per_ip = collections.defaultdict(list)
    for s in svcs:
        per_ip[s["ip"]].append(s)
    K = kev()
    L = ["", "---", "", "## Appendix: scan data", "",
         "_Generated directly from the scan database, not written by the AI._", ""]

    dur = scan.get("duration_s")
    L.append(f"- Scan started {iso(cur)}" + (f", took {dur // 60} min {dur % 60} s" if dur else "")
             + (f"; previous scan {iso(prev)}" if prev else "; first scan (baseline)"))
    L.append(f"- Hosts up: {scan.get('hosts_up')}; UniFi active clients: {scan.get('unifi_clients')}; "
             f"open ports: {len(svcs)}; services with CVE matches: {sum(1 for s in svcs if s['cve_count'])}")
    L.append(f"- CISA KEV catalogue: {len(K)} entries loaded; services with a KEV match: "
             f"{sum(1 for s in svcs if s['kev'])}")
    selfs = sorted(ip for ip, h in hosts.items() if h.get("is_self"))
    if selfs:
        L.append(f"- Scanner host ({', '.join(selfs)}) was re-scanned with a TCP connect scan")
    L.append("")

    L += ["### Devices", "",
          "| IP | Name | UniFi name | Vendor | MAC | Network | Connection | Open ports |",
          "|---|---|---|---|---|---|---|---|"]
    for ip in sorted(hosts, key=ip_key):
        h = hosts[ip]
        k = known_device(ip, h.get("mac"))
        if h.get("conn") == "wifi":
            conn = f"Wi-Fi: {h.get('uplink') or '?'}" + (f", SSID {h['essid']}" if h.get("essid") else "") \
                   + (f", {h['signal']} dBm" if h.get("signal") is not None else "")
        elif h.get("conn") == "wired":
            conn = f"Wired: {h.get('uplink') or '?'}"
        elif h.get("conn") == "infrastructure":
            conn = f"UniFi device ({h.get('uplink') or '?'})"
        else:
            conn = "not in UniFi client list"
        ports = ", ".join(str(s["port"]) for s in sorted(per_ip.get(ip, []), key=lambda s: s["port"])) or "none"
        L.append(f"| {ip} | {md(k['name'] if k else '')} | {md(h.get('unifi_name') or h.get('hostname'))} | "
                 f"{md(h.get('vendor'))} | {md(h.get('mac'))} | {md(h.get('network'))} | {md(conn)} | {ports} |")
    L.append("")

    L += ["### Services", "",
          "| Host | IP:port | Service | Product / version | Version confidence | CVEs | Max CVSS | "
          "With exploit | KEV | Internet-exposed |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(svcs, key=lambda s: (ip_key(s["ip"]), s["port"])):
        pv = " ".join(x for x in (s["product"], s["version"]) if x)
        L.append(f"| {md(s['host'])} | {s['ip']}:{s['port']} | {md(s['service'])} | {md(pv)} | "
                 f"{s['version_confidence'] if s['cve_count'] else ''} | {s['cve_count'] or ''} | {s['max_cvss'] or ''} | "
                 f"{s['exploit_count'] or ''} | {', '.join(s['kev'])} | {md(', '.join(s['internet_exposed']))} |")
    L.append("")

    noted = sorted({t["id"] for s in svcs for t in s["top_cves"] if "note" in t})
    if noted or SUPPRESS:
        L += ["### CVE notes applied", ""]
        L += [f"- {cid}: {CVE_NOTES[cid]}" for cid in noted]
        if SUPPRESS:
            L.append(f"- Suppressed from all results: {', '.join(sorted(SUPPRESS))}")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- run
def run(mode):
    parts = []
    svcs = []
    if mode == "full":
        c = db()
        cur, _ = scan_times(c)
        svcs = services(c, cur) if cur else []
        parts.append("## Inventory changes since last scan\n" + clip(get_changes()))
        exposed = [s for s in svcs if s["internet_exposed"]]
        parts.append("## Internet-exposed services found in the scan\n" + clip(
            [{k: s[k] for k in ("host", "ip", "port", "product", "version", "kev", "max_cvss",
                                "internet_exposed")} for s in exposed] or "none configured or found"))
        parts.append("## Services with notable CVE matches (grouped, ranked)\n" + clip(get_vulnerabilities(7.0)))
    for name in LOKI.get("auto_queries", []):
        parts.append(f"## Log query: {name}\n" + clip(run_log_query(name)))

    messages = [
        {"role": "system", "content": SYSTEM + "\n" + owner_context()},
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
    if severity == "critical" and mode == "full" and not critical_allowed(svcs):
        severity = "high"
        report = re.sub(r"SEVERITY:\s*critical", "SEVERITY: high", report, count=1, flags=re.I)
        report = report.replace("## Summary", "_(Severity capped at high: no known-exploited CVE on an "
                                              "internet-exposed service.)_\n\n## Summary", 1)
    if mode == "full":
        report += "\n" + appendix()
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
            summary = report.split("\n---\n")[0][:1500]      # AI part only, not the appendix
            requests.post(n["webhook"], json={
                "source": "netsentry", "mode": mode, "severity": severity,
                "title": f"NetSentry ({mode}): {severity.upper()}",
                "summary": summary, "report_file": path}, timeout=15)
        except Exception as e:
            log(f"webhook failed: {e}")


if __name__ == "__main__":
    main()
