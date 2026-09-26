#!/usr/bin/env python3
"""NetSentry scanner - builds a device / service / vulnerability inventory in SQLite.

Deterministic and read-only against the network: pulls the active client list from
the UDM Pro and runs nmap (service detection + vulners CVE matching).
No LLM is involved here; agent.py reads what this writes.
"""
import os
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CFG = yaml.safe_load(open(os.environ.get("NETSENTRY_CONFIG", "/config/config.yaml")))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,            -- MAC when known, else 'ip:<addr>'
  mac TEXT, ip TEXT, hostname TEXT, vendor TEXT, network TEXT, wired INTEGER,
  source TEXT, first_seen INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS ports (
  ip TEXT, port INTEGER, proto TEXT, service TEXT, product TEXT, version TEXT,
  first_seen INTEGER, last_seen INTEGER, PRIMARY KEY (ip, port, proto));
CREATE TABLE IF NOT EXISTS vulns (
  ip TEXT, port INTEGER, vuln_id TEXT, vtype TEXT, cvss REAL, exploit INTEGER,
  first_seen INTEGER, last_seen INTEGER, PRIMARY KEY (ip, port, vuln_id));
"""


def log(msg):
    print(f"[scanner] {msg}", flush=True)


def upsert_host(db, hid, mac, ip, hostname, vendor, network, wired, source, ts):
    db.execute(
        """INSERT INTO hosts (id, mac, ip, hostname, vendor, network, wired, source, first_seen, last_seen)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET
             ip       = COALESCE(excluded.ip, hosts.ip),
             mac      = COALESCE(excluded.mac, hosts.mac),
             hostname = COALESCE(excluded.hostname, hosts.hostname),
             vendor   = COALESCE(excluded.vendor, hosts.vendor),
             network  = COALESCE(excluded.network, hosts.network),
             wired    = COALESCE(excluded.wired, hosts.wired),
             source   = CASE WHEN instr(hosts.source, excluded.source) > 0 THEN hosts.source
                             ELSE hosts.source || ',' || excluded.source END,
             last_seen = excluded.last_seen""",
        (hid, mac, ip, hostname, vendor, network, wired, source, ts, ts),
    )


def unifi_clients():
    """Active clients from the UDM Pro (all VLANs). Use a local, view-only account."""
    u = CFG.get("unifi")
    if not u:
        return []
    s = requests.Session()
    s.verify = u.get("verify_ssl", False)
    r = s.post(f"{u['url']}/api/auth/login",
               json={"username": u["username"], "password": os.environ[u["password_env"]]},
               timeout=15)
    r.raise_for_status()
    r = s.get(f"{u['url']}/proxy/network/api/s/{u.get('site', 'default')}/stat/sta", timeout=30)
    r.raise_for_status()
    return r.json().get("data", [])


def nmap_scan():
    sc = CFG["scan"]
    cmd = ["nmap", *sc["nmap_args"].split(), "-oX", "-"]
    if sc.get("exclude"):
        cmd += ["--exclude", ",".join(sc["exclude"])]
    cmd += sc["targets"]
    log("running: " + " ".join(cmd))
    out = subprocess.run(cmd, capture_output=True, text=True, check=True,
                         timeout=sc.get("timeout_s", 4 * 3600)).stdout
    return ET.fromstring(out)


def ingest_nmap(db, root, ip2mac, ts):
    n_hosts = n_ports = n_vulns = 0
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr").lower(), a.get("vendor")
        if not ip:
            continue
        hn = h.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        # Other VLANs: nmap sees no MAC. Borrow UniFi's, else the last MAC we knew for this IP,
        # so a failed UniFi pull doesn't make every host look new.
        if not mac:
            mac = ip2mac.get(ip)
        if not mac:
            row = db.execute("SELECT mac FROM hosts WHERE ip=? AND mac IS NOT NULL "
                             "ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
            mac = row[0] if row else None
        upsert_host(db, mac or f"ip:{ip}", mac, ip, hostname, vendor, None, None, "nmap", ts)
        n_hosts += 1

        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            port, proto = int(p.get("portid")), p.get("protocol")
            svc = p.find("service")
            g = (lambda k: svc.get(k) if svc is not None else None)
            db.execute(
                """INSERT INTO ports (ip, port, proto, service, product, version, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip, port, proto) DO UPDATE SET
                     service=excluded.service, product=excluded.product,
                     version=excluded.version, last_seen=excluded.last_seen""",
                (ip, port, proto, g("name"), g("product"), g("version"), ts, ts))
            n_ports += 1

            for script in p.findall("script[@id='vulners']"):
                for t in script.findall("table/table"):
                    e = {el.get("key"): el.text for el in t.findall("elem")}
                    vid = e.get("id")
                    if not vid:
                        continue
                    db.execute(
                        """INSERT INTO vulns (ip, port, vuln_id, vtype, cvss, exploit, first_seen, last_seen)
                           VALUES (?,?,?,?,?,?,?,?)
                           ON CONFLICT(ip, port, vuln_id) DO UPDATE SET
                             cvss=excluded.cvss, exploit=excluded.exploit, last_seen=excluded.last_seen""",
                        (ip, port, vid, (e.get("type") or "").lower(), float(e.get("cvss") or 0),
                         1 if e.get("is_exploit") == "true" else 0, ts, ts))
                    n_vulns += 1
    return n_hosts, n_ports, n_vulns


def main():
    ts = int(time.time())
    os.makedirs(os.path.dirname(CFG["db"]) or ".", exist_ok=True)
    db = sqlite3.connect(CFG["db"])
    db.executescript(SCHEMA)

    ip2mac = {}
    try:
        clients = unifi_clients()
        for c in clients:
            mac = (c.get("mac") or "").lower() or None
            if not mac:
                continue
            ip = c.get("ip") or c.get("last_ip")
            if ip:
                ip2mac[ip] = mac
            upsert_host(db, mac, mac, ip, c.get("name") or c.get("hostname"), c.get("oui"),
                        c.get("network"), int(bool(c.get("is_wired"))), "unifi", ts)
        log(f"UniFi: {len(clients)} active clients")
    except Exception as e:  # keep going; nmap alone is still useful
        log(f"UniFi pull failed ({e}); continuing with nmap only")

    try:
        root = nmap_scan()
    except subprocess.CalledProcessError as e:
        log(f"nmap failed: {(e.stderr or '')[-800:]}")
        sys.exit(1)

    h, p, v = ingest_nmap(db, root, ip2mac, ts)
    db.execute("INSERT INTO scans (ts) VALUES (?)", (ts,))
    db.commit()
    log(f"done: {h} hosts up, {p} open ports, {v} vuln matches")


if __name__ == "__main__":
    main()
