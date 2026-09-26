#!/usr/bin/env python3
"""NetSentry scanner - builds a device / service / vulnerability inventory in SQLite.

Deterministic and read-only against the network: pulls the client and device lists
from a UniFi gateway and runs nmap (service detection + vulners CVE matching).
No LLM is involved here; agent.py reads what this writes.
"""
import ipaddress
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
SC = CFG["scan"]
NMAP_SERVICES = "/usr/share/nmap/nmap-services"

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
# Columns added after v1. migrate() adds any that an existing database lacks.
MIGRATIONS = {
    "scans": {"duration_s": "INTEGER", "hosts_up": "INTEGER", "unifi_clients": "INTEGER"},
    "hosts": {"unifi_name": "TEXT", "conn": "TEXT", "uplink": "TEXT", "essid": "TEXT",
              "signal": "INTEGER", "is_self": "INTEGER"},
}
HOST_FIELDS = ["mac", "ip", "hostname", "vendor", "network", "wired",
               "unifi_name", "conn", "uplink", "essid", "signal", "is_self"]
RADIO = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}


def log(msg):
    print(f"[scanner] {msg}", flush=True)


def migrate(db):
    db.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for col, typ in cols.items():
            if col not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")


def upsert_host(db, hid, source, ts, overwrite=(), **f):
    """Insert or update a host. Fields in `overwrite` replace stored values even when
    empty (UniFi's view of how a device connects is authoritative); others only fill in."""
    cols = ",".join(HOST_FIELDS)
    marks = ",".join("?" * len(HOST_FIELDS))
    upd = ",".join(f"{k}=excluded.{k}" if k in overwrite else f"{k}=COALESCE(excluded.{k}, hosts.{k})"
                   for k in HOST_FIELDS)
    db.execute(
        f"""INSERT INTO hosts (id,{cols},source,first_seen,last_seen) VALUES (?,{marks},?,?,?)
            ON CONFLICT(id) DO UPDATE SET {upd},
              source = CASE WHEN instr(hosts.source, excluded.source) > 0 THEN hosts.source
                            ELSE hosts.source || ',' || excluded.source END,
              last_seen = excluded.last_seen""",
        [hid, *[f.get(k) for k in HOST_FIELDS], source, ts, ts])


# ------------------------------------------------------------------ UniFi
def unifi_data():
    """Active clients plus UniFi devices (gateway, switches, APs). Use a local view-only account."""
    u = CFG.get("unifi")
    if not u:
        return [], []
    pw = os.environ.get(u.get("password_env", "UNIFI_PASSWORD"))
    if not pw:
        log("UniFi configured but no password set; skipping UniFi")
        return [], []
    s = requests.Session()
    s.verify = u.get("verify_ssl", False)
    r = s.post(f"{u['url']}/api/auth/login", json={"username": u["username"], "password": pw}, timeout=15)
    r.raise_for_status()
    base = f"{u['url']}/proxy/network/api/s/{u.get('site', 'default')}"
    clients = s.get(f"{base}/stat/sta", timeout=30).json().get("data", [])
    try:
        devices = s.get(f"{base}/stat/device", timeout=30).json().get("data", [])
    except Exception as e:
        log(f"UniFi device list failed ({e}); connection names will show MACs")
        devices = []
    return clients, devices


def describe_connection(c, names):
    """-> (conn, uplink, essid, signal) for one UniFi client."""
    if c.get("is_wired"):
        sw = names.get((c.get("sw_mac") or "").lower()) or c.get("last_uplink_name") or c.get("sw_mac") or "?"
        port = c.get("sw_port")
        return "wired", f"{sw} port {port}" if port else sw, None, None
    ap = names.get((c.get("ap_mac") or "").lower()) or c.get("last_uplink_name") or c.get("ap_mac") or "?"
    radio = RADIO.get(c.get("radio"), c.get("radio"))
    return "wifi", f"{ap} ({radio})" if radio else ap, c.get("essid"), c.get("signal")


def in_targets(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(t, strict=False) for t in SC["targets"])
    except ValueError:
        return False


def ingest_unifi(db, clients, devices, ts):
    names = {(d.get("mac") or "").lower(): d.get("name") or d.get("model") or d.get("mac")
             for d in devices if d.get("mac")}
    ip2mac = {}
    for d in devices:                      # the gateway, switches and APs themselves
        mac = (d.get("mac") or "").lower()
        if not mac or not in_targets(d.get("ip")):   # gateways often report their WAN address
            continue
        if d.get("ip"):
            ip2mac[d["ip"]] = mac
        upsert_host(db, mac, "unifi", ts, overwrite=("conn", "uplink", "essid", "signal"),
                    mac=mac, ip=d.get("ip"), unifi_name=names[mac], vendor="Ubiquiti",
                    conn="infrastructure", uplink=d.get("model"), wired=1)
    for c in clients:
        mac = (c.get("mac") or "").lower()
        if not mac:
            continue
        ip = c.get("ip") or c.get("last_ip")
        if ip:
            ip2mac[ip] = mac
        conn, uplink, essid, signal = describe_connection(c, names)
        upsert_host(db, mac, "unifi", ts,
                    overwrite=("conn", "uplink", "essid", "signal", "network", "wired"),
                    mac=mac, ip=ip, hostname=c.get("hostname"), unifi_name=c.get("name"),
                    vendor=c.get("oui"), network=c.get("network"), wired=int(bool(c.get("is_wired"))),
                    conn=conn, uplink=uplink, essid=essid, signal=signal)
    return ip2mac


# ------------------------------------------------------------------ nmap
def expand_ports(items):
    out = set()
    for item in items or []:
        s = str(item).strip()
        if "-" in s:
            a, b = s.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        elif s:
            out.add(int(s))
    return out


def top_tcp_ports(n):
    """Same list as nmap --top-ports N: TCP ports ranked by open-frequency in nmap-services."""
    ranked = []
    with open(NMAP_SERVICES) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3 or not parts[1].endswith("/tcp"):
                continue
            try:
                ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
            except ValueError:
                continue
    ranked.sort(key=lambda t: -t[0])
    out = []
    for _, p in ranked:
        if p not in out:
            out.append(p)
        if len(out) == n:
            break
    return set(out)


def nmap_args():
    args = SC["nmap_args"].split()
    if any(a in ("--top-ports", "-F") or a.startswith("-p") for a in args):
        return args                                   # ports chosen explicitly in nmap_args
    ports = top_tcp_ports(int(SC.get("top_ports", 1000))) | expand_ports(SC.get("extra_ports"))
    return args + ["-p", "T:" + ",".join(map(str, sorted(ports)))]


def run_nmap(args, targets, exclude=None):
    cmd = ["nmap", *args, "-oX", "-"]
    if exclude:
        cmd += ["--exclude", ",".join(exclude)]
    cmd += targets
    shown = [f"T:<{a.count(',') + 1} ports>" if a.startswith("T:") else a for a in cmd]
    log("running: " + " ".join(shown))
    out = subprocess.run(cmd, capture_output=True, text=True, check=True,
                         timeout=SC.get("timeout_s", 4 * 3600)).stdout
    return ET.fromstring(out)


def ingest_nmap(db, root, ip2mac, ts, force_self=False):
    """Returns (hosts, ports, vulns, self_ips)."""
    n_hosts = n_ports = n_vulns = 0
    self_ips = set()
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
        is_self = force_self or status.get("reason") == "localhost-response"
        if is_self:
            self_ips.add(ip)
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
        upsert_host(db, mac or f"ip:{ip}", "nmap", ts, mac=mac, ip=ip, hostname=hostname,
                    vendor=vendor, is_self=1 if is_self else None)
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
    return n_hosts, n_ports, n_vulns, self_ips


def main():
    t0 = time.time()
    ts = int(t0)
    os.makedirs(os.path.dirname(CFG["db"]) or ".", exist_ok=True)
    db = sqlite3.connect(CFG["db"])
    migrate(db)

    ip2mac, n_clients = {}, None
    try:
        clients, devices = unifi_data()
        ip2mac = ingest_unifi(db, clients, devices, ts)
        n_clients = len(clients) if (clients or devices) else None
        if n_clients is not None:
            log(f"UniFi: {len(clients)} active clients, {len(devices)} UniFi devices")
    except Exception as e:  # keep going; nmap alone is still useful
        log(f"UniFi pull failed ({e}); continuing with nmap only")

    args = nmap_args()
    try:
        root = run_nmap(args, SC["targets"], SC.get("exclude"))
    except subprocess.CalledProcessError as e:
        log(f"nmap failed: {(e.stderr or '')[-800:]}")
        sys.exit(1)
    h, p, v, self_ips = ingest_nmap(db, root, ip2mac, ts)

    # A SYN scan of the machine you're running on misses ports published through Docker.
    # Re-scan this host's own addresses with a normal TCP connect scan.
    self_ips |= set(SC.get("self_ips") or [])
    if self_ips and SC.get("self_connect_scan", True):
        args2 = ["-sT" if a == "-sS" else a for a in args]
        if "-sT" not in args2:
            args2.insert(0, "-sT")
        try:
            _, p2, v2, _ = ingest_nmap(db, run_nmap(args2, sorted(self_ips)), ip2mac, ts, force_self=True)
            log(f"self re-scan of {', '.join(sorted(self_ips))}: {p2} open ports")
        except subprocess.CalledProcessError as e:
            log(f"self re-scan failed: {(e.stderr or '')[-300:]}")

    ports_now = db.execute("SELECT count(*) FROM ports WHERE last_seen=?", (ts,)).fetchone()[0]
    vulns_now = db.execute("SELECT count(*) FROM vulns WHERE last_seen=?", (ts,)).fetchone()[0]
    dur = int(time.time() - t0)
    db.execute("INSERT INTO scans (ts, duration_s, hosts_up, unifi_clients) VALUES (?,?,?,?)",
               (ts, dur, h, n_clients))
    db.commit()
    log(f"done in {dur // 60}m{dur % 60:02d}s: {h} hosts up, {ports_now} open ports, {vulns_now} vuln matches")


if __name__ == "__main__":
    main()
