# NetSentry

Nightly network inventory (UniFi client list + nmap/vulners) and log review, summarised by a
local Ollama model. The model only gets read-only tools: it writes recommendations and never
changes anything.

```
SCAN_CRON:  scanner.py -> SQLite -> agent.py --mode full -> /data/reports (+ optional webhook)
LOGS_CRON:  agent.py --mode logs (named Loki queries)    -> /data/reports (+ optional webhook)
```

Each full report has two parts:
- **Findings** written by the model: severity, summary, up to 8 findings with evidence, actions and
  how to verify, and a watch list.
- **Appendix** generated directly from the scan database (never AI-written): every device with its
  UniFi name, MAC, network and connection (switch and port, or AP, band, SSID and signal), and every
  open service with detected version, CVE counts, CISA known-exploited matches and internet exposure.

## How findings are kept honest
- CVE matches are grouped per service and ranked; CVEs on the CISA Known Exploited Vulnerabilities
  list (downloaded daily, cached in `/data/kev.json`) rank first.
- Versions nmap can't pin down (e.g. Samba reported as `3.X - 4.X`) are marked low-confidence, and
  the model is told not to trust their CVE matches.
- `cve_notes` attaches context to specific CVEs (client-side-only, AD-DC-only, ...);
  `suppress_cves` drops verified false positives.
- `known_devices`, `accepted_risks` and `internet_exposed` in `config.yaml` tell the model what is
  expected on your network.
- Severity "critical" is enforced in code: it requires a known-exploited CVE on a service listed in
  `internet_exposed`. Anything else the model rates critical is capped at high.

## Requirements
- An Ollama instance with a tool-calling model (tested with `qwen3:14b`).
- Optional: a UniFi OS gateway (local view-only account) for the client inventory.
- Optional: Loki, for log review. `alloy.config` is an example Grafana Alloy setup.

## Install on Unraid
Search **NetSentry** in the Apps tab, or copy the template from
https://github.com/netadmindave/unraid-netsentry into `/boot/config/plugins/dockerMan/templates-user/`
and use Docker → Add Container. On first start the container writes
`/mnt/user/appdata/netsentry/config/config.yaml` and waits; edit it and restart.

The container is named `NetSentry` (Docker names are case-sensitive).

Unraid notes:
- Runs with host networking and `NET_RAW` so nmap can SYN-scan and see MAC addresses.
- A SYN scan of the machine you're scanning from misses Docker-published ports, so the host's own
  addresses are automatically re-scanned with a TCP connect scan (`self_connect_scan`).
- If other containers use a custom `br0` (macvlan/ipvlan) network, enable
  **Host access to custom networks** in Docker settings or the scanner can't reach them.

## Running by hand
```
docker exec NetSentry python /app/scanner.py
docker exec NetSentry python /app/agent.py --mode full
docker logs -f NetSentry
```

## Tuning
- Ollama: `OLLAMA_FLASH_ATTENTION=1` and `OLLAMA_KV_CACHE_TYPE=q8_0` roughly halve KV-cache
  VRAM, which makes `num_ctx: 32768` practical on a 16 GB card.
- Ports scanned are nmap's top 1000 (`top_ports`) plus `extra_ports`, which covers common homelab
  apps outside that list (Home Assistant 8123, Node-RED 1880, Proxmox 8006, Plex 32400, the *arr apps...).
- `-sV` probes can upset cheap IoT devices; list fragile IPs in `scan.exclude`.
- Use MAC addresses in `known_devices` where you can; they survive DHCP changes.
- The first full run is the baseline; change detection starts with the second.

## Responsible use and privacy
- Only scan networks you own or are authorised to test.
- The nmap `vulners` script sends detected product/version strings (CPEs) to vulners.com.
  Remove `--script vulners` from `nmap_args` for fully offline operation.
- CVE matches are based on version strings and include false positives; verify before acting.

## Development
Pushing to `main` builds `ghcr.io/netadmindave/netsentry:latest` via GitHub Actions; a weekly
scheduled rebuild picks up base-image and nmap security fixes.

## License
MIT for this repository. The container image also includes third-party software under its own
licenses, notably Nmap (Nmap Public Source License) and Python/Debian packages.
