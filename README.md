# NetSentry

Nightly network inventory (UniFi client list + nmap/vulners) and log review, summarised by a
local Ollama model. The model only gets read-only tools: it writes recommendations and never
changes anything.

```
SCAN_CRON:  scanner.py -> SQLite -> agent.py --mode full -> /data/reports (+ optional webhook)
LOGS_CRON:  agent.py --mode logs (named Loki queries)    -> /data/reports (+ optional webhook)
```

## Requirements
- An Ollama instance with a tool-calling model (tested with `qwen3:14b`).
- Optional: a UniFi OS gateway (local view-only account) for the client inventory.
- Optional: Loki, for log review. `alloy.config` is an example Grafana Alloy setup.

## Install on Unraid
Search **NetSentry** in the Apps tab, or copy the template from
https://github.com/netadmindave/unraid-templates into `/boot/config/plugins/dockerMan/templates-user/`
and use Docker → Add Container. On first start the container writes
`/mnt/user/appdata/netsentry/config/config.yaml` and waits; edit it and restart.

Unraid notes:
- Runs with host networking and `NET_RAW` so nmap can SYN-scan and see MAC addresses.
- If other containers use a custom `br0` (macvlan/ipvlan) network, enable
  **Host access to custom networks** in Docker settings or the scanner can't reach them.

## Running by hand
```
docker exec netsentry python /app/scanner.py
docker exec netsentry python /app/agent.py --mode full
docker logs -f netsentry
```

## Tuning
- Ollama: `OLLAMA_FLASH_ATTENTION=1` and `OLLAMA_KV_CACHE_TYPE=q8_0` roughly halve KV-cache
  VRAM, which makes `num_ctx: 32768` practical on a 16 GB card.
- `-sV` probes can upset cheap IoT devices; list fragile IPs in `scan.exclude`.
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
