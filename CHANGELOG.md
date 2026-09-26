# Changelog

## 2.0
- Report appendix generated from the database: device map (UniFi name, MAC, network, wired switch
  and port or Wi-Fi AP, band, SSID and signal) and a per-service table with CVE counts, CISA KEV
  matches and internet exposure.
- UniFi gateway, switches and APs are included in the inventory.
- CVE matches grouped per service and ranked; CISA Known Exploited Vulnerabilities cross-check.
- Low-confidence version detection flagged (e.g. Samba "3.X - 4.X").
- New config: `known_devices`, `accepted_risks`, `internet_exposed`, `cve_notes`, `suppress_cves`, `kev`.
- "critical" severity enforced in code: only a KEV CVE on an internet-exposed service qualifies.
- `top_ports` + `extra_ports` replace `--top-ports` so homelab ports outside nmap's top 1000 are scanned.
- The scanner host is re-scanned with a TCP connect scan to catch Docker-published ports.
- Scan duration and counts recorded; existing databases are migrated automatically.
- Docs use the Unraid container name `NetSentry`.

## 1.0
- Initial release.
