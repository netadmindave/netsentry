#!/usr/bin/env python3
"""NetSentry service entrypoint.

Keeps the container running (so Unraid shows it as a normal started app, with
autostart and update checks) and runs the jobs on cron schedules:

  SCAN_CRON   full run: scanner.py then agent.py --mode full   (default "0 3 * * *")
  LOGS_CRON   log review: agent.py --mode logs                 (default "15 * * * *"; empty = off)
  RUN_ON_START  "true" to do one full run when the container starts

Manual runs:  docker exec NetSentry python /app/scanner.py
              docker exec NetSentry python /app/agent.py --mode full
"""
import datetime as dt
import os
import shutil
import signal
import subprocess
import sys
import time

from croniter import croniter

CONFIG = os.environ.get("NETSENTRY_CONFIG", "/config/config.yaml")
DEFAULT_CONFIG = "/app/config.default.yaml"

JOBS = {
    "full": (os.environ.get("SCAN_CRON", "0 3 * * *"),
             [["python", "/app/scanner.py"], ["python", "/app/agent.py", "--mode", "full"]]),
    "logs": (os.environ.get("LOGS_CRON", "15 * * * *"),
             [["python", "/app/agent.py", "--mode", "logs"]]),
}


def log(msg):
    print(f"[netsentry {dt.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def run_job(name):
    for cmd in JOBS[name][1]:
        log(f"{name}: start {' '.join(cmd[1:])}")
        rc = subprocess.call(cmd)
        log(f"{name}: {' '.join(cmd[1:])} exited {rc}")
        if rc != 0:           # e.g. scan failed -> don't ask the model about stale data
            return rc
    return 0


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    if not os.path.exists(CONFIG):
        os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
        shutil.copy(DEFAULT_CONFIG, CONFIG)
        log(f"No config found. Wrote a default to {CONFIG}; edit it and restart the container.")
        while True:
            time.sleep(3600)

    jobs = {n: j for n, j in JOBS.items() if j[0].strip()}
    for n, (expr, _) in jobs.items():
        if not croniter.is_valid(expr):
            log(f"Invalid cron for {n}: '{expr}'")
            sys.exit(2)

    if os.environ.get("RUN_ON_START", "false").lower() == "true":
        run_job("full")

    nxt = {n: croniter(expr, dt.datetime.now()).get_next(dt.datetime) for n, (expr, _) in jobs.items()}
    for n, t in nxt.items():
        log(f"{n}: '{jobs[n][0]}', next run {t:%Y-%m-%d %H:%M}")

    while True:
        n = min(nxt, key=nxt.get)
        wait = (nxt[n] - dt.datetime.now()).total_seconds()
        if wait > 0:
            time.sleep(min(wait, 60))
            continue
        run_job(n)
        # Jobs run one at a time; anything that came due during a long run fires once, not repeatedly.
        now = dt.datetime.now()
        for m in nxt:
            if nxt[m] <= now:
                nxt[m] = croniter(jobs[m][0], now).get_next(dt.datetime)
        log(f"{n}: next run {nxt[n]:%Y-%m-%d %H:%M}")


if __name__ == "__main__":
    main()
