FROM python:3.12-slim

LABEL org.opencontainers.image.title="NetSentry" \
      org.opencontainers.image.description="Network inventory, CVE matching and log review with a local Ollama model" \
      org.opencontainers.image.source="https://github.com/netadmindave/netsentry"

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap tini tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests pyyaml croniter

WORKDIR /app
COPY scanner.py agent.py entrypoint.py config.default.yaml ./

ENV NETSENTRY_CONFIG=/config/config.yaml \
    PYTHONUNBUFFERED=1
VOLUME ["/config", "/data"]

# tini -g: forward stop signals to the whole process group, so a running nmap stops too
ENTRYPOINT ["tini", "-g", "--"]
CMD ["python", "/app/entrypoint.py"]
