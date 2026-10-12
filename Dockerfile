FROM python:3.12-slim

# Nmap for the Services module; ca-certificates for TLS to crt.sh, CISA, NVD, endoflife.date.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

# Optional: Amass for deeper discovery. Build with --build-arg AMASS_VERSION=v4.2.0 to include it.
ARG AMASS_VERSION=""
RUN if [ -n "$AMASS_VERSION" ]; then \
      curl -fsSL -o /tmp/amass.zip "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_amd64.zip" \
      && unzip -j /tmp/amass.zip '*/amass' -d /usr/local/bin && chmod +x /usr/local/bin/amass && rm /tmp/amass.zip; \
    fi

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt dnstwist

COPY . .
RUN useradd --create-home --uid 10001 runner && mkdir -p /data && chown runner /data
USER runner

ENV RUNNER_DATA_DIR=/data PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=5s CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
# One process (it owns the job queue), several threads for the web pages.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", "--bind", "0.0.0.0:8000", "wsgi:app"]
