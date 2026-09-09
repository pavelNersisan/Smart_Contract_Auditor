# Audit engine + API.
#
# NOTE: this image is provided for parity with the README's docker-compose
# workflow. It could not be built or run in the environment where this code was
# developed (no Docker available), so treat it as a starting point rather than
# a verified artifact. `pip install -e backend` is the tested path.
FROM python:3.11-slim AS base

# Node is installed because the WASM solc (`npm install solc`) is what makes the
# engine self-contained: no native solc download is needed at build or run time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/auditor

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
RUN pip install --no-cache-dir -e ./backend

# WASM Solidity compiler
RUN npm install --silent --no-fund --no-audit solc@0.8.24

RUN useradd --create-home --uid 1000 auditor
RUN mkdir -p /srv/auditor/.data && chown -R auditor:auditor /srv/auditor
USER auditor

ENV AUDITOR_HOST=0.0.0.0 \
    AUDITOR_PORT=8000 \
    AUDITOR_DATABASE_URL=sqlite:////srv/auditor/.data/audits.db \
    AUDITOR_REPORT_DIR=/srv/auditor/.data/reports

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["auditor", "serve", "--host", "0.0.0.0", "--port", "8000"]
