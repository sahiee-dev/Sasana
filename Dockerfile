FROM python:3.12-slim

# Non-root system user — Archeion never needs root after installation.
RUN useradd --system --no-create-home --shell /bin/false archeion

WORKDIR /app

# Copy only what the package needs. Build dependencies (tests, Rust binary,
# examples) are excluded via .dockerignore.
COPY pyproject.toml README.md ./
COPY sasana/ sasana/
COPY archeion/ archeion/
COPY sasana_cli.py verify.py ./

# Install Archeion extras only. cryptography is pulled in by the base package.
RUN pip install --no-cache-dir ".[archeion]"

# Key directory — only used when ARCHEION_PRIVATE_KEY env var is not set.
# Mount a named volume here for persistent key storage (see docker-compose.yml).
RUN mkdir -p /home/archeion/.archeion && chown archeion /home/archeion/.archeion
ENV HOME=/home/archeion

USER archeion

EXPOSE 8747

# Health check hits /health every 30 s. Start period gives uvicorn time to load.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c \
        "import urllib.request, sys; \
         r = urllib.request.urlopen('http://localhost:8747/health', timeout=4); \
         sys.exit(0 if r.status == 200 else 1)"

CMD ["archeion"]
