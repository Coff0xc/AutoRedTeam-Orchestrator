# Published image installs the default wheel. Experimental engine packages stay
# in a source checkout and are omitted here by the same setuptools excludes.
FROM python:3.12-slim AS builder

WORKDIR /src

RUN pip install --no-cache-dir build

COPY pyproject.toml _version.py mcp_stdio_server.py README.md ./
COPY core ./core
COPY handlers ./handlers
COPY utils ./utils
COPY autort ./autort
COPY cli ./cli

RUN pyproject-build --wheel --outdir /tmp/dist \
    && pip install --no-cache-dir --prefix=/opt/autort /tmp/dist/*.whl

FROM python:3.12-slim

LABEL maintainer="coff0xc"
LABEL org.opencontainers.image.source="https://github.com/Coff0xc/AutoRedTeam-Orchestrator"
LABEL org.opencontainers.image.description="Local MCP/AI attack-surface audit and evidence gate"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY --from=builder /opt/autort /usr/local

WORKDIR /app

RUN mkdir -p /app/data /app/logs /app/reports \
    && chown -R appuser:appuser /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    AUTORT_CAPABILITY_PROFILE=safe

VOLUME ["/app/data", "/app/logs", "/app/reports"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import mcp_stdio_server; print('ok')" || exit 1

USER appuser

CMD ["autoredteam-mcp"]
