# AutoRedTeam-Orchestrator Docker Image
# Multi-stage build for smaller image size

# ============ Build Stage ============
FROM python:3.10-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ============ Runtime Stage ============
FROM python:3.10-slim

LABEL maintainer="coff0xc"
LABEL description="AI-driven automated penetration testing framework based on MCP"
LABEL version="3.0.2"
LABEL org.opencontainers.image.source="https://github.com/Coff0xc/AutoRedTeam-Orchestrator"
LABEL org.opencontainers.image.description="AI-driven automated penetration testing framework with 101 MCP tools"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    # Optional: common security tools
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY core/ ./core/
COPY handlers/ ./handlers/
COPY modules/ ./modules/
COPY utils/ ./utils/
COPY config/ ./config/
COPY templates/ ./templates/
COPY payloads/ ./payloads/
COPY wordlists/ ./wordlists/
COPY mcp_stdio_server.py .
COPY VERSION .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=utf-8
ENV PYTHONDONTWRITEBYTECODE=1

# Expose volume mount points
VOLUME ["/app/config", "/app/data", "/app/logs", "/app/reports"]

# Default command
CMD ["python", "mcp_stdio_server.py"]
