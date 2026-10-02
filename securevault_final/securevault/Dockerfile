FROM python:3.11-slim

LABEL maintainer="Groupe 1 — EMSI Cryptographie 2025-2026"
LABEL description="SecureVault — Gestionnaire de Mots de Passe Sécurisé"

# Security: don't run as root
RUN groupadd -r securevault && useradd -r -g securevault -d /app securevault

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create all required data directories and set permissions
RUN mkdir -p /app/data/vaults /app/models \
    && chown -R securevault:securevault /app \
    && chmod -R 755 /app/data

# Switch to non-root user
USER securevault

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run with Flask dev server via socketio.run (supports WebSocket + threading)
CMD ["python", "main.py"]
