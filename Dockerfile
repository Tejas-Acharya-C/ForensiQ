# =============================================================================
# ForensiQ - Production Containerization Dockerfile (Phase 12)
# =============================================================================

# --- Stage 1: Build & Dependency Wheel Builder ---
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt psycopg[binary]==3.3.4


# --- Stage 2: Minimal Runtime Image ---
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    APP_ENV=production \
    DEBUG=false \
    PORT=8000

# Install runtime libpq for PostgreSQL connectivity and curl for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed wheels from builder
COPY --from=builder /install /usr/local

# Create non-root dedicated application user
RUN groupadd -g 10001 forensiq && \
    useradd -u 10001 -g forensiq -s /bin/bash -m forensiq

# Create evidence storage and staging directories with correct permissions
RUN mkdir -p /app/data/sources /app/data/staging && \
    chown -R forensiq:forensiq /app

# Copy application backend, frontend, and configuration
COPY --chown=forensiq:forensiq backend /app/backend
COPY --chown=forensiq:forensiq frontend /app/frontend
COPY --chown=forensiq:forensiq alembic.ini /app/alembic.ini
COPY --chown=forensiq:forensiq pyproject.toml /app/pyproject.toml

USER forensiq

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
