# Cyber Recovery Orchestrator - single-container image (API + SPA + lab).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Dependencies first for layer caching.
COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt

# Application code. Layout inside the image mirrors the repository:
#   /srv/backend     FastAPI app (package `app`)
#   /srv/frontend    static SPA served at "/"
#   /srv/evaluation  labeled ground truth consumed by the evaluation runner
COPY backend /srv/backend
COPY frontend /srv/frontend
COPY evaluation /srv/evaluation

# SQLite lab database location (mount a volume here to persist across runs).
RUN mkdir -p /srv/data

EXPOSE 8011

CMD ["python", "-m", "uvicorn", "--app-dir", "/srv/backend", "app.main:app", "--host", "0.0.0.0", "--port", "8011"]
