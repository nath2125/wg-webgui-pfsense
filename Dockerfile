FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Registry lives on a mounted volume.
RUN mkdir -p /data
VOLUME ["/data"]

# Run as a non-root user.
RUN useradd -r -u 10001 appuser && chown -R appuser:appuser /app /data
USER appuser

ENV DATABASE_URL=sqlite:////data/devices.db
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
