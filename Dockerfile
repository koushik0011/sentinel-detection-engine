FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY src/ ./src/
COPY rules/ ./rules/
COPY tests/ ./tests/

CMD ["python", "-m", "sentinel.cli", "test", "--rules", "rules/", "--telemetry", "tests/telemetry/"]
