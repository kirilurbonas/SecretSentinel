FROM python:3.12-slim AS builder

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1

COPY pyproject.toml ./

RUN pip install --upgrade pip && \
    pip install .

COPY app ./app

RUN python -m compileall app

FROM python:3.12-slim

WORKDIR /app

RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app/app ./app

USER sentinel

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

