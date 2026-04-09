FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.txt

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# WeasyPrint runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libpq-dev \
    libcairo2 \
    libpango-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libxml2 \
    libxslt1.1 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY app /app
COPY scripts/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

RUN mkdir -p /app/staticfiles /app/media

ENTRYPOINT ["/entrypoint.sh"]
