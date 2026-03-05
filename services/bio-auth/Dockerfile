# Bio-Auth Service — Python
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r requirements.txt

FROM python:3.11-slim
RUN groupadd -r cybershield && useradd -r -g cybershield -s /bin/false appuser
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
RUN chown -R appuser:cybershield /app
USER appuser
EXPOSE 8005
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8005/health')"
CMD ["uvicorn", "src.api.bio_auth_api:app", "--host", "0.0.0.0", "--port", "8005"]
