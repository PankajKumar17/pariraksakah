# Anti-Phishing Service — Python
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r requirements.txt

FROM python:3.11-slim
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN groupadd -r cybershield && useradd -r -g cybershield -s /bin/false appuser
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
RUN python -m playwright install --with-deps chromium && \
    mkdir -p /ms-playwright && \
    chown -R appuser:cybershield /app /ms-playwright
USER appuser
EXPOSE 8003
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8003/health')"
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8003"]
