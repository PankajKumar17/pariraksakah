# Self-Healing Service — Python stub (bypasses Rust build for demo)
FROM python:3.11-slim
RUN groupadd -r cybershield && useradd -r -g cybershield -s /bin/false appuser
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn prometheus-client
COPY src/runtime_monitor.py /app/
COPY src/self_healing_stub.py /app/
USER appuser
EXPOSE 8008
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8008/health')" || exit 1
CMD ["uvicorn", "self_healing_stub:app", "--host", "0.0.0.0", "--port", "8008"]
