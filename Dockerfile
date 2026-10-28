FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY gateway_worker ./gateway_worker
RUN pip install --no-cache-dir .

EXPOSE 8765
CMD ["python", "-m", "gateway_worker.cli", "serve", "--db", "/data/gateway.db", "--host", "0.0.0.0", "--port", "8765"]
