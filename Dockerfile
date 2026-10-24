# Full image with CPU torch (training / analyze). Runs as non-root.
# For ONNX-only VPS runtime prefer: Dockerfile.onnx
FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

COPY pyproject.toml README.md ./
COPY sysspectogram ./sysspectogram
COPY configs ./configs

RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir . \
    && chown -R appuser:appuser /app

USER appuser

VOLUME ["/data", "/dataset", "/artifacts"]

ENTRYPOINT ["python", "-m", "sysspectogram"]
CMD ["--help"]
