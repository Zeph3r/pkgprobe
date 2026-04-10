FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
COPY pkgprobe/ pkgprobe/
COPY pkgprobe_trace/ pkgprobe_trace/

RUN pip install --no-cache-dir uv && \
    uv pip install --system ".[trace,cloud]"

EXPOSE 8000

ENV PKGPROBE_BASE_OUTPUT_DIR=/data/jobs
ENV DATABASE_URL=sqlite:////data/pkgprobe_api.db

VOLUME ["/data"]

CMD ["uvicorn", "pkgprobe_trace.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
