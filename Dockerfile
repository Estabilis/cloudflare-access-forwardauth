# Pinned by digest: `python:3.13-slim` is a moving pointer; the digest is not.
FROM python:3.13-slim@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2

ARG COMMIT_SHA=dev
ENV COMMIT_SHA=$COMMIT_SHA \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

WORKDIR /app

# From the lock, with hashes: pip refuses anything that is not pinned with a hash.
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin guard
USER 10001

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers"]
