FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git ripgrep tini \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system protocol.file.allow never \
    && git config --system protocol.ext.allow never

WORKDIR /workspace

ENV CI=1 \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# This base intentionally contains no model client and no credentials. Build a provider-specific
# derived image, pin it by digest, and keep every GitHub write credential out of the worker.
ENTRYPOINT []
CMD ["python", "--version"]
