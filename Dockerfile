FROM python:3.12-slim-bookworm AS wheel-builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src /build/src

RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12-slim-bookworm AS package-smoke

COPY --from=wheel-builder /wheels /wheels
COPY scripts/package_smoke.py /opt/leftovers/package_smoke.py

RUN python -m venv /venv \
    && /venv/bin/python -m pip install \
        --no-index --no-deps --find-links=/wheels leftovers-agent

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65534:65534

CMD ["/venv/bin/python", "/opt/leftovers/package_smoke.py"]

FROM python:3.12-slim-bookworm AS tests

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        git ca-certificates passwd tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin leftovers

WORKDIR /app
COPY --chown=leftovers:leftovers AGENTS.md ARCHITECTURE.md CONTRIBUTING.md LICENSE Makefile PROTOCOL.md README.md SECURITY.md pyproject.toml /app/
COPY --chown=leftovers:leftovers .github /app/.github
COPY --chown=leftovers:leftovers src /app/src
COPY --chown=leftovers:leftovers tests /app/tests
COPY --chown=leftovers:leftovers config /app/config
COPY --chown=leftovers:leftovers examples /app/examples
COPY --chown=leftovers:leftovers sandbox /app/sandbox
COPY --chown=leftovers:leftovers schemas /app/schemas
COPY --chown=leftovers:leftovers schedules /app/schedules
COPY --chown=leftovers:leftovers scripts /app/scripts
COPY --chown=leftovers:leftovers vm /app/vm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

USER leftovers

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
