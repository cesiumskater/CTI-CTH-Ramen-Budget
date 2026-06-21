# syntax=docker/dockerfile:1.7
#
# ---------------------------------------------------------------------------
# ramen-cve — minimal, multi-stage, distroless-style image.
# ---------------------------------------------------------------------------
#
# Two stages:
#   * `build`  — installs the runtime deps + builds the wheel.
#   * `runtime` — copies only the wheel + site-packages into a slim base
#     image. Runs as a non-root user.
#
# Build:    docker build -t ramen-cve:local .
# Run once: docker run --rm -v $PWD/data:/data -v $PWD/cache:/cache \
#                ghcr.io/cesiumskater/ramen-cve:latest \
#                opml /data/feeds.opml --out-dir /data/out
# Compose:  see docker-compose.yml — one-command launch with mounts + env.
# ---------------------------------------------------------------------------

# Pin to a specific patch and slim variant so reproducibility is real.
ARG PYTHON_VERSION=3.12-slim-bookworm

FROM python:${PYTHON_VERSION} AS build

# Don't write .pyc files into the wheel; we install fresh in runtime.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

# Install just the bits build needs. `--no-install-recommends` keeps the
# layer slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject + LICENSE first so dependency-resolution layers cache when
# pyproject.toml is unchanged. The rest of the source is copied after.
COPY pyproject.toml LICENSE README.md ./
COPY src/ ./src/
COPY conftest.py threat_intel_hunter.py ./

# Build the wheel and install only the project + runtime deps into a
# dedicated venv we'll copy into the runtime stage.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

# ---------------------------------------------------------------------------

FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    # Default cache + output directories live under /data so a single
    # bind-mount surfaces both to the host.
    RAMEN_CACHE_DIR=/data/cache \
    RAMEN_OUT_DIR=/data/out

# Non-root user. UID/GID picked to match the conventional unprivileged
# slot — override at build time if it collides with the host's uid_map.
ARG UID=10001
ARG GID=10001
RUN groupadd --system --gid ${GID} ramen \
    && useradd --system --no-create-home --uid ${UID} --gid ${GID} --shell /sbin/nologin ramen

# Bring the venv and just enough of the source for the entry-point shim
# and bundled package data to resolve at runtime.
COPY --from=build /opt/venv /opt/venv

# /data is the runtime working tree — SQLite cache, audit log, per-run
# output. Create it owned by the ramen user BEFORE the USER directive
# so writes succeed both when the host bind-mounts /data and when it
# doesn't (e.g. `docker run --rm image hunt list` writes one audit row).
RUN mkdir -p /data && chown -R ramen:ramen /data
WORKDIR /data

# Mount points so a simple `docker run -v $PWD/data:/data` surfaces both
# the SQLite cache and the per-run output directory to the host.
VOLUME ["/data"]

USER ramen

# Healthcheck: `ramen-cve --version` exits 0 and prints the version. Cheap,
# proves the entry-point resolves + package data is reachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ramen-cve --version || exit 1

# The console-script entry-point is the obvious default; arguments after
# `docker run ... image-name` flow straight to ramen-cve.
ENTRYPOINT ["ramen-cve"]
CMD ["--help"]
