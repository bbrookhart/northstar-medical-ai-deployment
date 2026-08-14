# Northstar Polaris application image.
#
# The base is pinned by digest, not by tag, so a rebuild resolves the same bytes. Build tooling
# stays in the builder stage, and the runtime image has no compiler, no uv, and no package manager
# binaries, so an attacker who reaches the container cannot install anything.
#
# This image is for the local simulation. It is not a production deployment artifact, and nothing
# here substitutes for the vulnerability scanning, signing, and provenance recorded as unmet in
# ADR-013.

FROM python@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1 AS builder

# The environment is built at the path it will run from. A virtualenv relocated after creation
# keeps absolute interpreter shebangs, so the entrypoint would fail with a confusing
# "no such file or directory" at run time.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# uv is installed from its own pinned image rather than a curl-to-shell installer.
COPY --from=ghcr.io/astral-sh/uv@sha256:78bc42400d77b0678ba95765305c826652ed5431f399257271dda681d0318f03 /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies resolve from the lockfile alone, before application code is copied, so a source
# change cannot silently alter the dependency set.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

# README.md is copied here rather than with the manifests so that editing it does not invalidate
# the cached dependency layer; the project build itself needs it.
COPY README.md ./
COPY src ./src
RUN uv sync --locked --no-dev


FROM python@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1 AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 65532 polaris; \
    useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin polaris; \
    # Remove the package managers themselves. The dpkg database stays so vulnerability scanners
    # can still enumerate the base image contents.
    rm -rf /usr/local/lib/python3*/site-packages/pip* /usr/local/bin/pip*; \
    rm -f /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config

WORKDIR /app
COPY --from=builder --chown=root:root /app/.venv /app/.venv
COPY --from=builder --chown=root:root /app/src /app/src

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POLARIS_ENVIRONMENT=production

# The application never writes to its own code or dependencies.
USER 65532:65532

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200 else 1)"]

ENTRYPOINT ["uvicorn", "polaris.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
