export UV_CACHE_DIR ?= $(CURDIR)/.uv-cache

.PHONY: install format lint type test test-cov governance governance-report synthea-pull synthea-tool synthea-generate synthea-reproduce synthetic-data-build synthetic-data-verify verify run fhir-up fhir-seed fhir-integration fhir-down

install:
	uv sync --all-groups

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run ruff format --check .
	uv run ruff check .

type:
	uv run mypy src tests

test:
	uv run pytest

test-cov:
	uv run pytest --cov=polaris --cov-report=term-missing

governance:
	uv run python scripts/validate_traceability.py --check

governance-report:
	uv run python scripts/validate_traceability.py

synthea-pull:
	docker pull eclipse-temurin:17-jre-jammy@sha256:89e68b9bb83713510b63e2059a415792a7fc77e14b739a7d7ede97f6d9ca2c38

synthea-tool:
	uv run python scripts/synthea_toolchain.py download

synthea-generate:
	uv run python scripts/synthea_toolchain.py generate

synthea-reproduce:
	uv run python scripts/synthea_toolchain.py reproduce

synthetic-data-build:
	uv run python scripts/synthetic_fhir.py build

synthetic-data-verify:
	uv run python scripts/synthetic_fhir.py verify

verify: governance synthetic-data-verify lint type test-cov

run:
	uv run uvicorn polaris.main:create_app --factory --env-file .env --host 127.0.0.1 --port 8000

fhir-up:
	docker compose -f infrastructure/local/compose.fhir.yml up -d --wait

fhir-seed:
	uv run python scripts/hapi_fhir_lab.py seed

fhir-integration:
	POLARIS_HAPI_BASE_URL=http://127.0.0.1:18080/fhir uv run pytest -m integration

fhir-down:
	docker compose -f infrastructure/local/compose.fhir.yml down
