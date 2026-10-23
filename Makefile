.PHONY: dev lint format test verify-fingerprints verify-node-fetch

dev:
	uv sync --locked

lint:
	uv run --locked ruff format --check .
	uv run --locked ruff check .
	uv run --locked ty check skills/brotli-checker/scripts scripts tests

format:
	uv run --locked ruff check --fix .
	uv run --locked ruff format .

test:
	uv run --locked pytest

verify-fingerprints:
	uv run --locked python scripts/verify_fingerprints.py

verify-node-fetch:
	env -u NODE_OPTIONS -u NODE_PATH node skills/brotli-checker/scripts/verify_node_fetch.cjs
