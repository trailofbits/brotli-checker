.PHONY: dev lint format test security mutations verify-fingerprints verify-node-fetch

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

security:
	uv run --locked --group security zizmor --offline --pedantic .
	mkdir -p artifacts
	uv export --all-groups --locked --no-emit-project --output-file artifacts/requirements-audit.txt > /dev/null
	uv run --locked --group security pip-audit --strict --require-hashes --disable-pip --progress-spinner off -r artifacts/requirements-audit.txt

mutations:
	rm -f coverage/gremlins/gremlins.json
	uv run --locked --group mutation pytest --gremlins --no-cov --gremlin-executor=subprocess
	uv run --locked --group mutation python scripts/check_mutation_score.py

verify-fingerprints:
	uv run --locked python scripts/verify_fingerprints.py

verify-node-fetch:
	env -u NODE_OPTIONS -u NODE_PATH node skills/brotli-checker/scripts/verify_node_fetch.cjs
