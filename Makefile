# PoCEvolve — centralized build & test entry point
# Usage: make [target]

.PHONY: all setup test test-indexer clean

all: setup

# Install all dependencies (npm + pip) in one pass.
setup:
	npm ci --prefix PoCEvolve/src/indexer || npm install --prefix PoCEvolve/src/indexer
	pip install -r PoCEvolve/requirements.txt 2>/dev/null || true

# Run the full test suite (indexer tests only — other tests are project-specific).
test: test-indexer

# Run SCIP indexer tests (requires scip-typescript installed via `setup`).
test-indexer:
	cd PoCEvolve && PYTHONPATH=. python -m unittest discover -s src/indexer/tests -v

# Remove generated artifacts (node_modules from the indexer dir).
clean:
	rm -rf PoCEvolve/src/indexer/node_modules
	rm -rf PoCEvolve/src/indexer/*.scip PoCEvolve/src/indexer/tsconfig.json
