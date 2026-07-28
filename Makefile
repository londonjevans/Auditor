.PHONY: install format lint type test check release-evidence release-local

PYTHON ?= python
RELEASE_RUN_DIR ?=

install:
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

lint:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy src

test:
	$(PYTHON) -m pytest

check: lint type test

release-evidence:
	$(PYTHON) scripts/validate_release_evidence.py --run-dir "$(RELEASE_RUN_DIR)"

release-local: check release-evidence
