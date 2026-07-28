.PHONY: install format lint type test check release-artifacts release-evidence release-generate release-local

PYTHON ?= python
RELEASE_ID ?=
RELEASE_RUN_DIR ?=
RELEASE_ARTIFACT_EVIDENCE_OUTPUT ?=
RELEASE_REPORT_ROOT ?=
RELEASE_REPORT_PATH ?=
RELEASE_EVIDENCE_ROOT ?=
RELEASE_REPOSITORY_ROOT ?=
RELEASE_TARGET_REPOSITORY_ROOT ?=
RELEASE_ARTIFACT_EVIDENCE_PATH ?=
RELEASE_RUN_VERIFICATION_PATH ?=
RELEASE_REQUIRE_COMPLETE ?=

RELEASE_ARTIFACT_OUTPUT_FLAG = $(if $(strip $(RELEASE_ARTIFACT_EVIDENCE_OUTPUT)),--artifact-evidence-output "$(RELEASE_ARTIFACT_EVIDENCE_OUTPUT)",)
RELEASE_COMPLETION_FLAG = $(if $(filter 1 true yes,$(RELEASE_REQUIRE_COMPLETE)),--require-complete,)

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

release-artifacts:
	@test -n "$(RELEASE_RUN_DIR)" || { echo "RELEASE_RUN_DIR is required" >&2; exit 2; }
	$(PYTHON) scripts/validate_release_evidence.py \
		--artifact-only $(RELEASE_ARTIFACT_OUTPUT_FLAG) \
		--run-dir "$(RELEASE_RUN_DIR)"

release-evidence:
	@test -n "$(RELEASE_REPORT_ROOT)" || { echo "RELEASE_REPORT_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_REPORT_PATH)" || { echo "RELEASE_REPORT_PATH is required" >&2; exit 2; }
	@test -n "$(RELEASE_EVIDENCE_ROOT)" || { echo "RELEASE_EVIDENCE_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_REPOSITORY_ROOT)" || { echo "RELEASE_REPOSITORY_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_RUN_DIR)" || { echo "RELEASE_RUN_DIR is required" >&2; exit 2; }
	@test -n "$(RELEASE_TARGET_REPOSITORY_ROOT)" || { echo "RELEASE_TARGET_REPOSITORY_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_ARTIFACT_EVIDENCE_PATH)" || { echo "RELEASE_ARTIFACT_EVIDENCE_PATH is required" >&2; exit 2; }
	@test -n "$(RELEASE_RUN_VERIFICATION_PATH)" || { echo "RELEASE_RUN_VERIFICATION_PATH is required" >&2; exit 2; }
	$(PYTHON) scripts/validate_release_evidence.py \
		--full $(RELEASE_COMPLETION_FLAG) \
		--report-root "$(RELEASE_REPORT_ROOT)" \
		--report-path "$(RELEASE_REPORT_PATH)" \
		--evidence-root "$(RELEASE_EVIDENCE_ROOT)" \
		--release-repository "$(RELEASE_REPOSITORY_ROOT)" \
		--run-dir "$(RELEASE_RUN_DIR)" \
		--target-repository "$(RELEASE_TARGET_REPOSITORY_ROOT)" \
		--artifact-evidence-file "$(RELEASE_ARTIFACT_EVIDENCE_PATH)" \
		--run-verification-file "$(RELEASE_RUN_VERIFICATION_PATH)"

release-generate:
	@test -n "$(RELEASE_ID)" || { echo "RELEASE_ID is required" >&2; exit 2; }
	@test -n "$(RELEASE_REPORT_ROOT)" || { echo "RELEASE_REPORT_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_EVIDENCE_ROOT)" || { echo "RELEASE_EVIDENCE_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_REPOSITORY_ROOT)" || { echo "RELEASE_REPOSITORY_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_RUN_DIR)" || { echo "RELEASE_RUN_DIR is required" >&2; exit 2; }
	@test -n "$(RELEASE_TARGET_REPOSITORY_ROOT)" || { echo "RELEASE_TARGET_REPOSITORY_ROOT is required" >&2; exit 2; }
	@test -n "$(RELEASE_ARTIFACT_EVIDENCE_PATH)" || { echo "RELEASE_ARTIFACT_EVIDENCE_PATH is required" >&2; exit 2; }
	@test -n "$(RELEASE_RUN_VERIFICATION_PATH)" || { echo "RELEASE_RUN_VERIFICATION_PATH is required" >&2; exit 2; }
	$(PYTHON) scripts/generate_release_report.py \
		--release-id "$(RELEASE_ID)" \
		--report-root "$(RELEASE_REPORT_ROOT)" \
		--evidence-root "$(RELEASE_EVIDENCE_ROOT)" \
		--release-repository "$(RELEASE_REPOSITORY_ROOT)" \
		--run-dir "$(RELEASE_RUN_DIR)" \
		--target-repository "$(RELEASE_TARGET_REPOSITORY_ROOT)" \
		--artifact-evidence-file "$(RELEASE_ARTIFACT_EVIDENCE_PATH)" \
		--run-verification-file "$(RELEASE_RUN_VERIFICATION_PATH)"

release-local: check release-evidence
