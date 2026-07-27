#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: scripts/install_scanners.sh [--install]"
  echo
  echo "Supported automatic installation: macOS with Homebrew."
  echo "Packages: semgrep, gitleaks, trivy, osv-scanner, slither-analyzer."
  echo "CodeQL is intentionally separate; use GitHub's signed release bundle and a prebuilt database."
  echo "Without --install this script only prints the plan."
}

usage
if [[ "${1:-}" != "--install" ]]; then
  exit 0
fi

case "$(uname -s)" in
  Darwin)
    if ! command -v brew >/dev/null 2>&1; then
      echo "Homebrew is required for the supported macOS installation path." >&2
      exit 2
    fi
    echo "Installing scanner packages through the configured Homebrew repositories..."
    brew install semgrep gitleaks trivy osv-scanner
    if command -v pipx >/dev/null 2>&1; then
      pipx install slither-analyzer
    else
      echo "pipx is not installed; skipping optional Slither installation." >&2
      echo "Install slither-analyzer in an isolated Python environment if Solidity scanning is needed." >&2
    fi
    ;;
  *)
    echo "Automatic scanner installation is not supported on this platform." >&2
    echo "Install verified releases from the official projects; do not pipe remote scripts to a shell." >&2
    exit 2
    ;;
esac

echo "Installed versions:"
semgrep --version
gitleaks --version
trivy --version
osv-scanner --version
if command -v slither >/dev/null 2>&1; then
  slither --version
fi
