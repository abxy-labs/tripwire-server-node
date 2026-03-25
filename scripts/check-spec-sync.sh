#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_DIR="${ROOT_DIR}/spec"
SPEC_REPO="abxy-labs/tripwire-server-sdk-spec"

if [[ ! -d "${SPEC_DIR}" ]]; then
  echo "Local spec/ directory is missing."
  exit 1
fi

if [[ -n "${TRIPWIRE_SDK_SPEC_DIR:-}" ]]; then
  SOURCE_DIR="${TRIPWIRE_SDK_SPEC_DIR%/}"
  if [[ ! -d "${SOURCE_DIR}" ]]; then
    echo "TRIPWIRE_SDK_SPEC_DIR does not exist: ${SOURCE_DIR}"
    exit 1
  fi

  diff -ru "${SOURCE_DIR}" "${SPEC_DIR}"
  echo "Local spec/ matches ${SOURCE_DIR}."
  exit 0
fi

if [[ -n "${TRIPWIRE_MAIN_REPO_DIR:-}" ]]; then
  SOURCE_DIR="${TRIPWIRE_MAIN_REPO_DIR%/}/sdk-spec/server"
  if [[ ! -d "${SOURCE_DIR}" ]]; then
    echo "TRIPWIRE_MAIN_REPO_DIR does not contain sdk-spec/server: ${SOURCE_DIR}"
    exit 1
  fi

  diff -ru "${SOURCE_DIR}" "${SPEC_DIR}"
  echo "Local spec/ matches ${SOURCE_DIR}."
  exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE_PATH="${TMP_DIR}/tripwire-server-sdk-spec.tar.gz"
curl -fsSL \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${SPEC_REPO}/tarball/main" \
  -o "${ARCHIVE_PATH}"

tar -xzf "${ARCHIVE_PATH}" -C "${TMP_DIR}"

SOURCE_DIR="$(find "${TMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "${SOURCE_DIR}" ]]; then
  echo "Could not locate the extracted ${SPEC_REPO} archive."
  exit 1
fi

diff -ru "${SOURCE_DIR}" "${SPEC_DIR}"
echo "Local spec/ matches the public server SDK spec source of truth."
