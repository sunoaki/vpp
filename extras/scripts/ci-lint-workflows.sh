#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

# actionlint checks .github/workflows/*.yml against GitHub's own expression
# context table, which is what a YAML parser does not do. `jobs.<id>.env`
# holding `${{ runner.temp }}` parses as YAML and is rejected by GitHub with
# HTTP 422 "Unrecognized named-value: 'runner'", so the whole workflow file
# stops being a workflow. This script makes that class of defect fail here.
#
# The version is pinned and its archive is verified against the checksum the
# release publishes, so a changed or compromised download is detected rather
# than executed. 1.7.8 is the version where the bundled metadata of
# actions/download-artifact@v4 already declares the `artifact-ids` input that
# .github/workflows/{gre,mfib}-positive.yml pass, and where the `type:` keys of
# the local actions under .github/actions/ are still accepted; 1.7.7 reports
# the artifact-ids warnings and 1.7.9 onwards rejects those local actions.

set -eEo pipefail

ACTIONLINT_VERSION="1.7.8"
# Checksums of the release archives, published as
# actionlint_${ACTIONLINT_VERSION}_checksums.txt on the release page:
#   https://github.com/rhysd/actionlint/releases/tag/v${ACTIONLINT_VERSION}
ACTIONLINT_SHA256_LINUX_AMD64="be92c2652ab7b6d08425428797ceabeb16e31a781c07bc388456b4e592f3e36a"
ACTIONLINT_SHA256_LINUX_ARM64="4c65dbb2d59b409cdd75d47ffa8fa32af8f0eee573ac510468dc2275c48bf07c"

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
WS_ROOT="$(realpath "${SCRIPTDIR}/../..")"
WORKFLOW_DIR="${WS_ROOT}/.github/workflows"

fail() {
    echo "*******************************************************************" >&2
    echo "* WORKFLOW LINT FAILED" >&2
    echo "* $*" >&2
    echo "*******************************************************************" >&2
    exit 1
}

# The archive is chosen by machine, because the style job runs on x86_64 and a
# maintainer may run this script on arm64.
case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" && SHA256="${ACTIONLINT_SHA256_LINUX_AMD64}" ;;
    aarch64 | arm64) ARCH="arm64" && SHA256="${ACTIONLINT_SHA256_LINUX_ARM64}" ;;
    *) fail "No pinned actionlint archive for machine $(uname -m)" ;;
esac

for tool in curl tar sha256sum; do
    command -v "${tool}" >/dev/null 2>&1 \
        || fail "'${tool}' is needed to fetch and verify actionlint"
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

ARCHIVE="actionlint_${ACTIONLINT_VERSION}_linux_${ARCH}.tar.gz"
URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${ARCHIVE}"

echo "Downloading actionlint ${ACTIONLINT_VERSION} for linux/${ARCH}"
# --retry-all-errors is needed because a TLS connection reset is not one of the
# transient errors --retry covers on its own, and the release CDN is reached
# over TLS.
if ! curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
    --connect-timeout 20 --max-time 120 \
    -o "${WORKDIR}/${ARCHIVE}" "${URL}"; then
    # A download that fails must not fall through to a check that passes
    # without having run, so the missing binary is a failure and not a skip.
    fail "Could not download ${URL}; the workflows were not checked"
fi

echo "${SHA256}  ${WORKDIR}/${ARCHIVE}" | sha256sum -c - >/dev/null \
    || fail "Checksum of ${ARCHIVE} does not match the pinned ${SHA256}"

tar -xzf "${WORKDIR}/${ARCHIVE}" -C "${WORKDIR}" actionlint \
    || fail "Could not extract actionlint from ${ARCHIVE}"
ACTIONLINT="${WORKDIR}/actionlint"
"${ACTIONLINT}" --version >/dev/null || fail "${ARCHIVE} is not runnable"

# shellcheck and pyflakes are separate programs, and the checks that need them
# are skipped when they are absent; shellcheck's is disabled here so the run
# depends on nothing but the pinned binary.
shopt -s nullglob
workflows=("${WORKFLOW_DIR}"/*.yml)
shopt -u nullglob
[ "${#workflows[@]}" -gt 0 ] \
    || fail "No *.yml under ${WORKFLOW_DIR}; nothing was checked"

# actionlint prints a file's path relative to the current directory, so the run
# starts at the repository root and names the files .github/workflows/....yml.
cd "${WS_ROOT}"
workflows=("${workflows[@]#"${WS_ROOT}/"}")

echo "Checking ${#workflows[@]} workflow files with actionlint ${ACTIONLINT_VERSION}"
"${ACTIONLINT}" -shellcheck= "${workflows[@]}" \
    || fail "actionlint reported the errors above"

echo "*******************************************************************"
echo "* WORKFLOW LINT SUCCESSFULLY COMPLETED"
echo "*******************************************************************"
