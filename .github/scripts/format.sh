#!/bin/bash
# This file is part of Percona Server for MongoDB.
#
# Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the Server Side Public License, version 1,
#     as published by MongoDB, Inc.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     Server Side Public License for more details.
#
#     You should have received a copy of the Server Side Public License
#     along with this program. If not, see
#     <http://www.mongodb.com/licensing/server-side-public-license>.
#
#     As a special exception, the copyright holders give permission to link the
#     code of portions of this program with the OpenSSL library under certain
#     conditions as described in each individual source file and distribute
#     linked combinations including the program with the OpenSSL library. You
#     must comply with the Server Side Public License in all respects for
#     all of the code used other than as permitted herein. If you modify file(s)
#     with this exception, you may extend this exception to your version of the
#     file(s), but you are not obligated to do so. If you do not wish to do so,
#     delete this exception statement from your version. If you delete this
#     exception statement from all source files in the program, then also delete
#     it in the license file.
#
# Consolidated format script for PSMDB CI
#
# This script runs all code formatters and reports which ones found issues.
# It continues running all formatters even if earlier ones make changes,
# then provides a cumulative summary.
#
# Usage:
#   ./.github/scripts/format.sh
#
# Exit codes:
#   0 - All formatters passed (no changes needed)
#   1 - One or more formatters found issues (changes were made)
#   2 - A formatter crashed/failed to run
#

set -o pipefail

FAILED_FORMATTERS=()
EXIT_CODE=0
FORMATTER_CRASHED=0

# Get a hash of the current git diff state
get_diff_hash() {
    git diff 2>/dev/null | md5sum | cut -d' ' -f1
}

# Run a formatter and check for changes
# Arguments:
#   $1 - Display name of the formatter
#   $2 - Command to run
run_formatter() {
    local name="$1"
    local cmd="$2"

    echo "Running $name [$cmd] ..."

    # Capture git diff hash before running formatter
    local before_hash
    before_hash=$(get_diff_hash)

    # Run the formatter
    if ! eval "$cmd"; then
        echo ""
        echo "::error::$name crashed or failed to run"
        echo "ERROR: $name exited with non-zero status"
        FORMATTER_CRASHED=1
        return 1
    fi

    # Check if this formatter made any changes
    local after_hash
    after_hash=$(get_diff_hash)

    if [[ "$before_hash" != "$after_hash" ]]; then
        echo ">>> $name: found formatting issues"
        FAILED_FORMATTERS+=("$name")
        EXIT_CODE=1
    else
        echo ">>> $name: OK (no changes)"
    fi
    return 0
}

echo "Starting format check..."

# Run all formatters
run_formatter "clang-format" "python buildscripts/clang_format.py format" || true
run_formatter "pylinters" "python buildscripts/pylinters.py fix" || true
run_formatter "pylinters-scons" "python buildscripts/pylinters.py fix-scons" || true
run_formatter "eslint" "python buildscripts/eslint.py fix" || true

echo ""
echo "SUMMARY"

if [[ $FORMATTER_CRASHED -ne 0 ]]; then
    echo "::error::One or more formatters crashed during execution"
    echo "Please check the logs above for details."
    exit 2
fi

if [[ ${#FAILED_FORMATTERS[@]} -gt 0 ]]; then
    echo "::error::Formatting issues detected"
    echo ""
    echo "Formatters that found issues:"
    for fmt in "${FAILED_FORMATTERS[@]}"; do
        echo "  - $fmt"
    done
    echo ""
    echo "To fix locally, run:"
    echo ""
    echo "    ./.github/scripts/format.sh"
    echo ""
    echo "Or run individual formatters:"
    echo ""
    echo "    python buildscripts/clang_format.py format"
    echo "    python buildscripts/pylinters.py fix"
    echo "    python buildscripts/pylinters.py fix-scons"
    echo "    python buildscripts/eslint.py fix"
    echo ""
    echo "and commit the resulting changes."
    echo ""
    echo "AFFECTED FILES"
    git diff --stat
    echo ""
    echo "CUMULATIVE DIFF (first 1000 lines)"
    git diff | head -n 1000
    exit 1
else
    echo "All formatters passed successfully!"
    exit 0
fi
