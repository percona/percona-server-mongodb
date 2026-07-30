#!/bin/bash

# Self-contained standalone-mongod fixture for running mongo_cc_integration_test
# targets under `bazel test` (including on Bazel Remote Execution).
#
# Integration test binaries are CLIENTS: they connect to a fixture whose
# connection string is passed via --connectionString (default localhost:27017,
# see src/mongo/unittest/integration_test_main.idl). In the resmoke flow that
# fixture is started out-of-band on the CI host. On RBE there is no such host,
# so this wrapper starts a private standalone mongod inside the test action's
# own sandbox -- no Docker, no privileges, no change to the RBE worker image --
# runs the test against it, and tears it down.
#
# Wired in via `--run_under=//bazel:integration_test_wrapper` (see the
# psmdb_remote_integration_test config in .bazelrc.psmdb). The mongod binary is
# supplied through the test's runfiles by the mongo_cc_integration_test macro
# (data += //src/mongo/db:mongod, gated on //bazel/config:remote_test_enabled).

set -u

# --- Locate the test binary (mirrors bazel/test_wrapper.sh runfiles logic) ----
# With --nolegacy_external_runfiles the binary lives under $RUNFILES_DIR/_main/.
test_bin="$1"
shift
if [[ -n "${RUNFILES_DIR:-}" && ! -x "$test_bin" ]]; then
    test_bin="${RUNFILES_DIR}/_main/${test_bin}"
fi

# --- Locate mongod in the runfiles tree ---------------------------------------
# The macro adds //src/mongo/db:mongod to `data`, so its output lands at
# src/mongo/db/mongod under the runfiles root. Fall back to a search if the
# canonical path is not present (e.g. a future output-path change).
mongod_bin=""
for cand in \
    "${RUNFILES_DIR:-}/_main/src/mongo/db/mongod" \
    "src/mongo/db/mongod"; do
    if [[ -x "$cand" ]]; then
        mongod_bin="$cand"
        break
    fi
done
if [[ -z "$mongod_bin" ]]; then
    mongod_bin="$(find -L "${RUNFILES_DIR:-.}" . -type f -name mongod -perm -u+x 2>/dev/null | head -1)"
fi
if [[ -z "$mongod_bin" || ! -x "$mongod_bin" ]]; then
    echo "integration_test_wrapper: could not locate the mongod binary in runfiles" >&2
    exit 1
fi

# --- Fixture working directory (ephemeral, writable, per-action) --------------
fixture_dir="${TEST_TMPDIR:-/tmp}/it-fixture.$$"
dbpath="${fixture_dir}/db"
logpath="${fixture_dir}/mongod.log"
mkdir -p "$dbpath"

# Derive a port that avoids the well-known 27017 to reduce collision risk when
# actions are not fully network-isolated. mongod opens a TCP listener on
# 127.0.0.1:$port AND a Unix domain socket at $dbpath/mongodb-$port.sock.
port=$(( 20000 + ($$ % 20000) ))
sock="${dbpath}/mongodb-${port}.sock"

cleanup() {
    if [[ -n "${mongod_pid:-}" ]] && kill -0 "$mongod_pid" 2>/dev/null; then
        kill "$mongod_pid" 2>/dev/null
        wait "$mongod_pid" 2>/dev/null
    fi
}
trap cleanup EXIT

# --- Start the standalone mongod fixture --------------------------------------
# enableTestCommands + logComponentVerbosity{command:2} match the resmoke
# integration_tests_standalone suite (buildscripts/resmokeconfig/suites/).
"$mongod_bin" \
    --dbpath="$dbpath" \
    --port="$port" \
    --bind_ip=127.0.0.1 \
    --unixSocketPrefix="$dbpath" \
    --logpath="$logpath" \
    --setParameter=enableTestCommands=1 \
    --setParameter=logComponentVerbosity='{command:2}' &
mongod_pid=$!

# --- Wait for readiness -------------------------------------------------------
ready=0
for _ in $(seq 1 120); do
    if grep -q "Waiting for connections" "$logpath" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$mongod_pid" 2>/dev/null; then
        echo "integration_test_wrapper: mongod exited before accepting connections" >&2
        cat "$logpath" >&2 2>/dev/null
        exit 1
    fi
    sleep 0.5
done
if [[ "$ready" -ne 1 ]]; then
    echo "integration_test_wrapper: mongod did not become ready within timeout" >&2
    cat "$logpath" >&2 2>/dev/null
    exit 1
fi

# --- Choose the fixture transport ---------------------------------------------
# Default to TCP loopback (localhost:$port), which mirrors the resmoke fixture
# and is almost always available. Set PSMDB_IT_FIXTURE_TRANSPORT=uds to connect
# over the Unix domain socket instead -- fully hermetic, used to validate on RBE
# workers where loopback TCP might be restricted.
if [[ "${PSMDB_IT_FIXTURE_TRANSPORT:-tcp}" == "uds" ]]; then
    # URL-encode the socket path (mongo_uri requires the .sock suffix).
    conn="mongodb://${sock//\//%2F}"
else
    conn="localhost:${port}"
fi

# --- Run the test against the fixture -----------------------------------------
"$test_bin" "$@" --connectionString="$conn"
ret=$?

exit $ret
