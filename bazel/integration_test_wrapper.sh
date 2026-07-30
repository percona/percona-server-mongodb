#!/bin/bash

# Self-contained mongod fixture for running mongo_cc_integration_test targets
# under `bazel test` (including on Bazel Remote Execution).
#
# Integration test binaries are CLIENTS: they connect to a fixture whose
# connection string is passed via --connectionString (default localhost:27017,
# see src/mongo/unittest/integration_test_main.idl). In the resmoke flow that
# fixture is started out-of-band on the CI host. On RBE there is no such host,
# so this wrapper starts a private fixture inside the test action's own sandbox
# -- no Docker, no privileges, no change to the RBE worker image -- runs the
# test against it, and tears it down.
#
# Wired in via `--run_under=//bazel:integration_test_wrapper` (see the
# psmdb_remote_integration_test config in .bazelrc.psmdb). mongod, the wrapper,
# and any fixture-specific runfiles (x509 certs, mongo shell) are supplied
# through the test's runfiles by the mongo_cc_integration_test macro.
#
# The fixture topology is chosen per-test by the macro's `fixture` attribute,
# surfaced here as $PSMDB_IT_FIXTURE:
#   standalone (default) : one mongod on 127.0.0.1
#   replset              : a 2-node replica set (rs.initiate via the mongo shell)
#   tls                  : one mongod with TLS + X.509 cluster auth
#   grpc                 : one mongod with TLS + featureFlagGRPC

set -u

FIXTURE="${PSMDB_IT_FIXTURE:-standalone}"

# --- Locate the test binary (mirrors bazel/test_wrapper.sh runfiles logic) ----
# With --nolegacy_external_runfiles the binary lives under $RUNFILES_DIR/_main/.
test_bin="$1"
shift
if [[ -n "${RUNFILES_DIR:-}" && ! -x "$test_bin" ]]; then
    test_bin="${RUNFILES_DIR}/_main/${test_bin}"
fi

runfiles_main="${RUNFILES_DIR:-.}/_main"
cert_dir="${runfiles_main}/x509"

die() {
    echo "integration_test_wrapper: $*" >&2
    exit 1
}

# Locate a binary in the runfiles tree: try the canonical path, then search.
find_runfile_bin() {
    local relpath="$1" name="$2" cand
    for cand in "${runfiles_main}/${relpath}" "${relpath}"; do
        if [[ -x "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    find -L "${RUNFILES_DIR:-.}" . -type f -name "$name" -perm -u+x 2>/dev/null | head -1
}

mongod_bin="$(find_runfile_bin "src/mongo/db/mongod" mongod)"
[[ -n "$mongod_bin" && -x "$mongod_bin" ]] || die "could not locate the mongod binary in runfiles"

test_bin_name="$(basename "$test_bin")"

# --- Per-action ephemeral fixture root ----------------------------------------
fixture_dir=$(mktemp -d -p "${TEST_TMPDIR:-/tmp}" "${test_bin_name}_fixture.XXXXXX")

# mongod (and, under featureFlagGRPC, its gRPC ingress) creates a Unix domain
# socket at <unixSocketPrefix>/mongodb-<port>.sock. AF_UNIX paths are capped at
# ~107 chars (sockaddr_un.sun_path); $TEST_TMPDIR on an RBE worker
# (/worker/build/N/root/bazel-out/.../test.runfiles/_main/...) is long enough
# that appending the socket name overflows it -- gRPC's add_port treats that as
# fatal ("Path name should not have more than 107 characters"), so the listener
# never binds and the test hangs. Keep dbpath under $TEST_TMPDIR (disk space)
# but point the socket at a SHORT /tmp dir. mktemp ensures uniqueness for
# concurrent local runs.
sock_prefix=$(mktemp -d -p /tmp "${test_bin_name}_socks.XXXXXX")

# Track every mongod we spawn so the trap can tear them all down.
mongod_pids=()
# Set by start_mongod; read by wait_ready / wait_grpc_ready and fixture code.
last_node_pid=""
last_node_log=""
last_node_port=""
last_node_grpc_port=""

cleanup() {
    local pid
    for pid in "${mongod_pids[@]:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    rm -rf "${sock_prefix:-}" 2>/dev/null
}
trap cleanup EXIT

# Start one mongod. Args: <node-tag> [extra mongod flags...].
# mongod binds to port 0 so the kernel assigns a free ephemeral port; the
# actual port is obtained via wait_ready after startup.
# Populates last_node_dbpath, last_node_log, last_node_pid and appends to mongod_pids.
start_mongod() {
    local tag="$1"
    shift 1
    local dbpath="${fixture_dir}/${tag}"
    local logpath="${dbpath}/mongod.log"
    mkdir -p "$dbpath"
    last_node_dbpath="$dbpath"
    last_node_log="$logpath"
    "$mongod_bin" \
        --dbpath="$dbpath" \
        --port=0 \
        --bind_ip=127.0.0.1 \
        --unixSocketPrefix="$sock_prefix" \
        --logpath="$logpath" \
        --setParameter=enableTestCommands=1 \
        --setParameter=logComponentVerbosity='{command:2}' \
        "$@" &
    last_node_pid="$!"
    mongod_pids+=("$last_node_pid")
}

# Block until the given mongod is accepting TCP connections and extract the
# kernel-assigned port from the JSON log. Sets last_node_port.
# Args: <logpath> <pid>
wait_ready() {
    local logpath="$1" pid="$2"
    local i line port
    for ((i = 0; i < 240; i++)); do
        line=$(grep '"Waiting for connections"' "$logpath" 2>/dev/null | head -1)
        if [[ -n "$line" ]]; then
            port=$(printf '%s' "$line" | grep -oE '"port":[0-9]+' | grep -oE '[0-9]+')
            if [[ -n "$port" ]]; then
                last_node_port="$port"
                return 0
            fi
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "----- mongod log ($logpath) -----" >&2
            cat "$logpath" >&2 2>/dev/null
            die "mongod exited before accepting connections"
        fi
        sleep 0.5
    done
    echo "----- mongod log ($logpath) -----" >&2
    cat "$logpath" >&2 2>/dev/null
    die "mongod did not become ready within timeout"
}

# Block until the gRPC server has started and extract the kernel-assigned port
# from the "Started gRPC server" JSON log line. Sets last_node_grpc_port.
# Args: <logpath> <pid>
wait_grpc_ready() {
    local logpath="$1" pid="$2"
    local i line addr port
    for ((i = 0; i < 240; i++)); do
        line=$(grep '"Started gRPC server"' "$logpath" 2>/dev/null | head -1)
        if [[ -n "$line" ]]; then
            port=$(printf '%s' "$line" | grep -oE '"addresses":\["[0-9.]*:[0-9]+"' | grep -oE ':[0-9]+"' | grep -oE '[0-9]+')
            if [[ -n "$port" ]]; then
                last_node_grpc_port="$port"
                return 0
            fi
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "----- mongod log ($logpath) -----" >&2
            cat "$logpath" >&2 2>/dev/null
            die "mongod exited before gRPC server started"
        fi
        sleep 0.5
    done
    echo "----- mongod log ($logpath) -----" >&2
    cat "$logpath" >&2 2>/dev/null
    die "mongod gRPC server did not become ready within timeout"
}

require_certs() {
    local f
    for f in ca.pem server.pem client.pem; do
        [[ -f "${cert_dir}/${f}" ]] || die "missing x509 cert ${cert_dir}/${f} (is //x509:generate_main_certificates in this test's runfiles?)"
    done
}

# Extra args appended to the test binary invocation (set by tls/grpc fixtures).
test_extra_args=()

case "$FIXTURE" in
standalone)
    start_mongod standalone
    wait_ready "$last_node_log" "$last_node_pid"
    conn="localhost:${last_node_port}"
    ;;

tls)
    # A single mongod with TLS and X.509 cluster auth. The SSL test
    # (network_interface_ssl_test) reads its certs from $INSTALL_DIR/x509
    # and connects as the internal __system user over TLS.
    require_certs
    start_mongod tls \
        --tlsMode=requireTLS \
        --tlsCAFile="${cert_dir}/ca.pem" \
        --tlsCertificateKeyFile="${cert_dir}/server.pem" \
        --tlsClusterFile="${cert_dir}/server.pem" \
        --clusterAuthMode=x509 \
        --tlsAllowInvalidHostnames
    wait_ready "$last_node_log" "$last_node_pid"
    # The test resolves $INSTALL_DIR/x509/{ca,client,server}.pem itself.
    export INSTALL_DIR="${runfiles_main}"
    conn="localhost:${last_node_port}"
    ;;

grpc)
    # A single mongod with TLS + gRPC ingress. The test connects over the
    # gRPC egress path with TLS client credentials.
    require_certs
    # --grpcPort has a gte:1 validator so port 0 is rejected. Pick a random port
    # from a wide range; on RBE each action has its own network namespace so
    # cross-action clashes cannot occur. $RANDOM keeps local concurrent runs apart.
    grpc_port=$((40000 + RANDOM % 20000))
    start_mongod grpc \
        --tlsMode=preferTLS \
        --tlsCAFile="${cert_dir}/ca.pem" \
        --tlsCertificateKeyFile="${cert_dir}/server.pem" \
        --grpcPort="$grpc_port" \
        --setParameter=featureFlagGRPC=true
    grpc_log="$last_node_log"
    grpc_pid="$last_node_pid"
    wait_ready "$grpc_log" "$grpc_pid"
    wait_grpc_ready "$grpc_log" "$grpc_pid"
    # The gRPC egress client connects directly to the gRPC listener, so the
    # connection string must name the gRPC port (not the normal wire port).
    conn="localhost:${grpc_port}"
    test_extra_args=(
        --useEgressGRPC=true
        --tlsMode=preferTLS
        --tlsCAFile="${cert_dir}/ca.pem"
        --tlsCertificateKeyFile="${cert_dir}/client.pem"
    )
    ;;

replset)
    # A 2-node replica set. rs.initiate() is issued via the mongo shell
    # (staged as a runfile for this fixture), then we wait for a primary.
    mongo_bin="$(find_runfile_bin "src/mongo/shell/mongo" mongo)"
    [[ -n "$mongo_bin" && -x "$mongo_bin" ]] || die "could not locate the mongo shell in runfiles"
    start_mongod rs0 --replSet=rs0
    rs0_log="$last_node_log"
    rs0_pid="$last_node_pid"
    start_mongod rs1 --replSet=rs0
    rs1_log="$last_node_log"
    rs1_pid="$last_node_pid"
    wait_ready "$rs0_log" "$rs0_pid"
    p0="$last_node_port"
    wait_ready "$rs1_log" "$rs1_pid"
    p1="$last_node_port"
    # Initiate the set and wait for a writable primary in ONE shell process.
    # A fresh shell per poll cost ~2s startup each (minutes of wall clock);
    # a single long-lived connection also keeps db bound to the node we
    # initiated. Use runCommand({hello:1}) rather than the db.hello() helper
    # so this does not depend on shell-helper availability, and dump
    # rs.status() on timeout so a genuine election failure is diagnosable.
    init_js="
            assert.commandWorked(rs.initiate({_id: 'rs0', members: [
                {_id: 0, host: '127.0.0.1:${p0}'},
                {_id: 1, host: '127.0.0.1:${p1}'}]}));
            var ok = false;
            for (var i = 0; i < 120; i++) {
                try {
                    if (db.runCommand({hello: 1}).isWritablePrimary === true) {
                        ok = true;
                        break;
                    }
                } catch (e) {}
                sleep(500);
            }
            if (!ok) {
                print('integration_test_wrapper: no primary; rs.status() = ' + tojson(rs.status()));
            }
            quit(ok ? 0 : 1);
        "
    "$mongo_bin" --host 127.0.0.1 --port "$p0" --quiet --eval "$init_js" ||
        die "replica set did not elect a primary within timeout"
    # integration_test_main parses --connectionString with
    # ConnectionString::parse(), whose replica-set form is
    # "<setName>/<host1>,<host2>" -- NOT a mongodb:// URI (that yields
    # "FailedToParse: Did not consume whole string").
    conn="rs0/127.0.0.1:${p0},127.0.0.1:${p1}"
    ;;

*)
    die "unknown PSMDB_IT_FIXTURE='${FIXTURE}' (expected standalone|replset|tls|grpc)"
    ;;
esac

# --- Run the test against the fixture -----------------------------------------
"$test_bin" "$@" "${test_extra_args[@]}" --connectionString="$conn"
exit $?
