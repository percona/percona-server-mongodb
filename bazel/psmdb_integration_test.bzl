"""PSMDB (PSMDB-1924): RBE self-contained integration-test fixture wiring.

Extracted from the upstream `mongo_cc_integration_test` macro in
bazel/mongo_src_rules.bzl so upstream merges touch as little Percona code as
possible: that macro keeps only a small, clearly-marked call seam and delegates
the fixture logic here. See the "bazel/mongo_src_rules.bzl" conflict hint in
.mergai/invariants.md.
"""

# fixture kind -> extra runfiles the wrapper needs on the remote executor, on top
# of the wrapper script and mongod that every fixture needs. Keep the keys in
# sync with the `case "$FIXTURE"` in bazel/integration_test_wrapper.sh.
_FIXTURE_RUNFILES = {
    "standalone": [],
    "tls": ["//x509:generate_main_certificates"],
    "grpc": ["//x509:generate_main_certificates"],
    "replset": ["//src/mongo/shell:mongo"],
}

def psmdb_integration_test_data(name, fixture, data):
    """Return `data` plus the RBE fixture runfiles for `fixture`.

    Under --config=remote_test only, augments a mongo_cc_integration_test's `data`
    with the runfiles that let //bazel:integration_test_wrapper start `fixture` in the
    test action's own sandbox (there is no fixture host on RBE). The wrapper is wired
    as --run_under by the psmdb_remote_integration_test profile in .bazelrc.psmdb, and
    the run_under script must be a declared runfile to reach the remote executor
    (mirrors how the base rule adds //bazel:test_wrapper). Gated on remote_test so the
    default resmoke path, which provides its own fixture out-of-band, is not burdened
    with these dependencies. Fails at analysis time on an unknown fixture.
    """
    if fixture not in _FIXTURE_RUNFILES:
        fail("mongo_cc_integration_test(%s): unknown fixture '%s', expected one of %s" %
             (name, fixture, sorted(_FIXTURE_RUNFILES.keys())))
    return data + select({
        "//bazel/config:remote_test_enabled": [
            "//bazel:integration_test_wrapper",
            "//src/mongo/db:mongod",
        ] + _FIXTURE_RUNFILES[fixture],
        "//conditions:default": [],
    })
