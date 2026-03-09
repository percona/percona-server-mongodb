# Javascript dependencies that tests in the core suite import.
# This is useful when you need a dependency to be included in
# passthrough suites.
CORE_DATA = [
    "//jstests/aggregation/extras:merge_helpers.js",
    "//jstests/noPassthrough/libs:server_parameter_helpers.js",
    "//jstests/noPassthrough/libs/index_builds:index_build.js",
    "//jstests/sharding/libs:last_lts_mongod_commands.js",
    "//jstests/sharding/libs:last_lts_mongos_commands.js",
    "//src/third_party/schemastore.org:schemas",
    "//x509:generate_main_certificates",
]

# Javascript dependencies that tests in the concurrency suite import.
CONCURRENCY_DATA = [
    "//jstests/concurrency/fsm_libs:all_javascript_files",
    "//jstests/concurrency/fsm_utils:all_javascript_files",
    "//jstests/concurrency/fsm_workload_helpers",
    "//jstests/concurrency/fsm_workload_modifiers:all_subpackage_javascript_files",
    "//jstests/sharding/analyze_shard_key/libs:all_javascript_files",
]
