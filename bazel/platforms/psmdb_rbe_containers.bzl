# PSMDB override of upstream MongoDB's REMOTE_EXECUTION_CONTAINERS map.
#
# Loaded by bazel/platforms/platform_util.bzl as an override layer. For each
# distro_or_os key listed here, Bazel will send the ghcr.io URL below as the
# `container-image` exec property; it then becomes the routing key the
# RBE scheduler matches against worker-registered platform queues. Distros NOT
# listed here fall through to the upstream value in
# bazel/platforms/remote_execution_containers.bzl unchanged.
#
# Each `container-url` points to a multi-arch manifest list published by
# jenkins-pipelines' .github/workflows/build-psmdb-buildbarn-runners.yml.
# x86_64 and arm64 hosts pull different layers from the SAME manifest list,
# so a single URL string per distro suffices: there is NO `-x86_64`/
# `-aarch64` arch suffix on the image name. The arch dimension lives only
# in the `Pool` exec property (set by platform_util.bzl /
# local_config_platform.bzl), which routes to the right worker queue.
#
# debian-bookworm currently has no aarch64 source dir in the GHA matrix —
# its manifest list contains only the amd64 entry, which is still a valid
# (single-entry) multi-arch manifest. arm64 builds with debian12 will fail
# at image pull on the worker, so don't pair a debian-bookworm worker pool
# with `bazel_pool_value: aarch64` until that GHA matrix entry is added.
#
# Routing key === actual runtime image pulled by RBE workers.
# The per-version immutable tag (`:<psmdb-version>-<git-sha-of-jenkins-pipelines>`)
# gives us, for free:
#
#   * branch isolation
#       8.0 / 8.3 / master never collide on routing keys, even when the
#       underlying psmdb_builder_<version>.sh content is byte-for-byte
#       identical at a given moment in time.
#   * automatic action-cache invalidation per image rebuild
#       a new GHA run produces a new <git-sha> suffix → new routing key →
#       previously-cached actions don't satisfy the new platform tuple →
#       Bazel re-executes against the fresh worker. Old cache entries
#       remain accessible to anyone still building from a PSMDB checkout
#       that pins the older tag (see "Cross-release coexistence" below).
#   * ops-controlled rebuild cadence
#       no upstream-MongoDB SHA drift bleeds through. The only thing that
#       moves these values is a Percona-side commit (manual or GHA-bot
#       generated) that bumps the suffix after a deliberate image rebuild.
#
# Cross-release coexistence:
#   Multiple PSMDB release tags can be in active dev simultaneously
#   (e.g. release-8.0.20-8 cut from git-sha A, release-8.0.21-9 from B).
#   Each tag's checkout has its own copy of THIS file pinning a specific
#   immutable image tag. As long as the RBE ondemand-pools.yaml declares
#   pools for both image tags, both releases route correctly and share no
#   cache entries with each other. Ops drops a pool entry from
#   ondemand-pools.yaml only when the corresponding PSMDB release goes EOL.
#
# Maintenance:
#
#   1. After every successful run of jenkins-pipelines'
#      .github/workflows/build-psmdb-buildbarn-runners.yml that should
#      become the new "current" routing target for this PSMDB branch:
#        - update the `container-url` values below, swapping the
#          <git-sha> suffix in every entry to the new
#          ${{ github.sha }} of the GHA run.
#        - The matching pool entry in jenkins-pipelines'
#          IaC/buildbarn/ondemand/compose/config/ondemand-pools.yaml
#          must be added in lockstep, OR builds will succeed action
#          enqueue but fail FAILED_PRECONDITION at scheduler match.
#   2. On upstream merge from MongoDB:
#        - bazel/platforms/remote_execution_containers.bzl is upstream-
#          owned (auto-generated). It can drift freely — we don't read
#          its values for any distro listed here.
#        - bazel/platforms/platform_util.bzl IS PSMDB-modified (single
#          load + fall-through). If upstream changes its structure,
#          resolve the conflict to keep our `psmdb_entry` override path
#          (the deviation is small and easy to re-apply).

PSMDB_REMOTE_EXECUTION_CONTAINERS = {
    "amazon_linux_2023": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/amazonlinux-2023:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
    "debian12": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/debian-bookworm:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
    "rhel8": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/oraclelinux-8:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
    "rhel9": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/oraclelinux-9:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
    "ubuntu22": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/ubuntu-jammy:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
    "ubuntu24": {
        "container-url": "docker://ghcr.io/vorsel/psmdb-buildbarn-runners/ubuntu-noble:8.0-9b28c6ee49dc0118fe6bab8b7e28a87f8979be81",
    },
}
