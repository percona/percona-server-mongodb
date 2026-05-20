# PSMDB override of upstream MongoDB's REMOTE_EXECUTION_CONTAINERS map.
#
# Loaded by bazel/platforms/platform_util.bzl as an override layer. For each
# distro_or_os key listed here, Bazel will send the docker.io URL below as
# the `container-image` exec property; it then becomes the routing key the
# bb-scheduler matches against worker-registered platform queues. Distros
# NOT listed here fall through to the upstream value in
# bazel/platforms/remote_execution_containers.bzl unchanged.
#
# Each `container-url` points to a multi-arch manifest list published into
# the single Docker Hub repository docker.io/perconalab/psmdb-rbe by the
# Jenkins job `hetzner-psmdb-buildbarn-runners` (defined in jenkins-
# pipelines/IaC/buildbarn/runners/build-psmdb-buildbarn-runners.groovy).
# A parallel GHA workflow (jenkins-pipelines/.github/workflows/build-
# psmdb-buildbarn-runners.yml) publishes the same image set to ghcr.io
# for in-fork iteration; this file deliberately points at the DH copy so
# upstream PSMDB-2034 reviewers can pull without GHCR credentials.
#
# x86_64 and arm64 hosts pull different layers from the SAME manifest
# list, so a single URL string per distro suffices: there is NO
# `-x86_64`/`-aarch64` arch suffix on the image name. The arch dimension
# lives only in the `Pool` exec property (set by platform_util.bzl /
# local_config_platform.bzl), which routes to the right worker queue.
#
# Tag schema is `:<distro>-<psmdb-version>-<mongo-sha>` (immutable) with
# `:<distro>-<psmdb-version>` (moving) as a peer alias for dev iteration
# but never referenced from this file. `<mongo-sha>` is the commit SHA
# of the percona-server-mongodb branch the runner image was baked from
# (last commit that touched percona-packaging/scripts/psmdb_builder.sh
# at build time; see the *_resolve_plan_* stage in the Jenkins job).
#
# Routing key === actual runtime image pulled by RBE workers. The
# `<distro>-<psmdb-version>-<mongo-sha>` triple gives us, for free:
#
#   * branch isolation
#       8.0 / 8.3 / master never collide on routing keys, even when the
#       underlying psmdb_builder_<version>.sh content is byte-for-byte
#       identical at a given moment in time.
#   * automatic action-cache invalidation per image rebuild
#       a new Jenkins (or GHA) run that picks up a fresh psmdb_builder.sh
#       commit produces a new <mongo-sha> → new routing key →
#       previously-cached actions don't satisfy the new platform tuple →
#       Bazel re-executes against the fresh worker. Old cache entries
#       remain accessible to anyone still building from a PSMDB checkout
#       that pins the older tag (see "Cross-release coexistence" below).
#   * ops-controlled rebuild cadence
#       no upstream-MongoDB SHA drift bleeds through. The only thing
#       that moves these values is an ops-side commit (manual or
#       Jenkins/GHA-bot generated) that bumps the suffix after a
#       deliberate image rebuild.
#
# Cross-release coexistence:
#   On master multiple in-flight feature checkouts can pin different
#   image-shas simultaneously. Each checkout has its own copy of THIS
#   file pinning a specific immutable image tag. As long as the RBE
#   cluster's ondemand-pools.yaml declares pools for all referenced
#   image tags, builds route correctly and share no cache entries with
#   each other. Ops drops a pool entry from ondemand-pools.yaml only
#   when no remaining branch references it.
#
# Maintenance:
#
#   1. After every successful run of the Jenkins job
#      `hetzner-psmdb-buildbarn-runners` (or the parallel GHA workflow,
#      jenkins-pipelines/.github/workflows/build-psmdb-buildbarn-runners.yml)
#      that should become the new "current" routing target for this
#      PSMDB branch:
#        - update the `container-url` values below, swapping the
#          <mongo-sha> suffix in every entry to the SHA the build
#          actually baked in (printed by the job's "Resolve plan" stage
#          and visible in the merge-stage echo `Pushed ...:<distro>-
#          <version>-<sha>`).
#        - The matching pool entry in jenkins-pipelines'
#          IaC/buildbarn/ondemand/compose/config/ondemand-pools.yaml
#          must be added in lockstep, OR builds will succeed action
#          enqueue but fail FAILED_PRECONDITION at scheduler match.
#   2. On upstream merge from MongoDB:
#        - bazel/platforms/remote_execution_containers.bzl is upstream-
#          owned (auto-generated). It can drift freely — we don't read
#          its values for any distro listed here.
#        - bazel/platforms/platform_util.bzl IS PSMDB-modified
#          (single load + fall-through). If upstream changes its
#          structure, resolve the conflict to keep our `psmdb_entry`
#          override path (the deviation is small and easy to re-apply).

PSMDB_REMOTE_EXECUTION_CONTAINERS = {
    "amazon_linux_2023": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:amazonlinux-2023-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
    "debian12": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:debian-bookworm-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
    "rhel8": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:oraclelinux-8-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
    "rhel9": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:oraclelinux-9-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
    "ubuntu22": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:ubuntu-jammy-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
    "ubuntu24": {
        "container-url": "docker://docker.io/perconalab/psmdb-rbe:ubuntu-noble-8.0-07c5bd008df3acb6e853ebd7c4fefa609c0d03ef",
    },
}
