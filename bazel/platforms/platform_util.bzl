load("//bazel/platforms:remote_execution_containers.bzl", "REMOTE_EXECUTION_CONTAINERS")
load("//bazel/platforms:psmdb_rbe_containers.bzl", "PSMDB_REMOTE_EXECUTION_CONTAINERS")

def setup_platform(arch, distro_or_os, cache_silo):
    # PSMDB override: prefer PSMDB-specific image map for distros we serve
    # via the RBE cluster (ghcr.io/vorsel/psmdb-buildbarn-runners). Distros
    # we don't override fall through to upstream MongoDB's quay.io map and
    # will route to MongoDB's RBE cluster (or fail FAILED_PRECONDITION if
    # no such cluster is configured) — same behaviour as a vanilla upstream
    # checkout. See bazel/platforms/psmdb_rbe_containers.bzl for rationale
    # and maintenance procedure.
    psmdb_entry = PSMDB_REMOTE_EXECUTION_CONTAINERS.get(distro_or_os)
    container_url = (
        psmdb_entry["container-url"]
        if psmdb_entry
        else REMOTE_EXECUTION_CONTAINERS[distro_or_os]["container-url"]
    )

    exec_properties = {
        "container-image": container_url,
        "dockerNetwork": "standard",

        # PSMDB RBE workers register with explicit Pool=x86_64 / Pool=aarch64
        # (see jenkins-pipelines IaC/buildbarn/ondemand/compose/config/
        # ondemand-pools.yaml `bazel_pool_value`). Upstream's default of
        # "default" for non-amd64 was for EngFlow's ARM64 pool naming; we
        # diverge here so the routing key matches our worker registration.
        "Pool": "x86_64" if arch == "amd64" else "aarch64",
    }

    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:arm64" if arch == "arm64" else "@platforms//cpu:x86_64",
        ":" + distro_or_os,
        ":use_mongo_toolchain",
    ]

    if cache_silo:
        exec_properties.update({"cache-silo-key": distro_or_os + "_" + arch})
    else:
        # remote execution platforms assume a given kernel version
        constraint_values.append(":kernel_version_4_4_or_greater")

    native.platform(
        name = distro_or_os + "_" + arch + cache_silo,
        constraint_values = constraint_values,
        exec_properties = exec_properties,
    )
