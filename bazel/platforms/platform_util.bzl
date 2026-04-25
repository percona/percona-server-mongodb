load("//bazel/platforms:remote_execution_containers.bzl", "REMOTE_EXECUTION_CONTAINERS")
load("//bazel/platforms:psmdb_rbe_containers.bzl", "PSMDB_REMOTE_EXECUTION_CONTAINERS")

def setup_platform(arch, distro_or_os, cache_silo):
    # Percona override: prefer PSMDB-specific image map for distros we serve
    # via Percona BuildBarn (ghcr.io/vorsel/psmdb-buildbarn-runners). Distros
    # we don't override fall through to upstream MongoDB's quay.io map and
    # will route to MongoDB's BuildBarn (or fail FAILED_PRECONDITION if no
    # such cluster is configured) — same behaviour as a vanilla upstream
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

        # EngFlow's "default" pool is ARM64
        "Pool": "x86_64" if arch == "amd64" else "default",
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
