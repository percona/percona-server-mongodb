"""Repository rule for optionally loading mothra teams data."""

def _mothra_repo(ctx):
    """Creates a repository for mothra teams data.

    If the mothra directory exists, it will be used.
    Otherwise, a stub with empty teams will be created.
    """
    mothra_path = ctx.path(ctx.workspace_root).get_child("mothra")

    if mothra_path.exists:
        # Mothra directory exists, symlink to it
        for item in mothra_path.readdir():
            ctx.symlink(item, item.basename)

        ctx.file(
            "BUILD.bazel",
            """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "teams",
    srcs = glob(["mothra/teams/*.yaml"]),
)
""",
        )
    else:
        # Create a stub team file to satisfy runfiles resolution
        ctx.file(
            "mothra/teams/devprod.yaml",
            """# This is an intentionally empty stub. The real mothra repo was not cloned. For the real team mappings to be used, clone 10gen/mothra into mothra.
teams: []
""",
        )

        ctx.file(
            "BUILD.bazel",
            """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "teams",
    srcs = glob(["mothra/teams/*.yaml"]),
)
""",
        )

mothra_repository = repository_rule(
    implementation = _mothra_repo,
    local = True,
    configure = True,
)
