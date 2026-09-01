#!/usr/bin/env python3
import os
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(REPO_ROOT))

# This script should be careful not to disrupt automatic mechanism which
# may be expecting certain stdout, always print to stderr.
sys.stdout = sys.stderr

from bazel.wrapper_hook.install_modules import bootstrap_modules
from bazel.wrapper_hook.quality_checks import (
    _invocation_may_run_lint,
    _quality_checks_invocation,
    run_quality_checks,
)
from bazel.wrapper_hook.wrapper_debug import wrapper_debug
from bazel.wrapper_hook.wrapper_util import get_terminal_stream

wrapper_debug(f"wrapper hook script is using {sys.executable}")


# Append new_args before the '--' separator if it exists
def append_args(args, new_args):
    if "--" in args:
        separator_index = args.index("--")
        return args[:separator_index] + new_args + args[separator_index:]
    else:
        return args + new_args


def _has_config_value(args, name: str) -> bool:
    """True iff `--config=<name>` or `--config <name>` is present in args.

    Bazel accepts both forms; covering only `--config=<name>` lets the
    space-separated form slip past guards that gate RBE wiring.

    Stop scanning at the `--` separator: anything after it goes to the
    test/run binary, not to Bazel, so e.g.
    `bazel test //... -- --config psmdb_buildfarm` must NOT be mis-read
    as a Bazel config.
    """
    for i, a in enumerate(args):
        if a == "--":
            return False
        if a == f"--config={name}":
            return True
        if a == "--config" and i + 1 < len(args) and args[i + 1] == name:
            return True
    return False


def _supports_color(stream):
    if os.name == "nt":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return stream.isatty()
    except Exception:
        return False


def _info_prefix(stream):
    if _supports_color(stream):
        GREEN = "\x1b[0;32m"
        RESET = "\x1b[0m"
        return f"{GREEN}INFO{RESET}:"
    return "INFO:"


def _fmt_duration(seconds: float) -> str:
    return f"{seconds*1000:.1f} ms" if seconds < 1 else f"{seconds:.3f} s"


def _info(msg: str, printer=print, stream=None):
    run_with_terminal_output(lambda: printer(f"{_info_prefix(stream or sys.stdout)} {msg}"))


def run_with_terminal_output(func, *args, **kwargs):
    term_err = get_terminal_stream("MONGO_WRAPPER_STDERR_FD")
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        if term_err is not None:
            sys.stdout = term_err
            sys.stderr = term_err
        return func(*args, **kwargs)

    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


def _write_wrapper_status(*, handled: bool, exit_code: int) -> bool:
    status_file = os.environ.get("MONGO_BAZEL_WRAPPER_STATUS")
    if status_file is None:
        return False
    Path(status_file).write_text(
        f"handled={int(handled)}\nexit_code={exit_code}\n",
        encoding="utf-8",
    )
    return True


def _wrapper_status_is_handled() -> bool:
    """Return whether a re-executed wrapper child already handled the command."""

    status_file = os.environ.get("MONGO_BAZEL_WRAPPER_STATUS")
    if status_file is None:
        return False
    try:
        return "handled=1" in Path(status_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return False


def _prepare_bazel_configuration(
    args: list[str],
    *,
    apply_persisted_config: bool = False,
) -> tuple[list[str], bool, bool, list[str]]:
    """Apply the normal wrapper configuration without running generated-file setup."""

    from bazel.wrapper_hook.check_resources import check_resource
    from bazel.wrapper_hook.generate_common_bes_bazelrc import write_workstation_bazelrc
    from bazel.wrapper_hook.plus_interface import swap_default_config
    from bazel.wrapper_hook.write_wrapper_hook_bazelrc import write_wrapper_hook_bazelrc

    configured_args = list(args)
    added_options = []
    enterprise = True
    atlas = True
    enterprise_mod = REPO_ROOT / "src" / "mongo" / "db" / "modules" / "enterprise"
    if not enterprise_mod.exists():
        enterprise = False
        # PSMDB-2034: Skip the auto-injection of `--config=local`
        # when the user has explicitly opted into RBE remote execution
        # via `--config=psmdb_buildfarm`. Upstream's `--config=local`
        # resets `--remote_executor` and `--remote_cache` to the empty
        # string; appended after psmdb_buildfarm it silently turns the
        # build into a fully local one (Bazel's "later --config wins on
        # conflicting flags" rule), defeating the whole point of the RBE
        # flag. `--//bazel/config:build_enterprise=False` is otherwise
        # compensated for by the file-wide `build --build_enterprise=False`
        # line in .bazelrc.psmdb plus the explicit
        # `common:psmdb_buildfarm --//bazel/config:build_enterprise=False`
        # added in the RBE stanza, so dropping it here is safe.
        if not _has_config_value(args, "psmdb_buildfarm"):
            added_options.extend(["--//bazel/config:build_enterprise=False", "--config=local"])
            print(
                f"{enterprise_mod.relative_to(REPO_ROOT).as_posix()} missing, defaulting to "
                "local non-enterprise build (--config=local "
                "--//bazel/config:build_enterprise=False). Add the directory to not "
                "automatically add these options."
            )

    atlas_mod = REPO_ROOT / "src" / "mongo" / "db" / "modules" / "atlas"
    if not atlas_mod.exists():
        atlas = False
        added_options.append("--//bazel/config:build_atlas=False")

    configured_args.extend(added_options)
    config_mode = None
    user_specified_config = False
    for index, arg in enumerate(configured_args):
        value = None
        if arg.startswith("--config="):
            value = arg.split("=", 1)[1]
        elif arg == "--config" and index + 1 < len(configured_args):
            value = configured_args[index + 1]
        if value is not None:
            user_specified_config = True
            if value in {"opt", "dbg", "fastbuild", "dbg_aubsan", "dbg_tsan"}:
                config_mode = value
    if apply_persisted_config:
        # Normal Bazel invocations apply this inside test_runner_interface,
        # where the actual command and target positions are known. Pseudo
        # targets bypass that path, so resolve the persisted mode without
        # mutating their original argument vector.
        resolved_config = swap_default_config(
            [],
            "run",
            config_mode,
            False,
            False,
            user_specified_config,
        )
        if not user_specified_config and resolved_config is not None:
            added_options.append(f"--config={resolved_config}")

    if any(arg.startswith("--include_mongot") for arg in configured_args):
        os.makedirs("mongot-localdev", exist_ok=True)

    write_workstation_bazelrc(configured_args)
    write_wrapper_hook_bazelrc(configured_args)
    check_resource()
    return configured_args, enterprise, atlas, added_options


def _run_quality_check_generators() -> None:
    """Materialize ignored Bazel metadata required by whole-repository lint queries."""

    from bazel.auto_header.auto_header import gen_auto_headers
    from bazel.auto_header.gen_all_headers import spawn_all_headers_thread
    from bazel.resmoke.derive_suite_selectors import gen_suite_selectors
    from bazel.wrapper_hook.autogenerated_targets import autogenerate_targets

    all_headers_thread, all_headers_state = spawn_all_headers_thread(REPO_ROOT)
    suite_state = {}

    def generate_suites() -> None:
        suite_state["result"] = gen_suite_selectors(REPO_ROOT)

    suite_thread = threading.Thread(target=generate_suites, daemon=True)
    suite_thread.start()
    started = time.perf_counter()
    auto_headers_state = gen_auto_headers(REPO_ROOT)
    all_headers_thread.join()
    suite_thread.join()

    failures = []
    for label, state in (
        ("all_headers", all_headers_state),
        ("auto_headers", auto_headers_state),
    ):
        if state["ok"]:
            wrapper_debug(f'{label}: ({"wrote" if state["wrote"] else "nochange"})')
        else:
            print(f'[{label}] failed: {state["err"]!r}')
            failures.append(label)

    generated_suites = suite_state.get(
        "result", {"ok": False, "wrote": False, "err": "thread failed", "warnings": []}
    )
    if generated_suites["ok"]:
        for warning in generated_suites.get("warnings", []):
            _info(f"suite_selectors WARNING: {warning}")
    else:
        print(f'[suite_selectors] failed: {generated_suites["err"]!r}')
        failures.append("suite_selectors")

    _info(f"quality-check preparation: {_fmt_duration(time.perf_counter() - started)}")
    if failures:
        raise RuntimeError(f"quality-check generation failed: {', '.join(failures)}")
    autogenerate_targets(sys.argv, sys.argv[1])


def main():
    quality_checks_args = tuple(sys.argv[2:])
    quality_invocation = _quality_checks_invocation(quality_checks_args)
    if quality_invocation is not None:
        exit_code = 2
        try:
            bootstrap_modules(sys.argv[1], sys.argv[1:])
            if _invocation_may_run_lint(quality_invocation):
                _run_quality_check_generators()
            _configured_args, _enterprise, _atlas, added_options = _prepare_bazel_configuration(
                sys.argv,
                apply_persisted_config=True,
            )
            exit_code = run_quality_checks(
                sys.argv[1], quality_checks_args, extra_bazel_options=added_options
            ).exit_code
        except KeyboardInterrupt:
            exit_code = 130
        except SystemExit as exc:
            # Windows dependency bootstrap waits for a re-executed child and
            # then raises SystemExit with that child's status. The child has
            # already written the handled response, so do not overwrite it.
            if _wrapper_status_is_handled():
                return
            if os.environ.get("MONGO_BAZEL_WRAPPER_STATUS") is None:
                raise
            print(f"Unable to prepare the quality-check runner: SystemExit: {exc}")
            exit_code = 2
        except Exception as exc:
            print(f"Unable to prepare the quality-check runner: {type(exc).__name__}: {exc}")
            exit_code = 2

        try:
            wrote_status = _write_wrapper_status(handled=True, exit_code=exit_code)
        except OSError as exc:
            print(f"Unable to write Bazel wrapper status: {exc}")
            sys.exit(2)
        if not wrote_status:
            sys.exit(exit_code)
        return

    bootstrap_modules(sys.argv[1], sys.argv[1:])

    from bazel.auto_header.auto_header import gen_auto_headers
    from bazel.auto_header.gen_all_headers import spawn_all_headers_thread
    from bazel.resmoke.derive_suite_selectors import gen_suite_selectors
    from bazel.wrapper_hook.autogenerated_targets import autogenerate_targets

    # from bazel.wrapper_hook.git_age_check import check as git_age_check
    from bazel.wrapper_hook.plus_interface import check_bazel_command_type, test_runner_interface
    from bazel.wrapper_hook.rbe_auth import RbeAuthError, RbeAuthRequired, get_id_token

    th_all_header, hdr_state_all_header = spawn_all_headers_thread(REPO_ROOT)

    # Run resmoke suite selector generation in parallel with auto header generation
    suite_sel_state_container = {}

    def _run_suite_selectors():
        suite_sel_state_container["result"] = gen_suite_selectors(REPO_ROOT)

    th_suite_selectors = threading.Thread(target=_run_suite_selectors, daemon=True)
    th_suite_selectors.start()

    start = time.perf_counter()
    auto_hdr_state = gen_auto_headers(REPO_ROOT)
    th_all_header.join()
    th_suite_selectors.join()

    if hdr_state_all_header["ok"]:
        wrapper_debug(f'({"wrote" if hdr_state_all_header["wrote"] else "nochange"})')
    else:
        print(f'[all_headers] failed: {hdr_state_all_header["err"]!r}')

    if auto_hdr_state["ok"]:
        wrapper_debug(f'({"wrote" if auto_hdr_state["wrote"] else "nochange"})')
    else:
        print(f'[auto_headers] failed: {auto_hdr_state["err"]!r}')

    suite_sel_state = suite_sel_state_container.get(
        "result", {"ok": False, "wrote": False, "err": "thread failed", "count": 0, "warnings": []}
    )
    if suite_sel_state["ok"]:
        wrapper_debug(
            f'suite_selectors: ({"wrote" if suite_sel_state["wrote"] else "nochange"}, {suite_sel_state["count"]} suites)'
        )
        for warning in suite_sel_state.get("warnings", []):
            _info(f"suite_selectors WARNING: {warning}")
    else:
        print(f'[suite_selectors] failed: {suite_sel_state["err"]!r}')

    t_total_s = time.perf_counter() - start
    _info(f"pre-build generation: {_fmt_duration(t_total_s)}")

    # This is used to autogenerate a BUILD.bazel that creates
    # Filegroups for select tags - used to group targets for installing
    autogenerate_targets(sys.argv, sys.argv[1])

    enterprise = True
    atlas = True
    if check_bazel_command_type(sys.argv[1:]) not in ["clean", "shutdown", "version", None]:
        args, enterprise, atlas, _added_options = _prepare_bazel_configuration(sys.argv)
        # Disable git age check for now, to avoid issues wth merge commits
        # git_age_check()

        args = run_with_terminal_output(
            test_runner_interface,
            args[1:],
            autocomplete_query=os.environ.get("MONGO_AUTOCOMPLETE_QUERY") == "1",
            enterprise=enterprise,
            atlas=atlas,
        )

        # PSMDB-2034: pre-flight the RBE buildfarm credential cache when
        # this build is going to talk to the on-demand cluster. Detection
        # keys off `--config=psmdb_buildfarm` (the only config that
        # populates --remote_executor / --remote_cache / --bes_backend at
        # the bazel build command line — see .bazelrc.psmdb). Local /
        # CI-side EngFlow / public-release builds keep travelling through
        # engflow_auth above and never hit Dex.
        #
        # We do NOT append --remote_header / --bes_header here anymore.
        # That lived in PSMDB-2043 as a static one-shot Bearer baked
        # into argv, and it could not survive token expiry mid-build.
        # Authentication is now driven by Bazel's CredentialHelper
        # protocol — see `--credential_helper=…=bazel/wrapper_hook/credential_helper.py`
        # in .bazelrc.psmdb. Bazel re-invokes the helper whenever the
        # cached entry is about to expire, giving us mid-build rotation
        # for free.
        #
        # The pre-flight here only covers what the helper cannot do
        # itself: open a Device Code flow on a TTY. The helper runs as
        # a Bazel subprocess with no controlling terminal, so it can
        # only refresh, not log in fresh. Running `get_id_token()` here
        # makes sure the cache is seeded (or freshly refreshed) before
        # Bazel ever spawns the helper. CI runs that already have a
        # PSMDB_RBE_DEX_TOKEN / PSMDB_RBE_JENKINS_TOKEN exported skip
        # the pre-flight entirely — they don't need the local cache,
        # and forcing a Device Code flow on a non-TTY runner that
        # *does* have a valid CI token would just fail spuriously.
        if _has_config_value(args, "psmdb_buildfarm"):
            from bazel.wrapper_hook import rbe_auth

            # PSMDB_RBE_JENKINS_TOKEN_FILE is the preferred CI subject-token
            # source (sidecar-rotated path, see credential_helper.py). Treat
            # it as a CI-token presence signal too, so pre-flight is skipped
            # whenever credential_helper can authenticate non-interactively.
            #
            # PSMDB-2099 — ACTIONS_ID_TOKEN_REQUEST_URL is the GitHub Actions
            # equivalent: the runtime injects this env var only when the
            # workflow declares `permissions: id-token: write`, which is also
            # exactly when credential_helper's GHA tier can mint a fresh
            # subject_token on demand. Skipping pre-flight on its presence
            # avoids the misleading "RBE buildfarm needs a fresh login but
            # no TTY is attached" message on GHA runners (which never have
            # a TTY and never need an interactive Device Code flow because
            # they authenticate via OIDC subject_token exchange).
            ci_token_present = bool(
                os.environ.get("PSMDB_RBE_DEX_TOKEN", "").strip()
                or os.environ.get("PSMDB_RBE_JENKINS_TOKEN", "").strip()
                or os.environ.get("PSMDB_RBE_JENKINS_TOKEN_FILE", "").strip()
                or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "").strip()
            )
            if ci_token_present:
                wrapper_debug(
                    "rbe_auth: CI-token signal env var set "
                    "(PSMDB_RBE_DEX_TOKEN / PSMDB_RBE_JENKINS_TOKEN / "
                    "PSMDB_RBE_JENKINS_TOKEN_FILE / "
                    "ACTIONS_ID_TOKEN_REQUEST_URL); skipping pre-flight "
                    "(credential_helper will handle CI auth)"
                )
            else:
                wrapper_debug("rbe_auth: --config=psmdb_buildfarm detected, priming OIDC cache")
                pre = rbe_auth.status()
                wrapper_debug(
                    f"rbe_auth: cache before — present={pre.get('present')} "
                    f"fresh={pre.get('fresh')} expires_at={pre.get('expires_at', 0)} "
                    f"sub={pre.get('subject', '')!r}"
                )
                try:
                    run_with_terminal_output(get_id_token)
                except RbeAuthRequired as e:
                    _info(f"RBE auth: {e}")
                    sys.exit(4)
                except RbeAuthError as e:
                    _info(f"RBE auth failed: {e}")
                    sys.exit(4)
                post = rbe_auth.status()
                wrapper_debug(
                    f"rbe_auth: cache after  — present={post.get('present')} "
                    f"fresh={post.get('fresh')} expires_at={post.get('expires_at', 0)} "
                    f"groups={post.get('groups')}"
                )
    else:
        args = sys.argv[2:]

    os.chmod(os.environ.get("MONGO_BAZEL_WRAPPER_ARGS"), 0o644)
    with open(os.environ.get("MONGO_BAZEL_WRAPPER_ARGS"), "w") as f:
        if args:
            f.write("\n".join(args))
            f.write("\n")
    _write_wrapper_status(handled=False, exit_code=0)


if __name__ == "__main__":
    main()
