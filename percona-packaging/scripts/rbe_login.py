#!/usr/bin/env python3
"""
PSMDB-2043: Standalone CLI for the Bazel RBE buildfarm OIDC login.

Modes:
  rbe_login.py                force a fresh Device Code flow (overwrites cache)
  rbe_login.py --status       print cache state (no network)
  rbe_login.py --logout       wipe ~/.cache/rbe/token.json
  rbe_login.py --print-token  write the cached id_token to stdout (for grpcurl etc.)

Most users never need to invoke this directly: bazel/wrapper_hook/wrapper_hook.py
runs the same flow on demand the first time they `bazel build --config=psmdb_buildfarm`
on a new machine, and silently refreshes thereafter. This script exists for the
cases where wrapper_hook fails the user too late in the build (no TTY, revoked
refresh token mid-run), for ad-hoc smoke tests with `grpcurl`, and for Jenkins
runners that want to seed the token cache before invoking Bazel.

Lives in percona-packaging/scripts/ rather than bazel/wrapper_hook/ because:
  * it's a Percona-specific dev/ops utility, not a Bazel hook
  * the bazel/wrapper_hook py_library is imported by Bazel itself; mixing a
    runnable CLI in there is confusing
  * the original `bazel-rbe-login` filename matched the repo's `bazel-*`
    .gitignore rule (intended for Bazel's output symlinks at repo root), so
    git silently never tracked it. Being out of bazel/ entirely sidesteps that.
"""

import argparse
import datetime as dt
import pathlib
import sys


def _find_repo_root(start: pathlib.Path) -> pathlib.Path:
    """Walk up from `start` until we find a repo-root marker (`.bazelrc`
    or `MODULE.bazel`). Falls back to `start` if neither found, which
    keeps behaviour reasonable when the script is copied somewhere
    arbitrary (e.g. /usr/local/bin) and run on a system that has
    rbe_auth.py PYTHONPATH'd next to it.
    """
    cur = start.resolve()
    for parent in (cur, *cur.parents):
        if (parent / ".bazelrc").is_file() or (parent / "MODULE.bazel").is_file():
            return parent
    return start


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = _find_repo_root(SCRIPT_DIR)

if (REPO_ROOT / "bazel" / "wrapper_hook" / "rbe_auth.py").is_file():
    sys.path.insert(0, str(REPO_ROOT))
    from bazel.wrapper_hook import rbe_auth  # type: ignore[import-not-found]
else:
    sys.path.insert(0, str(SCRIPT_DIR))
    import rbe_auth  # type: ignore[import-not-found]


def _fmt_expiry(expires_at: int) -> str:
    if not expires_at:
        return "unknown"
    try:
        when = dt.datetime.fromtimestamp(expires_at, tz=dt.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return f"raw={expires_at}"
    delta = expires_at - int(dt.datetime.now(dt.timezone.utc).timestamp())
    suffix = "expired" if delta <= 0 else f"in {delta // 60}m{delta % 60}s"
    return f"{when.isoformat()} ({suffix})"


def _cmd_status() -> int:
    s = rbe_auth.status()
    if not s.get("present"):
        print("rbe-auth: no cached token (run `percona-packaging/scripts/rbe_login.py` to authenticate).")
        return 1
    print(f"rbe-auth: token cache    : {rbe_auth.CACHE_PATH}")
    print(f"rbe-auth: issuer         : {s.get('issuer', '')}")
    print(f"rbe-auth: subject        : {s.get('subject', '')}")
    print(f"rbe-auth: audience       : {s.get('audience', '')}")
    print(f"rbe-auth: groups         : {', '.join(s.get('groups') or []) or '(none)'}")
    print(f"rbe-auth: expires        : {_fmt_expiry(s.get('expires_at', 0))}")
    print(f"rbe-auth: usable now     : {'yes' if s.get('fresh') else 'no — refresh / re-login required'}")
    return 0 if s.get("fresh") else 2


def _cmd_logout() -> int:
    removed = rbe_auth.logout()
    if removed:
        print(f"rbe-auth: removed {rbe_auth.CACHE_PATH}")
    else:
        print("rbe-auth: nothing to remove (no cache present).")
    return 0


def _cmd_print_token() -> int:
    s = rbe_auth.status()
    if not s.get("present") or not s.get("fresh"):
        print(
            "rbe-auth: no usable cached token. Run `percona-packaging/scripts/rbe_login.py` first.",
            file=sys.stderr,
        )
        return 2
    cache = rbe_auth._load_cache()  # noqa: SLF001 — single-purpose CLI
    sys.stdout.write(cache.get("id_token", ""))
    sys.stdout.write("\n")
    return 0


def _cmd_login() -> int:
    try:
        rbe_auth.login()
    except rbe_auth.RbeAuthRequired as e:
        print(f"rbe-auth: {e}", file=sys.stderr)
        return 3
    except rbe_auth.RbeAuthError as e:
        print(f"rbe-auth: login failed: {e}", file=sys.stderr)
        return 4
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="rbe_login.py",
        description="Authenticate against the PSMDB Bazel RBE buildfarm (OIDC).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="show cache state without contacting the server")
    group.add_argument("--logout", action="store_true", help="delete the cached token file")
    group.add_argument(
        "--print-token",
        action="store_true",
        help="emit the cached id_token to stdout (for grpcurl / curl probes)",
    )
    args = parser.parse_args(argv)

    if args.status:
        return _cmd_status()
    if args.logout:
        return _cmd_logout()
    if args.print_token:
        return _cmd_print_token()
    return _cmd_login()


if __name__ == "__main__":
    sys.exit(main())
