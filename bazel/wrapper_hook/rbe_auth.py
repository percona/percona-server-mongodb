"""
PSMDB-2043: OIDC authentication for the on-demand Bazel RBE buildfarm.

Maintains a cached OIDC token in `~/.cache/rbe/token.json` and exposes a
single `get_id_token()` entry-point to `wrapper_hook.py`. When the cache
is stale and a refresh-token flow is impossible, runs the OAuth 2.0
Device Authorization Grant (RFC 8628) against the Dex IdP that fronts
the buildfarm — same IdP used by bb-browser / bb-scheduler-admin, same
GitHub team allow-list (Percona orgs + build-engineers / iit /
dev-psmdb).

No third-party deps: only `urllib`, `json`, `ssl`, `base64` from the
stdlib. Token is signed by Dex (RS256, key rotated by Dex every 6 h),
verified server-side by Envoy's jwt_authn filter on :8981 — we never
verify the signature on the client. We only decode the unsigned middle
segment to read the `exp` claim and decide if a refresh is due.

Constants below are HARDCODED on purpose. See PSMDB-2043 / variant D in
the design discussion: putting them in `.bazelrc.psmdb` (--action_env)
doesn't help because wrapper_hook runs *before* Bazel and reads env
directly; putting them in env vars adds onboarding ceremony nobody will
remember. When the buildfarm hostname migrates off `bb-psmdb.ddns.net`
(No-IP free DDNS, interim) onto a Percona-controlled domain, edit
ISSUER here in all three branches (v8.0, v8.3, master).
"""

import base64
import errno
import json
import os
import pathlib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# --- Buildfarm identity (see module docstring on how to migrate) -----
ISSUER = "https://bb-psmdb.ddns.net:5556"
CLIENT_ID = "bazel-cli"
AUDIENCE = "bazel-cli"
SCOPES = "openid groups offline_access"

# --- Token cache -----------------------------------------------------
# Per-user, mode 0600. Using ~/.cache/ rather than ~/.config/ because
# tokens are *cached* state — they get re-fetched on demand if missing
# and there is nothing to back up.
CACHE_PATH = pathlib.Path.home() / ".cache" / "rbe" / "token.json"

# How close to expiry we still consider a token usable. 60 s skew is
# generous against client/server clock drift and gives Bazel time to
# actually fire the request after we hand back the token.
EXP_SKEW_SECONDS = 60

# RFC 8628 polling interval cap (some servers respond with `slow_down`
# and expect the client to back off). Sane upper bound.
MAX_POLL_INTERVAL_SECONDS = 30

# Network timeout for /token, /device/code, /keys roundtrips. Generous
# because dev laptops behind corporate proxies sometimes take their
# sweet time on the first TLS handshake of the day.
HTTP_TIMEOUT_SECONDS = 15


class RbeAuthError(RuntimeError):
    """Anything that prevents us from getting a usable id_token."""


class RbeAuthRequired(RbeAuthError):
    """Interactive login is required but stdin/stderr is not a TTY.

    Wrapper_hook re-raises this to the user with a message pointing to
    `percona-packaging/scripts/rbe_login.py`. Used to fail fast on
    pre-checked-out CI runners
    so the build doesn't hang on the device-code polling loop until
    expires_in (5 min) elapses.
    """


# ---------------------------------------------------------------------
# JWT decoding (no signature verification — Envoy does that).
# ---------------------------------------------------------------------
def _decode_jwt_payload(jwt: str) -> dict:
    try:
        _, payload_b64, _ = jwt.split(".")
    except ValueError as e:
        raise RbeAuthError(f"malformed JWT (expected three dot-segments): {e}")
    # JWT uses base64url WITHOUT padding; restore it so b64decode works.
    pad = "=" * (-len(payload_b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
    except (ValueError, json.JSONDecodeError) as e:
        raise RbeAuthError(f"could not decode JWT payload: {e}")


def _is_token_fresh(jwt: str) -> bool:
    """True iff the JWT's `exp` is at least EXP_SKEW_SECONDS in the future."""
    try:
        exp = int(_decode_jwt_payload(jwt).get("exp", 0))
    except (RbeAuthError, TypeError, ValueError):
        return False
    return exp - int(time.time()) > EXP_SKEW_SECONDS


# ---------------------------------------------------------------------
# Cache I/O.
# ---------------------------------------------------------------------
def _load_cache() -> dict:
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        # Corrupt cache shouldn't be fatal — treat as no cache and let
        # the caller drive a fresh login.
        return {}


def _save_cache(data: dict) -> None:
    """Atomic write with mode 0600.

    `os.rename` is atomic on POSIX so a concurrent reader either sees
    the old file or the new one, never a half-written one. Two
    concurrent writers would both succeed; one of their token sets
    sticks. That's fine — refresh tokens are reusable until first use,
    and even if both writers exchanged independently the second one
    just writes a slightly fresher copy.
    """
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_PATH.with_suffix(CACHE_PATH.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.replace(str(tmp), str(CACHE_PATH))


# ---------------------------------------------------------------------
# HTTP plumbing.
# ---------------------------------------------------------------------
def _ssl_context() -> ssl.SSLContext:
    # System trust store — Let's Encrypt R10/R11 (current chain for
    # bb-psmdb.ddns.net) is in every modern distribution's CA bundle.
    return ssl.create_default_context()


def _post_form(url: str, form: dict) -> dict:
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=HTTP_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Dex returns OAuth-format JSON errors (e.g. invalid_grant,
        # authorization_pending) with non-2xx status. Surface the body
        # as a parsed dict so callers can act on the `error` field
        # rather than guessing from the HTTP status.
        try:
            return json.loads(e.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RbeAuthError(f"HTTP {e.code} from {url}: {e.reason}")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        raise RbeAuthError(f"network error talking to {url}: {e}")


# ---------------------------------------------------------------------
# OAuth flows.
# ---------------------------------------------------------------------
def _exchange_refresh_token(refresh_token: str) -> dict:
    """grant_type=refresh_token. Silent. Used between Device Code logins."""
    return _post_form(
        f"{ISSUER}/token",
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        },
    )


def _start_device_code() -> dict:
    return _post_form(
        f"{ISSUER}/device/code",
        {"client_id": CLIENT_ID, "scope": SCOPES},
    )


def _poll_device_token(device_code: str, interval: int, expires_in: int, *, status_stream) -> dict:
    """Poll /token with grant_type=device_code until success/denial/timeout.

    Honours RFC 8628 polling rules:
      * `authorization_pending` → keep polling at current interval
      * `slow_down` → bump interval by 5 s (capped) and keep polling
      * `expired_token` / `access_denied` → terminal failure
      * anything else with `error` field → surface it as RbeAuthError
      * absence of `error` = success → return token bundle as-is
    """
    deadline = time.monotonic() + expires_in
    while True:
        if time.monotonic() >= deadline:
            raise RbeAuthError(
                "device code expired before approval — re-run "
                "`percona-packaging/scripts/rbe_login.py` to try again"
            )
        time.sleep(interval)
        resp = _post_form(
            f"{ISSUER}/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
            },
        )
        err = resp.get("error")
        if not err:
            return resp
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval = min(interval + 5, MAX_POLL_INTERVAL_SECONDS)
            continue
        if err == "expired_token":
            raise RbeAuthError(
                "device code expired before approval — re-run "
                "`percona-packaging/scripts/rbe_login.py` to try again"
            )
        if err == "access_denied":
            raise RbeAuthError("login denied — your GitHub account is not in an allowed Percona team")
        raise RbeAuthError(f"OIDC token endpoint error: {err}: {resp.get('error_description', '')}")


# ---------------------------------------------------------------------
# UX.
# ---------------------------------------------------------------------
def _print_login_prompt(verification_uri_complete: str, user_code: str, expires_in: int, *, stream) -> None:
    """Single mid-build prompt — no pre-warning of upcoming expiry.

    Per design (PSMDB-2043 discussion): humans only see the prompt when
    their build is actually blocked. Same UX as `gh auth login` after a
    revoked token. No "your token expires in 7 days" notices.
    """
    minutes = max(1, expires_in // 60)
    print("", file=stream)
    print("[rbe-auth] Bazel RBE buildfarm requires login.", file=stream)
    print("[rbe-auth] Open this URL in any browser:", file=stream)
    print(f"[rbe-auth]   {verification_uri_complete}", file=stream)
    print(f"[rbe-auth] Confirm the user code: {user_code}", file=stream)
    print(f"[rbe-auth] Code expires in ~{minutes} min. Waiting…", file=stream)
    print("", file=stream)
    stream.flush()


# ---------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------
def _normalize_token_response(resp: dict) -> dict:
    """Translate a /token success body into our cache shape.

    We store `id_token` and `refresh_token` plus a precomputed
    `expires_at` so the next call can decide freshness without a
    round-trip. Keeping `access_token` too in case some future flow
    needs the AT against /userinfo.
    """
    if "id_token" not in resp:
        raise RbeAuthError(f"OIDC response missing id_token: {resp}")
    payload = _decode_jwt_payload(resp["id_token"])
    return {
        "id_token": resp["id_token"],
        "access_token": resp.get("access_token", ""),
        "refresh_token": resp.get("refresh_token", ""),
        "expires_at": int(payload.get("exp", 0)),
        "issuer": payload.get("iss", ""),
        "audience": payload.get("aud", ""),
        "subject": payload.get("sub", ""),
        "groups": payload.get("groups", []),
    }


def _is_tty(stream) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _do_device_code_login(*, status_stream) -> dict:
    """Run the Device Code flow end-to-end and persist the tokens.

    Caller is responsible for deciding TTY vs non-TTY.
    """
    start = _start_device_code()
    if "error" in start:
        raise RbeAuthError(f"/device/code error: {start['error']}: {start.get('error_description', '')}")
    _print_login_prompt(
        verification_uri_complete=start["verification_uri_complete"],
        user_code=start["user_code"],
        expires_in=int(start.get("expires_in", 300)),
        stream=status_stream,
    )
    tokens = _poll_device_token(
        device_code=start["device_code"],
        interval=int(start.get("interval", 5)),
        expires_in=int(start.get("expires_in", 300)),
        status_stream=status_stream,
    )
    cache = _normalize_token_response(tokens)
    _save_cache(cache)
    print("[rbe-auth] Login successful.", file=status_stream)
    return cache


def get_id_token(*, status_stream=None) -> str:
    """Return a fresh OIDC id_token for the buildfarm.

    Order of attempts:
      1. cached id_token still valid → return as-is (zero RTT)
      2. cached refresh_token usable → silent /token refresh
      3. interactive Device Code flow if status_stream is a TTY
      4. raise RbeAuthRequired otherwise (caller decides what to print)
    """
    if status_stream is None:
        status_stream = sys.stderr

    cache = _load_cache()

    # (1) Fast path: cached id_token still valid.
    cached_id = cache.get("id_token", "")
    if cached_id and _is_token_fresh(cached_id):
        return cached_id

    # (2) Silent refresh.
    refresh_token = cache.get("refresh_token", "")
    if refresh_token:
        resp = _exchange_refresh_token(refresh_token)
        if "error" not in resp and "id_token" in resp:
            cache = _normalize_token_response(resp)
            _save_cache(cache)
            return cache["id_token"]
        # Refresh failed (revoked, rotated out, GitHub team removed).
        # Fall through to interactive login. We do NOT clear the cache
        # here — if the user is non-TTY and we fail the next branch,
        # `rbe_login.py --status` should still surface the stale
        # cache for diagnostics.

    # (3) Interactive device code — TTY only.
    if not _is_tty(status_stream):
        raise RbeAuthRequired(
            "RBE buildfarm needs a fresh login but no TTY is attached. "
            "Run `percona-packaging/scripts/rbe_login.py` from an interactive "
            "shell to authenticate, then retry your build."
        )

    return _do_device_code_login(status_stream=status_stream)["id_token"]


def login(*, status_stream=None) -> dict:
    """Force the Device Code flow regardless of cache state.

    Returns the new cache dict. Used by the standalone
    `percona-packaging/scripts/rbe_login.py` CLI when the user knows
    their refresh token is bad (GitHub team change, manual revocation
    in Dex storage, etc.) and wants to re-prime without first hitting
    a build failure.
    """
    if status_stream is None:
        status_stream = sys.stderr
    if not _is_tty(status_stream):
        raise RbeAuthRequired("`rbe_login.py` requires a TTY.")
    return _do_device_code_login(status_stream=status_stream)


def logout() -> bool:
    """Wipe the cached tokens. Returns True if a cache existed."""
    try:
        CACHE_PATH.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
        raise


def status() -> dict:
    """Snapshot of the cache for `rbe_login.py --status`.

    Returns: {present, fresh, expires_at, subject, groups, audience}.
    Never raises. Never makes a network call.
    """
    cache = _load_cache()
    if not cache:
        return {"present": False, "fresh": False}
    id_token = cache.get("id_token", "")
    return {
        "present": True,
        "fresh": _is_token_fresh(id_token),
        "expires_at": cache.get("expires_at", 0),
        "subject": cache.get("subject", ""),
        "audience": cache.get("audience", ""),
        "groups": cache.get("groups", []),
        "issuer": cache.get("issuer", ""),
    }
