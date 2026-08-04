#!/usr/bin/env python3
"""
Minimal cleartext LDAP mock for PSMDB-2212 reproduction.

Phases:
  1) Allow `--max-successful-binds` immediate successful binds and
     `--max-successful-searches` successful searches (so one real auth works).
  2) The next SearchRequest hangs long enough for mongod's ldapTimeoutMS to
     fire; the next BindRequest after that also hangs (retry borrow timeout →
     nullptr), which is the PSMDB-2212 path.
  3) After those two hung ops, every further connection is closed immediately
     so AuthorizationManager background retries fail fast and the jstest does
     not stall on 30s sleeps.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError(f"length too large: {n}")


def enc_tag(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(content)) + content


def enc_int(tag: int, value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() + 7) // 8
        body = value.to_bytes(length, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return enc_tag(tag, body)


def enc_enum(value: int) -> bytes:
    return enc_int(0x0A, value)


def enc_octet(s: bytes | str) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    return enc_tag(0x04, s)


def ldap_message(msgid: int, protocol_op: bytes) -> bytes:
    return enc_tag(0x30, enc_int(0x02, msgid) + protocol_op)


def bind_response(msgid: int, result_code: int) -> bytes:
    op = enc_tag(0x61, enc_enum(result_code) + enc_octet(b"") + enc_octet(b""))
    return ldap_message(msgid, op)


def search_result_entry(msgid: int, dn: str) -> bytes:
    op = enc_tag(0x64, enc_octet(dn) + enc_tag(0x30, b""))
    return ldap_message(msgid, op)


def search_result_done(msgid: int, result_code: int, diag: bytes = b"") -> bytes:
    op = enc_tag(0x65, enc_enum(result_code) + enc_octet(b"") + enc_octet(diag))
    return ldap_message(msgid, op)


def extended_response(msgid: int, result_code: int = 0) -> bytes:
    op = enc_tag(0x78, enc_enum(result_code) + enc_octet(b"") + enc_octet(b""))
    return ldap_message(msgid, op)


def read_ber_len(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise ValueError("truncated length")
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    if n == 0 or i + n > len(data):
        raise ValueError("truncated long length")
    value = int.from_bytes(data[i : i + n], "big")
    return value, i + n


def try_parse_ldap_message(buf: bytes) -> tuple[int, int, int] | None:
    if not buf:
        return None
    if buf[0] != 0x30:
        raise ValueError(f"expected SEQUENCE, got tag {buf[0]:#x}")
    try:
        seq_len, i = read_ber_len(buf, 1)
    except ValueError:
        return None
    total = i + seq_len
    if len(buf) < total:
        return None
    if buf[i] != 0x02:
        raise ValueError(f"expected INTEGER messageID, got tag {buf[i]:#x}")
    id_len, i = read_ber_len(buf, i + 1)
    msgid = int.from_bytes(buf[i : i + id_len], "big")
    i += id_len
    protocol_tag = buf[i]
    return msgid, protocol_tag, total


class LDAPMock:
    LDAP_SUCCESS = 0

    BIND_REQUEST = 0x60
    UNBIND_REQUEST = 0x42
    SEARCH_REQUEST = 0x63
    EXTENDED_REQUEST = 0x77

    def __init__(
        self,
        host: str,
        port: int,
        max_successful_binds: int,
        max_successful_searches: int,
        hang_seconds: float,
        search_entry_dn: str,
    ):
        self.host = host
        self.port = port
        self.max_successful_binds = max_successful_binds
        self.max_successful_searches = max_successful_searches
        self.hang_seconds = hang_seconds
        self.search_entry_dn = search_entry_dn
        self._bind_count = 0
        self._search_count = 0
        self._hung_searches = 0
        self._hung_binds = 0
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None

    def _state_snapshot(self) -> str:
        return (
            f"binds={self._bind_count} searches={self._search_count} "
            f"hung_searches={self._hung_searches} hung_binds={self._hung_binds}"
        )

    def _claim_bind_success(self) -> bool:
        with self._lock:
            self._bind_count += 1
            return self._bind_count <= self.max_successful_binds

    def _claim_search_success(self) -> bool:
        with self._lock:
            self._search_count += 1
            return self._search_count <= self.max_successful_searches

    def _claim_hang_search(self) -> bool:
        """True = this is the one search that should hang for ldapTimeoutMS."""
        with self._lock:
            if self._hung_searches >= 1:
                return False
            self._hung_searches += 1
            return True

    def _claim_hang_bind(self) -> bool:
        """True = this is the one post-success bind that should hang (retry borrow)."""
        with self._lock:
            if self._hung_binds >= 1:
                return False
            self._hung_binds += 1
            return True

    def _hang(self, reason: str, addr) -> None:
        print(
            f"LDAP mock: hanging {self.hang_seconds}s for {reason} from {addr} "
            f"({self._state_snapshot()})",
            flush=True,
        )
        time.sleep(self.hang_seconds)

    def _handle(self, conn: socket.socket, addr) -> None:
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                while True:
                    parsed = try_parse_ldap_message(buf)
                    if parsed is None:
                        break
                    msgid, tag, total = parsed
                    buf = buf[total:]
                    print(
                        f"LDAP mock: from {addr} msgid={msgid} tag={tag:#x} "
                        f"({self._state_snapshot()})",
                        flush=True,
                    )
                    if tag == self.BIND_REQUEST:
                        if self._claim_bind_success():
                            conn.sendall(bind_response(msgid, self.LDAP_SUCCESS))
                        elif self._claim_hang_bind():
                            self._hang("bind timeout", addr)
                            return
                        else:
                            # Fail fast after the single timeout-inducing bind.
                            print(
                                f"LDAP mock: closing after timeout phase ({self._state_snapshot()})",
                                flush=True,
                            )
                            return
                    elif tag == self.SEARCH_REQUEST:
                        if self._claim_search_success():
                            if self.search_entry_dn:
                                conn.sendall(
                                    search_result_entry(msgid, self.search_entry_dn)
                                )
                            conn.sendall(search_result_done(msgid, self.LDAP_SUCCESS))
                        elif self._claim_hang_search():
                            self._hang("search timeout", addr)
                            return
                        else:
                            print(
                                f"LDAP mock: closing after timeout phase ({self._state_snapshot()})",
                                flush=True,
                            )
                            return
                    elif tag == self.UNBIND_REQUEST:
                        return
                    elif tag == self.EXTENDED_REQUEST:
                        conn.sendall(extended_response(msgid, self.LDAP_SUCCESS))
                    else:
                        print(
                            f"LDAP mock: unsupported tag {tag:#x}, closing", flush=True
                        )
                        return
        except Exception as ex:
            print(f"LDAP mock: connection error from {addr}: {ex}", flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(32)
        print(f"LDAP mock server is running at {self.host}:{self.port}", flush=True)
        try:
            while True:
                conn, addr = self._sock.accept()
                threading.Thread(
                    target=self._handle, args=(conn, addr), daemon=True
                ).start()
        finally:
            self._sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--max-successful-binds", type=int, default=3)
    parser.add_argument("--max-successful-searches", type=int, default=1)
    parser.add_argument(
        "--hang-seconds",
        type=float,
        default=3.0,
        help="Hang duration for the single timeout-inducing search/bind; "
        "must exceed mongod ldapTimeoutMS",
    )
    parser.add_argument(
        "--search-entry-dn",
        default="cn=testreaders,dc=percona,dc=com",
        help="DN returned on successful searches (empty to omit)",
    )
    args = parser.parse_args()
    LDAPMock(
        args.host,
        args.port,
        args.max_successful_binds,
        args.max_successful_searches,
        args.hang_seconds,
        args.search_entry_dn,
    ).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
