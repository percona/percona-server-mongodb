#!/usr/bin/env python3
"""A minimal mock LDAP server for the ldapauthz_mock test suite.

This server replaces a real OpenLDAP (slapd) deployment so that the ldapauthz
jstests can run hermetically.

It speaks just enough of the LDAPv3 protocol (RFC 4511) for what the ldapauthz
tests exercise:

  * simple bind (used both for the query/bind user and for PLAIN authentication
    of the external users),
  * search with base and subtree scope and (&...) / equality / presence
    filters, used for:
      - authorization group lookup
            dc=percona,dc=com??sub?(&(objectClass=groupOfNames)(member={USER}))
      - reverse group membership lookup
            {USER}?memberOf?base
      - user-to-DN mapping
            dc=percona,dc=com??sub?(&(objectClass=organizationalPerson)(sn={0}))

The directory contents mirror support-files/ldap-sasl/ldap/{users,groups}.ldif
and the expectations hard-coded in jstests/ldapauthz/_check.js. The single
source of truth here is the (short username -> groups) mapping below; everything
else (DNs, passwords, member / memberOf attributes) is derived from it so it
cannot drift.

The protocol parsing/encoding is handled by ldaptor; bind and search are
implemented by hand so the server has full control over how DNs are returned on
the wire. That matters for the special-character entries: slapd returns DNs with
hex escaping (e.g. cn=specchar\\2C\\2B\\3D\\5C,...) and _check.js expects exactly
that form, so those DNs are emitted verbatim rather than being re-serialized by a
generic DN library.
"""

import argparse
import sys

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

BASE_DN = "dc=percona,dc=com"

# The bind/query user used by mongod (ldapQueryUser / ldapQueryPassword).
ADMIN_DN = "cn=admin,dc=percona,dc=com"
ADMIN_PASSWORD = "password"

# Password suffix appended to the short user name, mirroring settings.conf
# (LDAP_PASS_SUFFIX) and support-files/ldap-sasl/ldap/users.ldif.
PASSWORD_SUFFIX = "9a5S"

# Short user names exactly as listed in jstests/ldapauthz/_check.js
# (shortusernames). The last two exercise DN special-character handling.
USERS = [
    "exttestro",
    "exttestrw",
    "extotherro",
    "extotherrw",
    "extbothro",
    "extbothrw",
    "exttestrwotherro",
    "exttestrootherrw",
    "Surname\\, Name",
    'Question? Mark! *{[(\\<\\>)]} #\\"\\+\\\\',
]

# group cn -> member short user names. Mirrors
# support-files/ldap-sasl/ldap/groups.ldif. The special-character group is keyed
# by its hex-escaped wire DN (see SPECCHAR_GROUP_DN) because that is the exact
# string _check.js expects to see returned as a role.
GROUPS = {
    "testreaders": ["exttestro", "extbothro", "exttestrootherrw"],
    "testwriters": ["exttestrw", "extbothrw", "exttestrwotherro"],
    "otherreaders": ["extotherro", "extbothro", "exttestrwotherro"],
    "otherwriters": ["extotherrw", "extbothrw", "exttestrootherrw"],
    "testusers": [
        "exttestro",
        "exttestrwotherro",
        "exttestrw",
        "exttestrootherrw",
        "extbothro",
        "extbothrw",
    ],
    "otherusers": [
        "extotherro",
        "exttestrwotherro",
        "extotherrw",
        "exttestrootherrw",
        "extbothro",
        "extbothrw",
    ],
}

# The special-character group. groups.ldif stores its DN with character escaping
# (cn=specchar\,\+\=\\,...) but slapd returns it -- and _check.js expects it --
# in hex-escaped form. We emit this exact string on the wire.
SPECCHAR_GROUP_DN = "cn=specchar\\2C\\2B\\3D\\5C,dc=percona,dc=com"
SPECCHAR_MEMBERS = ["Surname\\, Name", 'Question? Mark! *{[(\\<\\>)]} #\\"\\+\\\\']

VERBOSE = False


def log(*args):
    if VERBOSE:
        print("[ldap_mock]", *args, flush=True)


def user_dn(short_name):
    return "cn=" + short_name + "," + BASE_DN


def group_dn(cn):
    return "cn=" + cn + "," + BASE_DN


def to_str(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


class Entry:
    """An in-memory directory entry.

    dn is the exact string emitted on the wire (objectName) and used to build
    member / memberOf references. attrs maps lower-cased attribute name to a list
    of string values used for filter matching and to satisfy attribute requests.
    """

    def __init__(self, dn, attrs, password=None):
        self.dn = dn
        self.norm = dn.lower()
        self.attrs = {k.lower(): list(v) for k, v in attrs.items()}
        # A synthetic "dn" attribute so that templates requesting ?dn? work.
        self.attrs.setdefault("dn", [dn])
        self.password = password


def build_directory():
    """Build the directory from the (user -> groups) source of truth."""
    entries = []

    # Base entry and the bind/query user.
    entries.append(Entry(BASE_DN, {"objectclass": ["dcObject", "organization"], "dc": ["percona"]}))
    entries.append(
        Entry(
            ADMIN_DN,
            {"objectclass": ["organizationalRole"], "cn": ["admin"]},
            password=ADMIN_PASSWORD,
        )
    )

    # Compute group membership keyed by short user name.
    member_of = {u: [] for u in USERS}
    for cn, members in GROUPS.items():
        gdn = group_dn(cn)
        for m in members:
            member_of[m].append(gdn)
    for m in SPECCHAR_MEMBERS:
        member_of[m].append(SPECCHAR_GROUP_DN)

    # User entries.
    for short in USERS:
        dn = user_dn(short)
        entries.append(
            Entry(
                dn,
                {
                    "objectclass": ["organizationalPerson", "person"],
                    "cn": [short],
                    "sn": [short],
                    "memberof": member_of[short],
                },
                password=short + PASSWORD_SUFFIX,
            )
        )

    # Group entries.
    for cn, members in GROUPS.items():
        entries.append(
            Entry(
                group_dn(cn),
                {
                    "objectclass": ["groupOfNames"],
                    "cn": [cn],
                    "member": [user_dn(m) for m in members],
                },
            )
        )
    entries.append(
        Entry(
            SPECCHAR_GROUP_DN,
            {
                "objectclass": ["groupOfNames"],
                "cn": ["specchar,+=\\"],
                "member": [user_dn(m) for m in SPECCHAR_MEMBERS],
            },
        )
    )

    return entries


def match_substrings(f, entry):
    """Evaluate an LDAP substring filter, e.g. (sn=ext*) or (cn=Sur*me*Name).

    Matches case-insensitively against any value of the attribute, honouring the optional
    initial / any* / final components in order (RFC 4511 4.5.1.7.2). The components must
    match non-overlapping, left to right.
    """
    attr = to_str(f.type).lower()
    initial = None
    final = None
    anys = []
    for sub in f.substrings:
        s = to_str(sub.value).lower()
        if isinstance(sub, pureldap.LDAPFilter_substrings_initial):
            initial = s
        elif isinstance(sub, pureldap.LDAPFilter_substrings_final):
            final = s
        elif isinstance(sub, pureldap.LDAPFilter_substrings_any):
            anys.append(s)

    for value in entry.attrs.get(attr, []):
        v = value.lower()
        pos = 0
        if initial is not None:
            if not v.startswith(initial):
                continue
            pos = len(initial)
        matched = True
        for a in anys:
            idx = v.find(a, pos)
            if idx == -1:
                matched = False
                break
            pos = idx + len(a)
        if not matched:
            continue
        # The final component must not overlap what initial/any already consumed.
        if final is not None and not (v.endswith(final) and len(v) - len(final) >= pos):
            continue
        return True
    return False


def match_filter(f, entry):
    """Evaluate a parsed ldaptor filter object against an entry."""
    if isinstance(f, pureldap.LDAPFilter_and):
        return all(match_filter(x, entry) for x in f)
    if isinstance(f, pureldap.LDAPFilter_or):
        return any(match_filter(x, entry) for x in f)
    if isinstance(f, pureldap.LDAPFilter_not):
        return not match_filter(f.value, entry)
    if isinstance(f, pureldap.LDAPFilter_present):
        attr = to_str(f.value).lower()
        return len(entry.attrs.get(attr, [])) > 0
    if isinstance(f, pureldap.LDAPFilter_equalityMatch):
        attr = to_str(f.attributeDesc.value).lower()
        val = to_str(f.assertionValue.value).lower()
        return any(v.lower() == val for v in entry.attrs.get(attr, []))
    if isinstance(f, pureldap.LDAPFilter_substrings):
        return match_substrings(f, entry)
    # Unknown filter -> be permissive so searches are not silently dropped.
    log("unhandled filter type", type(f).__name__)
    return True


SCOPE_BASE = pureldap.LDAP_SCOPE_baseObject
SCOPE_ONE = pureldap.LDAP_SCOPE_singleLevel
SCOPE_SUB = pureldap.LDAP_SCOPE_wholeSubtree


def has_unescaped_comma(s):
    """True if s contains a comma that is not backslash-escaped (RFC 4514 §2.4).

    DNs in this directory use the cn=Surname\\, Name form, so a literal comma inside an
    RDN must not be mistaken for a DN component separator.
    """
    i = 0
    while i < len(s):
        if s[i] == "\\":
            i += 2  # skip the escaped character (e.g. \, or \\)
            continue
        if s[i] == ",":
            return True
        i += 1
    return False


def in_scope(entry, base_norm, scope):
    if scope == SCOPE_BASE:
        return entry.norm == base_norm
    if scope == SCOPE_ONE:
        if not entry.norm.endswith("," + base_norm):
            return False
        head = entry.norm[: -(len("," + base_norm))]
        # Single level == exactly one RDN above the base, i.e. no further (unescaped)
        # component separator in the head.
        return not has_unescaped_comma(head)
    # whole subtree (default)
    return entry.norm == base_norm or entry.norm.endswith("," + base_norm)


class MockLDAPServer(LDAPServer):
    def connectionMade(self):
        peer = self.transport.getPeer()
        log("connection from", getattr(peer, "host", "?"), getattr(peer, "port", "?"))
        LDAPServer.connectionMade(self)

    def handle_LDAPBindRequest(self, request, controls, reply):
        dn = to_str(request.dn)
        auth = request.auth
        if isinstance(auth, str):
            auth = auth.encode("utf-8")

        # Anonymous bind.
        if dn == "" and auth == b"":
            log("bind anonymous -> OK")
            return pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)

        expected = self.factory.passwords.get(dn.lower())
        if expected is not None and auth == expected.encode("utf-8"):
            log("bind", dn, "-> OK")
            return pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode, matchedDN=dn.encode("utf-8")
            )

        log("bind", dn, "-> invalidCredentials")
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
            errorMessage=b"invalid credentials",
        )

    def handle_LDAPSearchRequest(self, request, controls, reply):
        base_norm = to_str(request.baseObject).lower()
        scope = request.scope
        requested = [to_str(a).lower() for a in request.attributes]
        log("search base=%r scope=%s attrs=%s" % (base_norm, scope, requested))

        count = 0
        for entry in self.factory.entries:
            if not in_scope(entry, base_norm, scope):
                continue
            if not match_filter(request.filter, entry):
                continue
            attributes = self._select_attributes(entry, requested)
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName=entry.dn.encode("utf-8"), attributes=attributes
                )
            )
            count += 1
        log("search -> %d entries" % count)
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)

    @staticmethod
    def _select_attributes(entry, requested):
        def encode(name, values):
            return (name.encode("utf-8"), [v.encode("utf-8") for v in values])

        # No attributes requested, or "*": return all real attributes (skip the
        # synthetic "dn" pseudo-attribute and never expose userPassword).
        if not requested or "*" in requested:
            return [encode(k, v) for k, v in entry.attrs.items() if k not in ("userpassword", "dn")]
        # "1.1" means "no attributes".
        if requested == ["1.1"]:
            return []
        result = []
        for name in requested:
            if name in entry.attrs:
                result.append(encode(name, entry.attrs[name]))
        return result


class MockLDAPServerFactory(ServerFactory):
    protocol = MockLDAPServer

    def __init__(self, entries):
        self.entries = entries
        self.passwords = {e.norm: e.password for e in entries if e.password is not None}


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Mock LDAP server for ldapauthz tests")
    parser.add_argument("--port", type=int, required=True, help="TCP port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind to")
    parser.add_argument("--verbose", action="store_true", help="log binds and searches")
    args = parser.parse_args()
    VERBOSE = args.verbose

    entries = build_directory()
    factory = MockLDAPServerFactory(entries)

    reactor.listenTCP(args.port, factory, interface=args.host)
    # Printed on stdout so the JS wrapper (ldap_mock.js) can wait for readiness.
    print("LDAP mock server is running on %s:%d" % (args.host, args.port), flush=True)
    reactor.run()


if __name__ == "__main__":
    main()
