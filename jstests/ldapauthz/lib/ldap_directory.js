/**
 * Single source of truth for the mock LDAP directory used by the ldapauthz_mock suite.
 *
 * Both ends of the suite derive their data from this module so they cannot drift:
 *   - the Python mock server (lib/ldap_mock.py) is fed this data as JSON, serialised and
 *     passed on the command line by lib/ldap_mock.js;
 *   - the test-side authorization checks (_check.js) build their expectations from the
 *     same (user -> groups) mapping here.
 *
 * The directory contents mirror support-files/ldap-sasl/ldap/{users,groups}.ldif. The
 * single source of truth is the (short username -> groups) mapping below; everything else
 * (DNs, passwords, member / memberOf attributes) is derived from it.
 */

export const BASE_DN = "dc=percona,dc=com";

// The bind/query user used by mongod (ldapQueryUser / ldapQueryPassword).
export const ADMIN_DN = "cn=admin," + BASE_DN;
export const ADMIN_PASSWORD = "password";

// Password suffix appended to the short user name, mirroring settings.conf
// (LDAP_PASS_SUFFIX) and support-files/ldap-sasl/ldap/users.ldif.
export const PASSWORD_SUFFIX = "9a5S";

// Short user names. The last two exercise DN special-character handling.
export const USERS = [
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
];

// group cn -> member short user names. Mirrors support-files/ldap-sasl/ldap/groups.ldif.
export const GROUPS = {
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
};

// The special-character group. groups.ldif stores its DN with character escaping
// (cn=specchar\,\+\=\\,...) but slapd returns it -- and the tests expect it -- in
// hex-escaped form. This exact string is emitted on the wire and used as a role.
export const SPECCHAR_GROUP_DN = "cn=specchar\\2C\\2B\\3D\\5C," + BASE_DN;
export const SPECCHAR_GROUP_CN = "specchar,+=\\";
export const SPECCHAR_MEMBERS = ["Surname\\, Name", 'Question? Mark! *{[(\\<\\>)]} #\\"\\+\\\\'];

export function userDn(shortName) {
    return "cn=" + shortName + "," + BASE_DN;
}

export function groupDn(cn) {
    return "cn=" + cn + "," + BASE_DN;
}

// Short user names exactly as the tests authenticate them.
export const shortusernames = USERS;

// user DN -> list of role (group) DNs the user must be authorized for. Derived from
// GROUPS (and the special-character group) so it stays in sync with the mock directory.
// Order is irrelevant: _check.js compares the two sides as sets.
export const rolesmap = (function () {
    const map = {};
    for (const short of USERS) {
        map[userDn(short)] = [];
    }
    for (const [cn, members] of Object.entries(GROUPS)) {
        for (const m of members) {
            map[userDn(m)].push(groupDn(cn));
        }
    }
    for (const m of SPECCHAR_MEMBERS) {
        map[userDn(m)].push(SPECCHAR_GROUP_DN);
    }
    return map;
})();

/**
 * The directory specification handed to lib/ldap_mock.py as JSON (see lib/ldap_mock.js).
 */
export function directorySpec() {
    return {
        base_dn: BASE_DN,
        admin_dn: ADMIN_DN,
        admin_password: ADMIN_PASSWORD,
        password_suffix: PASSWORD_SUFFIX,
        users: USERS,
        groups: GROUPS,
        specchar_group_dn: SPECCHAR_GROUP_DN,
        specchar_group_cn: SPECCHAR_GROUP_CN,
        specchar_members: SPECCHAR_MEMBERS,
    };
}
