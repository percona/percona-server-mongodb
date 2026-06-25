// Check authorization result.
//
// The expected (user DN -> role DNs) mapping is derived from the shared directory
// source of truth (jstests/ldapauthz/lib/ldap_directory.js), the same data fed to the
// mock LDAP server, so the two cannot drift.

import {rolesmap, shortusernames} from "jstests/ldapauthz/lib/ldap_directory.js";

export {rolesmap, shortusernames};

//{
//	"authInfo" : {
//		"authenticatedUsers" : [
//			{
//				"user" : "cn=exttestro,dc=percona,dc=com",
//				"db" : "$external"
//			}
//		],
//		"authenticatedUserRoles" : [
//			{
//				"role" : "cn=testusers,dc=percona,dc=com",
//				"db" : "admin"
//			},
//			{
//				"role" : "cn=testreaders,dc=percona,dc=com",
//				"db" : "admin"
//			}
//		]
//	},
//	"ok" : 1
//}
export function checkConnectionStatus(username, cs, name_to_dn) {
    "use strict";

    assert.eq(cs.authInfo.authenticatedUsers[0].db, "$external");

    const user = cs.authInfo.authenticatedUsers[0].user;
    assert.eq(user, username);
    let userdn = username;
    if (name_to_dn !== undefined) {
        userdn = name_to_dn(username);
    }
    const userroles = rolesmap[userdn];
    assert(userroles, "Unexpected user");
    let authorizedroles = [];
    // all authorized roles must be in our rolesmap
    cs.authInfo.authenticatedUserRoles.forEach(function (entry) {
        assert(
            userroles.includes(entry.role),
            `User '${user}' was authorized to unexpected role '${entry.role}'`,
        );
        authorizedroles.push(entry.role);
    });
    // all roles from our rolesmap must be authorized
    userroles.forEach(function (entry) {
        assert(
            authorizedroles.includes(entry),
            `User '${user}' was not authorized '${entry}' role`,
        );
    });
}
