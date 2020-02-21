// Check authorization result

const shortusernames = [
    "exttestro",
    "exttestrw",
    "extotherro",
    "extotherrw",
    "extbothro",
    "extbothrw",
    "exttestrwotherro",
    "exttestrootherrw",
];

const rolesmap = {
    "cn=exttestro,dc=percona,dc=com": [
        "cn=testreaders,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
    ],
    "cn=exttestrw,dc=percona,dc=com": [
        "cn=testwriters,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
    ],
    "cn=extotherro,dc=percona,dc=com": [
        "cn=otherreaders,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
    "cn=extotherrw,dc=percona,dc=com": [
        "cn=otherwriters,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
    "cn=extbothro,dc=percona,dc=com": [
        "cn=testreaders,dc=percona,dc=com",
        "cn=otherreaders,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
    "cn=extbothrw,dc=percona,dc=com": [
        "cn=testwriters,dc=percona,dc=com",
        "cn=otherwriters,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
    "cn=exttestrwotherro,dc=percona,dc=com": [
        "cn=testwriters,dc=percona,dc=com",
        "cn=otherreaders,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
    "cn=exttestrootherrw,dc=percona,dc=com": [
        "cn=testreaders,dc=percona,dc=com",
        "cn=otherwriters,dc=percona,dc=com",
        "cn=testusers,dc=percona,dc=com",
        "cn=otherusers,dc=percona,dc=com",
    ],
};

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
function checkConnectionStatus(username, cs, name_to_dn)
{
    'use strict'

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
    cs.authInfo.authenticatedUserRoles.forEach(function(entry){
        assert(userroles.includes(entry.role), `User '${user}' was authorized to unexpected role '${entry.role}'`);
        authorizedroles.push(entry.role);
    });
    // all roles from our rolesmap must be authorized
    userroles.forEach(function(entry){
        assert(authorizedroles.includes(entry), `User '${user}' was not authorized '${entry}' role`);
    });
}

