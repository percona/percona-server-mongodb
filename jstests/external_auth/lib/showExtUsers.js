// name: Retrieve External Users
// mode: auth

function showExtUsersRun() {
    "use strict";
    var db = conn.getDB("admin");

    assert(db.auth("localadmin", "localadmin9a5S"));

    // display users from test database

    print("test database:");
    print("--------------");

    var findtest = 0;

    db.getSiblingDB("$external")
        .getUsers()
        .forEach(function (u) {
            printjson(u);
            findtest++;
        });
}

showExtUsersRun();
