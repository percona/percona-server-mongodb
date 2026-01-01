// name: External user login
// mode: auth

function exttestroLoginRun() {
    "use strict";
    var db = conn.getDB("$external");

    assert(
        db.getSiblingDB("$external").auth({
            user: "exttestro",
            pwd: "exttestro9a5S",
            mechanism: "PLAIN",
            digestPasswd: false,
        }),
    );
}

exttestroLoginRun();
