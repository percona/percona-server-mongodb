// name: Local user login
// mode: auth

function localTestROloginRun() {
    "use strict";
    var db = conn.getDB("test");

    assert(
        db.auth({
            user: "localtestro",
            pwd: "localtestro9a5S",
        }),
    );
}

localTestROloginRun();
