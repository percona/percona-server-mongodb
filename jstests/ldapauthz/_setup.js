// Prepare for start with auth enabled
// - create 'root' user

function setupRun()
{
    'use strict'

    var conn = MongoRunner.runMongod();
    var db = conn.getDB("admin");

    // create administrator
    db.createUser({
        user: 'admin',
        pwd: 'password',
        roles: [ 'root' ]
    });

    MongoRunner.stopMongod(conn);
}

setupRun()
