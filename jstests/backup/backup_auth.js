(function() {
'use strict';

// Run Mongo in auth mode
var dbPath = MongoRunner.dataPath + 'original';
var conn = MongoRunner.runMongod({
    auth: '',
    dbpath: dbPath,
});
var adminDB = conn.getDB('admin');

// Create root user first
adminDB.createUser({user: 'root', pwd: 'pass', roles: ['root']});
assert(adminDB.auth('root', 'pass'), 'root auth failed');

// Create backup and non-backup users
adminDB.createUser({user: 'backup', pwd: 'pass', roles: ['backup']});
adminDB.createUser({user: 'nobackup', pwd: 'pass', roles: ['dbAdmin']});

// Creating backup user on non-admin collection fails
var other = conn.getDB('other');
assert.throws(function() {
    other.createUser({user: 'backup-other', pwd: 'pass', roles: ['backup']});
});

// Logging in with backup user on some other database fails
adminDB.logout();
assert(!other.auth('backup', 'pass'), 'backup auth on other must fail');

// Log in with non-backup user and try performing backup (which fails)
adminDB.logout();
assert(adminDB.auth('nobackup', 'pass'), 'nobackup auth failed');
var backupPath1 = MongoRunner.dataPath + 'backup1';
mkdir(backupPath1);
assert.commandFailed(adminDB.runCommand({createBackup: 1, backupDir: backupPath1}));

// Log in with backup user and perform backup
adminDB.logout();
assert(adminDB.auth('backup', 'pass'), 'backup auth failed');
var backupPath2 = MongoRunner.dataPath + 'backup2';
mkdir(backupPath2);
assert.commandWorked(adminDB.runCommand({createBackup: 1, backupDir: backupPath2}));

// Log in with root user and perform backup
adminDB.logout();
assert(adminDB.auth('root', 'pass'), 'root auth failed');
var backupPath3 = MongoRunner.dataPath + 'backup3';
mkdir(backupPath3);
assert.commandWorked(adminDB.runCommand({createBackup: 1, backupDir: backupPath3}));

MongoRunner.stopMongod(conn);
})();
