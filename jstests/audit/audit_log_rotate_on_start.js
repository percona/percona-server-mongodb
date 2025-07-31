if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

const auditLogDir = getDBPath() + '/auditLogs';

// Runs a mongod instance with the given configuration and stops it immediately.
function runAndStopMongod(config) {
    const conn = MongoRunner.runMongod(config);
    assert.neq(conn, null, "Failed to start mongod with config: " + tojson(config));
    MongoRunner.stopMongod(conn);
}

// Returns an array of audit log files in the auditLogDir
// that start with the fileName.
function getFiles(fileName) {
    return ls(auditLogDir).filter(function(path) {
        return path.startsWith(auditLogDir + '/' + fileName);
    });
}

// Returns the number of audit log files in the 'auditLogDir'
// that start with the 'fileName'.
function countFiles(fileName) {
    return getFiles(fileName).length;
}

// Returns the current audit log file, which is the one that ends with 'fileName'
// and is not rotated.
function getCurrentFile(fileName) {
    const files = getFiles(fileName).filter(function(path) {
        return path.endsWith(fileName);
    });

    assert.eq(files.length, 1, "Expected exactly one current audit log file");
    return files[0];
}

// Returns an array of rotated audit log files, which are those that do not end with
// auditLogFileName.
function getRotatedFiles(fileName) {
    const files = getFiles(fileName);
    return files.filter(function(path) {
        return !path.endsWith(fileName);
    });
}

// Initializes the audit log directory by removing existing files
// and creating the directory if it does not exist.
function initAuditLogDir() {
    if (fileExists(auditLogDir)) {
        ls(auditLogDir).forEach(function(path) {
            removeFile(path);
        });
    }
    mkdir(auditLogDir);
}

// Returns UTC timestamp in the format YYYY-MM-DDTHH-MM-SS
// for the given date or the current date if no date is provided.
// The timestamp is formatted in the same way as the rotated file suffix.
function getUTCTimestamp(date) {
    function pad(n) { return n < 10 ? '0' + n : n; }

    return date.getUTCFullYear() + '-' +
           pad(date.getUTCMonth() + 1) + '-' +
           pad(date.getUTCDate()) + 'T' +
           pad(date.getUTCHours()) + '-' +
           pad(date.getUTCMinutes()) + '-' +
           pad(date.getUTCSeconds());
}

// Runs the test for a given audit log file name and format with logRotate=rename option (default).
function runTestRename(fileName, format) {
    const auditPath = auditLogDir + '/' + fileName;
    const config = {
        auditDestination: 'file',
        auditPath: auditPath,
        auditFormat: format,
    };

    // Ensure the audit log directory is clean before starting the test
    initAuditLogDir();
    assert.eq(getFiles(fileName).length, 0, "Expected no audit log files initially");

    // 1st run: expect 1 file to be created.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), 1, "Expected 1 audit log file after starting 1st mongod");
    const firstFileContent = cat(getFiles(fileName)[0]);

    // 2nd run: expect 2 files and the first file to be rotated.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), 2, "Expected 2 audit log files after starting 2nd mongod");
    const rotatedFiles = getRotatedFiles(fileName);
    assert.eq(rotatedFiles.length, 1, "Expected one rotated audit log file after");

    const secondFileContent = cat(getCurrentFile(fileName));
    const rotatedFileContent = cat(rotatedFiles[0]);
    assert.neq(firstFileContent,
               secondFileContent,
               "Expected different content in audit log files after second mongod start");
    assert.eq(rotatedFileContent,
              firstFileContent,
              "Expected rotated log file to match the first log file content");

    // 3rd run: expect 3 files.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), 3, "Expected 3 audit log files after starting 3rd mongod");

    for (const rotated of getRotatedFiles(fileName)) {
        assert(isValidDateSuffix(rotated, auditPath),
               "Expected rotated file to have a valid date suffix: " + rotated);
    }
}

// Runs the test for a given audit log file name and format with logRotate=reopen option.
function runTestReopen(fileName, format) {
    const auditPath = auditLogDir + '/' + fileName;
    const config = {
        auditDestination: 'file',
        auditPath: auditPath,
        auditFormat: format,
        logRotate: 'reopen',
        logappend: "",
    };

    // Ensure the audit log directory is clean before starting the test
    initAuditLogDir();
    assert.eq(getFiles(fileName).length, 0, "Expected no audit log files initially");

    // 1st run: expect 1 file to be created.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), 1, "Expected 1 audit log file after starting 1st mongod");
    const firstFileContent = cat(getFiles(fileName)[0]);

    // 2nd run: expect 1 file to be reopened, not rotated.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), 1, "Expected 1 audit log files after starting 2nd mongod");
    const rotatedFiles = getRotatedFiles(fileName);
    assert.eq(rotatedFiles.length, 0, "Expected no rotated audit log file after");

    // expect the file to be reopened in append mode
    const secondFileContent = cat(getCurrentFile(fileName));
    assert(
        secondFileContent.startsWith(firstFileContent),
        "Expected second file content to start with first file content (file reopened in append mode)");
}

// Runs the test for a given audit log file name and format with logRotate=rename,
// simulating a case where the rotated log file already exists.
// This can happen if mongod is restarted quickly and generates the same timestamped
// filename as a previous instance. In this case, instead of overwriting the file,
// mongod should reopen the existing file in append mode.
function runTestRenameFileExist(fileName, format) {
    const auditPath = auditLogDir + '/' + fileName;

    // Maximum number of seconds to create rotated files ahead of the current time.
    // This should be big enough to make sure that the second instance of mongod will
    // attempt to rename the audit log file to a file that already exists.
    const maxSeconds = 15;

    const config = {
        auditDestination: 'file',
        auditPath: auditPath,
        auditFormat: format,
        logRotate: 'rename',
        logappend: "",
    };

    // Ensure the audit log directory is clean before starting the test
    initAuditLogDir();
    assert.eq(getFiles(fileName).length, 0, "Expected no audit log files initially");

    // generate rotated file names
    let now = new Date();
    let existingRotatedFiles = [];
    for (let i = 0; i < maxSeconds; i++) {
        const rotatedAuditPath = auditPath + '.' + getUTCTimestamp(now);
        existingRotatedFiles.push(rotatedAuditPath);
        now.setSeconds(now.getSeconds() + 1);
    }

    // create rotated files with their own names as content
    for (const rotated of existingRotatedFiles) {
        writeFile(rotated, rotated + '\n');
    }

    assert.eq(getFiles(fileName).length, maxSeconds, "Expected " + maxSeconds + " audit log files");

    // 1st run: expect 1 additional file to be created - the not rotated audit log file.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), maxSeconds + 1, `Expected ${maxSeconds + 1} audit log file after starting 1st mongod`);
    const firstFileContent = cat(getCurrentFile(fileName));

    // 2nd run: expect file to be appended, not rotated.
    runAndStopMongod(config);
    assert.eq(countFiles(fileName), maxSeconds + 1, `Expected ${maxSeconds + 1} audit log files after starting 2nd mongod`);
    const rotatedFiles = getRotatedFiles(fileName);
    assert.eq(rotatedFiles.length, maxSeconds, `Expected ${maxSeconds} rotated audit log files`);

    const secondFileContent = cat(getCurrentFile(fileName));
    assert(
        secondFileContent.startsWith(firstFileContent),
        "Expected second file content to start with first file content (file reopened in append mode)");

    // Make sure the created rotated files contain their own names and mongod did not overwrite them.
    for (const rotated of existingRotatedFiles) {
        const content = cat(rotated);
        assert.eq(content, rotated + '\n',
                   "Expected rotated file to contain its own name: " + rotated);
    }
}

runTestRenameFileExist('auditFileName.json', 'JSON');
runTestRenameFileExist('auditFileName.bson', 'BSON');

runTestRename('auditFileName.json', 'JSON');
runTestRename('auditFileName.bson', 'BSON');

runTestReopen('auditFileName.json', 'JSON');
runTestReopen('auditFileName.bson', 'BSON');
