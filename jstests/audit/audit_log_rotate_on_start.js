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

// Runs the test for given audit log file name and format.
function runTest(fileName, format) {
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

runTest('auditFileName.json', 'JSON');
runTest('auditFileName.bson', 'BSON');
