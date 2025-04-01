// test that configuration parameters are correctly loaded from
// both deprecated configuration section 'audit' and new configuration
// section 'auditLog'

var basePath = 'jstests';
if (TestData.testData !== undefined) {
    basePath = TestData.testData;
}
load(basePath + '/audit/_audit_helpers.js');

var configFile = basePath + '/libs/config_files/audit_config.yaml';
var configFileDeprecated = basePath + '/libs/config_files/audit_config_deprecated.yaml';
var configFileBasic = basePath + '/libs/config_files/audit_config_basic.yaml';
var configFileFork = basePath + '/libs/config_files/audit_config_fork.yaml';

var defaultNameJson = 'auditLog.json'
var defaultNameBson = 'auditLog.bson'
var logPath = getDBPath() + '/server.log'
var defaultPathJson = getDBPath() + '/' + defaultNameJson;
var defaultPathBson = getDBPath() + '/' + defaultNameBson;

auditTest(
    'auditConfig',
    function(m, restartServer) {
        var adminDB = m.getDB('admin');
    },
    { config: configFile }
);

auditTest(
    'auditConfigDeprecated',
    function(m, restartServer) {
        var adminDB = m.getDB('admin');
    },
    { config: configFileDeprecated }
);

// Default path for audit log:
// format: JSON
// no logpath provided
removeFile(defaultNameJson)
auditTest(
    'defaultAuditPathJSONCwd',
    function(m, restartServer) {
        assert.eq(fileExists(defaultNameJson), true);
    },
    { config: configFileBasic, auditFormat: 'JSON' }
)
removeFile(defaultNameJson)

// Default path for audit log:
// format: BSON
// no logpath provided
removeFile(defaultNameBson)
auditTest(
    'defaultAuditPathBSONCwd',
    function(m, restartServer) {
        assert.eq(fileExists(defaultNameBson), true);
    },
    { config: configFileBasic, auditFormat: 'BSON' }
)
removeFile(defaultNameBson)

// Default path for audit log:
// format: JSON
// logpath provided
removeFile(defaultPathJson)
auditTest(
    'defaultAuditPathJSONLogpath',
    function(m, restartServer) {
        assert.eq(fileExists(defaultPathJson), true);
    },
    { config: configFileBasic, auditFormat: 'JSON', logpath: logPath }
)
removeFile(defaultPathJson)

// Default path for audit log:
// format: BSON
// logpath provided
removeFile(defaultPathBson)
auditTest(
    'defaultAuditPathBSONLogpath',
    function(m, restartServer) {
        assert.eq(fileExists(defaultPathBson), true);
    },
    { config: configFileBasic, auditFormat: 'BSON', logpath: logPath }
)
removeFile(defaultPathBson)

// Test for creating audit log with relative path when forking.
removeFile(defaultNameJson)
auditTest(
    'relativeAuditPathWhenForking',
    function(m, restartServer) {
        assert.eq(fileExists(defaultNameJson), true);
    },
    { config: configFileFork, logpath: logPath}
)

removeFile(defaultNameJson)

// Destination: console
// Expect no file created
removeFile(defaultNameJson)
auditTest(
    'destinationConsoleNoAuditFileCreated',
    function(m, restartServer) {
        assert.eq(fileExists(defaultNameJson), false);
    },
    { config: configFileBasic, auditDestination: 'console' }
)
