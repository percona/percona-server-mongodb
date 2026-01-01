// test that configuration parameters are correctly loaded from
// both deprecated configuration section 'audit' and new configuration
// section 'auditLog'

import {auditTest, getDBPath} from "jstests/audit/_audit_helpers.js";

let basePath = "jstests";
if (TestData.testData !== undefined) {
    basePath = TestData.testData;
}

const configFile = basePath + "/libs/config_files/audit_config.yaml";
const configFileDeprecated = basePath + "/libs/config_files/audit_config_deprecated.yaml";
const configFileBasic = basePath + "/libs/config_files/audit_config_basic.yaml";
const configFileEmpty = basePath + "/libs/config_files/audit_config_empty.yaml";
const configFileDestinationEmpty = basePath + "/libs/config_files/audit_config_destination_empty.yaml";

const auditConfigPath = "audit_config_test.json";
const defaultNameJson = "auditLog.json";
const defaultNameBson = "auditLog.bson";
const logPath = getDBPath() + "/server.log";
const defaultPathJson = getDBPath() + "/" + defaultNameJson;
const defaultPathBson = getDBPath() + "/" + defaultNameBson;

auditTest(
    "auditConfig",
    function (m, restartServer) {
        let adminDB = m.getDB("admin");
    },
    {config: configFile},
);
removeFile(auditConfigPath);

auditTest(
    "auditConfigDeprecated",
    function (m, restartServer) {
        let adminDB = m.getDB("admin");
    },
    {config: configFileDeprecated},
);
removeFile(auditConfigPath);

// Default path for audit log:
// format: JSON
// no logpath provided
removeFile(defaultNameJson);
auditTest(
    "defaultAuditPathJSONCwd",
    function (m, restartServer) {
        assert.eq(fileExists(defaultNameJson), true);
    },
    {config: configFileBasic, auditFormat: "JSON"},
);
removeFile(defaultNameJson);

// Default path for audit log:
// format: BSON
// no logpath provided
removeFile(defaultNameBson);
auditTest(
    "defaultAuditPathBSONCwd",
    function (m, restartServer) {
        assert.eq(fileExists(defaultNameBson), true);
    },
    {config: configFileBasic, auditFormat: "BSON"},
);
removeFile(defaultNameBson);

// Default path for audit log:
// format: JSON
// logpath provided
removeFile(defaultPathJson);
auditTest(
    "defaultAuditPathJSONLogpath",
    function (m, restartServer) {
        assert.eq(fileExists(defaultPathJson), true);
    },
    {config: configFileBasic, auditFormat: "JSON", logpath: logPath},
);
removeFile(defaultPathJson);

// Default path for audit log:
// format: BSON
// logpath provided
removeFile(defaultPathBson);
auditTest(
    "defaultAuditPathBSONLogpath",
    function (m, restartServer) {
        assert.eq(fileExists(defaultPathBson), true);
    },
    {config: configFileBasic, auditFormat: "BSON", logpath: logPath},
);
removeFile(defaultPathBson);

// Destination: console
// Expect no file created
removeFile(defaultNameJson);
auditTest(
    "destinationConsoleNoAuditFileCreated",
    function (m, restartServer) {
        assert.eq(fileExists(defaultNameJson), false);
    },
    {config: configFileBasic, auditDestination: "console"},
);

// Destination: not defined
// Expect no file created
removeFile(defaultNameJson);
removeFile(defaultNameBson);
auditTest(
    "destinationNotDefinedNoAuditFileCreated",
    function (m, restartServer) {
        assert.eq(fileExists(defaultNameJson), false);
        assert.eq(fileExists(defaultNameBson), false);
    },
    {config: configFileEmpty},
);

// Destination: ''
// Expect no file created
removeFile(defaultNameJson);
removeFile(defaultNameBson);
auditTest(
    "destinationEmptyNoAuditFileCreated",
    function (m, restartServer) {
        assert.eq(fileExists(defaultNameJson), false);
        assert.eq(fileExists(defaultNameBson), false);
    },
    {config: configFileDestinationEmpty},
);
