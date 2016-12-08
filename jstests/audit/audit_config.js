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
