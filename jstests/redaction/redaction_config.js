// test that security.redactClientLogData configuration parameter is
// correctly loaded from config file

(function () {
    "use strict";

    var basePath = "jstests";
    if (TestData.testData !== undefined) {
        basePath = TestData.testData;
    }

    var configFile = basePath + "/libs/config_files/redaction_config.yaml";

    // turn redaction on using config file
    var conn = MongoRunner.runMongod({config: configFile});
    var db = conn.getDB("test");

    // compare reported redactClientLogData with the value set in the config file
    {
        var res = db.getSiblingDB("admin").runCommand({getParameter: 1, "redactClientLogData": 1});
        assert.commandWorked(res, "getParameter failed to get redactClientLogData");
        assert.eq(res.redactClientLogData, true);
    }

    MongoRunner.stopMongod(conn);
})();
