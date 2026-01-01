// test that security.redactClientLogData configuration parameter is
// correctly loaded from config file

import {ShardingTest} from "jstests/libs/shardingtest.js";

(function () {
    "use strict";

    var basePath = "jstests";
    if (TestData.testData !== undefined) {
        basePath = TestData.testData;
    }

    var configFile = basePath + "/libs/config_files/redaction_config.yaml";

    // turn redaction on using config file
    var conn = new ShardingTest({
        shards: 2,
        mongos: 1,
        other: {
            mongosOptions: {config: configFile},
        },
    });
    var db = conn.getDB("test");

    // compare reported redactClientLogData with the value set in the config file
    {
        var res = db.getSiblingDB("admin").runCommand({getParameter: 1, "redactClientLogData": 1});
        assert.commandWorked(res, "getParameter failed to get redactClientLogData");
        assert.eq(res.redactClientLogData, true);
    }

    conn.stop();
})();
