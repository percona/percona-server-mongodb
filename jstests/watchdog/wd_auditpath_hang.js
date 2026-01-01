// Storage Node Watchdog - validate watchdog monitors --auditpath
//
import {CharybdefsControl} from "jstests/watchdog/lib/charybdefs_lib.js";
import {testFuseAndMongoD} from "jstests/watchdog/lib/wd_test_common.js";

if (assert.commandWorked(isPSMDBOrEnterprise(db.runCommand({buildInfo: 1})))) {
    let control = new CharybdefsControl("auditpath_hang");

    const auditPath = control.getMountPath();

    testFuseAndMongoD(control, {
        auditDestination: "file",
        auditFormat: "JSON",
        auditPath: auditPath + "/auditLog.json",
    });
}
