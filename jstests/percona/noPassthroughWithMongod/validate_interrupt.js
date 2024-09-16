// Tests that the validate command can be interrupted by timeout specified in 'validate'
// command. This should cause validate() to fail with an ExceededTimeLimit error.
// Original validate_interrupt.js has two issues:
// - 1000 documents is not enough to trigger timeout (at least 4096 is necessary)
// - using failpoint makes this test to succeed even with those storage engines
//   which doesn't support interrupting validation

'use strict';

(function() {
    if (db.serverStatus().storageEngine.name === "mmapv1") {
        print("Validate command cannot be interrupted on 'mmapv1' storage engine. Skipping test.");
        return;
    }

    var t = db.validate_interrupt;
    t.drop();

    var bulk = t.initializeUnorderedBulkOp();

    var i;
    for (i = 0; i < 500000; i++) {
        bulk.insert({a: i});
    }
    assert.writeOK(bulk.execute());

    var res = t.runCommand({validate: t.getName(), full: true, maxTimeMS: 1000});

    if (res.ok === 0) {
        assert.eq(res.code,
                  ErrorCodes.MaxTimeMSExpired,
                  'validate command did not time out:\n' + tojson(res));
    } else {
        // validate() should only succeed if it EBUSY'd. See SERVER-23131.
        var numWarnings = res.warnings.length;
        // validate() could EBUSY when verifying the index and/or the RecordStore, so EBUSY could
        // appear once or twice.
        assert((numWarnings === 1) || (numWarnings === 2),
               'Expected 1 or 2 validation warnings:\n' + tojson(res));
        const re=new RegExp("Could not complete validation of table:(collection|index)-([0-9]+)-([0-9]+). This is a transient issue as the collection was actively in use by other operations.");
        assert(res.warnings[0].match(re), 'Expected a transient issue warning:\n' + tojson(res));
        if (numWarnings === 2) {
            assert(res.warnings[1].match(re), 'Expected a transient issue warning:\n' + tojson(res));
        }
    }
})();
