/**
 * PSMDB-1893: Verify server parameters that control 'disks' and 'mounts' subsections
 * under systemMetrics in FTDC data.
 *
 * - diagnosticDataCollectionEnableSystemMetricsDisks
 * - diagnosticDataCollectionEnableSystemMetricsMounts
 *
 * Both default to true. When set to false, the corresponding subsection is omitted
 * from getDiagnosticData().data.systemMetrics.
 *
 * Separate tests for each metric (startup + runtime).
 */
import {getParameter, setParameter} from "jstests/libs/ftdc.js";

function assertSystemMetricsSubsection(adminDb, subsectionName, expectedPresent, msg) {
    assert.soon(
        () => {
            const result = adminDb.runCommand("getDiagnosticData");
            assert.commandWorked(result);
            const systemMetrics = result.data.systemMetrics;
            if (!systemMetrics) {
                return false;
            }
            if (systemMetrics.hasOwnProperty(subsectionName) === expectedPresent) {
                const subsection = systemMetrics.hasOwnProperty(subsectionName)
                    ? systemMetrics[subsectionName]
                    : "(absent)";
                jsTestLog("getDiagnosticData systemMetrics." + subsectionName + ": " + tojson(subsection));
                return true;
            }
            return false;
        },
        msg,
        10000,
    );
}

// ========== diagnosticDataCollectionEnableSystemMetricsDisks ==========

// --- Startup: disks false ---
let conn = MongoRunner.runMongod({
    setParameter: {diagnosticDataCollectionEnableSystemMetricsDisks: false},
});
let adminDb = conn.getDB("admin");

assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsDisks"), false);

assertSystemMetricsSubsection(
    adminDb,
    "disks",
    false,
    "FTDC systemMetrics should omit 'disks' when param is false at startup",
);

// Enable at runtime and verify subsection appears
assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsDisks: true}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsDisks"), true);

assertSystemMetricsSubsection(
    adminDb,
    "disks",
    true,
    "FTDC systemMetrics should include 'disks' when enabled at runtime after startup disabled",
);

MongoRunner.stopMongod(conn);

// --- Runtime: disks false then true ---
conn = MongoRunner.runMongod();
adminDb = conn.getDB("admin");

assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsDisks"), true);

assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsDisks: false}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsDisks"), false);

assertSystemMetricsSubsection(
    adminDb,
    "disks",
    false,
    "FTDC systemMetrics should omit 'disks' when param is false at runtime",
);

assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsDisks: true}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsDisks"), true);

MongoRunner.stopMongod(conn);

// ========== diagnosticDataCollectionEnableSystemMetricsMounts ==========

// --- Startup: mounts false ---
conn = MongoRunner.runMongod({
    setParameter: {diagnosticDataCollectionEnableSystemMetricsMounts: false},
});
adminDb = conn.getDB("admin");

assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsMounts"), false);

assertSystemMetricsSubsection(
    adminDb,
    "mounts",
    false,
    "FTDC systemMetrics should omit 'mounts' when param is false at startup",
);

// Enable at runtime and verify subsection appears
assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsMounts: true}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsMounts"), true);

assertSystemMetricsSubsection(
    adminDb,
    "mounts",
    true,
    "FTDC systemMetrics should include 'mounts' when enabled at runtime after startup disabled",
);

MongoRunner.stopMongod(conn);

// --- Runtime: mounts false then true ---
conn = MongoRunner.runMongod();
adminDb = conn.getDB("admin");

assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsMounts"), true);

assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsMounts: false}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsMounts"), false);

assertSystemMetricsSubsection(
    adminDb,
    "mounts",
    false,
    "FTDC systemMetrics should omit 'mounts' when param is false at runtime",
);

assert.commandWorked(setParameter(adminDb, {diagnosticDataCollectionEnableSystemMetricsMounts: true}));
assert.eq(getParameter(adminDb, "diagnosticDataCollectionEnableSystemMetricsMounts"), true);

assertSystemMetricsSubsection(
    adminDb,
    "mounts",
    true,
    "FTDC systemMetrics should include 'mounts' when param is true at runtime",
);

MongoRunner.stopMongod(conn);
