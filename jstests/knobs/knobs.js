var adminDB = db.getSiblingDB("admin");

// test cursorTimeoutMillis
{
    var c = adminDB.runCommand({getParameter: 1, cursorTimeoutMillis: 1});
    assert.commandWorked(c);
    assert.eq(c.cursorTimeoutMillis, 9);
}
// test internalQueryPlannerEnableIndexIntersection
{
    var c = adminDB.runCommand({getParameter: 1, internalQueryPlannerEnableIndexIntersection: 1});
    assert.commandWorked(c);
    assert.eq(c.internalQueryPlannerEnableIndexIntersection, false);
}
// test ttlMonitorEnabled
{
    var c = adminDB.runCommand({getParameter: 1, ttlMonitorEnabled: 1});
    assert.commandWorked(c);
    assert.eq(c.ttlMonitorEnabled, false);
}
// test ttlMonitorSleepSecs
{
    var c = adminDB.runCommand({getParameter: 1, ttlMonitorSleepSecs: 1});
    assert.commandWorked(c);
    assert.eq(c.ttlMonitorSleepSecs, 7);
}
