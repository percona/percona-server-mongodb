import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

// Function to check if the OIDC feature is included in the build info's 'proFeatures' field.
function checkBuildInfo(clusterClass) {
    const test = new OIDCFixture({oidcProviders: [], idps: []});
    test.setup(clusterClass);

    const buildInfo = assert.commandWorked(test.admin.runCommand({buildInfo: 1}));
    assert(buildInfo, "Failed to get build info");
    assert(buildInfo.perconaFeatures.includes("OIDC"),
           "OIDC feature should be included in build info");

    test.teardown();
}

checkBuildInfo(StandaloneMongod);
checkBuildInfo(ShardedCluster);
