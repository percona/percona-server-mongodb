load('jstests/telemetry/_telemetry_helpers.js');

// check for LDAP test configuration
function isLDAPTestConfigured() {
    return TestData.ldapServers && TestData.ldapQueryUser && TestData.ldapQueryPassword;
}

// options for enabling LDAP
const ldapOptions = {
    ldapServers: TestData.ldapServers,
    ldapQueryUser: TestData.ldapQueryUser,
    ldapQueryPassword: TestData.ldapQueryPassword,
    ldapTransportSecurity: 'none',
};

// options for enabling LDAP with authorization
const ldapAuthzOptions =
    Object.merge(ldapOptions, {ldapAuthzQueryTemplate: '{USER}?memberOf?base'});

// options for enabling OIDC authentication
const oidcOptions = {
    setParameter: {
        oidcIdentityProviders: JSON.stringify([{
            issuer: "https://localhost",
            authNamePrefix: "test-prefix",
            audience: "test-audience",
            clientId: "test-client-id",
            useAuthorizationClaim: false,
        }]),
    }
};

// default values for telementry data fields related to authentication/authorization methods
const authMethodFieldsDefault = {
    oidc_enabled: "false",
    ldap_enabled: "false",
    ldap_authorization_enabled: "false",
    ldap_sasl_authentication_enabled: "false",
    kerberos_enabled: "false",
    x509_enabled: "true",
};

// check if all fields are defined in telemetry data
function assertFieldsDefined(data) {
    Object.keys(authMethodFieldsDefault).forEach(field => {
        assert(data[field] !== undefined, `${field} is not defined in telemetry data`);
    });
}

// check if all fields have expected default values
function assertDefaultFields(data) {
    Object.keys(authMethodFieldsDefault).forEach(field => {
        assert.eq(data[field],
                  authMethodFieldsDefault[field],
                  `${field} should be ${authMethodFieldsDefault[field]}, but got ${data[field]}`);
    });
}

// returns telemetry data for mongod with given options
function getMongodTelemetry(options) {
    print("Starting mongod with options: " + tojson(options));
    var conn = MongoRunner.runMongod(options);

    assert(setParameterOpts.perconaTelemetryGracePeriod, "perconaTelemetryGracePeriod is not set");
    sleep(setParameterOpts.perconaTelemetryGracePeriod * 1000);

    const data = getTelmDataByConn(conn);
    assert(data.length > 0, "No telemetry data found");
    print("Telemetry data collected: " + tojson(data));

    MongoRunner.stopMongod(conn);

    return data[0];
}

// returns telemetry data for mongos with given options
function getMongosTelemetry(options) {
    print("Starting mongos with options: " + tojson(options));

    var st = new ShardingTest({
        shards: 1,
        config: 1,
        mongos: 1,
        rs: {nodes: 1, setParameter: setParameterOpts},
        mongosOptions: options,
        configOptions: {setParameter: setParameterOpts}
    });

    assert(setParameterOpts.perconaTelemetryGracePeriod, "perconaTelemetryGracePeriod is not set");
    sleep(setParameterOpts.perconaTelemetryGracePeriod * 1000);

    getTelmDataByConn(st.shard0);
    const data = getTelmDataForMongos();
    assert(data.length > 0, "No telemetry data found");
    print("Telemetry data collected: " + tojson(data));

    st.stop();

    return data[0];
}

// returns telemetry data from mongod with given options
function getTelemetry(getTelemetryFunc, options = {}) {
    mkdir(telmPath);
    cleanupTelmDir();

    options.setParameter = Object.merge(setParameterOpts, options.setParameter || {});

    return getTelemetryFunc(options);
}

// test for specific field in telemetry data with provided options for mongod
function testFields(getTelemetryFunc, fields, options = {}) {
    const data = getTelemetry(getTelemetryFunc, options);
    assertFieldsDefined(data);
    if (!Array.isArray(fields)) {
        fields = [fields];
    }

    fields.forEach(field => {
        assert.eq(data[field], "true", `${field} should be true`);
    });
}

// test for specific authentication method fields in telemetry data
function testAuthMethodFields(getTelemetryFunc, mechanisms, fields, options = {}) {
    if (mechanisms) {
        if (!options.setParameter) {
            options.setParameter = {};
        }
        options.setParameter.authenticationMechanisms = mechanisms;
    }

    testFields(getTelemetryFunc, fields, options);
}

for (const getTelemetryFunc of [getMongodTelemetry, getMongosTelemetry]) {
    // check default values
    const defaultData = getTelemetry(getTelemetryFunc);
    assertDefaultFields(defaultData);

    // authentication mechanisms tests
    testAuthMethodFields(getTelemetryFunc, "GSSAPI", "kerberos_enabled");
    testAuthMethodFields(getTelemetryFunc, "MONGODB-X509", "x509_enabled");
    testAuthMethodFields(getTelemetryFunc, "PLAIN", "ldap_sasl_authentication_enabled");
    testAuthMethodFields(getTelemetryFunc,
                         "GSSAPI,MONGODB-X509,PLAIN",
                         ["kerberos_enabled", "x509_enabled", "ldap_sasl_authentication_enabled"]);

    // check if OIDC feature is enabled
    if (defaultData.pro_features.includes('OIDC')) {
        testAuthMethodFields(getTelemetryFunc, "MONGODB-OIDC", "oidc_enabled", oidcOptions);
    } else {
        print("OIDC feature is not enabled, skipping oidc_enabled test");
    }

    // check if LDAP tests are configured
    if (isLDAPTestConfigured()) {
        testFields(getTelemetryFunc, "ldap_enabled", ldapOptions);

        // LDAP authorization is not supported by mongos
        if (getTelemetryFunc !== getMongosTelemetry) {
            testFields(
                getTelemetryFunc, ["ldap_enabled", "ldap_authorization_enabled"], ldapAuthzOptions);
        }
    } else {
        print(
            "LDAP related TestData fields are not defined, skipping ldap_enabled and ldap_authorizaiton_enabled tests");
    }
}
