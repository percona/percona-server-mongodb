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

// TLS options accepting both TLS and plain connections with CA file configured
const tlsOptions = {
    tlsMode: 'allowTLS',
    tlsCertificateKeyFile: 'jstests/libs/server.pem',
    tlsCAFile: 'jstests/libs/ca.pem',
};

// TLS options without CA file
// requires tlsUseSystemCA server parameter because TLS cannot be used without a chain of trust
const tlsSystemCAOptions = {
    tlsMode: 'allowTLS',
    tlsCertificateKeyFile: 'jstests/libs/server.pem',
};

// options for enabling server (cluster membership) x.509 authentication
// transitionToAuth allows test to access server without authentication
// (transitionToAuth is only compatible with x509 but not sendX509 cluster auth mode)
// preferTLS is required because x.509 cluster authentication needs TLS for outgoing connections
const x509ServerOptions = Object.merge(tlsOptions, {
    tlsMode: 'preferTLS',
    clusterAuthMode: 'x509',
    transitionToAuth: '',
});

// default values for telementry data fields related to authentication/authorization methods
const authMethodFieldsDefault = {
    oidc_enabled: "false",
    ldap_enabled: "false",
    ldap_authorization_enabled: "false",
    ldap_sasl_authentication_enabled: "false",
    kerberos_enabled: "false",
    x509_enabled: "false",
    x509_server_enabled: "false",
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
// clusterOptions are applied to shard and config server nodes
function getMongosTelemetry(options, clusterOptions = {}) {
    print("Starting mongos with options: " + tojson(options));

    var st = new ShardingTest({
        shards: 1,
        config: 1,
        mongos: 1,
        // test certificates are only valid for localhost
        useHostname: false,
        rs: Object.merge({nodes: 1, setParameter: setParameterOpts}, clusterOptions),
        mongosOptions: options,
        configOptions: Object.merge({setParameter: setParameterOpts}, clusterOptions)
    });

    assert(setParameterOpts.perconaTelemetryGracePeriod, "perconaTelemetryGracePeriod is not set");
    sleep(setParameterOpts.perconaTelemetryGracePeriod * 1000);

    getTelmDataByConn(st.shard0);
    const data = getTelmDataForMongos();
    assert(data.length > 0, "No telemetry data found");
    print("Telemetry data collected: " + tojson(data));

    if (options.clusterAuthMode) {
        // consistency checks in st.stop() try to authenticate as cluster member using x.509
        // which requires TLS on the shell side, so stop cluster components directly
        st.stopAllMongos();
        st.stopAllShards();
        st.stopAllConfigServers();
    } else {
        st.stop();
    }

    return data[0];
}

// returns telemetry data from mongod with given options
function getTelemetry(getTelemetryFunc, options = {}, clusterOptions = {}) {
    mkdir(telmPath);
    cleanupTelmDir();

    options.setParameter = Object.merge(setParameterOpts, options.setParameter || {});

    return getTelemetryFunc(options, clusterOptions);
}

// test for specific field in telemetry data with provided options for mongod
function testFields(
    getTelemetryFunc, fields, options = {}, clusterOptions = {}, expected = "true") {
    const data = getTelemetry(getTelemetryFunc, options, clusterOptions);
    assertFieldsDefined(data);
    if (!Array.isArray(fields)) {
        fields = [fields];
    }

    fields.forEach(field => {
        assert.eq(data[field], expected, `${field} should be ${expected}`);
    });
}

// test for specific authentication method fields in telemetry data
function testAuthMethodFields(
    getTelemetryFunc, mechanisms, fields, options = {}, expected = "true") {
    if (mechanisms) {
        if (!options.setParameter) {
            options.setParameter = {};
        }
        options.setParameter.authenticationMechanisms = mechanisms;
    }

    testFields(getTelemetryFunc, fields, options, {}, expected);
}

for (const getTelemetryFunc of [getMongodTelemetry, getMongosTelemetry]) {
    // check default values
    const defaultData = getTelemetry(getTelemetryFunc);
    assertDefaultFields(defaultData);

    // authentication mechanisms tests
    testAuthMethodFields(getTelemetryFunc, "GSSAPI", "kerberos_enabled");
    testAuthMethodFields(getTelemetryFunc, "PLAIN", "ldap_sasl_authentication_enabled");
    testAuthMethodFields(getTelemetryFunc,
                         "GSSAPI,MONGODB-X509,PLAIN",
                         ["kerberos_enabled", "x509_enabled", "ldap_sasl_authentication_enabled"],
                         Object.merge(tlsOptions, {}));
    testAuthMethodFields(getTelemetryFunc, "MONGODB-OIDC", "oidc_enabled", oidcOptions);

    // client x.509 authentication requires MONGODB-X509 mechanism, TLS and CA file or system CA
    testAuthMethodFields(
        getTelemetryFunc, "MONGODB-X509", "x509_enabled", Object.merge(tlsOptions, {}));
    testAuthMethodFields(getTelemetryFunc, "MONGODB-X509", "x509_enabled", {}, "false");
    testAuthMethodFields(getTelemetryFunc,
                         "MONGODB-X509",
                         "x509_enabled",
                         Object.merge(tlsSystemCAOptions, {setParameter: {tlsUseSystemCA: true}}));
    testAuthMethodFields(
        getTelemetryFunc, "SCRAM-SHA-256", "x509_enabled", Object.merge(tlsOptions, {}), "false");

    // server x.509 authentication requires clusterAuthMode x509/sendX509, TLS and CA file
    testFields(
        getTelemetryFunc, "x509_server_enabled", Object.merge(x509ServerOptions, {}), tlsOptions);
    testFields(
        getTelemetryFunc, "x509_server_enabled", Object.merge(tlsOptions, {}), tlsOptions, "false");

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
