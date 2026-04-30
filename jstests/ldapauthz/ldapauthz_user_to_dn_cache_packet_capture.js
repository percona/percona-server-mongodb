/**
 * Compare userToDN mapping-related LDAP traffic with cache on vs off
 * using tcpdump writing pcap files, then counting a cleartext marker in decoded
 * packets.
 *
 * Requires tcpdump with visibility to mongod->LDAP traffic.
 * Requires root: packet capture needs privileges tcpdump does not have for a normal user.
 *
 */
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

(function () {
    "use strict";

    if (_isWindows()) {
        jsTestLog("Skipping test: Windows is not supported for this capture scenario");
        quit();
    }

    // Skip unless root: tcpdump capture on the chosen interface typically requires elevated privileges.
    if (runProgram("sh", "-c", 'test "$(id -u)" -eq 0') !== 0) {
        jsTestLog("Skipping test: not running as root (effective UID is not 0)");
        quit();
    }

    // Skip if tcpdump is not installed
    if (runProgram("sh", "-c", "command -v tcpdump >/dev/null") !== 0) {
        jsTestLog("Skipping test: tcpdump is not installed or not on PATH");
        quit();
    }

    load("jstests/ldapauthz/_check.js");

    const kSIGINT = 2;
    const username = "exttestro";
    const userpwd = "exttestro9a5S";

    const nameToDn = function (name) {
        return "cn=" + name + ",dc=percona,dc=com";
    };

    const ldapQueryMapping =
        '[{match: "(.+)", ldapQuery: "dc=percona,dc=com??sub?(&(objectClass=organizationalPerson)(sn={0}))"}]';

    const mappingWireMarker = "organizationalPerson";

    function baseMongodOpts(extraSetParams) {
        const setParameter = Object.assign(
            {
                authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
                ldapUserCacheInvalidationInterval: 1,
                ldapShouldRefreshUserCacheEntries: false,
            },
            extraSetParams || {},
        );
        return {
            auth: "",
            ldapServers: TestData.ldapServers,
            ldapTransportSecurity: "none",
            ldapBindMethod: "simple",
            ldapQueryUser: TestData.ldapQueryUser,
            ldapQueryPassword: TestData.ldapQueryPassword,
            ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
            ldapUserToDNMapping: ldapQueryMapping,
            setParameter: setParameter,
        };
    }

    function authLDAPUser(conn) {
        const db = conn.getDB("$external");
        const ok = db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"});
        if (ok) {
            checkConnectionStatus(username, db.runCommand({connectionStatus: 1}), nameToDn);
            db.logout();
        }
        return ok;
    }

    function parseTrailingIntegerFromProgramOutput(raw) {
        const m = raw.trim().match(/(\d+)\s*$/);
        assert(m, "no trailing integer in program output: " + tojson(raw));
        return parseInt(m[1], 10);
    }

    function countMarkerInPcap(pcapPath, marker, countPath) {
        const script =
            "count=$(tcpdump -r " +
            tojson(pcapPath) +
            " -A 2>/dev/null | grep -cF " +
            tojson(marker) +
            ' || true); echo -n "$count" > ' +
            tojson(countPath);
        assert.eq(0, runMongoProgram("bash", "-c", script), "bash/tcpdump/grep pipeline failed");

        clearRawMongoProgramOutput();
        assert.eq(0, runMongoProgram("cat", countPath), "reading count file failed");
        return parseTrailingIntegerFromProgramOutput(rawMongoProgramOutput(".*"));
    }

    function assertPcapNonEmpty(pcapPath) {
        clearRawMongoProgramOutput();
        assert.eq(
            0,
            runMongoProgram(
                "bash",
                "-c",
                "sz=$(stat -c%s " + tojson(pcapPath) + ' 2>/dev/null || echo 0); echo -n "$sz"',
            ),
        );
        const sz = parseTrailingIntegerFromProgramOutput(rawMongoProgramOutput(".*"));
        assert.gt(
            sz,
            40,
            "pcap too small or missing; tcpdump likely saw no packets (caps/netns/interface). path=" + pcapPath,
        );

        clearRawMongoProgramOutput();
        assert.eq(
            0,
            runMongoProgram(
                "bash",
                "-c",
                "n=$(tcpdump -r " + tojson(pcapPath) + ' -nn 2>/dev/null | wc -l); echo -n "$n"',
            ),
        );
        const lines = parseTrailingIntegerFromProgramOutput(rawMongoProgramOutput(".*"));
        assert.gt(lines, 0, "tcpdump -r produced no packet lines for " + pcapPath);
    }

    class LdapPortCapture {
        constructor(pcapPath, iface) {
            this.pcapPath = pcapPath;
            this.iface = iface || "lo";
            this.pid = undefined;
        }

        start() {
            const args = ["tcpdump", "-i", this.iface, "-nn", "-s0", "-l", "dst", "port", "389", "-w", this.pcapPath];
            this.pid = _startMongoProgram({args: args});
            assert(checkProgram(this.pid).alive, "tcpdump failed to start");
            sleep(1500);
        }

        stop() {
            if (this.pid === undefined) {
                return;
            }
            stopMongoProgramByPid(this.pid, kSIGINT);
            waitProgram(this.pid);
            this.pid = undefined;
            sleep(500);
        }
    }

    function runTwiceAuthedCapture(extraSetParams, pcapPath, iface) {
        const countPath = pcapPath + ".mapping_marker_count";
        const cap = new LdapPortCapture(pcapPath, iface);
        const conn = MongoRunner.runMongod(baseMongodOpts(extraSetParams));
        assert(conn, "Cannot start mongod instance");
        createAdminUser(conn);

        cap.start();
        sleep(2000);
        assert(authLDAPUser(conn), "first auth should succeed");
        sleep(2000);
        assert(authLDAPUser(conn), "second auth should succeed");
        sleep(2000);
        cap.stop();

        MongoRunner.stopMongod(conn);

        assertPcapNonEmpty(pcapPath);
        const n = countMarkerInPcap(pcapPath, mappingWireMarker, countPath);
        jsTestLog("marker count for " + pcapPath + ": " + n);
        return n;
    }

    const iface = TestData.ldapTcpdumpInterface || "lo";
    jsTestLog("tcpdump interface: " + iface + " (override with TestData.ldapTcpdumpInterface)");

    const pcapCached = MongoRunner.dataPath + "ldap_user_to_dn_cache_on_" + Date.now() + ".pcap";
    const pcapNoCache = MongoRunner.dataPath + "ldap_user_to_dn_cache_off_" + Date.now() + ".pcap";

    // The query to LDAP should appear once if using userToDN cache
    jsTestLog("Capture: two PLAIN auths, userToDN cache on (defaults)...");
    const countCacheOn = runTwiceAuthedCapture({}, pcapCached, iface);
    assert.eq(1, countCacheOn);

    // The query to LDAP should appear 4 times without cache
    jsTestLog("Capture: two PLAIN auths, userToDN cache off (TTL=0)...");
    const countCacheOff = runTwiceAuthedCapture({ldapUserToDNCacheTTLSeconds: 0}, pcapNoCache, iface);
    assert.eq(4, countCacheOff);
})();
