/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */


#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include "mongo/db/audit/audit_options.h"
#include "mongo/db/server_options.h"

#include "mongo/util/options_parser/environment.h"

#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"
#include "mongo/unittest/temp_dir.h"


namespace mongo {
namespace {
namespace moe = mongo::optionenvironment;
namespace fs = boost::filesystem;

#define ASSERT_BOOST_SUCCESS(ec) ASSERT_FALSE(ec) << ec.message()

// Set of util functions which asserts instead of throwing exceptions

void changeDir(const fs::path& dir) {
    boost::system::error_code ec;

    fs::current_path(dir, ec);
    ASSERT_BOOST_SUCCESS(ec);
}

fs::path getCwd() {
    boost::system::error_code ec;

    const auto cwd = fs::current_path(ec);
    ASSERT_BOOST_SUCCESS(ec);

    return cwd;
}

template <typename T>
void set(moe::Environment& env, const moe::Key& key, T&& value) {
    ASSERT_OK(env.set(key, moe::Value(std::forward<T>(value))));
}

class ValidateAuditOptionsTestFixture : public mongo::unittest::Test {
protected:
    static constexpr auto kDefaultPathJson = "auditLog.json";
    static constexpr auto kDefaultPathBson = "auditLog.bson";
    static constexpr auto kTempDirPrefix = "ValidateAuditOptionsTestFixture";

    void setUp() override {
        // Reset audit options and set up default server parameters
        auditOptions = AuditOptions();

        _tmpDir = std::make_unique<unittest::TempDir>(kTempDirPrefix);
        _cwd = getCwd();
        changeDir(_tmpDir->path());

        // make sure cwd is correct
        serverGlobalParams.cwd = getCwd().string();
    }

    void tearDown() override {
        // Restore the original working directory and clean up the temporary directory
        changeDir(_cwd);
        _tmpDir.reset();
        _cwd = fs::path();
    }

private:
    fs::path _cwd;
    std::unique_ptr<unittest::TempDir> _tmpDir;
};

// Test default behavior when no audit log options are set
TEST_F(ValidateAuditOptionsTestFixture, Default) {
    moe::Environment env;

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    // expect no file created if 'destination' is not set
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
}

// Test destination is set to empty string
TEST_F(ValidateAuditOptionsTestFixture, DestinationEmptyString) {
    moe::Environment env;
    set(env, "auditLog.destination", "");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    // expect no file created if 'destination' is empty string
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
}

// Test BSON format with default path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatBSON_DefaultPath) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "BSON");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / kDefaultPathBson);
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
}

// Test JSON format with default path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatJSON_DefaultPath) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "JSON");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / kDefaultPathJson);
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
}

// Test BSON format with default path derived from log path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatBSON_DefaultPathFromLog) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "BSON");

    unittest::TempDir tmpDir(kTempDirPrefix);
    const auto tmpDirPath = fs::path(tmpDir.path());
    serverGlobalParams.logpath = (tmpDirPath / "log.log").string();

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, tmpDirPath / kDefaultPathBson);
    ASSERT_FALSE(fs::exists(tmpDirPath / kDefaultPathBson));
}

// Test JSON format with default path derived from log path
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_FormatJSON_DefaultPathFromLog) {
    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.format", "JSON");

    unittest::TempDir tmpDir(kTempDirPrefix);
    const auto tmpDirPath = fs::path(tmpDir.path());
    serverGlobalParams.logpath = (tmpDirPath / "log.log").string();

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, tmpDirPath / kDefaultPathJson);
    ASSERT_FALSE(fs::exists(tmpDirPath / kDefaultPathJson));
}

// Test custom path for audit log file
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, getCwd() / path);
    ASSERT_FALSE(fs::exists(path));
}

// Test custom path when the directory does not exist
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath_DirectoryNotExists) {
    const auto path = "bad_dir/auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_EQ(validateAuditOptions(), ErrorCodes::BadValue);
}

// Test custom path with simulated fork (changing working directory)
TEST_F(ValidateAuditOptionsTestFixture, DestinationFile_CustomPath_Fork) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "file");
    set(env, "auditLog.path", path);

    // Simulate fork by changing current working directory
    unittest::TempDir tmpDir(kTempDirPrefix);
    const auto cwd = getCwd();
    changeDir(tmpDir.path());

    ScopeGuard sg = [cwd] {
        changeDir(cwd);
    };

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_EQ(auditOptions.path, cwd / path);
    ASSERT_FALSE(fs::exists(cwd / path));
}

// Test file is not created if destination is console
TEST_F(ValidateAuditOptionsTestFixture, DestinationConsole_FileNotCreated) {

    moe::Environment env;
    set(env, "auditLog.destination", "console");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
}

// Test file is not created if destination is console and path is provided
TEST_F(ValidateAuditOptionsTestFixture, DestinationConsole_PathProvided_FileNotCreated) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "console");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_FALSE(fs::exists(path));
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
}

// Test file is not created if destination is syslog
TEST_F(ValidateAuditOptionsTestFixture, DestinationSyslog_FileNotCreated) {

    moe::Environment env;
    set(env, "auditLog.destination", "syslog");

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
}

// Test file is not created if destination is syslog and path is provided
TEST_F(ValidateAuditOptionsTestFixture, DestinationSyslog_PathProvided_FileNotCreated) {
    const auto path = "auditFileName.json";

    moe::Environment env;
    set(env, "auditLog.destination", "syslog");
    set(env, "auditLog.path", path);

    ASSERT_OK(storeAuditOptions(env));
    ASSERT_OK(validateAuditOptions());
    ASSERT_FALSE(fs::exists(path));
    ASSERT_FALSE(fs::exists(kDefaultPathBson));
    ASSERT_FALSE(fs::exists(kDefaultPathJson));
}

}  // namespace
}  // namespace mongo
