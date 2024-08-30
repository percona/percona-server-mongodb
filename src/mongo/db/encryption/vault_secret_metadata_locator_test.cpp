/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2024-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/encryption/vault_secret_metadata_locator.h"

#include <sstream>
#include <stdexcept>

#include "mongo/unittest/unittest.h"

namespace mongo::encryption::detail {
#define ASSERT_LOCATOR_EQ(secretPath, expectedEngineConfigPath, expectedMetadataPath) \
    do {                                                                              \
        VaultSecretMetadataLocator l(secretPath);                                     \
        ASSERT_EQ(l.engineConfigPath, expectedEngineConfigPath);                      \
        ASSERT_EQ(l.metadataPath, expectedMetadataPath);                              \
    } while (false)

TEST(VaultSecretMetadataLocatorTest, ValidSecretPathIsOk) {
    ASSERT_LOCATOR_EQ("alpha/data/bravo", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("alpha/data/bravo/charlie", "alpha/config", "alpha/metadata/bravo/charlie");
    ASSERT_LOCATOR_EQ(
        "alpha/data/bravo/charlie/delta", "alpha/config", "alpha/metadata/bravo/charlie/delta");
    ASSERT_LOCATOR_EQ("alpha/bravo/data/kilo", "alpha/bravo/config", "alpha/bravo/metadata/kilo");
    ASSERT_LOCATOR_EQ("alpha/bravo/charlie/data/kilo",
                      "alpha/bravo/charlie/config",
                      "alpha/bravo/charlie/metadata/kilo");
    ASSERT_LOCATOR_EQ("alpha/bravo/charlie/data/kilo/lima/mike",
                      "alpha/bravo/charlie/config",
                      "alpha/bravo/charlie/metadata/kilo/lima/mike");

    ASSERT_LOCATOR_EQ(
        "alpha/data/bravo/charlie/data", "alpha/config", "alpha/metadata/bravo/charlie/data");
    ASSERT_LOCATOR_EQ("alpha/data/bravo/data", "alpha/config", "alpha/metadata/bravo/data");
    ASSERT_LOCATOR_EQ("alpha/data/data", "alpha/config", "alpha/metadata/data");

    ASSERT_LOCATOR_EQ("data/alpha/bravo/data/charlie",
                      "data/alpha/bravo/config",
                      "data/alpha/bravo/metadata/charlie");
    ASSERT_LOCATOR_EQ(
        "data/alpha/data/charlie", "data/alpha/config", "data/alpha/metadata/charlie");
    ASSERT_LOCATOR_EQ("data/data/charlie", "data/config", "data/metadata/charlie");

    ASSERT_LOCATOR_EQ("data/data/data", "data/config", "data/metadata/data");

    ASSERT_LOCATOR_EQ("alpha/data/bravo/foodata/datafoo/charlie",
                      "alpha/config",
                      "alpha/metadata/bravo/foodata/datafoo/charlie");
    ASSERT_LOCATOR_EQ("alpha/data/bravo/foodatafoo/charlie",
                      "alpha/config",
                      "alpha/metadata/bravo/foodatafoo/charlie");
    ASSERT_LOCATOR_EQ("alpha/foodata/datafoo/bravo/data/charlie",
                      "alpha/foodata/datafoo/bravo/config",
                      "alpha/foodata/datafoo/bravo/metadata/charlie");
    ASSERT_LOCATOR_EQ("alpha/foodatafoo/bravo/data/charlie",
                      "alpha/foodatafoo/bravo/config",
                      "alpha/foodatafoo/bravo/metadata/charlie");

    ASSERT_LOCATOR_EQ("metadata/data/metadata", "metadata/config", "metadata/metadata/metadata");
}

TEST(VaultSecretMetadataLocatorTest, LeadingAndTrailingSlashesAreIgnored) {
    ASSERT_LOCATOR_EQ("/alpha/data/bravo", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("/data/data/data", "data/config", "data/metadata/data");
    ASSERT_LOCATOR_EQ("/metadata/data/metadata", "metadata/config", "metadata/metadata/metadata");

    ASSERT_LOCATOR_EQ("alpha/data/bravo/", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("data/data/data/", "data/config", "data/metadata/data");
    ASSERT_LOCATOR_EQ("metadata/data/metadata/", "metadata/config", "metadata/metadata/metadata");

    ASSERT_LOCATOR_EQ("/alpha/data/bravo/", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("/data/data/data/", "data/config", "data/metadata/data");
    ASSERT_LOCATOR_EQ("/metadata/data/metadata/", "metadata/config", "metadata/metadata/metadata");

    ASSERT_LOCATOR_EQ("///alpha/data/bravo", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("/alpha/data/bravo///", "alpha/config", "alpha/metadata/bravo");
    ASSERT_LOCATOR_EQ("///alpha/data/bravo///", "alpha/config", "alpha/metadata/bravo");
}

#define ASSERT_INVALID_PATH(secretPath)                                                            \
    do {                                                                                           \
        std::ostringstream msg;                                                                    \
        msg << "Invalid Vault secret path: `" << secretPath << "`.";                               \
        ASSERT_THROWS_WHAT(VaultSecretMetadataLocator(secretPath), std::runtime_error, msg.str()); \
    } while (false)

TEST(VaultSecretMetadataLocatorTest, InvalidSecretPathIsOk) {
    ASSERT_INVALID_PATH("/");
    ASSERT_INVALID_PATH("///");
    ASSERT_INVALID_PATH("alpha");
    ASSERT_INVALID_PATH("/alpha/");
    ASSERT_INVALID_PATH("alpha/bravo/charlie");
    ASSERT_INVALID_PATH("//alpha/bravo/charlie//");
    ASSERT_INVALID_PATH("alpha/bravo/data");
    ASSERT_INVALID_PATH("data/bravo/charlie");
    ASSERT_INVALID_PATH("data/data");
    ASSERT_INVALID_PATH("data");
    ASSERT_INVALID_PATH("alpha/metadata/charlie");
    ASSERT_INVALID_PATH("alpha/foodata/charlie");
    ASSERT_INVALID_PATH("alpha/datafoo/charlie");
    ASSERT_INVALID_PATH("alpha/foodatafoo/charlie");
}

#define ASSERT_AMBIGUOUS_PATH(secretPath)                                                          \
    do {                                                                                           \
        std::ostringstream msg;                                                                    \
        msg << "Ambiguous Vault secret path: `" << secretPath << "` cannot be split into an "      \
            << "engine mount path and a secret path on that engine due to multiple `/data/` "      \
            << "components. Please specify an unambiguous secret path in the "                     \
            << "`security.vault.secret` during master key rotation or initial node setup.";        \
        ASSERT_THROWS_WHAT(VaultSecretMetadataLocator(secretPath), std::runtime_error, msg.str()); \
    } while (false)

TEST(VaultSecretMetadataLocatorTest, AmbiguousSecretPathIsNotOK) {
    ASSERT_AMBIGUOUS_PATH("alpha/data/data/bravo");
    ASSERT_AMBIGUOUS_PATH("alpha/data/data/data/bravo");
    ASSERT_AMBIGUOUS_PATH("alpha/data/bravo/data/data");
    ASSERT_AMBIGUOUS_PATH("data/data/alpha/data/bravo");

    ASSERT_AMBIGUOUS_PATH("alpha/data/bravo/data/charlie");
    ASSERT_AMBIGUOUS_PATH("alpha/data/bravo/data/charlie/data/delta");
    ASSERT_AMBIGUOUS_PATH("alpha/data/data/bravo/data/charlie");
    ASSERT_AMBIGUOUS_PATH("alpha/data/bravo/data/data/charlie");

    ASSERT_AMBIGUOUS_PATH("//alpha/data/bravo/data/charlie//");

    ASSERT_AMBIGUOUS_PATH("data/data/data/data");

    ASSERT_AMBIGUOUS_PATH("alpha/data/metadata/data/bravo");
    ASSERT_AMBIGUOUS_PATH("alpha/data/foodata/data/bravo");
    ASSERT_AMBIGUOUS_PATH("alpha/data/datafoo/data/bravo");
    ASSERT_AMBIGUOUS_PATH("alpha/data/foodatafoo/data/bravo");
}
}  // namespace mongo::encryption::detail
