/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2026-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/recycle_bin/recycle_bin.h"

#include "mongo/db/namespace_string.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/uuid.h"

#include <boost/none.hpp>
#include <boost/optional/optional.hpp>

namespace mongo {
namespace {

// --------------------------------------------------------------------------
// makeRecycleBinNss
// --------------------------------------------------------------------------

TEST(RecycleBinNssTest, MakeBasicNamespace) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "mycoll");
    auto result = makeRecycleBinNss(nss, 1713260000);
    ASSERT_EQ(result.dbName(), nss.dbName());
    ASSERT_EQ(result.coll(), "system.recycle_bin.mycoll.1713260000");
}

TEST(RecycleBinNssTest, MakeNamespaceWithUuid) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "mycoll");
    auto uuid = UUID::parse("12345678-1234-1234-1234-123456789abc").getValue();
    auto result = makeRecycleBinNss(nss, 1713260000, uuid);
    ASSERT_EQ(result.coll(), "system.recycle_bin.mycoll.1713260000.12345678");
}

TEST(RecycleBinNssTest, MakeNamespacePreservesDatabase) {
    auto nss = NamespaceString::createNamespaceString_forTest("otherdb", "stuff");
    auto result = makeRecycleBinNss(nss, 999);
    ASSERT_EQ(result.dbName(),
              DatabaseName::createDatabaseName_forTest(boost::none, "otherdb"));
}

TEST(RecycleBinNssTest, MakeNamespaceWithDotInCollectionName) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "my.dotted.coll");
    auto result = makeRecycleBinNss(nss, 1713260000);
    ASSERT_EQ(result.coll(), "system.recycle_bin.my.dotted.coll.1713260000");
}

// --------------------------------------------------------------------------
// parseRecycleBinNss
// --------------------------------------------------------------------------

TEST(RecycleBinNssTest, ParseBasicNamespace) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.1713260000");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "mycoll");
    ASSERT_EQ(parsed->dropTimeSecs, 1713260000);
    ASSERT_EQ(parsed->recycleBinNss, nss);
}

TEST(RecycleBinNssTest, ParseNamespaceWithUuidSuffix) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.1713260000.abcd1234");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "mycoll");
    ASSERT_EQ(parsed->dropTimeSecs, 1713260000);
}

TEST(RecycleBinNssTest, ParseNamespaceWithAllDigitUuidSuffix) {
    // UUID prefix can be all digits (e.g., UUID starting with "12345678-...").
    // Must not be mis-parsed as a timestamp.
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.1713260000.12345678");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "mycoll");
    ASSERT_EQ(parsed->dropTimeSecs, 1713260000);
}

TEST(RecycleBinNssTest, ParseNamespaceWithDottedCollectionName) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.my.dotted.coll.1713260000");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "my.dotted.coll");
    ASSERT_EQ(parsed->dropTimeSecs, 1713260000);
}

TEST(RecycleBinNssTest, ParseNamespaceWithDottedCollectionNameAndUuid) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.my.dotted.coll.1713260000.abcd1234");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "my.dotted.coll");
    ASSERT_EQ(parsed->dropTimeSecs, 1713260000);
}

TEST(RecycleBinNssTest, ParseReturnsNoneForNonRecycleBinNamespace) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "regular_collection");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForSystemButNotRecycleBin) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "system.views");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForPrefixOnly) {
    auto nss = NamespaceString::createNamespaceString_forTest("mydb", "system.recycle_bin.");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForMissingTimestamp) {
    auto nss =
        NamespaceString::createNamespaceString_forTest("mydb", "system.recycle_bin.mycoll");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForNonNumericTimestamp) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.notanumber");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForZeroTimestamp) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.0");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

TEST(RecycleBinNssTest, ParseReturnsNoneForNegativeTimestamp) {
    auto nss = NamespaceString::createNamespaceString_forTest(
        "mydb", "system.recycle_bin.mycoll.-1");
    auto parsed = parseRecycleBinNss(nss);
    ASSERT(!parsed.has_value());
}

// --------------------------------------------------------------------------
// makeRecycleBinNss -> parseRecycleBinNss round-trip
// --------------------------------------------------------------------------

TEST(RecycleBinNssTest, RoundTripBasic) {
    auto original = NamespaceString::createNamespaceString_forTest("testdb", "employees");
    long long ts = 1713260000;
    auto recycleBinNss = makeRecycleBinNss(original, ts);
    auto parsed = parseRecycleBinNss(recycleBinNss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "employees");
    ASSERT_EQ(parsed->dropTimeSecs, ts);
}

TEST(RecycleBinNssTest, RoundTripWithUuid) {
    auto original = NamespaceString::createNamespaceString_forTest("testdb", "employees");
    auto uuid = UUID::parse("abcdef01-2345-6789-abcd-ef0123456789").getValue();
    long long ts = 1713260000;
    auto recycleBinNss = makeRecycleBinNss(original, ts, uuid);
    auto parsed = parseRecycleBinNss(recycleBinNss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "employees");
    ASSERT_EQ(parsed->dropTimeSecs, ts);
}

TEST(RecycleBinNssTest, RoundTripDottedCollectionName) {
    auto original = NamespaceString::createNamespaceString_forTest("testdb", "a.b.c");
    long long ts = 1713260000;
    auto recycleBinNss = makeRecycleBinNss(original, ts);
    auto parsed = parseRecycleBinNss(recycleBinNss);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->originalCollection, "a.b.c");
    ASSERT_EQ(parsed->dropTimeSecs, ts);
}

// --------------------------------------------------------------------------
// kRecycleBinPrefix
// --------------------------------------------------------------------------

TEST(RecycleBinNssTest, PrefixConstant) {
    ASSERT_EQ(kRecycleBinPrefix, "system.recycle_bin."_sd);
}

}  // namespace
}  // namespace mongo
