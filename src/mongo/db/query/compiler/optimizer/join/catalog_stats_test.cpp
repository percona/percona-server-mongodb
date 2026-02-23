/**
 *    Copyright (C) 2026-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/db/query/compiler/optimizer/join/catalog_stats.h"

#include "mongo/bson/json.h"
#include "mongo/db/query/compiler/optimizer/join/unit_test_helpers.h"
#include "mongo/unittest/unittest.h"

namespace mongo::join_ordering {
using CatalogStatsTest = JoinOrderingTestFixture;

TEST_F(CatalogStatsTest, FieldsAreUnique) {
    UniqueFieldInformation uniqueFields =
        buildUniqueFieldInfo({fromjson("{foo: 1}"),
                              fromjson("{bar: 1}"),
                              fromjson("{baz: -1, qux: 1}"),
                              fromjson("{a: 1, b: 1, c: 1}"),
                              fromjson("{b: 1, c: 1, d: 1, e: 1}")});

    // Exact match in unique fields.
    ASSERT_TRUE(fieldsAreUnique({"foo"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"bar"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"baz", "qux"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"qux", "baz"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"a", "b", "c"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"b", "c", "d", "e"}, uniqueFields));

    // Superset of unique fields.
    ASSERT_TRUE(fieldsAreUnique({"foo", "nonexistent"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"baz", "qux", "nonexistent"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"a", "b", "c", "foo"}, uniqueFields));
    ASSERT_TRUE(fieldsAreUnique({"bar", "foo.subfield"}, uniqueFields));

    // Subset of a unique field set is not unique.
    ASSERT_FALSE(fieldsAreUnique({"baz"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"qux"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"b", "c", "d"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"baz", "nonexistent"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"baz", "a", "b"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"nonexistent"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"a", "b", "cc"}, uniqueFields));

    // Subfield of a unique field is not unique.
    ASSERT_FALSE(fieldsAreUnique({"foo.subfield"}, uniqueFields));
    ASSERT_FALSE(fieldsAreUnique({"baz", "qux.subfield"}, uniqueFields));
}
}  // namespace mongo::join_ordering
