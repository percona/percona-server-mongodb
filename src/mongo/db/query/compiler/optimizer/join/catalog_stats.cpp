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

namespace mongo::join_ordering {

boost::optional<UniqueFieldSet> buildUniqueFieldSetForIndex(const BSONObj& keyPattern,
                                                            FieldToBit& fieldToBit) {
    UniqueFieldSet uniqueFields;
    for (const auto& elem : keyPattern) {
        FieldPath fieldPath{elem.fieldName()};

        // Find the bit assigned to this field or assign a new one, being careful not to exceed the
        // max number of bits allowed in our bitset.
        if (!fieldToBit.contains(fieldPath)) {
            if (fieldToBit.size() == kMaxUniqueFieldsPerCollection) {
                return boost::none;
            }
            fieldToBit.emplace(fieldPath, fieldToBit.size());
        }
        uniqueFields.set(fieldToBit.at(fieldPath));
    }
    return uniqueFields;
}

bool fieldsAreUnique(const std::set<FieldPath>& ndvFields,
                     const UniqueFieldInformation& uniqueFields) {
    // Use 'fieldToBit' to construct a bitset for the NDV fields. It's not an issue if an NDV field
    // is missing from 'fieldToBit' because of the superset check; see below.
    UniqueFieldSet ndvSet;
    for (const auto& ndvField : ndvFields) {
        if (auto it = uniqueFields.fieldToBit.find(ndvField); it != uniqueFields.fieldToBit.end()) {
            ndvSet.set(it->second);
        }
    }

    if (uniqueFields.uniqueFieldSet.contains(ndvSet)) {
        return true;
    }

    // Check if the NDV fields are a superset of some unique field set. For example, if index
    // {a: 1, b: 1} is unique, we know that NDV fields {a, b, c} represent unique data. 'c' may or
    // may not be tracked in 'fieldToBit'; it doesn't matter!
    return std::any_of(uniqueFields.uniqueFieldSet.begin(),
                       uniqueFields.uniqueFieldSet.end(),
                       [&ndvSet](UniqueFieldSet ufs) { return (ndvSet & ufs) == ufs; });
}
}  // namespace mongo::join_ordering
