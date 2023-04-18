/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

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

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/encryption/error.h"
#include "mongo/util/str.h"

namespace mongo::encryption {
class ErrorBuilder {
public:
    ErrorBuilder(const StringData& what, const StringData& reason = StringData()) {
        _builder.append("what", what);
        if (!reason.empty()) {
            _builder.append("reason", reason);
        }
    }

    ErrorBuilder(const StringData& what, const Error& reason) {
        _builder.append("what", what);
        _builder.append("reason", reason.toBSON());
    }

    ErrorBuilder& append(const StringData& name, const StringData& value) {
        _builder.append(name, value);
        return *this;
    }

    template <typename T,
              typename = std::void_t<
                  decltype(std::declval<T>().serialize(&std::declval<BSONObjBuilder&>()))>>
    ErrorBuilder& append(const StringData& name, const T& value) {
        BSONObjBuilder sb = _builder.subobjStart(name);
        value.serialize(&sb);
        sb.done();
        return *this;
    }

    template <typename Iterator,
              typename = std::void_t<decltype(std::declval<BSONArrayBuilder>().append(
                  std::declval<Iterator>(), std::declval<Iterator>()))>>
    ErrorBuilder& append(const StringData& name, Iterator begin, Iterator end) {
        BSONArrayBuilder sb = _builder.subarrayStart(name);
        sb.append(begin, end);
        sb.done();
        return *this;
    }

    Error error() {
        return Error(_builder.obj());
    }

private:
    BSONObjBuilder _builder;
};

enum class KeyOperationType : std::uint8_t { read, save };

class KeyErrorBuilder : public ErrorBuilder {
public:
    KeyErrorBuilder(KeyOperationType opType, const StringData& reason)
        : ErrorBuilder(str::stream() << "key " << to_string(opType) << " failed", reason) {}

private:
    static StringData to_string(KeyOperationType opType) {
        switch (opType) {
            case KeyOperationType::read:
                return "reading";
            case KeyOperationType::save:
                return "saving";
        }
        throw std::invalid_argument(
            std::to_string(std::underlying_type_t<KeyOperationType>(opType)));
    }
};
}  // namespace mongo::encryption
