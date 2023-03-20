/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2022-present Percona and/or its affiliates. All rights reserved.

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
#include <stdexcept>
#include <string>
#include <type_traits>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/encryption/key_id.h"

namespace mongo::encryption {
class KeyError : public std::runtime_error {
public:
    /// @brief Returns more detailed explanatory information about the error
    /// than the `what` member function does.
    ///
    /// @note The member function also makes the class loggable with LOGV2.
    BSONObj toBSON() const {
        return _info;
    }

    const char* what() const noexcept override {
        return _info.getField("reason").valueStringData().rawData();
    }

private:
    friend class KeyErrorBuilder;
    explicit KeyError(BSONObj&& info) : std::runtime_error(""), _info(std::move(info)) {}

    BSONObj _info;
};

enum class KeyOperationType : std::uint8_t {
    read,
    save
};

inline StringData to_string(KeyOperationType opType) {
    switch (opType) {
        case KeyOperationType::read: return "read";
        case KeyOperationType::save: return "save";
    }
    throw std::invalid_argument(std::to_string(std::underlying_type_t<KeyOperationType>(opType)));
}

class KeyErrorBuilder {
public:
    KeyErrorBuilder(KeyOperationType opType, const StringData& reason) {
        _builder.append("failedOperation", to_string(opType));
        _builder.append("reason", reason.empty() ? StringData("") : reason);
    }

    KeyErrorBuilder& append(const StringData& name, const StringData& value) {
        _builder.append(name, value);
        return *this;
    }

    KeyErrorBuilder& append(const StringData& name, const KeyId& value) {
        BSONObjBuilder sb = _builder.subobjStart(name);
        value.serialize(&sb);
        sb.done();
        return *this;
    }

    KeyError error() {
        return KeyError(_builder.obj());
    }

private:
    BSONObjBuilder _builder;
};
}  // namespace mongo::encryption
