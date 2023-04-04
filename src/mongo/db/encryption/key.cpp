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

#include "mongo/db/encryption/key.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

#include "mongo/platform/random.h"
#include "mongo/util/base64.h"
#include "mongo/util/secure_zero_memory.h"

namespace mongo::encryption {
Key::~Key() {
    secureZeroMemory(data(), size());
}

Key::Key(SecureRandom& srng) {
    srng.fill(data(), size());
}

Key::Key() {
    SecureRandom().fill(data(), size());
}

Key::Key(const std::uint8_t* keyData, std::size_t keyDataSize) {
    StringData s(reinterpret_cast<const char*>(keyData), keyDataSize);
    if (keyDataSize == base64::encodedLength(kLength) && base64::validate(s)) {
        std::string decodedKey = base64::decode(s);
        std::memcpy(data(), decodedKey.c_str(), kLength);
        return;
    } else if (keyDataSize == kLength) {
        std::memcpy(data(), keyData, kLength);
        return;
    } else {
        std::ostringstream msg;
        msg << "invalid data for an encryption key: it must be a byte string of length " << kLength
            << " in either raw or base64-encoded form";
        throw std::runtime_error(msg.str());
    }
}

std::string Key::base64() const {
    return base64::encode(data(), size());
}
}  // namespace mongo::encryption
