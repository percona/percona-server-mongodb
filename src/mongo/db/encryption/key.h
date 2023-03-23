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

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace mongo {
class SecureRandom;
namespace encryption {

class Key {
public:
    ~Key();

    Key(const Key&) = default;
    Key& operator=(const Key&) = default;
    Key(Key&&) = default;
    Key& operator=(Key&&) = default;

    Key();
    explicit Key(SecureRandom& srng);
    explicit Key(const std::string& base64);
    explicit Key(const std::uint8_t* keyData);

    friend bool operator==(const Key& lhs, const Key& rhs) noexcept {
        return lhs._data == rhs._data;
    }

    const std::uint8_t* data() const noexcept {
        return _data.data();
    }
    constexpr std::size_t size() const noexcept {
        return _data.size();
    }
    std::string base64() const;

    static constexpr std::size_t kLength = 32;

private:
    std::uint8_t* data() noexcept {
        return _data.data();
    }

    std::array<std::uint8_t, kLength> _data;
};
}  // namespace encryption
}  // namespace mongo
