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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/optional.hpp>

#include <kmip.h>

#include "mongo/base/secure_allocator.h"
#include "mongo/db/encryption/key_state.h"

namespace mongo::encryption {
class Key;
namespace detail {

class KmipExchange {
public:
    enum class State : std::uint8_t {
        kNotStarted = 0,
        kTransmittingRequest,
        kReceivingResponseLength,
        kReceivingResponseValue,
        kResponseReceived
    };

    class Span {
    public:
        Span(const SecureVector<std::byte>& buffer)
            : _data(buffer->data()), _size(buffer->size()) {}
        Span(std::byte* data, std::size_t size) : _data(data), _size(size) {}
        Span(std::uint8_t* data, std::size_t size)
            : _data(reinterpret_cast<std::byte*>(data)), _size(size) {}

        std::byte* data() noexcept {
            return _data;
        }
        std::size_t size() noexcept {
            return _size;
        }

    private:
        std::byte* _data;
        std::size_t _size;
    };

    virtual ~KmipExchange() = default;

    KmipExchange(const KmipExchange& other) = delete;
    KmipExchange& operator=(const KmipExchange& other) = delete;

    KmipExchange(KmipExchange&& other) = default;
    KmipExchange& operator=(KmipExchange&& other) = default;

    KmipExchange();

    void state(State state);
    State state() const noexcept {
        return _state;
    }

    Span span() noexcept {
        return _span;
    }

protected:
    virtual void encodeRequest() = 0;
    void encodeRequestMessage(const RequestMessage& reqMsg);
    std::size_t decodeValueLength() const;
    std::shared_ptr<ResponseBatchItem> decodeResponseBatchItem();


    // As per KMIP standard (plese see [1] for more details), each message
    // being transmitted is encoded in using the TTLV (Tag, Type, Length, Value)
    // mechanism, where each field has the following sizes
    // 1. Tag - 3 bytes
    // 2. Type - 1 byte
    // 3. Length - 4 bytes
    // 4. Value - number of bytes encoded in the `Length` field.
    //
    // In summary, it is required to read the first 8 bytes to determine
    // the length of the response message.
    //
    // [1] https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581260
    static constexpr std::size_t _kKmipTagSize = 3;
    static constexpr std::size_t _kKmipTypeSize = 1;
    static constexpr std::size_t _kKmipLengthSize = 4;
    static constexpr std::size_t _kKmipTagTypeSize = _kKmipTagSize + _kKmipTypeSize;
    static constexpr std::size_t _kKmipTagTypeLengthSize = _kKmipTagTypeSize + _kKmipLengthSize;

    static constexpr std::size_t _kBufferBlockSize = 1024;

    std::shared_ptr<KMIP> _ctx;
    KmipExchange::State _state;
    SecureVector<std::byte> _buffer;
    Span _span;
};


class KmipExchangeRegisterSymmetricKey : public KmipExchange {
public:
    KmipExchangeRegisterSymmetricKey(const Key& key) : _key(key) {}

    void encodeRequest() override;
    std::string decodeKeyId();

private:
    const Key& _key;
};

class KmipExchangeActivate : public KmipExchange {
public:
    KmipExchangeActivate(const std::string& keyId) : _keyId(keyId) {}

    void encodeRequest() override;

    /// @brief Does nothing if the activation has succeeded or throws
    /// `std::runtime_error` otherwise.
    void verifyResponse();

private:
    const std::string& _keyId;
};

class KmipExchangeGetSymmetricKey : public KmipExchange {
public:
    KmipExchangeGetSymmetricKey(const std::string& keyId) : _keyId(keyId) {}

    void encodeRequest() override;
    boost::optional<Key> decodeKey();

private:
    const std::string& _keyId;
};

class KmipExchangeGetKeyState : public KmipExchange {
public:
    KmipExchangeGetKeyState(const std::string& keyId) : _keyId(keyId) {}

    void encodeRequest() override;
    boost::optional<KeyState> decodeKeyState();

private:
    const std::string& _keyId;
};

}  // namespace detail
}  // namespace mongo::encryption
