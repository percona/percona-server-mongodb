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
#include <memory>
#include <string>

#include <boost/optional.hpp>

#include "mongo/db/encryption/key_state.h"
#include "mongo/db/encryption/kmip_exchange.h"
#include "mongo/util/assert_util_core.h"

namespace mongo::encryption {
class Key;
namespace detail {
/// @brief The class encapsulates a series of KMIP exchanges
/// (i.e. request-response pairs) between a client and a server.
class KmipSession {
public:
    virtual ~KmipSession() = default;

    KmipSession(const KmipSession&) = delete;
    KmipSession& operator=(const KmipSession&) = delete;

    KmipSession(KmipSession&&) = default;
    KmipSession& operator=(KmipSession&&) = default;

    KmipSession() = default;

    /// @brief Creates the next exchange in the series.
    ///
    /// The function must be called when the previous exchange, if any, is
    /// completed. It creates the next request (as a part of a `KmipExchange`
    /// object) to send to the server or `nullptr` if the communication must be
    /// stopped.
    virtual std::shared_ptr<KmipExchange> nextExchange() = 0;
};

class KmipSessionRegisterSymmetricKey : public KmipSession {
private:
    enum class State : std::uint8_t { kNotStarted, kRegistering, kActivating, kFinished };

public:
    KmipSessionRegisterSymmetricKey(const Key& key, bool withActivation = true)
        : _key(key), _withActivation(withActivation), _state(State::kNotStarted) {}

    std::shared_ptr<KmipExchange> nextExchange() override {
        switch (_state) {
            case State::kNotStarted:
                _register = std::make_shared<KmipExchangeRegisterSymmetricKey>(_key);
                _state = State::kRegistering;
                return _register;
            case State::kRegistering:
                invariant(_register->state() == KmipExchange::State::kResponseReceived);
                _keyId = _register->decodeKeyId();
                _register = nullptr;
                if (!_withActivation) {
                    _state = State::kFinished;
                    return nullptr;
                }
                _activate = std::make_shared<KmipExchangeActivate>(_keyId);
                _state = State::kActivating;
                return _activate;
            case State::kActivating:
                invariant(_activate->state() == KmipExchange::State::kResponseReceived);
                _activate->verifyResponse();
                _activate = nullptr;
                _state = State::kFinished;
                return nullptr;
            case State::kFinished:
                return nullptr;
        }
        // suppress the `control reaches end of non-void function` warning
        return nullptr;
    }

    const std::string& keyId() const {
        invariant(_state == State::kFinished);
        return _keyId;
    }

private:
    const Key& _key;
    bool _withActivation;
    State _state;
    std::shared_ptr<KmipExchangeRegisterSymmetricKey> _register;
    std::shared_ptr<KmipExchangeActivate> _activate;
    std::string _keyId;
};

class KmipSessionGetSymmetricKey : public KmipSession {
private:
    /// @brief A session state (not a key state).
    enum class State : std::uint8_t { kNotStarted, kVerifying, kRetrieving, kFinished };

public:
    KmipSessionGetSymmetricKey(const std::string& keyId, bool verifyState)
        : _keyId(keyId), _verifyState(verifyState), _state(State::kNotStarted) {}

    std::shared_ptr<KmipExchange> nextExchange() override {
        auto transitionToRetrievingState = [this]() {
            _getKeyState = nullptr;
            _getKey = std::make_shared<KmipExchangeGetSymmetricKey>(_keyId);
            _state = State::kRetrieving;
            return _getKey;
        };
        auto transitionToFinishedState = [this]() {
            _getKeyState = nullptr;
            _getKey = nullptr;
            _state = State::kFinished;
            return nullptr;
        };
        switch (_state) {
            case State::kNotStarted:
                if (_verifyState) {
                    _getKeyState = std::make_shared<KmipExchangeGetKeyState>(_keyId);
                    _state = State::kVerifying;
                    return _getKeyState;
                }
                return transitionToRetrievingState();
            case State::kVerifying:
                invariant(_getKeyState->state() == KmipExchange::State::kResponseReceived);
                if (_keyState = _getKeyState->decodeKeyState();
                    _keyState && *_keyState == KeyState::kActive) {
                    return transitionToRetrievingState();
                }
                return transitionToFinishedState();
            case State::kRetrieving:
                invariant(_getKey->state() == KmipExchange::State::kResponseReceived);
                _key = _getKey->decodeKey();
                return transitionToFinishedState();
            case State::kFinished:
                return nullptr;
        }
        // suppress the `control reaches end of non-void function` warning
        return nullptr;
    }

    const boost::optional<Key>& key() const {
        invariant(_state == State::kFinished);
        return _key;
    }

    const boost::optional<KeyState>& keyState() const {
        invariant(_state == State::kFinished);
        return _keyState;
    }

private:
    std::string _keyId;
    bool _verifyState;
    State _state;
    std::shared_ptr<KmipExchangeGetKeyState> _getKeyState;
    std::shared_ptr<KmipExchangeGetSymmetricKey> _getKey;
    boost::optional<KeyState> _keyState;
    boost::optional<Key> _key;
};

class KmipSessionGetKeyState : public KmipSession {
private:
    /// @brief A session state (not a key state).
    enum class State : std::uint8_t { kNotStarted, kInProgress, kFinished };

public:
    KmipSessionGetKeyState(const std::string& keyId) : _keyId(keyId), _state(State::kNotStarted) {}

    std::shared_ptr<KmipExchange> nextExchange() override {
        switch (_state) {
            case State::kNotStarted:
                _getKeyState = std::make_shared<KmipExchangeGetKeyState>(_keyId);
                _state = State::kInProgress;
                return _getKeyState;
            case State::kInProgress:
                invariant(_getKeyState->state() == KmipExchange::State::kResponseReceived);
                _keyState = _getKeyState->decodeKeyState();
                _state = State::kFinished;
                _getKeyState = nullptr;
                return nullptr;
            case State::kFinished:
                return nullptr;
        }
        // suppress the `control reaches end of non-void function` warning
        return nullptr;
    }

    const boost::optional<KeyState>& keyState() const {
        invariant(_state == State::kFinished);
        return _keyState;
    }

private:
    std::string _keyId;
    State _state;
    std::shared_ptr<KmipExchangeGetKeyState> _getKeyState;
    boost::optional<KeyState> _keyState;
};
}  // namespace detail
}  // namespace mongo::encryption
