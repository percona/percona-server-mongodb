/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/base/string_data.h"

#include <string>

// Forward declaration of the encryption key DB's active-keyId accessor.
//
// This header is deliberately free of any WiredTiger or EncryptionKeyDB
// includes so that the small `storage_wiredtiger_customization_hooks` library
// (which has no WT dependency) can call into the keydb without pulling in
// `<wiredtiger.h>`. The function is defined in `encryption_keydb.cpp` and
// resolved at final-binary link time.
namespace mongo {
namespace encryption {

// Returns the active keyId for the given database name, allocating a fresh
// "<dbName>.<UUID>" generation and persisting it in the keys DB if none is
// currently active. Thread-safe.
//
// Precondition: the encryption key DB must be initialized (i.e. encryption
// is enabled and the WiredTiger storage engine has constructed its
// DataAtRestEncryption instance). The customization hook that calls this
// function is only registered when encryption is enabled, so this is
// satisfied by construction.
std::string getOrCreateActiveKeyIdForDb(StringData dbName);

}  // namespace encryption
}  // namespace mongo
