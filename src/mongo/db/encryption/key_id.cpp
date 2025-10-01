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

#include "mongo/db/encryption/key_id.h"

#include <array>
#include <utility>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/str.h"

namespace mongo::encryption {
namespace {
template <typename DerivedProductType>
struct KeyIdFactoryWrapper {
    static std::unique_ptr<KeyId> create(const BSONObj& o) {
        return DerivedProductType::create(o);
    }
};

using FactoryFn = std::unique_ptr<KeyId> (*)(const BSONObj&);
}  // namespace

std::unique_ptr<KeyId> KeyId::fromStorageEngineEncryptionOptions(const BSONObj& options) {
    static const std::array<std::pair<StringData, FactoryFn>, 2u> factories = {
        {{StringData(VaultSecretId::_kSeeoFieldName), KeyIdFactoryWrapper<VaultSecretId>::create},
         {StringData(KmipKeyId::_kSeeoFieldName), KeyIdFactoryWrapper<KmipKeyId>::create}}};

    std::unique_ptr<KeyId> result;
    for (const auto& elem : options) {
        auto factory = std::find_if(
            factories.begin(), factories.end(), [name = elem.fieldNameStringData()](const auto& f) {
                return f.first == name;
            });
        if (factory == factories.end()) {
            // Ignore an unknown filed names for the forward compatibility purpose.
            continue;
        }
        if (result) {
            throw std::runtime_error("more that one encryption method is specified");
        }
        if (elem.type() != BSONType::object) {
            throw std::runtime_error(str::stream()
                                     << "'" << factory->first << "' is not a BSON object");
        }
        try {
            result = factory->second(elem.Obj());
        } catch (const std::runtime_error& e) {
            throw std::runtime_error(str::stream()
                                     << "invalid '" << factory->first << "': " << e.what());
        }
    }
    return result;
}

std::unique_ptr<VaultSecretId> VaultSecretId::create(const BSONObj& o) {
    BSONElement pathElem = o.getField("path");
    if (pathElem.eoo()) {
        throw std::runtime_error("no 'path' field");
    }
    if (pathElem.type() != BSONType::string) {
        throw std::runtime_error("the 'path' field is not a string");
    }
    std::string path = pathElem.String();
    if (path.empty()) {
        throw std::runtime_error("the 'path' field must be a non-empty string");
    }

    BSONElement versionElem = o.getField("version");
    if (versionElem.eoo()) {
        throw std::runtime_error("no 'version' field");
    }
    // Version is serialized as string to wark aroud BSON limitations.
    // @see `VaultSecretId::_serializeImpl`.
    if (versionElem.type() != BSONType::string) {
        throw std::runtime_error("the 'version' field is not a string");
    }
    std::istringstream versionStr(versionElem.String());
    std::uint64_t version = 0;
    versionStr >> version;
    if (version == 0) {
        throw std::runtime_error(
            "the 'version' field must be a positive "
            "integer serialized as a string");
    }
    return std::make_unique<VaultSecretId>(path, version);
}

std::unique_ptr<KmipKeyId> KmipKeyId::create(const BSONObj& o) {
    BSONElement keyIdElem = o.getField("keyId");
    if (keyIdElem.eoo()) {
        throw std::runtime_error("no 'keyId' field");
    }
    if (keyIdElem.type() != BSONType::string) {
        throw std::runtime_error("the 'keyId' field is not a string");
    }
    std::string keyId = keyIdElem.String();
    if (keyId.empty()) {
        throw std::runtime_error("the 'keyId' field must be a non-empty string");
    }
    return std::make_unique<KmipKeyId>(keyId);
}

void KeyId::serializeToStorageEngineEncryptionOptions(BSONObjBuilder* b) const {
    BSONObjBuilder sb = b->subobjStart(_seeoFieldName());
    _serializeValueToSeeo(&sb);
    sb.done();
}

const char* KeyFilePath::_seeoFieldName() const noexcept {
    invariant(false &&
              "An encryption key file path must be never serialized to storage engnie metadata.");
    return nullptr;
}

void KeyFilePath::_serializeValueToSeeo(BSONObjBuilder* b) const {
    invariant(false &&
              "An encryption key file path must be never serialized to storage engnie metadata.");
}

void VaultSecretId::_serializeValueToSeeo(BSONObjBuilder* b) const {
    _serializeImpl(b);
}

void KmipKeyId::_serializeValueToSeeo(BSONObjBuilder* b) const {
    b->append("keyId", _keyId);
}

void KeyFilePath::serialize(BSONObjBuilder* b) const {
    b->append("encryptionKeyFilePath", _path);
}

void KeyFilePath::serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const {
    // NOTE: not adding '_path' due to security concerns
    b->append(fieldName, "local");
}

void VaultSecretId::serialize(BSONObjBuilder* b) const {
    BSONObjBuilder sb = b->subobjStart("vaultSecretIdentifier");
    _serializeImpl(&sb);
    sb.done();
}

void VaultSecretId::serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const {
    BSONObjBuilder sb = b->subobjStart(fieldName);
    BSONObjBuilder ssb = sb.subobjStart("vault");
    _serializeImpl(&ssb);
    ssb.done();
    sb.done();
}

void VaultSecretId::_serializeImpl(BSONObjBuilder* b) const {
    b->append("path", _path);
    // serialize the version as a string to work around the BSON limitation
    // on serializable types: only `int` or `long long` can be serialized as
    // integer numbers
    b->append("version", str::stream() << _version);
}

void KmipKeyId::serialize(BSONObjBuilder* b) const {
    b->append("kmipKeyIdentifier", _keyId);
}

void KmipKeyId::serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const {
    BSONObjBuilder sb = b->subobjStart(StringData{fieldName});
    BSONObjBuilder ssb = sb.subobjStart("kmip");
    ssb.append("keyId", _keyId);
    ssb.done();
    sb.done();
}

void KeyFilePath::accept(KeyIdConstVisitor& v) const {
    v.visit(*this);
}

void VaultSecretId::accept(KeyIdConstVisitor& v) const {
    v.visit(*this);
}

void KmipKeyId::accept(KeyIdConstVisitor& v) const {
    v.visit(*this);
}

WtKeyIds& WtKeyIds::instance() {
    static WtKeyIds ids;
    return ids;
}
}  // namespace mongo::encryption
