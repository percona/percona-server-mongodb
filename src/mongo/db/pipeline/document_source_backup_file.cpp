/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2024-present Percona and/or its affiliates. All rights reserved.

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


#include "mongo/db/pipeline/document_source_backup_file.h"

#include <array>
#include <memory>
#include <string>
#include <utility>

#include "mongo/base/data_range.h"
#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/db/exec/document_value/document.h"
#include "mongo/db/namespace_string.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/intrusive_counter.h"
#include "mongo/util/str.h"
#include "mongo/util/uuid.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery


namespace mongo {

namespace {
constexpr StringData kBackupId = "backupId"_sd;
constexpr StringData kFile = "file"_sd;
constexpr StringData kByteOffset = "byteOffset"_sd;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_INTERNAL_DOCUMENT_SOURCE(_backupFile,
                                  DocumentSourceBackupFile::LiteParsed::parse,
                                  DocumentSourceBackupFile::createFromBson,
                                  true);
}  // namespace

ALLOCATE_DOCUMENT_SOURCE_ID(_backupFile, DocumentSourceBackupFile::id)

using boost::intrusive_ptr;

std::unique_ptr<DocumentSourceBackupFile::LiteParsed> DocumentSourceBackupFile::LiteParsed::parse(
    const NamespaceString& nss, const BSONElement& spec, const LiteParserOptions& options) {

    return std::make_unique<DocumentSourceBackupFile::LiteParsed>(spec.fieldName());
}

const char* DocumentSourceBackupFile::getSourceName() const {
    return kStageName.data();
}

Value DocumentSourceBackupFile::serialize(const SerializationOptions& opts) const {
    return Value{Document{{getSourceName(),
                           Document{{kBackupId, Value(_backupId)},
                                    {kFile, Value(_filePath)},
                                    {kByteOffset, Value(_byteOffset)}}}}};
}

DocumentSource::GetNextResult DocumentSourceBackupFile::doGetNext() {
    if (_file.eof()) {
        return GetNextResult::makeEOF();
    }

    auto byteOffset = _file.tellg();
    _file.read(_dataBuf.data(), kBlockSize);
    uassert(ErrorCodes::FileStreamFailed,
            str::stream() << "Error reading file " << _filePath << " at offset " << byteOffset,
            !_file.bad());
    auto bytesRead = _file.gcount();
    auto eof = _file.eof();

    Document doc;
    doc = Document{{"byteOffset"_sd, static_cast<long long>(byteOffset)},
                   {"data"_sd, BSONBinData(_dataBuf.data(), bytesRead, BinDataGeneral)},
                   {"endOfFile"_sd, eof}};

    return doc;
}

intrusive_ptr<DocumentSource> DocumentSourceBackupFile::createFromBson(
    BSONElement spec, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // This cursor is non-tailable so we don't touch pExpCtx->tailableMode here

    uassert(ErrorCodes::FailedToParse,
            str::stream() << kStageName << " parameters must be specified in an object, but found: "
                          << typeName(spec.type()),
            spec.type() == Object);

    auto backupId = UUID::fromCDR(std::array<unsigned char, UUID::kNumBytes>{});
    std::string filePath;
    long long byteOffset = 0;

    for (auto&& elem : spec.embeddedObject()) {
        const auto fieldName = elem.fieldNameStringData();

        if (fieldName == kBackupId) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a binary data value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::BinData);
            backupId = uassertStatusOK(UUID::parse(elem));
        } else if (fieldName == kFile) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a string value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::String);
            filePath = elem.String();
        } else if (fieldName == kByteOffset) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a long integer value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::NumberLong);
            byteOffset = elem.Long();
        } else {
            uasserted(ErrorCodes::FailedToParse,
                      str::stream() << "Unrecognized option '" << fieldName << "' in " << kStageName
                                    << " stage");
        }
    }

    uassert(ErrorCodes::InvalidOptions,
            str::stream() << "'" << kByteOffset << "' parameter cannot be less than zero",
            byteOffset >= 0);

    std::ifstream iFile(filePath, std::ios_base::in | std::ios_base::binary);
    uassert(ErrorCodes::FileOpenFailed,
            str::stream() << "Failed to open file " << filePath,
            iFile.is_open());
    iFile.seekg(byteOffset);
    uassert(ErrorCodes::FileOpenFailed,
            str::stream() << "Failed to set read position " << byteOffset << " in file "
                          << filePath,
            !iFile.fail());
    invariant(byteOffset == iFile.tellg());

    return make_intrusive<DocumentSourceBackupFile>(
        pExpCtx, backupId, std::move(filePath), byteOffset, std::move(iFile));
}

DocumentSourceBackupFile::DocumentSourceBackupFile(const intrusive_ptr<ExpressionContext>& expCtx,
                                                   UUID backupId,
                                                   std::string filePath,
                                                   long long byteOffset,
                                                   std::ifstream file)
    : DocumentSource(kStageName, expCtx),
      _dataBuf(),
      _backupId(backupId),
      _filePath(std::move(filePath)),
      _byteOffset(byteOffset),
      _file(std::move(file)) {}

DocumentSourceBackupFile::~DocumentSourceBackupFile() {
    _file.close();
}

}  // namespace mongo
