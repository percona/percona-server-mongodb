/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2021-present Percona and/or its affiliates. All rights reserved.

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


#include "mongo/platform/basic.h"

#include "mongo/db/pipeline/document_source_backup_cursor_extend.h"

#include "mongo/logv2/log.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery


namespace mongo {

namespace {
constexpr StringData kBackupId = "backupId"_sd;
constexpr StringData kTimestamp = "timestamp"_sd;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_DOCUMENT_SOURCE(backupCursorExtend,
                         DocumentSourceBackupCursorExtend::LiteParsed::parse,
                         DocumentSourceBackupCursorExtend::createFromBson,
                         AllowedWithApiStrict::kAlways);
}  // namespace

ALLOCATE_DOCUMENT_SOURCE_ID(backupCursorExtend, DocumentSourceBackupCursorExtend::id)

using boost::intrusive_ptr;

std::unique_ptr<DocumentSourceBackupCursorExtend::LiteParsed>
DocumentSourceBackupCursorExtend::LiteParsed::parse(const NamespaceString& nss,
                                                    const BSONElement& spec,
                                                    const LiteParserOptions& options) {

    return std::make_unique<DocumentSourceBackupCursorExtend::LiteParsed>(spec.fieldName());
}

const char* DocumentSourceBackupCursorExtend::getSourceName() const {
    return kStageName.data();
}

Value DocumentSourceBackupCursorExtend::serialize(const SerializationOptions& opts) const {
    return Value(
        Document{{getSourceName(),
                  Document{{kBackupId, Value(_backupId)}, {kTimestamp, Value(_extendTo)}}}});
}

DocumentSource::GetNextResult DocumentSourceBackupCursorExtend::doGetNext() {
    if (_fileIt != _filenames.end()) {
        Document doc = {{"filename"_sd, *_fileIt}};
        ++_fileIt;

        return doc;
    }

    return GetNextResult::makeEOF();
}

intrusive_ptr<DocumentSource> DocumentSourceBackupCursorExtend::createFromBson(
    BSONElement spec, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // This cursor is non-tailable so we don't touch pExpCtx->tailableMode here

    uassert(ErrorCodes::FailedToParse,
            str::stream() << kStageName << " parameters must be specified in an object, but found: "
                          << typeName(spec.type()),
            spec.type() == Object);

    boost::optional<UUID> backupId = boost::none;
    boost::optional<Timestamp> extendTo;

    for (auto&& elem : spec.embeddedObject()) {
        const auto fieldName = elem.fieldNameStringData();

        if (fieldName == kBackupId) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a UUID value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::BinData && elem.binDataType() == BinDataType::newUUID);
            auto res = UUID::parse(elem);
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << "stage failed to parse as UUID",
                    res.isOK());
            backupId = res.getValue();
        } else if (fieldName == kTimestamp) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a Timestamp value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::Date || elem.type() == BSONType::bsonTimestamp);
            extendTo = elem.timestamp();
        } else {
            uasserted(ErrorCodes::FailedToParse,
                      str::stream() << "Unrecognized option '" << fieldName << "' in " << kStageName
                                    << " stage");
        }
    }

    uassert(ErrorCodes::InvalidOptions,
            str::stream() << "Required parameter missing: " << kBackupId,
            backupId);

    uassert(ErrorCodes::InvalidOptions,
            str::stream() << "Required parameter missing: " << kTimestamp,
            extendTo);

    return new DocumentSourceBackupCursorExtend(pExpCtx, *backupId, *extendTo);
}

DocumentSourceBackupCursorExtend::DocumentSourceBackupCursorExtend(
    const boost::intrusive_ptr<ExpressionContext>& expCtx,
    const UUID& backupId,
    const Timestamp& extendTo)
    : DocumentSource(kStageName, expCtx),
      _backupId(backupId),
      _extendTo(extendTo),
      _backupCursorExtendState(pExpCtx->getMongoProcessInterface()->extendBackupCursor(
          pExpCtx->getOperationContext(), backupId, extendTo)),
      _filenames(_backupCursorExtendState.filePaths),
      _fileIt(_filenames.begin()) {}

DocumentSourceBackupCursorExtend::~DocumentSourceBackupCursorExtend() = default;
}  // namespace mongo
