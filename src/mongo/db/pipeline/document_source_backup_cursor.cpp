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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery

#include "mongo/platform/basic.h"

#include "mongo/db/pipeline/document_source_backup_cursor.h"

#include "mongo/logv2/log.h"

namespace mongo {

namespace {
constexpr StringData kDisableIncrementalBackup = "disableIncrementalBackup"_sd;
constexpr StringData kIncrementalBackup = "incrementalBackup"_sd;
constexpr StringData kBlockSize = "blockSize"_sd;
constexpr StringData kThisBackupName = "thisBackupName"_sd;
constexpr StringData kSrcBackupName = "srcBackupName"_sd;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_DOCUMENT_SOURCE(backupCursor,
                         DocumentSourceBackupCursor::LiteParsed::parse,
                         DocumentSourceBackupCursor::createFromBson,
                         AllowedWithApiStrict::kAlways);
}  // namespace

using boost::intrusive_ptr;

std::unique_ptr<DocumentSourceBackupCursor::LiteParsed>
DocumentSourceBackupCursor::LiteParsed::parse(const NamespaceString& nss, const BSONElement& spec) {

    return std::make_unique<DocumentSourceBackupCursor::LiteParsed>(spec.fieldName());
}

const char* DocumentSourceBackupCursor::getSourceName() const {
    return kStageName.rawData();
}

Value DocumentSourceBackupCursor::serialize(
    boost::optional<ExplainOptions::Verbosity> explain) const {
    return Value(Document{
        {getSourceName(),
         Document{
             {kDisableIncrementalBackup,
              _backupOptions.disableIncrementalBackup ? Value(true) : Value()},
             {kIncrementalBackup, _backupOptions.incrementalBackup ? Value(true) : Value()},
             {kBlockSize, Value(_backupOptions.blockSizeMB)},
             {kThisBackupName,
              _backupOptions.thisBackupName ? Value(*_backupOptions.thisBackupName) : Value()},
             {kSrcBackupName,
              _backupOptions.srcBackupName ? Value(*_backupOptions.srcBackupName) : Value()}}}});
}

DocumentSource::GetNextResult DocumentSourceBackupCursor::doGetNext() {
    if (_backupCursorState.preamble) {
        Document doc = _backupCursorState.preamble.get();
        _backupCursorState.preamble = boost::none;

        return doc;
    }

    // Streaming cursor may be absent when options.disableIncrementalBackup == true
    if (!_backupCursorState.streamingCursor) {
        return GetNextResult::makeEOF();
    }

    if (_docIt == _backupBlocks.cend()) {
        constexpr std::size_t batchSize = 100;
        _backupBlocks = uassertStatusOK(
            _backupCursorState.streamingCursor->getNextBatch(pExpCtx->opCtx, batchSize));
        _docIt = _backupBlocks.cbegin();
        // Empty batch means streaming cursor is exhausted
        if (_backupBlocks.empty()) {
            return GetNextResult::makeEOF();
        }
    }

    // If length or offset is not 0 then output 4 fields,
    // otherwise output filename, fileSize only
    Document doc;
    if (_docIt->length() != 0 || _docIt->offset() != 0) {
        doc = Document{{"filename"_sd, _docIt->filePath()},
                       {"offset"_sd, static_cast<long long>(_docIt->offset())},
                       {"length"_sd, static_cast<long long>(_docIt->length())},
                       {"fileSize"_sd, static_cast<long long>(_docIt->fileSize())}};
    } else {
        doc = Document{{"filename"_sd, _docIt->filePath()},
                       {"fileSize"_sd, static_cast<long long>(_docIt->fileSize())}};
    }
    ++_docIt;

    return doc;
}

intrusive_ptr<DocumentSource> DocumentSourceBackupCursor::createFromBson(
    BSONElement spec, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // The anticipated usage of a backup cursor: open the backup cursor, consume the results, copy
    // data off disk, close the backup cursor. The backup cursor must be successfully closed for
    // the data copied to be valid. Hence, the caller needs a way to keep the cursor open after
    // consuming the results, as well as the ability to send "heartbeats" to prevent the client
    // cursor manager from timing out the backup cursor. A backup cursor does consume resources;
    // in the event the calling process crashes, the cursors should eventually be timed out.
    pExpCtx->tailableMode = TailableModeEnum::kTailable;

    uassert(ErrorCodes::FailedToParse,
            str::stream() << kStageName << " parameters must be specified in an object, but found: "
                          << typeName(spec.type()),
            spec.type() == Object);

    StorageEngine::BackupOptions options;

    for (auto&& elem : spec.embeddedObject()) {
        const auto fieldName = elem.fieldNameStringData();

        if (fieldName == kDisableIncrementalBackup) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a boolean value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::Bool);
            options.disableIncrementalBackup = elem.boolean();
        } else if (fieldName == kIncrementalBackup) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a boolean value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::Bool);
            options.incrementalBackup = elem.boolean();
        } else if (fieldName == kBlockSize) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be an integer value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::NumberInt);
            options.blockSizeMB = elem.Int();
        } else if (fieldName == kThisBackupName) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a string value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::String);
            options.thisBackupName = elem.String();
        } else if (fieldName == kSrcBackupName) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a string value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::String);
            options.srcBackupName = elem.String();
        } else {
            uasserted(ErrorCodes::FailedToParse,
                      str::stream() << "Unrecognized option '" << fieldName << "' in " << kStageName
                                    << " stage");
        }
    }

    uassert(ErrorCodes::InvalidOptions,
            str::stream() << "'" << kIncrementalBackup << "' and '" << kDisableIncrementalBackup
                          << "' parameters are mutually exclusive. Cannot enable both",
            !(options.incrementalBackup && options.disableIncrementalBackup));
    uassert(ErrorCodes::InvalidOptions,
            str::stream() << "'" << kThisBackupName << "' and '" << kSrcBackupName
                          << "' parameters are only allowed when '" << kIncrementalBackup
                          << "' is true",
            options.incrementalBackup || !(options.thisBackupName || options.srcBackupName));

    return new DocumentSourceBackupCursor(std::move(options), pExpCtx);
}

DocumentSourceBackupCursor::DocumentSourceBackupCursor(
    StorageEngine::BackupOptions&& options, const intrusive_ptr<ExpressionContext>& expCtx)
    : DocumentSource(kStageName, expCtx),
      _backupOptions(options),
      _backupCursorState(
          pExpCtx->mongoProcessInterface->openBackupCursor(pExpCtx->opCtx, _backupOptions)),
      _backupBlocks(std::move(_backupCursorState.otherBackupBlocks)),
      _docIt(_backupBlocks.cbegin()) {}

DocumentSourceBackupCursor::~DocumentSourceBackupCursor() {
    try {
        pExpCtx->mongoProcessInterface->closeBackupCursor(pExpCtx->opCtx,
                                                          _backupCursorState.backupId);
    } catch (DBException& exc) {
        LOGV2_FATAL(29091,
                    "Error closing a backup cursor with Id {backupId}",
                    "Error closing a backup cursor.",
                    "backupId"_attr = _backupCursorState.backupId);
    }
}
}  // namespace mongo
