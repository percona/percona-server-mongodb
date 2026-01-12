/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2026-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/exec/agg/backup_cursor_stage.h"

#include "mongo/db/exec/agg/document_source_to_stage_registry.h"
#include "mongo/db/pipeline/document_source_backup_cursor.h"
#include "mongo/logv2/log.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery

namespace mongo {

boost::intrusive_ptr<exec::agg::Stage> documentSourceBackupCursorToStageFn(
    const boost::intrusive_ptr<DocumentSource>& source) {
    auto* ds = dynamic_cast<DocumentSourceBackupCursor*>(source.get());

    tassert(188601, "expected 'DocumentSourceBackupCursor' type", ds);

    return make_intrusive<exec::agg::BackupCursorStage>(
        ds->kStageName, ds->getExpCtx(), ds->_backupOptions);
}

namespace exec::agg {

REGISTER_AGG_STAGE_MAPPING(backupCursorStage,
                           DocumentSourceBackupCursor::id,
                           documentSourceBackupCursorToStageFn);

BackupCursorStage::BackupCursorStage(StringData stageName,
                                     const boost::intrusive_ptr<ExpressionContext>& pExpCtx,
                                     StorageEngine::BackupOptions backupOptions)
    : Stage(stageName, pExpCtx),
      _backupOptions(std::move(backupOptions)),
      _backupCursorState(pExpCtx->getMongoProcessInterface()->openBackupCursor(
          pExpCtx->getOperationContext(), _backupOptions)),
      _kvBackupBlocks(std::move(_backupCursorState.otherKVBackupBlocks)),
      _docIt(_kvBackupBlocks.cbegin()) {}

BackupCursorStage::~BackupCursorStage() {
    try {
        pExpCtx->getMongoProcessInterface()->closeBackupCursor(pExpCtx->getOperationContext(),
                                                               _backupCursorState.backupId);
    } catch (DBException&) {
        LOGV2_FATAL(
            29095, "Error closing a backup cursor.", "backupId"_attr = _backupCursorState.backupId);
    }
}

GetNextResult BackupCursorStage::doGetNext() {
    if (_backupCursorState.preamble) {
        Document doc = _backupCursorState.preamble.get();
        _backupCursorState.preamble = boost::none;
        return doc;
    }

    // Streaming cursor may be absent when options.disableIncrementalBackup == true
    if (!_backupCursorState.streamingCursor) {
        return GetNextResult::makeEOF();
    }

    if (_docIt == _kvBackupBlocks.cend()) {
        constexpr std::size_t batchSize = 100;
        _kvBackupBlocks =
            uassertStatusOK(_backupCursorState.streamingCursor->getNextBatch(batchSize));
        _docIt = _kvBackupBlocks.cbegin();
        // Empty batch means streaming cursor is exhausted
        if (_kvBackupBlocks.empty()) {
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

}  // namespace exec::agg
}  // namespace mongo
