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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

#include "mongo/db/storage/wiredtiger/wiredtiger_backup_cursor_hooks.h"

#include "mongo/db/db_raii.h"
#include "mongo/db/dbhelpers.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/storage/encryption_hooks.h"
#include "mongo/logv2/log.h"
#include "mongo/util/fail_point.h"

namespace mongo {

namespace {

MONGO_FAIL_POINT_DEFINE(backupCursorErrorAfterOpen);

auto initializer() {
    return std::make_unique<WiredTigerBackupCursorHooks>();
}
}  // namespace

void WiredTigerBackupCursorHooks::registerInitializer() {
    BackupCursorHooks::registerInitializer(&initializer);
}

bool WiredTigerBackupCursorHooks::enabled() const {
    return true;
}

void WiredTigerBackupCursorHooks::fsyncLock(OperationContext* opCtx) {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(50885, "The node is already fsyncLocked.", _state != kFsyncLocked);
    uassert(50884,
            "The existing backup cursor must be closed before fsyncLock can succeed.",
            _state != kBackupCursorOpened);
    uassert(29097,
            "The running hot backup ('createBackup' command) must be completed before fsyncLock "
            "can succeed.",
            _state != kHotBackup);
    auto* engine = opCtx->getServiceContext()->getStorageEngine();
    uassertStatusOK(engine->beginBackup(opCtx));
    _state = kFsyncLocked;
}

void WiredTigerBackupCursorHooks::fsyncUnlock(OperationContext* opCtx) {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(50888, "The node is not fsyncLocked.", _state == kFsyncLocked);
    auto* engine = opCtx->getServiceContext()->getStorageEngine();
    engine->endBackup(opCtx);
    _state = kInactive;
}

BackupCursorState WiredTigerBackupCursorHooks::openBackupCursor(
    OperationContext* opCtx, const StorageEngine::BackupOptions& options) {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(50887, "The node is currently fsyncLocked.", _state != kFsyncLocked);
    uassert(50886,
            "The existing backup cursor must be closed before $backupCursor can succeed.",
            _state != kBackupCursorOpened);
    uassert(29098,
            "The running hot backup ('createBackup' command) must be completed before "
            "$backupCursor can succeed.",
            _state != kHotBackup);

    // Replica sets must also return the opTime's of the earliest and latest oplog entry. The
    // range represented by the oplog start/end values must exist in the backup copy, but are
    // not expected to be exact.
    repl::OpTime oplogStart;
    repl::OpTime oplogEnd;

    // If the oplog exists, capture the last oplog entry before opening the backup cursor. This
    // value will be checked again after the cursor is established to guarantee it still exists
    // (and was not truncated before the backup cursor was established.
    {
        AutoGetCollectionForRead coll(opCtx, NamespaceString::kRsOplogNamespace);
        if (coll.getCollection()) {
            BSONObj lastEntry;
            if (Helpers::getLast(
                    opCtx, NamespaceString::kRsOplogNamespace.ns().c_str(), lastEntry)) {
                auto oplogEntry = fassertNoTrace(50913, repl::OplogEntry::parse(lastEntry));
                oplogEnd = oplogEntry.getOpTime();
            }
        }
    }

    auto* engine = opCtx->getServiceContext()->getStorageEngine();

    // Capture the checkpointTimestamp before and after opening a cursor. If it hasn't moved,
    // the checkpointTimestamp is known to be exact. If it has moved, uassert and have the user
    // retry.
    boost::optional<Timestamp> checkpointTimestamp;
    if (engine->supportsRecoverToStableTimestamp()) {
        checkpointTimestamp = engine->getLastStableRecoveryTimestamp();
    };

    auto filesToBackup =
        uassertStatusOK(engine->beginNonBlockingBackup(opCtx, checkpointTimestamp, options));
    _state = kBackupCursorOpened;
    _openCursor = UUID::gen();
    LOGV2(29093, "Opened backup cursor", "backupId"_attr = _openCursor.get());

    // A backup cursor is open. Any exception code path must leave the BackupCursorService in an
    // inactive state.
    ScopeGuard closeCursorGuard(
        [this, opCtx, &lk] { _closeBackupCursor(opCtx, _openCursor.get(), lk); });

    uassert(50919,
            "Failpoint hit after opening the backup cursor.",
            !MONGO_unlikely(backupCursorErrorAfterOpen.shouldFail()));

    // Ensure the checkpointTimestamp hasn't moved. A subtle case to catch is the first stable
    // checkpoint coming out of initial sync racing with opening the backup cursor.
    if (checkpointTimestamp && engine->supportsRecoverToStableTimestamp()) {
        auto requeriedCheckpointTimestamp = engine->getLastStableRecoveryTimestamp();
        if (!requeriedCheckpointTimestamp ||
            requeriedCheckpointTimestamp.get() < checkpointTimestamp.get()) {
            LOGV2_FATAL(50916,
                        "The last stable recovery timestamp went backwards. Original: "
                        "{checkpointTimestamp} Found: {requeriedCheckpointTimestamp}",
                        "The last stable recovery timestamp went backwards",
                        "checkpointTimestamp"_attr = checkpointTimestamp.get(),
                        "requeriedCheckpointTimestamp"_attr = requeriedCheckpointTimestamp);
        }

        uassert(50915,
                str::stream() << "A checkpoint took place while opening a backup cursor.",
                checkpointTimestamp == requeriedCheckpointTimestamp);
    };

    // If the oplog exists, capture the first oplog entry after opening the backup cursor.
    // Ensure it is before the `oplogEnd` value.
    if (!oplogEnd.isNull()) {
        BSONObj firstEntry;
        uassert(50912,
                str::stream() << "No oplog records were found.",
                Helpers::getSingleton(
                    opCtx, NamespaceString::kRsOplogNamespace.ns().c_str(), firstEntry));
        auto oplogEntry = fassertNoTrace(50918, repl::OplogEntry::parse(firstEntry));
        oplogStart = oplogEntry.getOpTime();
        uassert(50917,
                str::stream() << "Oplog rolled over while establishing the backup cursor.",
                oplogStart < oplogEnd);
    }

    std::deque<BackupBlock> eseBackupBlocks;
    auto* encHooks = EncryptionHooks::get(opCtx->getServiceContext());
    if (encHooks->enabled()) {
        eseBackupBlocks =
            uassertStatusOK(encHooks->beginNonBlockingBackup(opCtx, checkpointTimestamp, options));
    }

    BSONObjBuilder builder;
    builder << "backupId" << _openCursor.get();
    builder << "dbpath" << storageGlobalParams.dbpath;
    if (!oplogStart.isNull()) {
        builder << "oplogStart" << oplogStart.toBSON();
        builder << "oplogEnd" << oplogEnd.toBSON();
    }

    // Notably during initial sync, a node may have an oplog without a stable checkpoint.
    if (checkpointTimestamp) {
        builder << "checkpointTimestamp" << checkpointTimestamp.get();
    }

    // Copy backup options to metadata
    builder << "disableIncrementalBackup" << options.disableIncrementalBackup;
    builder << "incrementalBackup" << options.incrementalBackup;
    builder << "blockSize" << options.blockSizeMB;
    if (options.thisBackupName) {
        builder << "thisBackupName" << *options.thisBackupName;
    }
    if (options.srcBackupName) {
        builder << "srcBackupName" << *options.srcBackupName;
    }

    Document preamble{{"metadata"_sd, builder.obj()}};

    closeCursorGuard.dismiss();
    return {_openCursor.get(),
            std::move(preamble),
            std::move(filesToBackup),
            std::move(eseBackupBlocks)};
}

void WiredTigerBackupCursorHooks::closeBackupCursor(OperationContext* opCtx, const UUID& backupId) {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    _closeBackupCursor(opCtx, backupId, lk);
}

void WiredTigerBackupCursorHooks::_closeBackupCursor(OperationContext* opCtx,
                                                     const UUID& backupId,
                                                     WithLock) {
    uassert(50880, "There is no backup cursor to close.", _state == kBackupCursorOpened);
    uassert(50879,
            str::stream() << "Can only close the running backup cursor. To close: " << backupId
                          << " Running: " << _openCursor.get(),
            backupId == _openCursor.get());
    auto* engine = opCtx->getServiceContext()->getStorageEngine();
    engine->endNonBlockingBackup(opCtx);
    auto* encHooks = EncryptionHooks::get(opCtx->getServiceContext());
    if (encHooks->enabled()) {
        fassert(50934, encHooks->endNonBlockingBackup(opCtx));
    }
    LOGV2(29092, "Closed backup cursor", "backupId"_attr = backupId);
    _state = kInactive;
    _openCursor = boost::none;
}

BackupCursorExtendState WiredTigerBackupCursorHooks::extendBackupCursor(OperationContext* opCtx,
                                                                        const UUID& backupId,
                                                                        const Timestamp& extendTo) {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(50887, "The node is currently fsyncLocked.", _state != kFsyncLocked);
    uassert(29099,
            "Hot backup ('createBackup' command) is currently in progress.",
            _state != kHotBackup);
    uassert(50886,
            "Cannot extend backup cursor because backup cursor is not open",
            _state == kBackupCursorOpened);
    uassert(29094,
            "backupId provided to $backupCursorExtend does not match active backup",
            _openCursor == backupId);
    // wait for extendTo
    auto* replCoord = repl::ReplicationCoordinator::get(opCtx->getServiceContext());
    if (auto status = replCoord->awaitTimestampCommitted(opCtx, extendTo); !status.isOK()) {
        LOGV2_FATAL(29096,
                    "Wait for target timestamp has failed",
                    "reason"_attr = status,
                    "timestamp"_attr = extendTo);
    }

    // return value
    BackupCursorExtendState result;
    // use WiredTigerKVEngine::extendBackupCursor
    {
        auto* engine = opCtx->getServiceContext()->getStorageEngine();
        auto res = engine->extendBackupCursor(opCtx);
        if (!res.isOK()) {
            LOGV2_FATAL(29095, "Failed to extend backup cursor", "reason"_attr = res.getStatus());
        }
        result.filenames = std::move(res.getValue());
    }
    // use extendBackupCursor on KeyDB
    auto* encHooks = EncryptionHooks::get(opCtx->getServiceContext());
    if (encHooks->enabled()) {
        auto res = encHooks->extendBackupCursor(opCtx);
        if (!res.isOK()) {
            LOGV2_FATAL(29095, "Failed to extend backup cursor", "reason"_attr = res.getStatus());
        }
        result.filenames.insert(result.filenames.end(),
                                make_move_iterator(res.getValue().begin()),
                                make_move_iterator(res.getValue().end()));
    }

    return result;
}

bool WiredTigerBackupCursorHooks::isBackupCursorOpen() const {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    return _state == kBackupCursorOpened;
}

void WiredTigerBackupCursorHooks::tryEnterHotBackup() {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(29101,
            "The node is fsyncLocked. fsyncUnlock must be called before hot backup can be started.",
            _state != kFsyncLocked);
    uassert(29102,
            "The existing backup cursor must be closed before hot backup can be started.",
            _state != kBackupCursorOpened);
    uassert(29103,
            "The running hot backup ('createBackup' command) must be completed before another hot "
            "backup can be started.",
            _state != kHotBackup);
    _state = kHotBackup;
}

void WiredTigerBackupCursorHooks::deactivateHotBackup() {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    uassert(29100, "There is no hot backup in progress.", _state == kHotBackup);
    _state = kInactive;
}

WiredTigerHotBackupGuard::WiredTigerHotBackupGuard(OperationContext* opCtx)
    : _hooks(dynamic_cast<WiredTigerBackupCursorHooks*>(
          BackupCursorHooks::get(opCtx->getServiceContext()))) {
    invariant(_hooks);
    invariant(_hooks->enabled());
    _hooks->tryEnterHotBackup();
}

WiredTigerHotBackupGuard::~WiredTigerHotBackupGuard() {
    _hooks->deactivateHotBackup();
}

}  // namespace mongo
