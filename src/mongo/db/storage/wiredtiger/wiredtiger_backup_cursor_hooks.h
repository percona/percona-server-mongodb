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

#pragma once

#include "mongo/db/storage/backup_cursor_hooks.h"
#include "mongo/util/concurrency/with_lock.h"

namespace mongo {

class WiredTigerBackupCursorHooks : public BackupCursorHooks {
public:
    static void registerInitializer();

    WiredTigerBackupCursorHooks(StorageEngine* storageEngine) : _storageEngine(storageEngine) {}

    virtual ~WiredTigerBackupCursorHooks() override = default;

    virtual bool enabled() const override;

    virtual void fsyncLock(OperationContext* opCtx) override;

    virtual void fsyncUnlock(OperationContext* opCtx) override;

    virtual BackupCursorState openBackupCursor(
        OperationContext* opCtx, const StorageEngine::BackupOptions& options) override;

    virtual void closeBackupCursor(OperationContext* opCtx, const UUID& backupId) override;

    virtual BackupCursorExtendState extendBackupCursor(OperationContext* opCtx,
                                                       const UUID& backupId,
                                                       const Timestamp& extendTo) override;

    virtual bool isBackupCursorOpen() const override;

private:
    friend class WiredTigerHotBackupGuard;

    void tryEnterHotBackup();

    void deactivateHotBackup();

    void _closeBackupCursor(OperationContext* opCtx, const UUID& backupId, WithLock);

    StorageEngine* _storageEngine;

    enum State { kInactive, kFsyncLocked, kBackupCursorOpened, kHotBackup };

    // This mutex serializes all access into this class.
    mutable stdx::mutex _mutex;
    State _state = kInactive;
    // When state is `kBackupCursorOpened`, _openCursor contains the cursorId of the active backup
    // cursor. Otherwise it is boost::none.
    boost::optional<UUID> _openCursor = boost::none;
};

class WiredTigerHotBackupGuard {
public:
    explicit WiredTigerHotBackupGuard(OperationContext* opCtx);
    ~WiredTigerHotBackupGuard();

private:
    WiredTigerBackupCursorHooks* _hooks;
};

}  // namespace mongo
