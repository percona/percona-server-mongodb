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


#pragma once

#include <fstream>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include "mongo/base/checked_cast.h"
#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/client/dbclient_connection.h"
#include "mongo/client/dbclient_cursor.h"
#include "mongo/db/repl/base_cloner.h"
#include "mongo/db/repl/initial_sync_shared_data.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/repl/task_runner.h"
#include "mongo/executor/task_executor.h"
#include "mongo/util/concurrency/thread_pool.h"
#include "mongo/util/functional.h"
#include "mongo/util/net/hostandport.h"
#include "mongo/util/progress_meter.h"
#include "mongo/util/time_support.h"
#include "mongo/util/uuid.h"


namespace mongo::repl {

class FCBFileCloner final : public BaseCloner {
public:
    struct Stats {
        std::string filePath;
        size_t fileSize;
        Date_t start;
        Date_t end;
        size_t receivedBatches{0};
        size_t writtenBatches{0};
        size_t bytesCopied{0};

        std::string toString() const;
        BSONObj toBSON() const;
        void append(BSONObjBuilder* builder) const;
    };

    /**
     * Type of function to schedule file system tasks with the executor.
     */
    using ScheduleFsWorkFn = unique_function<StatusWith<executor::TaskExecutor::CallbackHandle>(
        executor::TaskExecutor::CallbackFn)>;

    /**
     * Constructor for FCBFileCloner
     *
     * remoteFileName: Path of file to copy on remote system.
     * remoteFileSize: Size of remote file in bytes, used for progress messages and stats only.
     * relativePath: Path of file relative to dbpath on the remote system, as a
     *               boost::filesystem::path generic path.
     */
    FCBFileCloner(const UUID& backupId,
                  const std::string& remoteFileName,
                  size_t remoteFileSize,
                  const std::string& relativePath,
                  InitialSyncSharedData* sharedData,
                  const HostAndPort& source,
                  DBClientConnection* client,
                  StorageInterface* storageInterface,
                  ThreadPool* dbPool);

    ~FCBFileCloner() override = default;

    /**
     * Waits for any file system work to finish or fail.
     */
    void waitForFilesystemWorkToComplete();

protected:
    InitialSyncSharedData* getSharedData() const override {
        return checked_cast<InitialSyncSharedData*>(BaseCloner::getSharedData());
    }

    ClonerStages getStages() final;

private:
    class FCBFileClonerQueryStage : public ClonerStage<FCBFileCloner> {
    public:
        FCBFileClonerQueryStage(std::string name, FCBFileCloner* cloner, ClonerRunFn stageFunc)
            : ClonerStage<FCBFileCloner>(std::move(name), cloner, stageFunc) {}

        bool checkSyncSourceValidityOnRetry() override {
            // Sync source validity is assured by the backup ID not existing if the sync source
            // is restarted or otherwise becomes invalid.
            return false;
        }

        bool isTransientError(const Status& status) override {
            if (isCursorError(status)) {
                return true;
            }
            return ErrorCodes::isRetriableError(status);
        }

        static bool isCursorError(const Status& status) {
            // Our cursor was killed on the sync source.
            return (status == ErrorCodes::CursorNotFound) ||
                (status == ErrorCodes::OperationFailed) || (status == ErrorCodes::QueryPlanKilled);
        }
    };

    /**
     * Overriden to allow the BaseCloner to use the initial syncer log component.
     */
    logv2::LogComponent getLogComponent() override;

    // TODO: do we need Stats/getStats in this class?
    /**
     * The preStage sets the begin time in _stats and makes sure the destination file
     * can be created.
     */
    void preStage() final;

    /**
     * The postStage sets the end time in _stats.
     */
    void postStage() final;


    /**
     * Stage function that executes a query to retrieve the file data.  For each
     * batch returned by the upstream node, handleNextBatch will be called with the data.  This
     * stage will finish when the entire query is finished or failed.
     */
    AfterStageBehavior queryStage();

    /**
     * Put all results from a query batch into a buffer, and schedule it to be written to disk.
     */
    void handleNextBatch(DBClientCursor& cursor);

    /**
     * Called whenever there is a new batch of documents ready from the DBClientConnection.
     *
     * Each document returned will be inserted via the storage interfaceRequest storage
     * interface.
     */
    void writeDataToFilesystemCallback(const executor::TaskExecutor::CallbackArgs& cbd);

    /**
     * Sends an (aggregation) query command to the source. That query command with be parameterized
     * based on copy progress.
     */
    void runQuery();

    /**
     * Convenience call to get the file offset under a lock.
     */
    size_t getFileOffset();

    // All member variables are labeled with one of the following codes indicating the
    // synchronization rules for accessing them.
    //
    // (R)  Read-only in concurrent operation; no synchronization required.
    // (S)  Self-synchronizing; access according to class's own rules.
    // (M)  Reads and writes guarded by _mutex (defined in base class).
    // (X)  Access only allowed from the main flow of control called from run() or constructor.
    const UUID _backupId;                    // (R)
    const std::string _remoteFileName;       // (R)
    size_t _remoteFileSize;                  // (R)
    const std::string _relativePathString;   // (R)
    boost::filesystem::path _localFilePath;  // (X)

    FCBFileClonerQueryStage _queryStage;  // (R)

    std::ofstream _localFile;  // (M)
    // File offset we will request from the remote side in the next query.
    off_t _fileOffset = 0;  // (M)
    bool _sawEof = false;  // (X)

    // Data read from source to insert.
    std::vector<BSONObj> _dataToWrite;  // (M)
    // Putting _fsWorkTaskRunner last ensures anything the database work threads depend on
    // like _dataToWrite, is destroyed after those threads exit.
    TaskRunner _fsWorkTaskRunner;  // (R)
    //  Function for scheduling filesystem work using the executor.
    ScheduleFsWorkFn _scheduleFsWorkFn;  // (R)

    ProgressMeter _progressMeter;  // (X) progress meter for this instance.
    Stats _stats;                  // (M)

    static constexpr int kProgressMeterSecondsBetween = 60;
    static constexpr int kProgressMeterCheckInterval = 128;
};

}  // namespace mongo::repl
