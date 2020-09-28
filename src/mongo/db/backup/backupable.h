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

#include <string>

#include "mongo/base/status.h"

namespace mongo {
    class OperationContext;
}

namespace percona {

struct S3BackupParameters {
    std::string profile;  // empty value means default profile
    std::string region;  // empty value means default region (US_EAST_1)
    std::string endpoint;  // endpoint override, for example  "127.0.0.1:9000"
    std::string scheme{"HTTPS"};  // HTTP/HTTPS, by default HTTPS
    bool useVirtualAddressing{true};  // true by default
    std::string bucket;  // S3 bucket name
    std::string path;  // path inside bucket (may be empty)
    std::string accessKeyId;  // access key id
    std::string secretAccessKey;  // secret access key
    int threadPoolSize{4};  //  thread pool size for multipart uploads
};

/**
 * The interface which provides the ability to perform hot
 * backups of the storage engine.
 */
struct Backupable {
    virtual ~Backupable() {}

    /**
     * Perform hot backup.
     * @param path destination path to perform backup into.
     * @return Status code of the operation.
     */
    virtual mongo::Status hotBackup(mongo::OperationContext* opCtx, const std::string& path) {
        return mongo::Status(mongo::ErrorCodes::IllegalOperation,
                             "This engine doesn't support hot backup.");
    }

    /**
     * Perform hot backup into the file/stream in the tar archive format.
     * @param path destination path to perform backup into.
     * @return Status code of the operation.
     */
    virtual mongo::Status hotBackupTar(mongo::OperationContext* opCtx, const std::string& path) {
        return mongo::Status(mongo::ErrorCodes::IllegalOperation,
                             "This engine doesn't support hot backup to the tar format.");
    }

    /**
     * Perform hot backup to S3-compatible storage.
     * @param s3params parameters of server connection and backup location.
     * @return Status code of the operation.
     */
    virtual mongo::Status hotBackup(mongo::OperationContext* opCtx, const S3BackupParameters& s3params) {
        return mongo::Status(mongo::ErrorCodes::IllegalOperation,
                             "This engine doesn't support hot backup to S3-compatible storage.");
    }
};

}  // end of percona namespace.
