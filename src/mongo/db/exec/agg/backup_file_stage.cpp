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

#include "mongo/db/exec/agg/backup_file_stage.h"

#include "mongo/bson/bsonmisc.h"
#include "mongo/db/exec/agg/document_source_to_stage_registry.h"
#include "mongo/db/pipeline/document_source_backup_file.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/str.h"

namespace mongo {

boost::intrusive_ptr<exec::agg::Stage> documentSourceBackupFileToStageFn(
    const boost::intrusive_ptr<DocumentSource>& source) {
    auto* ds = dynamic_cast<DocumentSourceBackupFile*>(source.get());

    tassert(188603, "expected 'DocumentSourceBackupFile' type", ds);

    return make_intrusive<exec::agg::BackupFileStage>(
        ds->kStageName, ds->getExpCtx(), ds->_backupId, ds->_filePath, ds->_byteOffset);
}

namespace exec::agg {

REGISTER_AGG_STAGE_MAPPING(backupFileStage,
                           DocumentSourceBackupFile::id,
                           documentSourceBackupFileToStageFn);

BackupFileStage::BackupFileStage(StringData stageName,
                                 const boost::intrusive_ptr<ExpressionContext>& pExpCtx,
                                 UUID backupId,
                                 std::string filePath,
                                 long long byteOffset)
    : Stage(stageName, pExpCtx),
      _dataBuf(),
      _backupId(backupId),
      _filePath(std::move(filePath)),
      _byteOffset(byteOffset),
      _file(_filePath, std::ios_base::in | std::ios_base::binary) {
    tassert(ErrorCodes::FileOpenFailed,
            str::stream() << "Failed to open file " << _filePath,
            _file.is_open());
    _file.seekg(_byteOffset);
    tassert(ErrorCodes::FileOpenFailed,
            str::stream() << "Failed to set read position " << _byteOffset << " in file "
                          << _filePath,
            !_file.fail());
    invariant(_byteOffset == _file.tellg());
}


BackupFileStage::~BackupFileStage() {
    _file.close();
}

GetNextResult BackupFileStage::doGetNext() {
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

    Document doc = Document{{"byteOffset"_sd, static_cast<long long>(byteOffset)},
                            {"data"_sd, BSONBinData(_dataBuf.data(), bytesRead, BinDataGeneral)},
                            {"endOfFile"_sd, eof}};

    return doc;
}

}  // namespace exec::agg
}  // namespace mongo
