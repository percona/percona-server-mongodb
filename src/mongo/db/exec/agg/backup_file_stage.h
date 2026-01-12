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

#pragma once

#include "mongo/db/exec/agg/stage.h"
#include "mongo/util/uuid.h"

#include <array>
#include <fstream>
#include <string>

namespace mongo::exec::agg {

/**
 * Stage implementation for $_backupFile.
 */
class BackupFileStage final : public Stage {
public:
    BackupFileStage(StringData stageName,
                    const boost::intrusive_ptr<ExpressionContext>& pExpCtx,
                    UUID backupId,
                    std::string filePath,
                    long long byteOffset);

    ~BackupFileStage() override;

private:
    static constexpr std::streamsize kBlockSize = 1 << 20;

    GetNextResult doGetNext() override;

    std::array<char, kBlockSize> _dataBuf;
    const UUID _backupId;
    const std::string _filePath;
    const long long _byteOffset;
    std::ifstream _file;
};

}  // namespace mongo::exec::agg
