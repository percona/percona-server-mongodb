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

#include <array>
#include <fstream>
#include <set>
#include <string>

#include <boost/optional.hpp>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/db/pipeline/document_source.h"
#include "mongo/util/uuid.h"

namespace mongo {

class DocumentSourceBackupFile final : public DocumentSource {
public:
    static constexpr StringData kStageName = "$_backupFile"_sd;

    /**
     * Parses a $_backupFile stage from 'spec'.
     */
    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement spec, const boost::intrusive_ptr<ExpressionContext>& pCtx);

    DocumentSourceBackupFile(const boost::intrusive_ptr<ExpressionContext>& expCtx,
                             UUID backupId,
                             std::string filePath,
                             long long byteOffset,
                             std::ifstream file);

    DocumentSourceBackupFile(const DocumentSourceBackupFile&) = delete;
    DocumentSourceBackupFile& operator=(const DocumentSourceBackupFile&) = delete;
    DocumentSourceBackupFile(DocumentSourceBackupFile&&) = delete;
    DocumentSourceBackupFile& operator=(DocumentSourceBackupFile&&) = delete;

    ~DocumentSourceBackupFile() override;

    const char* getSourceName() const override;

    StageConstraints constraints([[maybe_unused]] Pipeline::SplitState pipeState) const override {
        StageConstraints constraints{StreamType::kStreaming,
                                     PositionRequirement::kFirst,
                                     HostTypeRequirement::kNone,
                                     DiskUseRequirement::kNoDiskUse,
                                     FacetRequirement::kNotAllowed,
                                     TransactionRequirement::kNotAllowed,
                                     LookupRequirement::kAllowed,
                                     UnionRequirement::kNotAllowed,
                                     ChangeStreamRequirement::kDenylist};
        constraints.isIndependentOfAnyCollection = true;
        constraints.requiresInputDocSource = false;
        return constraints;
    }

    Value serialize(const SerializationOptions& opts = SerializationOptions()) const final;

    boost::optional<DistributedPlanLogic> distributedPlanLogic() final {
        return boost::none;
    }

    void addVariableRefs(std::set<Variables::Id>* refs) const final {}

protected:
    GetNextResult doGetNext() override;

private:
    static constexpr std::streamsize kBlockSize = 1 << 20;

    std::array<char, kBlockSize> _dataBuf;
    const UUID _backupId;
    const std::string _filePath;
    const long long _byteOffset;
    std::ifstream _file;
};

}  // namespace mongo
