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

#include "mongo/db/pipeline/document_source.h"
#include "mongo/util/intrusive_counter.h"

namespace mongo {

class DocumentSourceBackupCursor : public DocumentSource {
public:
    template <typename T, typename... Args, typename>
    friend boost::intrusive_ptr<T> make_intrusive(Args&&...);
    virtual boost::intrusive_ptr<DocumentSourceBackupCursor> clone() const {
        return make_intrusive<std::decay_t<decltype(*this)>>(*this);
    }

    static constexpr StringData kStageName = "$backupCursor"_sd;

    /**
     * Convenience method for creating a $backupCursor stage.
     */
    static boost::intrusive_ptr<DocumentSourceBackupCursor> create(
        const BSONObj& filter, const boost::intrusive_ptr<ExpressionContext>& expCtx);

    /**
     * Parses a $backupCursor stage from 'elem'.
     */
    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement elem, const boost::intrusive_ptr<ExpressionContext>& pCtx);

    virtual ~DocumentSourceBackupCursor() = default;

    const char* getSourceName() const override;

    StageConstraints constraints(Pipeline::SplitState pipeState) const override {
        StageConstraints constraints{
            StreamType::kStreaming,
            PositionRequirement::kFirst,
            HostTypeRequirement::kNone,  // TODO: see $currentOp for example
            DiskUseRequirement::kNoDiskUse,
            FacetRequirement::kNotAllowed,
            TransactionRequirement::kNotAllowed,
            LookupRequirement::kAllowed,
            ChangeStreamRequirement::kBlacklist};
        constraints.isIndependentOfAnyCollection = true;
        constraints.requiresInputDocSource = false;
        return constraints;
    }

    Value serialize(
        boost::optional<ExplainOptions::Verbosity> explain = boost::none) const override;

    boost::optional<DistributedPlanLogic> distributedPlanLogic() final {
        return boost::none;
    }

protected:
    DocumentSourceBackupCursor(const DocumentSourceBackupCursor& other)
        : DocumentSourceBackupCursor(
              other.serialize().getDocument().toBson().firstElement().embeddedObject(),
              other.pExpCtx) {}

    GetNextResult getNext() override;
    DocumentSourceBackupCursor(const BSONObj& query,
                               const boost::intrusive_ptr<ExpressionContext>& expCtx);
};

}  // namespace mongo
