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

namespace mongo {

class DocumentSourceBackupCursorExtend : public DocumentSource {
public:
    static constexpr StringData kStageName = "$backupCursorExtend"_sd;

    class LiteParsed final : public LiteParsedDocumentSource {
    public:
        using LiteParsedDocumentSource::LiteParsedDocumentSource;

        static std::unique_ptr<LiteParsed> parse(const NamespaceString& nss,
                                                 const BSONElement& spec);

        stdx::unordered_set<NamespaceString> getInvolvedNamespaces() const final {
            return stdx::unordered_set<NamespaceString>();
        }

        PrivilegeVector requiredPrivileges(bool isMongos,
                                           bool bypassDocumentValidation) const final {
            return {Privilege(ResourcePattern::forClusterResource(), ActionType::fsync)};
        }

        bool isInitialSource() const final {
            return true;
        }

        // Ideally this stage should only support local read concern, but PBM executes it with
        // "majority" read concern. So in order to be compatible with that we allow 'local' and
        // 'majority' read concerns.
        ReadConcernSupportResult supportsReadConcern(repl::ReadConcernLevel level,
                                                     bool isImplicitDefault) const final {
            // return onlyReadConcernLocalSupported(kStageName, level, isImplicitDefault);
            return {{(level != repl::ReadConcernLevel::kLocalReadConcern &&
                      level != repl::ReadConcernLevel::kMajorityReadConcern) &&
                         !isImplicitDefault,
                     {ErrorCodes::InvalidOptions,
                      str::stream() << "Aggregation stage " << kStageName
                                    << " cannot run with a readConcern other than 'local' or "
                                       "'majority'. Current readConcern: "
                                    << repl::readConcernLevels::toString(level)}},
                    {{ErrorCodes::InvalidOptions,
                      str::stream() << "Aggregation stage " << kStageName
                                    << " does not permit default readConcern to be applied."}}};
        }

        void assertSupportsMultiDocumentTransaction() const final {
            transactionNotSupported(kStageName);
        }
    };

    /**
     * Parses a $backupCursor stage from 'spec'.
     */
    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement spec, const boost::intrusive_ptr<ExpressionContext>& pCtx);

    ~DocumentSourceBackupCursorExtend() override;

    const char* getSourceName() const override;

    StageConstraints constraints(Pipeline::SplitState pipeState) const override {
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
    DocumentSourceBackupCursorExtend(const boost::intrusive_ptr<ExpressionContext>& expCtx,
                                     const UUID& backupId,
                                     const Timestamp& extendTo);

private:
    const UUID _backupId;
    const Timestamp _extendTo;
    BackupCursorExtendState _backupCursorExtendState;
    // Convenience reference to _backupCursorExtendState.filenames
    const std::deque<std::string>& _filenames;
    // Document iterator
    std::deque<std::string>::const_iterator _fileIt;
};

}  // namespace mongo
