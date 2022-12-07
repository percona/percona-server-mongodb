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

class DocumentSourceBackupCursor : public DocumentSource {
public:
    static constexpr StringData kStageName = "$backupCursor"_sd;

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

        void assertSupportsMultiDocumentTransaction() const {
            transactionNotSupported(kStageName);
        }
    };

    /**
     * Parses a $backupCursor stage from 'spec'.
     */
    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement spec, const boost::intrusive_ptr<ExpressionContext>& pCtx);

    ~DocumentSourceBackupCursor() override;

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
    GetNextResult doGetNext() override;
    DocumentSourceBackupCursor(StorageEngine::BackupOptions&& options,
                               const boost::intrusive_ptr<ExpressionContext>& expCtx);

private:
    const StorageEngine::BackupOptions _backupOptions;
    BackupCursorState _backupCursorState;
    // Convenience reference to _backupCursorState.backupInformation
    const StorageEngine::BackupInformation& _backupInformation;
    // Document iterator
    StorageEngine::BackupInformation::const_iterator _docIt;
    // Block iterator (for incremental backups)
    std::vector<StorageEngine::BackupBlock>::const_iterator _blockIt;
};

}  // namespace mongo
