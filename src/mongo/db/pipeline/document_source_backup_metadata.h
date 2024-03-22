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

#include <memory>
#include <set>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/none.hpp>
#include <boost/optional/optional.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <wiredtiger.h>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/db/auth/action_type.h"
#include "mongo/db/auth/privilege.h"
#include "mongo/db/auth/resource_pattern.h"
#include "mongo/db/exec/document_value/value.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/pipeline/document_source.h"
#include "mongo/db/pipeline/expression_context.h"
#include "mongo/db/pipeline/lite_parsed_document_source.h"
#include "mongo/db/pipeline/pipeline.h"
#include "mongo/db/pipeline/stage_constraints.h"
#include "mongo/db/pipeline/variables.h"
#include "mongo/db/query/query_shape/serialization_options.h"
#include "mongo/stdx/unordered_set.h"


namespace mongo {

class DocumentSourceBackupMetadata final : public DocumentSource {
public:
    static constexpr StringData kStageName = "$backupMetadata"_sd;

    class LiteParsed final : public LiteParsedDocumentSource {
    public:
        using LiteParsedDocumentSource::LiteParsedDocumentSource;

        static std::unique_ptr<LiteParsed> parse(const NamespaceString& nss,
                                                 const BSONElement& spec);

        stdx::unordered_set<NamespaceString> getInvolvedNamespaces() const override {
            return {};
        }

        PrivilegeVector requiredPrivileges(bool isMongos,
                                           bool bypassDocumentValidation) const override {
            return {Privilege(ResourcePattern::forClusterResource(), ActionType::fsync)};
        }

        bool isInitialSource() const override {
            return true;
        }

        void assertSupportsMultiDocumentTransaction() const override {
            transactionNotSupported(kStageName);
        }
    };

    /**
     * Parses a $backupMetadata stage from 'spec'.
     */
    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement spec, const boost::intrusive_ptr<ExpressionContext>& pCtx);

    DocumentSourceBackupMetadata(const boost::intrusive_ptr<ExpressionContext>& expCtx,
                                 boost::filesystem::path wtPath);

    DocumentSourceBackupMetadata(const DocumentSourceBackupMetadata&) = delete;
    DocumentSourceBackupMetadata& operator=(const DocumentSourceBackupMetadata&) = delete;
    DocumentSourceBackupMetadata(DocumentSourceBackupMetadata&&) = delete;
    DocumentSourceBackupMetadata& operator=(DocumentSourceBackupMetadata&&) = delete;

    ~DocumentSourceBackupMetadata() override;

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

    Value serialize(const SerializationOptions& opts = SerializationOptions{}) const override;

    boost::optional<DistributedPlanLogic> distributedPlanLogic() override {
        return boost::none;
    }

    void addVariableRefs(std::set<Variables::Id>* refs) const override {}

protected:
    GetNextResult doGetNext() override;

private:
    // Ensure connection close even if exception is thrown from constructor
    // sessions and cursors are closed by connection close
    struct WTConnectionGuard {
        WT_CONNECTION* _conn = nullptr;
        WTConnectionGuard() = default;
        WTConnectionGuard(const WTConnectionGuard&) = delete;
        WTConnectionGuard& operator=(const WTConnectionGuard&) = delete;
        WTConnectionGuard(WTConnectionGuard&&) = delete;
        WTConnectionGuard& operator=(WTConnectionGuard&&) = delete;
        ~WTConnectionGuard();
    };

    // create path from ident
    std::string identPath(const StringData ident) const;

    const boost::filesystem::path _wtPath;
    bool _dirPerDB = false;
    bool _dirForIndexes = false;
    WTConnectionGuard _wtConnGuard;
    WT_SESSION* _session = nullptr;
    WT_CURSOR* _mdbCatalogCursor = nullptr;
    WT_CURSOR* _sizeStorerCursor = nullptr;
};

}  // namespace mongo
