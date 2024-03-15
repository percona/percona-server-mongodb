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


#include "mongo/db/pipeline/document_source_backup_metadata.h"

#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <memory>
#include <string>
#include <utility>

#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/db/exec/document_value/document.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/pipeline/document_source.h"
#include "mongo/db/query/allowed_contexts.h"
#include "mongo/db/query/query_shape/serialization_options.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/intrusive_counter.h"
#include "mongo/util/str.h"


#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery


namespace mongo {

namespace {
constexpr StringData kBackupPath = "backupPath"_sd;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_DOCUMENT_SOURCE(backupMetadata,
                         DocumentSourceBackupMetadata::LiteParsed::parse,
                         DocumentSourceBackupMetadata::createFromBson,
                         AllowedWithApiStrict::kAlways);
}  // namespace

using boost::intrusive_ptr;

std::unique_ptr<DocumentSourceBackupMetadata::LiteParsed>
DocumentSourceBackupMetadata::LiteParsed::parse(const NamespaceString& nss,
                                                const BSONElement& spec) {

    return std::make_unique<DocumentSourceBackupMetadata::LiteParsed>(spec.fieldName());
}

const char* DocumentSourceBackupMetadata::getSourceName() const {
    return kStageName.rawData();
}

Value DocumentSourceBackupMetadata::serialize(const SerializationOptions& opts) const {
    return Value{Document{{getSourceName(), Document{{kBackupPath, _wtPath}}}}};
}

DocumentSource::GetNextResult DocumentSourceBackupMetadata::doGetNext() {
        return GetNextResult::makeEOF();
}

intrusive_ptr<DocumentSource> DocumentSourceBackupMetadata::createFromBson(
    BSONElement spec, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // This cursor is non-tailable so we don't touch pExpCtx->tailableMode here

    uassert(ErrorCodes::FailedToParse,
            str::stream() << kStageName << " parameters must be specified in an object, but found: "
                          << typeName(spec.type()),
            spec.type() == Object);

    std::string wtPath;

    for (auto&& elem : spec.embeddedObject()) {
        const auto fieldName = elem.fieldNameStringData();

        if (fieldName == kBackupPath) {
            uassert(ErrorCodes::TypeMismatch,
                    str::stream() << "The '" << fieldName << "' parameter of the " << kStageName
                                  << " stage must be a string value, but found: "
                                  << typeName(elem.type()),
                    elem.type() == BSONType::String);
            wtPath = elem.String();
        } else {
            uasserted(ErrorCodes::FailedToParse,
                      str::stream() << "Unrecognized option '" << fieldName << "' in " << kStageName
                                    << " stage");
        }
    }

    // TODO: open wiredTiger instance in read-only mode
    // uassert(ErrorCodes::InvalidOptions,
    //        str::stream() << "'" << kIncrementalBackup << "' and '" << kDisableIncrementalBackup
    //                      << "' parameters are mutually exclusive. Cannot enable both",
    //        !(options.incrementalBackup && options.disableIncrementalBackup));

    return make_intrusive<DocumentSourceBackupMetadata>(pExpCtx, std::move(wtPath));
}

DocumentSourceBackupMetadata::DocumentSourceBackupMetadata(
    const intrusive_ptr<ExpressionContext>& expCtx, std::string wtPath)
    : DocumentSource(kStageName, expCtx), _wtPath(std::move(wtPath)) {}

DocumentSourceBackupMetadata::~DocumentSourceBackupMetadata() {
    // TODO: close wiredTiger instance
}
}  // namespace mongo
