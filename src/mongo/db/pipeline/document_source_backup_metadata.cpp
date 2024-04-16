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

#include <memory>
#include <string>
#include <utility>

#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <fmt/format.h>
#include <wiredtiger.h>

#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/db/exec/document_value/document.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/pipeline/document_source.h"
#include "mongo/db/query/allowed_contexts.h"
#include "mongo/db/query/query_shape/serialization_options.h"
#include "mongo/db/storage/bson_collection_catalog_entry.h"
#include "mongo/db/storage/storage_engine_metadata.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/intrusive_counter.h"


#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery


namespace mongo {

namespace {
constexpr StringData kBackupPath = "backupPath"_sd;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_DOCUMENT_SOURCE(backupMetadata,
                         DocumentSourceBackupMetadata::LiteParsed::parse,
                         DocumentSourceBackupMetadata::createFromBson,
                         AllowedWithApiStrict::kAlways);

std::string _getWTMetadata(WT_SESSION* session, const std::string& uri) {
    return uassertStatusOK(WiredTigerUtil::getMetadata(session, uri));
}

std::string getTableWTMetadata(WT_SESSION* session, StringData ident) {
    return _getWTMetadata(session, "table:{}"_format(ident));
}

std::string getFileWTMetadata(WT_SESSION* session, StringData ident) {
    return _getWTMetadata(session, "file:{}.wt"_format(ident));
}

struct SizeInfo {
    long long numRecords;
    long long dataSize;
};

SizeInfo getSizeInfo(const NamespaceString& ns,
                     const StringData ident,
                     WT_CURSOR* sizeStorerCursor) {
    const auto sizeStorerUri = "table:{}"_format(ident);
    WT_ITEM sizeStorerKey = {sizeStorerUri.c_str(), sizeStorerUri.size()};
    sizeStorerCursor->set_key(sizeStorerCursor, &sizeStorerKey);
    auto ret = sizeStorerCursor->search(sizeStorerCursor);
    if (ret != 0) {
        LOGV2_WARNING(29140,
                      "No sizeStorer info for collection",
                      "ns"_attr = ns,
                      "uri"_attr = sizeStorerUri,
                      "reason"_attr = wiredtiger_strerror(ret));
        return {0, 0};
    }

    WT_ITEM item;
    uassertWTOK(sizeStorerCursor->get_value(sizeStorerCursor, &item), sizeStorerCursor->session);
    BSONObj obj{static_cast<const char*>(item.data)};
    return {obj["numRecords"].safeNumberLong(), obj["dataSize"].safeNumberLong()};
}

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
    return Value{Document{{getSourceName(), Document{{kBackupPath, _wtPath.string()}}}}};
}

std::string DocumentSourceBackupMetadata::identPath(const StringData ident) const {
    return (_wtPath / (ident.toString() + ".wt")).string();
}

DocumentSource::GetNextResult DocumentSourceBackupMetadata::doGetNext() {
    int ret = _mdbCatalogCursor->next(_mdbCatalogCursor);
    if (ret == WT_NOTFOUND) {
        return GetNextResult::makeEOF();
    }
    uassertWTOK(ret, _session);

    WT_ITEM catalogValue;
    uassertWTOK(_mdbCatalogCursor->get_value(_mdbCatalogCursor, &catalogValue), _session);
    BSONObj rawCatalogEntry(static_cast<const char*>(catalogValue.data));
    NamespaceString ns(NamespaceString::parseFromStringExpectTenantIdInMultitenancyMode(
        rawCatalogEntry.getStringField("ns"_sd)));

    const auto collIdent = rawCatalogEntry["ident"_sd].checkAndGetStringData();

    auto sizeInfo = getSizeInfo(ns, collIdent, _sizeStorerCursor);

    BSONObjBuilder indexFilesBob;
    BSONObjBuilder storageMetadataBob;

    {
        BSONObjBuilder collbob{storageMetadataBob.subobjStart(collIdent)};
        collbob.append("tableMetadata"_sd, getTableWTMetadata(_session, collIdent));
        collbob.append("fileMetadata"_sd, getFileWTMetadata(_session, collIdent));
    }

    if (auto elem = rawCatalogEntry["idxIdent"_sd]; elem.type() == Object) {
        const auto idxIdent = elem.Obj();
        BSONCollectionCatalogEntry::MetaData catalogEntry;
        catalogEntry.parse(rawCatalogEntry["md"_sd].Obj());
        for (const auto& index : catalogEntry.indexes) {
            const auto ident = idxIdent[index.nameStringData()].checkAndGetStringData();
            indexFilesBob.append(ident, identPath(ident));
            BSONObjBuilder idxbob{storageMetadataBob.subobjStart(ident)};
            idxbob.append("tableMetadata"_sd, getTableWTMetadata(_session, ident));
            idxbob.append("fileMetadata"_sd, getFileWTMetadata(_session, ident));
        }
    }

    return Document{{"ns"_sd, ns.toString()},
                    {"metadata"_sd, rawCatalogEntry},
                    {"numRecords"_sd, sizeInfo.numRecords},
                    {"dataSize"_sd, sizeInfo.dataSize},
                    {"collectionFile"_sd, identPath(collIdent)},
                    {"indexFiles"_sd, indexFilesBob.done()},
                    {"storageMetadata"_sd, storageMetadataBob.done()},
                    {"directoryPerDB"_sd, _dirPerDB},
                    {"directoryForIndexes"_sd, _dirForIndexes}};
}

intrusive_ptr<DocumentSource> DocumentSourceBackupMetadata::createFromBson(
    BSONElement spec, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // This cursor is non-tailable so we don't touch pExpCtx->tailableMode here

    uassert(ErrorCodes::FailedToParse,
            fmt::format("{} parameters must be specified in an object, but found: {}",
                        kStageName,
                        typeName(spec.type())),
            spec.type() == Object);

    boost::filesystem::path wtPath;

    for (auto&& elem : spec.embeddedObject()) {
        const auto fieldName = elem.fieldNameStringData();

        if (fieldName == kBackupPath) {
            uassert(ErrorCodes::TypeMismatch,
                    fmt::format(
                        "The '{}' parameter of the {} stage must be a string value, but found: {}",
                        fieldName,
                        kStageName,
                        typeName(elem.type())),
                    elem.type() == BSONType::String);
            wtPath = elem.String();
        } else {
            uasserted(
                ErrorCodes::FailedToParse,
                fmt::format("Unrecognized option '{}' in the {} stage", fieldName, kStageName));
        }
    }

    uassert(ErrorCodes::InvalidOptions,
            fmt::format("For {} stage the '{}' parameter cannot be empty", kStageName, kBackupPath),
            !wtPath.empty());

    return make_intrusive<DocumentSourceBackupMetadata>(pExpCtx, std::move(wtPath));
}

DocumentSourceBackupMetadata::DocumentSourceBackupMetadata(
    const intrusive_ptr<ExpressionContext>& expCtx, boost::filesystem::path wtPath)
    : DocumentSource(kStageName, expCtx), _wtPath(std::move(wtPath)) {
    // read storage metadata
    // in case of any failures we can safely throw exception
    StorageEngineMetadata metadata{_wtPath.string()};
    uassertStatusOK(metadata.read());
    const BSONObj& options = metadata.getStorageEngineOptions();
    if (auto elem = options.getField("directoryPerDB"_sd); elem.isBoolean()) {
        _dirPerDB = elem.boolean();
    }
    if (auto elem = options.getField("directoryForIndexes"_sd); elem.isBoolean()) {
        _dirForIndexes = elem.boolean();
    }

    // open wiredTiger instance in read-only mode
    const auto* wtConfig = "config_base=false";
    WT_CONNECTION* conn = nullptr;
    uassertWTOK(wiredtiger_open(_wtPath.c_str(), nullptr, wtConfig, &conn), nullptr);
    // store created connection in the guard
    // any exceptions after this point will trigger guard's destructor which will
    // destroy connection object explicitly and all sessions/cursors implicitly
    _wtConnGuard._conn = conn;

    // open session and cursors
    uassertWTOK(conn->open_session(conn, nullptr, nullptr, &_session), nullptr);
    uassertWTOK(
        _session->open_cursor(_session, "table:_mdb_catalog", nullptr, nullptr, &_mdbCatalogCursor),
        _session);
    uassertWTOK(
        _session->open_cursor(_session, "table:sizeStorer", nullptr, nullptr, &_sizeStorerCursor),
        _session);
}

DocumentSourceBackupMetadata::WTConnectionGuard::~WTConnectionGuard() {
    if (_conn) {
        _conn->close(_conn, nullptr);
    }
}

// destructor of _wtConnGuard closes wiredTiger connection
// on connection close all open sessions and cursors are desstroyed by wiredTiger
// so no need to destroy them here
DocumentSourceBackupMetadata::~DocumentSourceBackupMetadata() = default;
}  // namespace mongo
