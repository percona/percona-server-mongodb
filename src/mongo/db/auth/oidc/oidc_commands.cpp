/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.

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

#include <fmt/format.h>

#include "mongo/db/auth/action_type.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/commands.h"

#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/commands.h"
#include "mongo/logv2/log.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

template <ActionType RequiredAction>
class OidcKeysCommand : public BasicCommand {
public:
    using BasicCommand::BasicCommand;

private:
    bool adminOnly() const final {
        return true;
    }

    Status checkAuthForOperation(OperationContext* opCtx,
                                 const DatabaseName& dbName,
                                 const BSONObj& cmdObj) const override {

        auto authzSess = AuthorizationSession::get(opCtx->getClient());

        if (!authzSess->isAuthorizedForActionsOnResource(
                ResourcePattern::forClusterResource(dbName.tenantId()), RequiredAction)) {
            return Status(ErrorCodes::Unauthorized,
                          fmt::format("not authorized to execute command {}", cmdObj.toString()));
        }

        return Status::OK();
    }

    bool supportsWriteConcern(const BSONObj& cmdObj) const override {
        return false;
    }

    AllowedOnSecondary secondaryAllowed(ServiceContext* context) const override {
        return AllowedOnSecondary::kAlways;
    }
};

class OidcListKeys : public OidcKeysCommand<ActionType::oidcListKeys> {
public:
    explicit OidcListKeys() : OidcKeysCommand("oidcListKeys") {}

private:
    // The format of the result is as follows:
    // {
    //     "keySets": {
    //         "<issuer_url>": {
    //             "keys": [
    //                 {
    //                     "kid": "<keyId>",
    //                     ... other fields of the JWK ...
    //                 },
    //                 ... other keys ...
    //             ]
    //         },
    //         ... other issuers ...
    //     }
    // }
    bool run(OperationContext* opCtx,
             const DatabaseName&,
             const BSONObj&,
             BSONObjBuilder& result) override {

        const auto& registry = OidcIdentityProvidersRegistry::get(opCtx->getServiceContext());

        BSONObjBuilder resultKeySets{result.subobjStart("keySets")};
        registry.visitJWKManagers([&resultKeySets](const auto& issuer, auto manager) {
            BSONObjBuilder resultKeySet{
                resultKeySets.subobjStart(StringData{issuer.data(), issuer.size()})};

            BSONArrayBuilder resultKeys{resultKeySet.subarrayStart("keys")};

            for (const auto& [_, key] : manager->getKeys()) {
                resultKeys.append(key);
            }
        });

        return true;
    }

    std::string help() const override {
        return "List the JWKs for the IdPs configured on this node";
    }
};

MONGO_REGISTER_COMMAND(OidcListKeys).forShard();

class OidcRefreshKeys : public OidcKeysCommand<ActionType::oidcRefreshKeys> {
public:
    explicit OidcRefreshKeys() : OidcKeysCommand("oidcRefreshKeys") {}

private:
    // Combines multiple Status objects into a single Status.
    // The input vector must contain only non-OK statuses.
    Status combineStatuses(const std::vector<Status>& statuses) {
        if (statuses.empty()) {
            return Status::OK();
        }

        if (statuses.size() == 1) {
            return statuses[0];
        }

        StringBuilder combinedMessage;
        combinedMessage << "Multiple errors occurred while refreshing:\n";
        for (const auto& status : statuses) {
            invariant(!status.isOK());
            combinedMessage << status.toString() << "\n";
        }

        return Status(ErrorCodes::OperationFailed, combinedMessage.str());
    }

    bool run(OperationContext* opCtx,
             const DatabaseName&,
             const BSONObj&,
             BSONObjBuilder&) override {

        const auto& registry = OidcIdentityProvidersRegistry::get(opCtx->getServiceContext());

        // Load keys for all JWK managers even if some of them fail.
        // At the end, combine all failures into a single Status in order to
        // report all errors at once instead of stopping at the first one.
        std::vector<Status> statuses;
        registry.visitJWKManagers([&statuses](const auto& issuer, auto manager) {
            auto status = manager->loadKeys();
            if (!status.isOK()) {
                statuses.emplace_back(status.withContext(
                    fmt::format("Failed to refresh keys for IdP: '{}'", issuer)));

                LOGV2_WARNING(29141,
                              "Failed to refresh keys for IdP",
                              "issuer"_attr = issuer,
                              "error"_attr = status);
            }
        });

        uassertStatusOK(combineStatuses(statuses));

        return true;
    }

    std::string help() const override {
        return "Refresh the JWKs for the IdPs configured on this node";
    }
};

MONGO_REGISTER_COMMAND(OidcRefreshKeys).forShard();

}  // namespace mongo
