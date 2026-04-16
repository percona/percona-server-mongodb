/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kCommand

#include "mongo/platform/basic.h"

#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/catalog/collection_catalog.h"
#include "mongo/db/catalog/rename_collection.h"
#include "mongo/db/commands.h"
#include "mongo/db/commands/recycle_bin_undelete_gen.h"
#include "mongo/db/namespace_string.h"

namespace mongo {
namespace {

class UndeleteCollectionCmd final : public TypedCommand<UndeleteCollectionCmd> {
public:
    using Request = UndeleteCollection;
    using Reply = typename Request::Reply;

    std::string help() const override {
        return "{ undeleteCollection: 1, recycleNamespace: <nss>, to: <coll> } "
               "Restores a soft-dropped collection from __recycle_bin.* to db.to";
    }

    bool adminOnly() const override {
        return true;
    }

    AllowedOnSecondary secondaryAllowed(ServiceContext*) const override {
        return AllowedOnSecondary::kNever;
    }

    class Invocation final : public InvocationBase {
    public:
        using InvocationBase::InvocationBase;

        Reply typedRun(OperationContext* opCtx) {
            const auto& recycleNss = request().getRecycleNamespace();
            uassert(ErrorCodes::IllegalOperation,
                    "recycleNamespace must be a __recycle_bin.* collection",
                    recycleNss.isRecycleBinCollection());

            const NamespaceString targetNss(recycleNss.db(), request().getTo());
            uassert(ErrorCodes::BadValue,
                    "Target namespace must stay in the same database",
                    recycleNss.dbName() == targetNss.dbName());

            uassert(ErrorCodes::NamespaceExists,
                    str::stream() << "Target collection already exists: " << targetNss,
                    !CollectionCatalog::get(opCtx)->lookupCollectionByNamespace(opCtx, targetNss));

            RenameCollectionOptions options;
            options.stayTemp = true;
            validateAndRunRenameCollection(opCtx, recycleNss, targetNss, options);
            return Reply();
        }

        NamespaceString ns() const override {
            return NamespaceString();
        }

        bool supportsWriteConcern() const override {
            return true;
        }

        void doCheckAuthorization(OperationContext* opCtx) const override {
            const auto& recycleNss = request().getRecycleNamespace();
            const NamespaceString targetNss(recycleNss.db(), request().getTo());
            auto* auth = AuthorizationSession::get(opCtx->getClient());
            uassert(ErrorCodes::Unauthorized,
                    "Not authorized to undelete collection",
                    auth->isAuthorizedForActionsOnNamespace(recycleNss, ActionType::renameCollection) &&
                        auth->isAuthorizedForActionsOnNamespace(targetNss, ActionType::renameCollection));
        }
    };
} undeleteCollectionCmd;

}  // namespace
}  // namespace mongo
