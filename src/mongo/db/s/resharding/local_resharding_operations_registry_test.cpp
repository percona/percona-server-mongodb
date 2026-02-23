/**
 *    Copyright (C) 2026-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/db/s/resharding/local_resharding_operations_registry.h"

#include "mongo/base/error_codes.h"
#include "mongo/db/dbdirectclient.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/repl/mock_repl_coord_server_fixture.h"
#include "mongo/db/s/resharding/coordinator_document_gen.h"
#include "mongo/db/s/resharding/donor_document_gen.h"
#include "mongo/db/s/resharding/recipient_document_gen.h"
#include "mongo/s/resharding/common_types_gen.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/uuid.h"

#include <fmt/format.h>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kTest

namespace mongo {
namespace {

using Role = LocalReshardingOperationsRegistry::Role;

const NamespaceString kNs1 = NamespaceString::createNamespaceString_forTest("db.coll1");
const NamespaceString kNs2 = NamespaceString::createNamespaceString_forTest("db.coll2");
const BSONObj kShardKeyPattern = BSON("x" << 1);

NamespaceString makeTempReshardingNss(const NamespaceString& sourceNss, const UUID& sourceUUID) {
    auto tempColl = fmt::format(
        "{}{}", NamespaceString::kTemporaryReshardingCollectionPrefix, sourceUUID.toString());
    return NamespaceString::createNamespaceString_forTest(sourceNss.db_forSharding(), tempColl);
}

CommonReshardingMetadata makeMetadata(const NamespaceString& sourceNss,
                                      const UUID& reshardingUUID = UUID::gen(),
                                      const UUID& sourceUUID = UUID::gen()) {
    auto tempNss = makeTempReshardingNss(sourceNss, sourceUUID);
    return CommonReshardingMetadata(
        reshardingUUID, sourceNss, sourceUUID, std::move(tempNss), kShardKeyPattern);
}

BSONObj makeCoordinatorStateDoc(const NamespaceString& sourceNss,
                                const UUID& reshardingUUID,
                                const UUID& sourceUUID,
                                CoordinatorStateEnum state = CoordinatorStateEnum::kInitializing) {
    ReshardingCoordinatorDocument doc(state, {}, {});
    doc.setCommonReshardingMetadata(makeMetadata(sourceNss, reshardingUUID, sourceUUID));
    return doc.toBSON();
}

BSONObj makeDonorStateDoc(const NamespaceString& sourceNss,
                          const UUID& reshardingUUID,
                          const UUID& sourceUUID) {
    ReshardingDonorDocument doc;
    doc.setCommonReshardingMetadata(makeMetadata(sourceNss, reshardingUUID, sourceUUID));
    doc.setMutableState(DonorShardContext{});
    doc.setRecipientShards({});
    return doc.toBSON();
}

BSONObj makeRecipientStateDoc(const NamespaceString& sourceNss,
                              const UUID& reshardingUUID,
                              const UUID& sourceUUID) {
    ReshardingRecipientDocument doc;
    doc.setCommonReshardingMetadata(makeMetadata(sourceNss, reshardingUUID, sourceUUID));
    doc.setMutableState(RecipientShardContext{});
    doc.setDonorShards({});
    doc.setMinimumOperationDurationMillis(0);
    return doc.toBSON();
}

void createCollectionAndInsert(OperationContext* opCtx,
                               const NamespaceString& nss,
                               const std::vector<BSONObj>& docs) {
    DBDirectClient client(opCtx);
    ASSERT_TRUE(client.createCollection(nss));
    for (const auto& doc : docs) {
        client.insert(nss, doc);
    }
}

class LocalReshardingOperationsRegistryResyncFromDiskTest : public MockReplCoordServerFixture {};

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest, EmptyCollectionsRegistryRemainsEmpty) {
    createCollectionAndInsert(opCtx(), NamespaceString::kConfigReshardingOperationsNamespace, {});
    createCollectionAndInsert(opCtx(), NamespaceString::kDonorReshardingOperationsNamespace, {});
    createCollectionAndInsert(
        opCtx(), NamespaceString::kRecipientReshardingOperationsNamespace, {});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    ASSERT_FALSE(registry.getOperation(kNs1));
    ASSERT_FALSE(registry.getOperation(kNs2));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest,
       CoordinatorDocOnlyRegistryHasCoordinatorRole) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kConfigReshardingOperationsNamespace,
                              {makeCoordinatorStateDoc(kNs1, reshardingUUID, sourceUUID)});
    createCollectionAndInsert(opCtx(), NamespaceString::kDonorReshardingOperationsNamespace, {});
    createCollectionAndInsert(
        opCtx(), NamespaceString::kRecipientReshardingOperationsNamespace, {});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
    ASSERT_EQ(op->metadata.getReshardingUUID(), reshardingUUID);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest, DonorDocOnlyRegistryHasDonorRole) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(opCtx(), NamespaceString::kConfigReshardingOperationsNamespace, {});
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kDonorReshardingOperationsNamespace,
                              {makeDonorStateDoc(kNs1, reshardingUUID, sourceUUID)});
    createCollectionAndInsert(
        opCtx(), NamespaceString::kRecipientReshardingOperationsNamespace, {});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kDonor));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest,
       RecipientDocOnlyRegistryHasRecipientRole) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(opCtx(), NamespaceString::kConfigReshardingOperationsNamespace, {});
    createCollectionAndInsert(opCtx(), NamespaceString::kDonorReshardingOperationsNamespace, {});
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kRecipientReshardingOperationsNamespace,
                              {makeRecipientStateDoc(kNs1, reshardingUUID, sourceUUID)});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kRecipient));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest,
       MultipleRolesSameNssRegistryHasAllRoles) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kConfigReshardingOperationsNamespace,
                              {makeCoordinatorStateDoc(kNs1, reshardingUUID, sourceUUID)});
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kDonorReshardingOperationsNamespace,
                              {makeDonorStateDoc(kNs1, reshardingUUID, sourceUUID)});
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kRecipientReshardingOperationsNamespace,
                              {makeRecipientStateDoc(kNs1, reshardingUUID, sourceUUID)});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
    ASSERT_TRUE(op->roles.count(Role::kDonor));
    ASSERT_TRUE(op->roles.count(Role::kRecipient));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest,
       QuiescedCoordinatorDocOnlyRegistryRemainsEmpty) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(
        opCtx(),
        NamespaceString::kConfigReshardingOperationsNamespace,
        {makeCoordinatorStateDoc(
            kNs1, reshardingUUID, sourceUUID, CoordinatorStateEnum::kQuiesced)});
    createCollectionAndInsert(opCtx(), NamespaceString::kDonorReshardingOperationsNamespace, {});
    createCollectionAndInsert(
        opCtx(), NamespaceString::kRecipientReshardingOperationsNamespace, {});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    ASSERT_FALSE(registry.getOperation(kNs1));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest, MultipleOperationsRegistryHasAll) {
    auto uuid1 = UUID::gen();
    auto uuid2 = UUID::gen();
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kConfigReshardingOperationsNamespace,
                              {makeCoordinatorStateDoc(kNs1, uuid1, UUID::gen())});
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kDonorReshardingOperationsNamespace,
                              {makeDonorStateDoc(kNs2, uuid2, UUID::gen())});

    LocalReshardingOperationsRegistry registry;
    registry.resyncFromDisk(opCtx());

    auto op1 = registry.getOperation(kNs1);
    auto op2 = registry.getOperation(kNs2);
    ASSERT_TRUE(op1);
    ASSERT_TRUE(op2);
    ASSERT_EQ(op1->metadata.getSourceNss(), kNs1);
    ASSERT_EQ(op2->metadata.getSourceNss(), kNs2);
    ASSERT_TRUE(op1->roles.count(Role::kCoordinator));
    ASSERT_TRUE(op2->roles.count(Role::kDonor));
}

TEST_F(LocalReshardingOperationsRegistryResyncFromDiskTest, ClearsExistingStateBeforeRepopulating) {
    auto reshardingUUID = UUID::gen();
    auto sourceUUID = UUID::gen();
    createCollectionAndInsert(opCtx(),
                              NamespaceString::kConfigReshardingOperationsNamespace,
                              {makeCoordinatorStateDoc(kNs1, reshardingUUID, sourceUUID)});
    createCollectionAndInsert(opCtx(), NamespaceString::kDonorReshardingOperationsNamespace, {});
    createCollectionAndInsert(
        opCtx(), NamespaceString::kRecipientReshardingOperationsNamespace, {});

    LocalReshardingOperationsRegistry registry;
    registry.registerOperation(Role::kDonor, makeMetadata(kNs2));
    ASSERT_TRUE(registry.getOperation(kNs2));

    registry.resyncFromDisk(opCtx());

    ASSERT_TRUE(registry.getOperation(kNs1));
    ASSERT_FALSE(registry.getOperation(kNs2));
}

TEST(LocalReshardingOperationsRegistryTest, GetUnknownNamespace) {
    LocalReshardingOperationsRegistry registry;
    ASSERT_FALSE(registry.getOperation(kNs1));
}

TEST(LocalReshardingOperationsRegistryTest, RegisterOneRole) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
}

TEST(LocalReshardingOperationsRegistryTest, RegisterMultipleRolesSameNamespace) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);
    registry.registerOperation(Role::kDonor, meta);
    registry.registerOperation(Role::kRecipient, meta);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 3u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
    ASSERT_TRUE(op->roles.count(Role::kDonor));
    ASSERT_TRUE(op->roles.count(Role::kRecipient));
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
}

TEST(LocalReshardingOperationsRegistryTest, RegisterMultipleNamespaces) {
    LocalReshardingOperationsRegistry registry;
    auto meta1 = makeMetadata(kNs1);
    auto meta2 = makeMetadata(kNs2);
    registry.registerOperation(Role::kCoordinator, meta1);
    registry.registerOperation(Role::kDonor, meta2);

    auto op1 = registry.getOperation(kNs1);
    auto op2 = registry.getOperation(kNs2);
    ASSERT_TRUE(op1);
    ASSERT_TRUE(op2);
    ASSERT_EQ(op1->roles.size(), 1u);
    ASSERT_EQ(op2->roles.size(), 1u);
    ASSERT_EQ(op1->metadata.getSourceNss(), kNs1);
    ASSERT_EQ(op2->metadata.getSourceNss(), kNs2);
}

TEST(LocalReshardingOperationsRegistryTest, UnregisterOnlyRoleRemovesEntry) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);
    registry.unregisterOperation(Role::kCoordinator, meta);

    ASSERT_FALSE(registry.getOperation(kNs1));
}

TEST(LocalReshardingOperationsRegistryTest, UnregisterOneOfMultipleRoles) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);
    registry.registerOperation(Role::kDonor, meta);
    registry.unregisterOperation(Role::kCoordinator, meta);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kDonor));
}

TEST(LocalReshardingOperationsRegistryTest, UnregisterLastRoleRemovesEntry) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);
    registry.registerOperation(Role::kDonor, meta);
    registry.unregisterOperation(Role::kCoordinator, meta);
    registry.unregisterOperation(Role::kDonor, meta);

    ASSERT_FALSE(registry.getOperation(kNs1));
}

TEST(LocalReshardingOperationsRegistryTest, UnregisterNonExistentRoleNamespaceIsNoOp) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.unregisterOperation(Role::kCoordinator, meta);
    ASSERT_FALSE(registry.getOperation(kNs1));

    registry.registerOperation(Role::kCoordinator, meta);
    registry.unregisterOperation(Role::kDonor, meta);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
}

TEST(LocalReshardingOperationsRegistryTest, UnregisterWithNonMatchingMetadataIsNoOp) {
    LocalReshardingOperationsRegistry registry;
    auto meta1 = makeMetadata(kNs1, UUID::gen(), UUID::gen());
    auto meta2 = makeMetadata(kNs1, UUID::gen(), UUID::gen());
    registry.registerOperation(Role::kCoordinator, meta1);
    registry.unregisterOperation(Role::kCoordinator, meta2);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
}

TEST(LocalReshardingOperationsRegistryTest, RegisterDuplicateRoleNamespaceSameMetadataIsNoOp) {
    LocalReshardingOperationsRegistry registry;
    auto meta = makeMetadata(kNs1);
    registry.registerOperation(Role::kCoordinator, meta);
    registry.registerOperation(Role::kCoordinator, meta);

    auto op = registry.getOperation(kNs1);
    ASSERT_TRUE(op);
    ASSERT_EQ(op->roles.size(), 1u);
    ASSERT_TRUE(op->roles.count(Role::kCoordinator));
    ASSERT_EQ(op->metadata.getSourceNss(), kNs1);
}

TEST(LocalReshardingOperationsRegistryTest,
     GetOperationWithMultipleOpsForSameNssThrowsTransientInconsistency) {
    LocalReshardingOperationsRegistry registry;
    auto meta1 = makeMetadata(kNs1, UUID::gen(), UUID::gen());
    auto meta2 = makeMetadata(kNs1, UUID::gen(), UUID::gen());
    registry.registerOperation(Role::kCoordinator, meta1);
    registry.registerOperation(Role::kCoordinator, meta2);

    ASSERT_THROWS_CODE(registry.getOperation(kNs1), DBException, ErrorCodes::PrimarySteppedDown);
}

}  // namespace

}  // namespace mongo
