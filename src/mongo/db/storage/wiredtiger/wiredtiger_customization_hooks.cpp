// Copyright (c) MongoDB, Inc.
// SPDX-License-Identifier: SSPL-1.0

#include "mongo/db/storage/wiredtiger/wiredtiger_customization_hooks.h"

#include "mongo/base/init.h"  // IWYU pragma: keep
#include "mongo/db/database_name_util.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/namespace_string_util.h"
#include "mongo/db/service_context.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/decorable.h"
#include "mongo/util/str.h"

#include <memory>
#include <string_view>
#include <utility>

#include <boost/none.hpp>

namespace mongo {
using namespace std::literals::string_view_literals;
namespace {

class WiredTigerCustomizationHooksEncryption : public WiredTigerCustomizationHooks {
public:
    /**
     * Returns true if the customization hooks are enabled.
     */
    bool enabled() const override {
        return true;
    }

    /**
     *  Gets an additional configuration string for the provided table name on a
     *  `WT_SESSION::create` call.
     */
    std::string getTableCreateConfig(std::string_view tableName) override {
        NamespaceString ns = NamespaceStringUtil::deserialize(
            boost::none, tableName, SerializationContext::stateDefault());
        std::string keyIdStr =
            DatabaseNameUtil::serialize(ns.dbName(), SerializationContext::stateDefault());
        std::string_view keyid(keyIdStr);
        // Keep compatibility with v3.6 after SERVER-34617
        const size_t minsize = 6;  // Minimum size which allows following condition to be true
        if (keyid.size() >= minsize && (keyid == "system"sv || keyid.starts_with("table:"sv)))
            keyid = "/default"sv;
        return str::stream() << "encryption=(name=percona,keyid=\"" << keyid << "\"),";
    }
};

ServiceContext::ConstructorActionRegisterer setWiredTigerCustomizationHooks{
    "SetWiredTigerCustomizationHooks", [](ServiceContext* service) {
        if (encryptionGlobalParams.enableEncryption) {
            auto customizationHooks = std::make_unique<WiredTigerCustomizationHooksEncryption>();
            WiredTigerCustomizationHooks::set(service, std::move(customizationHooks));
        } else {
            auto customizationHooks = std::make_unique<WiredTigerCustomizationHooks>();
            WiredTigerCustomizationHooks::set(service, std::move(customizationHooks));
        }
    }};

const auto getCustomizationHooks =
    ServiceContext::declareDecoration<std::unique_ptr<WiredTigerCustomizationHooks>>();

const auto getWiredTigerCustomizationHooksRegistry =
    ServiceContext::declareDecoration<WiredTigerCustomizationHooksRegistry>();

}  // namespace


WiredTigerCustomizationHooksRegistry& WiredTigerCustomizationHooksRegistry::get(
    ServiceContext* service) {
    return getWiredTigerCustomizationHooksRegistry(service);
}


void WiredTigerCustomizationHooksRegistry::addHook(
    std::unique_ptr<WiredTigerCustomizationHooks> custHook) {
    invariant(custHook);
    _hooks.push_back(std::move(custHook));
}

std::string WiredTigerCustomizationHooksRegistry::getTableCreateConfig(
    std::string_view tableName) const {
    str::stream config;
    for (const auto& h : _hooks) {
        config << h->getTableCreateConfig(tableName);
    }
    return config;
}

void WiredTigerCustomizationHooks::set(ServiceContext* service,
                                       std::unique_ptr<WiredTigerCustomizationHooks> customHooks) {
    auto& hooks = getCustomizationHooks(service);
    invariant(customHooks);
    hooks = std::move(customHooks);
}

WiredTigerCustomizationHooks* WiredTigerCustomizationHooks::get(ServiceContext* service) {
    return getCustomizationHooks(service).get();
}

WiredTigerCustomizationHooks::~WiredTigerCustomizationHooks() {}

bool WiredTigerCustomizationHooks::enabled() const {
    return false;
}

std::string WiredTigerCustomizationHooks::getTableCreateConfig(std::string_view tableName) {
    return "";
}

}  // namespace mongo
