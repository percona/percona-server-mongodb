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

#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"

#include <map>
#include <ranges>
#include <tuple>
#include <vector>

#include <boost/optional/optional.hpp>

#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/bson/json.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/tenant_id.h"
#include "mongo/idl/idl_parser.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/str.h"


namespace mongo {
namespace {
constexpr const char* kParameterName = "oidcIdentityProviders";

struct IssuerAudiencePair {
    StringData issuer;
    StringData audience;
};

struct JWKSPollSecsIndexes {
    using JWKSPollSecsType = decltype(std::declval<OidcIdentityProviderConfig>().getJWKSPollSecs());
    JWKSPollSecsType jwksPollSecs;
    std::size_t differentValuesCount;
    std::vector<std::size_t> indexes;
};

bool operator<(const IssuerAudiencePair& lhs, const IssuerAudiencePair& rhs) noexcept {
    return std::tie(lhs.issuer, lhs.audience) < std::tie(rhs.issuer, rhs.audience);
}

template <typename R>
requires std::ranges::range<R> && std::is_same_v<std::ranges::range_value_t<R>, std::size_t>
str::stream errorMsgHeader(const R& indexes) {
    str::stream s;
    s << "In ";
    for (std::size_t i{0u}; auto index : indexes) {
        s << (i++ == 0 ? "" : ", ") << "`" << kParameterName << "[" << index << "]`";
    }
    s << ": ";
    return s;
}

void validate(const OidcIdentityProviderConfig& conf, std::size_t index) {
    static constexpr std::string_view kLegalChars{
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"};
    auto authNamePrefix{static_cast<std::string_view>(conf.getAuthNamePrefix())};
    if (auto pos{authNamePrefix.find_first_not_of(kLegalChars)}; pos != std::string_view::npos) {
        uasserted(77702,
                  errorMsgHeader(std::views::single(index))
                      << "`" << OidcIdentityProviderConfig::kAuthNamePrefixFieldName
                      << "` contains illegal char `" << authNamePrefix[pos]
                      << "`. Only [a-zA-Z0-9_-] are allowed.");
    }
    uassert(77703,
            errorMsgHeader(std::views::single(index))
                << "`" << OidcIdentityProviderConfig::kClientIdFieldName << "` must present if `"
                << OidcIdentityProviderConfig::kSupportsHumanFlowsFieldName
                << "` is `true`, which is the default.",
            conf.getSupportsHumanFlows() ? static_cast<bool>(conf.getClientId()) : true);
    uassert(
        77704,
        errorMsgHeader(std::views::single(index))
            << "`" << OidcIdentityProviderConfig::kAuthorizationClaimFieldName
            << "` must present if `" << OidcIdentityProviderConfig::kUseAuthorizationClaimFieldName
            << "` is `true`, which is the default.",
        conf.getUseAuthorizationClaim() ? static_cast<bool>(conf.getAuthorizationClaim()) : true);
}

void validate(const OidcIdentityProvidersServerParameter& param) {
    // Indexes of `OidcIdentityProviderConfig`s with enabled `supportsHumanFlows`
    std::vector<std::size_t> humanFlowsIndexes;
    // Indexes of `OidcIdentityProviderConfig`s with specified `matchPattern`
    std::vector<std::size_t> matchPatternIndexes;
    // Mapping from `{issuer, audience}` pair to the indexes of those
    // `OidcIdentityProviderConfig`s that have those particular `issuer` and
    // `audience` values.
    std::map<IssuerAudiencePair, std::vector<std::size_t>> equalAudienceIndexes;

    std::map<StringData, JWKSPollSecsIndexes> jwksPollSecsMap;

    for (std::size_t i{0u}; i < param._data.size(); ++i) {
        const auto& conf{param._data[i]};
        validate(conf, i);
        if (conf.getSupportsHumanFlows()) {
            humanFlowsIndexes.push_back(i);
        }
        if (conf.getMatchPattern()) {
            matchPatternIndexes.push_back(i);
        }
        equalAudienceIndexes[{conf.getIssuer(), conf.getAudience()}].push_back(i);

        auto it = jwksPollSecsMap.find(conf.getIssuer());
        if (it == jwksPollSecsMap.end()) {
            jwksPollSecsMap[conf.getIssuer()] = {conf.getJWKSPollSecs(), 0, {i}};
        } else {
            it->second.indexes.push_back(i);
            if (it->second.jwksPollSecs != conf.getJWKSPollSecs()) {
                it->second.differentValuesCount++;
            }
        }
    }

    for (std::size_t i{0u}; i < matchPatternIndexes.size(); ++i) {
        uassert(77705,
                errorMsgHeader(std::views::iota(i, matchPatternIndexes[i]))
                    << "configurations without the `matchPattern` field "
                    << "must be listed after those with the `matchPattern` field",
                matchPatternIndexes[i] == i);
    }
    if (humanFlowsIndexes.size() > 1) {
        std::vector<std::size_t> humanFlowsNoMatchPatternIndexes;
        std::ranges::set_difference(humanFlowsIndexes,
                                    matchPatternIndexes,
                                    std::back_inserter(humanFlowsNoMatchPatternIndexes));
        uassert(77706,
                errorMsgHeader(humanFlowsNoMatchPatternIndexes)
                    << "`supportsHumanFlows` enabled but there is no `matchPattern`. "
                    << "If more that one configuration has `supportsHumanFlow` enabled, "
                    << "then all such configurations must have `matchPattern`.",
                humanFlowsNoMatchPatternIndexes.empty());
    }
    for (const auto& [issAud, indexes] : equalAudienceIndexes) {
        uassert(77707,
                errorMsgHeader(indexes)
                    << "`issuer` values are equal (`" << issAud.issuer
                    << "`) and `audience` values are also eqaul (`" << issAud.audience
                    << "`). `audience` should be unique for each "
                    << "configuration that shares an `issuer`.",
                indexes.size() < 2);
    }

    for (const auto& [issuer, valuePair] : jwksPollSecsMap) {
        uassert(77708,
                errorMsgHeader(valuePair.indexes)
                    << "`jwksPollSecs` values are different for the same `issuer` (`" << issuer
                    << "`). `jwksPollSecs` should be the same for each "
                    << "configuration that shares an `issuer`.",
                valuePair.differentValuesCount == 0);
    }
}

void paramDeserialize(OidcIdentityProvidersServerParameter& param, const BSONArray& arr) {
    for (std::size_t i{0u}; const BSONElement& elem : arr) {
        IDLParserContext ctx{str::stream() << kParameterName << "[" << i++ << "]"};
        ctx.checkAndAssertType(elem, mongo::Object);
        auto config{OidcIdentityProviderConfig::parse(ctx, elem.Obj())};

        // The default value for array fields is not supported by IDL,
        // so the default value is set here manually.
        if (!config.getLogClaims().has_value()) {
            config.setLogClaims(std::vector<StringData>{"iss", "sub"});
        }
        param._data.push_back(std::move(config));
    }
    validate(param);
}
}  // namespace

void OidcIdentityProvidersServerParameter::append(OperationContext*,
                                                  BSONObjBuilder* b,
                                                  StringData name,
                                                  const boost::optional<TenantId>&) {
    BSONArrayBuilder configArrayBuilder{b->subarrayStart(name)};
    for (const auto& config : _data) {
        BSONObjBuilder configBuilder{configArrayBuilder.subobjStart()};
        config.serialize(&configBuilder);
        configBuilder.doneFast();
    }
    configArrayBuilder.doneFast();
}

Status OidcIdentityProvidersServerParameter::set(const BSONElement& elem,
                                                 const boost::optional<TenantId>&) try {
    IDLParserContext ctx{kParameterName};
    ctx.checkAndAssertType(elem, mongo::Array);
    paramDeserialize(*this, BSONArray(elem.Obj()));
    return Status::OK();
} catch (const DBException& e) {
    return e.toStatus();
}

Status OidcIdentityProvidersServerParameter::setFromString(StringData str,
                                                           const boost::optional<TenantId>&) try {
    uassert(ErrorCodes::TypeMismatch,
            str::stream() << "`" << kParameterName << "` is not an array serialized to a string",
            isArray(str));
    paramDeserialize(*this, BSONArray{fromjson(str)});
    return Status::OK();
} catch (const DBException& e) {
    return e.toStatus();
}
}  // namespace mongo
