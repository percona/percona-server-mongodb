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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kNetwork

#include "mongo/db/encryption/vault_client.h"

#include <cstddef>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <boost/tokenizer.hpp>

#include "mongo/base/data_range.h"
#include "mongo/base/static_assert.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/bson/json.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/read_file_to_secure_string.h"
#include "mongo/db/encryption/vault_secret_metadata_locator.h"
#include "mongo/db/json.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/duration.h"
#include "mongo/util/invariant.h"
#include "mongo/util/net/http_client.h"
#include "mongo/util/str.h"
#include "mongo/util/time_support.h"

namespace mongo::encryption {
namespace {
class PositiveUint64 {
public:
    explicit PositiveUint64(long long value) : _value((invariant(value > 0), value)) {}
    operator std::uint64_t() const noexcept {
        return _value;
    }

private:
    std::uint64_t _value;
};

class BadHttpReponse : public std::runtime_error {
public:
    BadHttpReponse(const char* operation, std::uint16_t code, const StringData& body)
        : std::runtime_error(str::stream()
                             << "Bad HTTP response from the Vault server while " << operation
                             << "; statusCode: " << code << "; body: `" << body << "`") {}
};

class InvalidVaultResponse : public std::runtime_error {
public:
    explicit InvalidVaultResponse(const std::string& reason)
        : std::runtime_error(str::stream() << "Invalid Vault response: " << reason) {}

    InvalidVaultResponse(const StringData& fieldName, const StringData& reason)
        : std::runtime_error(str::stream() << "Invalid Vault response: `" << fieldName << "` "
                                           << reason << ".") {}
};

class ReachedMaxVersions : public std::runtime_error {
public:
    explicit ReachedMaxVersions(const std::string& secretPath)
        : std::runtime_error(
              str::stream()
              << "The number of versions of the secret `" << secretPath
              << "` has reached the value of the parameter `max_versions` on the secret or "
                 "the secrets engine. The key write would overwrite the oldest secret version and "
                 "thus aborted. Please increase `max_versions` parameter in the secret metadata or "
                 "the secrets engine config.") {}
};

class DelayGenerator {
public:
    Milliseconds operator()() {
        // Randomize the delay in +- 20% range to reduce the probability of two
        // `mongod` processes making simultaneous requests to a Vault server.
        Milliseconds ret(static_cast<Milliseconds::rep>(_delay.count() * _dist(_gen)));
        _delay += Milliseconds(2000);
        return ret;
    }

private:
    std::random_device _rd;
    std::mt19937 _gen{_rd()};
    std::uniform_real_distribution<double> _dist{0.8, 1.2};
    Milliseconds _delay{1000};
};

struct SecretMetadata {
    std::uint64_t maxVersions{0};
    std::uint64_t oldestVersion{0};
    std::uint64_t currentVersion{0};
};

template <typename T>
T bsonObjectGetNestedValue(const BSONObj& object, const StringData& path) {
    invariant(!path.empty());

    static constexpr const char* kNotObject = "is missing or not an object";
    static constexpr const char* kNotInteger = "is missing or not an integer";
    static constexpr const char* kNotString = "is missing or not a string";

    using tokenizer = boost::tokenizer<boost::char_separator<char>>;
    tokenizer tok(path, boost::char_separator<char>("."));
    tokenizer::iterator next = tok.begin();
    tokenizer::iterator cur = next++;
    BSONElement elem = object[*cur];
    for (; next != tok.end(); cur = next, elem = elem[*cur], ++next) {
        if (elem.type() != mongo::Object) {
            throw InvalidVaultResponse(*cur, kNotObject);
        }
    }

    if constexpr (std::is_same_v<long long, T>) {
        return elem.type() == mongo::NumberInt || elem.type() == mongo::NumberLong
            ? elem.numberLong()
            : throw InvalidVaultResponse(path, kNotInteger);
    } else if constexpr (std::is_same_v<std::string, T>) {
        return elem.type() == mongo::String ? elem.String()
                                            : throw InvalidVaultResponse(path, kNotString);
    } else if constexpr (std::is_same_v<BSONObj, T>) {
        return elem.type() == mongo::Object ? elem.Obj()
                                            : throw InvalidVaultResponse(path, kNotObject);
    } else {
        MONGO_STATIC_ASSERT_MSG(!std::is_same_v<T, T>, "unsupported type");
    }
}

template <>
std::uint64_t bsonObjectGetNestedValue<std::uint64_t>(const BSONObj& object,
                                                      const StringData& path) {
    long long value = bsonObjectGetNestedValue<long long>(object, path);
    return value < 0 ? throw InvalidVaultResponse(path, "is negative")
                     : static_cast<std::uint64_t>(value);
}

template <>
PositiveUint64 bsonObjectGetNestedValue<PositiveUint64>(const BSONObj& object,
                                                        const StringData& path) {
    long long value = bsonObjectGetNestedValue<long long>(object, path);
    return value <= 0 ? throw InvalidVaultResponse(path, "is not positive") : PositiveUint64(value);
}

std::string genPutKeyReqBody(const std::string& key,
                             std::optional<std::uint64_t> cas = std::nullopt) {
    str::stream data;
    data << R"json({)json";
    if (cas) {
        data << R"json("options": {"cas": )json" << *cas << R"json(}, )json";
    }
    data << R"json("data": {"value": ")json" << key << R"json("}})json";
    return data;
}
}  // namespace

class VaultClient::Impl {
public:
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    Impl(Impl&&) = default;
    Impl& operator=(Impl&&) = default;

    Impl(const std::string& host,
         int port,
         const std::string& token,
         const std::string& tokenFile,
         const std::string& serverCaFile,
         bool checkMaxVersions,
         bool disableTls,
         long timeout);

    std::pair<std::string, std::uint64_t> getKey(const std::string& secretPath,
                                                 std::uint64_t secretVersion = 0) const;
    std::uint64_t putKey(const std::string& secretPath, const std::string& key) const;

private:
    std::uint64_t requestEngineMaxVersions(const StringData& url) const;
    std::optional<SecretMetadata> requestSecretMetadata(const StringData& url) const;
    SecretMetadata getSecretMetadata(const std::string& secretPath) const;

    static constexpr std::uint16_t kHttpStatusCodeOk = 200;
    static constexpr std::uint16_t kHttpStatusCodeBadRequest = 400;
    static constexpr std::uint16_t kHttpStatusCodeNotFound = 404;

    static constexpr std::uint64_t kDefaultMaxVersions = 10;

    std::unique_ptr<HttpClient> _httpClient;
    // concatenation of the URL's scheme, authority and the constant part of the path;
    std::string _urlHead;
    bool _checkMaxVersions;
};

VaultClient::Impl::Impl(const std::string& host,
                        int port,
                        const std::string& token,
                        const std::string& tokenFile,
                        const std::string& serverCaFile,
                        bool checkMaxVersions,
                        bool disableTls,
                        long timeout)
    : _httpClient(HttpClient::createWithoutConnectionPool()),
      _urlHead(str::stream() << (disableTls ? "http://" : "https://") << host << ":" << port
                             << "/v1/"),
      _checkMaxVersions(checkMaxVersions) {
    if (timeout > 0) {
        _httpClient->setConnectTimeout(Seconds(timeout));
        _httpClient->setTimeout(Seconds(timeout));
    }
    if (!serverCaFile.empty()) {
        _httpClient->setCAFile(serverCaFile);
    }
    _httpClient->allowInsecureHTTP(disableTls);


    std::vector<std::string> headers(1, "X-Vault-Token: ");
    headers.at(0).append(!token.empty() ? token
                                        : std::string_view(*detail::readFileToSecureString(
                                              tokenFile, "Vault token")));
    _httpClient->setHeaders(headers);
}


std::uint64_t VaultClient::Impl::requestEngineMaxVersions(const StringData& url) const {
    HttpClient::HttpReply reply = _httpClient->request(HttpClient::HttpMethod::kGET, url);

    ConstDataRangeCursor cur = reply.body.getCursor();
    StringData replyBody(cur.data(), cur.length());
    LOGV2_DEBUG(29124,
                4,
                "Vault: get a secrets engine config",
                "request.method"_attr = "GET",
                "request.url"_attr = url,
                "response.code"_attr = reply.code,
                "response.body"_attr = replyBody);
    if (reply.code != kHttpStatusCodeOk) {
        throw BadHttpReponse("getting a secrets engine config", reply.code, replyBody);
    }

    return bsonObjectGetNestedValue<std::uint64_t>(fromjson(replyBody.toString().c_str()),
                                                   "data.max_versions");
}

std::optional<SecretMetadata> VaultClient::Impl::requestSecretMetadata(
    const StringData& url) const {
    HttpClient::HttpReply reply = _httpClient->request(HttpClient::HttpMethod::kGET, url);

    ConstDataRangeCursor cur = reply.body.getCursor();
    StringData replyBody(cur.data(), cur.length());
    LOGV2_DEBUG(29125,
                4,
                "Vault: get secret metadata",
                "request.method"_attr = "GET",
                "request.url"_attr = url,
                "response.code"_attr = reply.code,
                "response.body"_attr = replyBody);
    if (reply.code == kHttpStatusCodeNotFound) {
        // metadata doesn't exist if key hasn't been created yet
        return std::nullopt;
    }
    if (reply.code != kHttpStatusCodeOk) {
        throw BadHttpReponse("getting secret metadata", reply.code, replyBody);
    }

    BSONObj bson = fromjson(replyBody.toString().c_str());
    BSONObj data = bsonObjectGetNestedValue<BSONObj>(bson, "data");
    return SecretMetadata{bsonObjectGetNestedValue<std::uint64_t>(data, "max_versions"),
                          bsonObjectGetNestedValue<std::uint64_t>(data, "oldest_version"),
                          bsonObjectGetNestedValue<std::uint64_t>(data, "current_version")};
}

SecretMetadata VaultClient::Impl::getSecretMetadata(const std::string& secretPath) const {
    auto chooseMaxVersions = [](std::uint64_t engineMaxVersions, std::uint64_t secretMaxVersions) {
        if (secretMaxVersions == 0) {
            return engineMaxVersions == 0 ? kDefaultMaxVersions : engineMaxVersions;
        } else if (engineMaxVersions == 0) {
            return secretMaxVersions == 0 ? kDefaultMaxVersions : secretMaxVersions;
        }
        return std::max(engineMaxVersions, secretMaxVersions);
    };

    detail::VaultSecretMetadataLocator locator(secretPath);
    str::stream engineConfigUrl;
    engineConfigUrl << _urlHead << locator.engineConfigPath;
    str::stream secretMetadataUrl;
    secretMetadataUrl << _urlHead << locator.metadataPath;

    std::uint64_t engineMaxVersions = requestEngineMaxVersions(engineConfigUrl);
    if (auto metadata = requestSecretMetadata(secretMetadataUrl); metadata) {
        metadata->maxVersions = chooseMaxVersions(engineMaxVersions, metadata->maxVersions);
        return *metadata;
    }
    return SecretMetadata{engineMaxVersions == 0 ? kDefaultMaxVersions : engineMaxVersions, 0, 0};
}

std::pair<std::string, std::uint64_t> VaultClient::Impl::getKey(const std::string& secretPath,
                                                                std::uint64_t secretVersion) const {
    str::stream url;
    url << _urlHead << secretPath;
    if (secretVersion > 0) {
        url << "?version=" << secretVersion;
    }
    HttpClient::HttpReply reply = _httpClient->request(HttpClient::HttpMethod::kGET, url);

    ConstDataRangeCursor cur = reply.body.getCursor();
    StringData replyBody(cur.data(), cur.length());
    LOGV2_DEBUG(29126,
                4,
                "Vault: get a secret",
                "request.method"_attr = "GET",
                "request.url"_attr = url,
                "response.code"_attr = reply.code,
                "response.body"_attr = replyBody);
    if (reply.code == kHttpStatusCodeNotFound) {
        return {std::string(), 0};
    }
    if (reply.code != kHttpStatusCodeOk) {
        throw BadHttpReponse("getting a secret", reply.code, replyBody);
    }

    BSONObj bson = fromjson(replyBody.toString().c_str());
    BSONObj data = bsonObjectGetNestedValue<BSONObj>(bson, "data");
    std::uint64_t versionGot = bsonObjectGetNestedValue<PositiveUint64>(data, "metadata.version");
    if (secretVersion > 0 && versionGot != secretVersion) {
        throw InvalidVaultResponse(str::stream() << "requested the key of version " << secretVersion
                                                 << " but got version " << versionGot);
    }
    return {bsonObjectGetNestedValue<std::string>(data, "data.value"), versionGot};
}

std::uint64_t VaultClient::Impl::putKey(const std::string& secretPath,
                                        const std::string& key) const {
    static const StringData kVersionMismatchErrorMsg =
        "check-and-set parameter did not match the current version";
    str::stream url;
    url << _urlHead << secretPath;

    for (unsigned remainingAttemptCount = _checkMaxVersions ? 3 : 1;;) {
        std::string reqBody;
        if (_checkMaxVersions) {
            SecretMetadata metadata = getSecretMetadata(secretPath);
            if (metadata.currentVersion >= metadata.maxVersions) {
                throw ReachedMaxVersions(secretPath);
            }
            reqBody = genPutKeyReqBody(key, metadata.currentVersion);
        } else {
            reqBody = genPutKeyReqBody(key);
        }

        HttpClient::HttpReply reply =
            _httpClient->request(HttpClient::HttpMethod::kPOST, url, reqBody);

        ConstDataRangeCursor cur = reply.body.getCursor();
        StringData replyBody(cur.data(), cur.length());
        LOGV2_DEBUG(29127,
                    4,
                    "Vault: put a secret",
                    "request.method"_attr = "POST",
                    "request.url"_attr = url,
                    "request.body"_attr = reqBody,
                    "response.code"_attr = reply.code,
                    "response.body"_attr = replyBody);
        if (--remainingAttemptCount > 0 && reply.code == kHttpStatusCodeBadRequest &&
            replyBody.find(kVersionMismatchErrorMsg) != std::string::npos) {
            static DelayGenerator g;
            Milliseconds delay = g();
            LOGV2_WARNING(29128,
                          "Failed to put a key to the Vault server due to version mismatch. "
                          "Retrying after a delay.",
                          "delay"_attr = delay);
            mongo::sleepFor(delay);
            continue;
        }
        if (reply.code != kHttpStatusCodeOk) {
            throw BadHttpReponse("putting a secret", reply.code, replyBody);
        }

        return bsonObjectGetNestedValue<PositiveUint64>(fromjson(replyBody.toString().c_str()),
                                                        "data.version");
    }
    MONGO_UNREACHABLE;
}

VaultClient::~VaultClient() = default;

VaultClient::VaultClient(VaultClient&&) = default;
VaultClient& VaultClient::operator=(VaultClient&&) = default;

VaultClient::VaultClient(const std::string& host,
                         int port,
                         const std::string& token,
                         const std::string& tokenFile,
                         const std::string& serverCaFile,
                         bool checkMaxVersions,
                         bool disableTls,
                         long timeout)
    : _impl(std::make_unique<Impl>(
          host, port, token, tokenFile, serverCaFile, checkMaxVersions, disableTls, timeout)) {}

std::pair<std::string, std::uint64_t> VaultClient::getKey(const std::string& secretPath,
                                                          std::uint64_t secretVersion) const {
    return _impl->getKey(secretPath, secretVersion);
}

std::uint64_t VaultClient::putKey(const std::string& secretPath, const std::string& key) const {
    return _impl->putKey(secretPath, key);
}
}  // namespace mongo::encryption
