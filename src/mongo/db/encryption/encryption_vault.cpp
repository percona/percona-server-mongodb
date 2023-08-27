/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/encryption/encryption_vault.h"

#include <sstream>

#include <curl/curl.h>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/read_file_to_secure_string.h"
#include "mongo/db/json.h"
#include "mongo/logv2/log.h"

namespace mongo::encryption::detail {

namespace {

class CURLGuard {
    CURLGuard(const CURLGuard&) = delete;
    CURLGuard& operator=(const CURLGuard&) = delete;

public:
    CURLGuard() {}
    ~CURLGuard() {
        curl_global_cleanup();
    }

    void initialize() {
        CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);
        if (ret != CURLE_OK) {
            throw std::runtime_error(str::stream()
                                     << "failed to initialize CURL: " << static_cast<int64_t>(ret));
        }

        curl_version_info_data* version_data = curl_version_info(CURLVERSION_NOW);
        if (!(version_data->features & CURL_VERSION_SSL)) {
            throw std::runtime_error(str::stream()
                                     << "Curl lacks SSL support, cannot continue");
        }
    }
};

class Curl_session_guard {
    Curl_session_guard(const Curl_session_guard&) = delete;
    Curl_session_guard& operator=(const Curl_session_guard&) = delete;

public:
    Curl_session_guard(CURL *curl)
        : curl(curl)
    {}
    ~Curl_session_guard()
    {
        if (curl != nullptr)
            curl_easy_cleanup(curl);
    }

private:
    CURL *curl;
};

class Curl_slist_guard {
    Curl_slist_guard(const Curl_slist_guard&) = delete;
    Curl_slist_guard& operator=(const Curl_slist_guard&) = delete;

public:
    Curl_slist_guard(curl_slist *list)
        : list(list)
    {}
    ~Curl_slist_guard() {
        if (list != nullptr)
            curl_slist_free_all(list);
    }

private:
    curl_slist *list;
};

size_t write_response_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    *(str::stream*)userdata << std::string(ptr, nmemb);
    return nmemb;
}

CURLcode setup_curl_options(CURL *curl) {
    CURLcode curl_res = CURLE_OK;
    (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L)) != CURLE_OK ||
    (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) != CURLE_OK ||
    (!encryptionGlobalParams.vaultServerCAFile.empty() &&
        (curl_res = curl_easy_setopt(curl, CURLOPT_CAINFO, encryptionGlobalParams.vaultServerCAFile.c_str())) != CURLE_OK
    ) ||
    (curl_res = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL)) != CURLE_OK ||
    (curl_res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, encryptionGlobalParams.vaultTimeout)) != CURLE_OK ||
    (curl_res = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, encryptionGlobalParams.vaultTimeout)) != CURLE_OK;
    return curl_res;
}

void throw_CURL_error(CURLcode curl_res, const char curl_errbuf[], const char* msg) {
    str::stream ss;
    ss << msg << "; CURL error code: " << curl_res << "; CURL error message: ";
    if (curl_errbuf[0])
        ss << curl_errbuf;
    else
        ss << curl_easy_strerror(curl_res);
    throw std::runtime_error(ss);
}

std::uint64_t parse_version(const BSONElement& version, const char* elem_path) {
    auto message = [elem_path](const char* reason) {
        std::ostringstream msg;
        msg << "Ivalid Vault response: '" << elem_path << "'' " << reason
            << ". Please make sure the secret is stored in the engine of the `kv-v2` type.";
        return msg.str();
    };
    if (version.eoo()) {
        throw std::runtime_error(message("is missing"));
    }
    long long v = version.type() == mongo::NumberInt || version.type() == mongo::NumberLong
        ? version.numberLong()
        : throw std::runtime_error(message("is not an integer"));
    return v > 0 ? static_cast<std::uint64_t>(v)
                 : throw std::runtime_error(message("does not have a positive value"));
}

} // namespace

std::pair<std::string, std::uint64_t> vaultReadKey(const std::string& secretPath,
                                                   std::uint64_t secretVersion) {
    char curl_errbuf[CURL_ERROR_SIZE]{0}; // should be available until curl_easy_cleanup
    long http_code{0};
    long verifyresult{0};
    CURLGuard guard;
    guard.initialize();

    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error(str::stream()
                                 << "Cannot initialize curl session");
    }
    Curl_session_guard curl_session_guard(curl);

    CURLcode curl_res = CURLE_OK;
    str::stream response;

    SecureString xVaultTokenHeader("X-Vault-Token: ");
    xVaultTokenHeader->append(
        !encryptionGlobalParams.vaultToken.empty()
        ? encryptionGlobalParams.vaultToken
        : static_cast<std::string_view>(*readFileToSecureString(encryptionGlobalParams.vaultTokenFile,
                                                                "Vault token")));

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, xVaultTokenHeader->c_str());
    Curl_slist_guard curl_slist_guard(headers);

    auto url_query = [](std::uint64_t version) {
        return version > 0 ? std::string(str::stream() << "?version=" << version) : std::string();
    };

    if ((curl_res = setup_curl_options(curl)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&response))) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_URL,
                                     std::string(str::stream()
                                     << (encryptionGlobalParams.vaultDisableTLS ? "http://" : "https://")
                                     << encryptionGlobalParams.vaultServerName
                                     << ':'       << encryptionGlobalParams.vaultPort
                                     << "/v1/"    << secretPath
                                     << url_query(secretVersion)).c_str())) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers)) != CURLE_OK ||
        (curl_res = curl_easy_perform(curl)) != CURLE_OK ||
        (curl_res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code)) != CURLE_OK ||
        (curl_res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verifyresult)) != CURLE_OK) {
        throw_CURL_error(curl_res, curl_errbuf, "Error reading key from the Vault");
    }

    // verify result 0 means success
    // log() << "SSL verifyresult is " << verifyresult;
    // response may contain encryption key
    // log() << std::string(response);
    LOGV2_DEBUG(29031, 4, "HTTP code (GET): {code}", "code"_attr = http_code);
    if (http_code == 404) {
        // requested value does not exist - return empty string
        return {std::string(), 0};
    }
    if (http_code / 100 != 2) {
        // not success - throw error
        throw std::runtime_error(str::stream()
                                 << "Error reading key from the Vault; HTTP code: "
                                 << http_code);
    }
    BSONObj bson = fromjson(response);
    BSONElement data1 = bson["data"];
    if (data1.eoo() || !data1.isABSONObj()) {
        throw std::runtime_error("Error parsing Vault response");
    }
    BSONElement metadata = data1.Obj()["metadata"];
    if (metadata.eoo() || metadata.type() != BSONType::Object) {
        throw std::runtime_error(
            "Invalid Vault response: 'data.metadata' is "
            "missing or is not an object.");
    }
    std::uint64_t versionGot = parse_version(metadata.Obj()["version"], "data.metadata.version");
    if (secretVersion > 0 && versionGot != secretVersion) {
        throw std::runtime_error(str::stream()
                                 << "Invalid Vault response: requested the key of version "
                                 << secretVersion << " but got version " << versionGot);
    }
    BSONElement data2 = data1.Obj()["data"];
    if (data2.eoo() || !data2.isABSONObj()) {
        throw std::runtime_error("Error parsing Vault response");
    }
    BSONElement value = data2.Obj()["value"];
    if (value.eoo() || value.type() != mongo::String) {
        throw std::runtime_error("Error parsing Vault response");
    }
    return {value.String(), versionGot};
}

std::uint64_t vaultWriteKey(const std::string& secretPath, std::string const& key) {
    char curl_errbuf[CURL_ERROR_SIZE]{0}; // should be available until curl_easy_cleanup
    long http_code{0};
    CURLGuard guard;
    guard.initialize();

    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error(str::stream()
                                 << "Cannot initialize curl session");
    }
    Curl_session_guard curl_session_guard(curl);

    CURLcode curl_res = CURLE_OK;
    str::stream response;

    SecureString xVaultTokenHeader("X-Vault-Token: ");
    xVaultTokenHeader->append(
        !encryptionGlobalParams.vaultToken.empty()
        ? encryptionGlobalParams.vaultToken
        : static_cast<std::string_view>(*readFileToSecureString(encryptionGlobalParams.vaultTokenFile,
                                                                "Vault token")));

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, xVaultTokenHeader->c_str());
    Curl_slist_guard curl_slist_guard(headers);

    std::string urlstr = std::string(str::stream()
                                     << (encryptionGlobalParams.vaultDisableTLS ? "http://" : "https://")
                                     << encryptionGlobalParams.vaultServerName
                                     << ':'       << encryptionGlobalParams.vaultPort
                                     << "/v1/"    << secretPath);
    std::string postdata = std::string(str::stream()
                                       << "{\"data\": "
                                       << "{\"value\": \"" << key
                                       << "\"}}");
    if ((curl_res = setup_curl_options(curl)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&response))) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_URL, urlstr.c_str())) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers)) != CURLE_OK ||
        (curl_res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str())) != CURLE_OK ||
        (curl_res = curl_easy_perform(curl)) != CURLE_OK ||
        (curl_res = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code)) != CURLE_OK) {
        throw_CURL_error(curl_res, curl_errbuf, "Error writing key to the Vault");
    }

    // log() << std::string(response);
    LOGV2_DEBUG(29032, 4, "HTTP code (POST): {code}", "code"_attr = http_code);
    if (http_code / 100 != 2) {
        // not success - throw error
        throw std::runtime_error(str::stream()
                                 << "Error writing key to the Vault; HTTP code: "
                                 << http_code);
    }

    BSONObj bson = fromjson(response);
    BSONElement data = bson["data"];
    if (data.eoo() || data.type() != BSONType::Object) {
        throw std::runtime_error("Invalid Vault response: 'data' is misssing or is not an object");
    }
    return parse_version(data.Obj()["version"], "data.version");
}

}  // namespace mongo::encryption::detail
