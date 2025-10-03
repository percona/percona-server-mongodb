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

#include "mongo/util/net/http_client.h"
#include "mongo/util/net/http_client_mock.h"

#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"

#include "mongo/db/encryption/vault_client.h"

namespace mongo::encryption {
namespace {

class MockHttpClientProviderImpl : public HttpClientProvider {
public:
    MockHttpClientProviderImpl() : _mockHttpClient(nullptr) {
        registerHTTPClientProvider(this);
    }

    std::unique_ptr<HttpClient> create() override {
        ASSERT(_mockHttpClient);
        return std::move(_mockHttpClient);
    }

    std::unique_ptr<HttpClient> createWithoutConnectionPool() override {
        ASSERT(_mockHttpClient);
        return std::move(_mockHttpClient);
    }

    std::unique_ptr<HttpClient> createWithFirewall(const std::vector<CIDR>& cidrDenyList) override {
        ASSERT(_mockHttpClient);
        return std::move(_mockHttpClient);
    }

    BSONObj getServerStatus() override {
        return BSONObj();
    }

    void setMock(std::unique_ptr<HttpClient> mock) {
        _mockHttpClient = std::move(mock);
    }

private:
    std::unique_ptr<HttpClient> _mockHttpClient;
} mockHttpClientProvider;

class VaultClientTest : public unittest::Test {
protected:
    VaultClient createClientWithToken(std::string token) {
        return VaultClient(std::string{kTestHost}, kTestPort, token, "", "", false, true, 1000);
    }

    VaultClient createClient() {
        return createClientWithToken("");
    }

    void setMockHttpClient(std::unique_ptr<HttpClient> mock) {
        mockHttpClientProvider.setMock(std::move(mock));
    }

    static constexpr auto kTestHost = "vault.example"_sd;
    static constexpr auto kTestPort = 8200;
    static constexpr auto kOpenAPISpecEndpoint = "sys/internal/specs/openapi"_sd;

    static std::string getOpenAPISpecUrl(StringData host, int port, bool useTLS = false) {
        return fmt::format(
            "{}://{}:{}/v1/{}", useTLS ? "https" : "http", host, port, kOpenAPISpecEndpoint);
    }
};


TEST_F(VaultClientTest, OpenAPISpec_EmptyResponse) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};
    const MockHttpClient::Response response{200, {}, ""};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    VaultClient client(std::string{kTestHost}, kTestPort, "", "", "", false, true, 1000);

    const auto status = client.getOpenAPISpec();
    ASSERT_OK(status);
    ASSERT_BSONOBJ_EQ(status.getValue(), BSONObj());
}

TEST_F(VaultClientTest, OpenAPISpec_ValidResponse) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};
    const MockHttpClient::Response response{200, {}, R"json({
            "openapi": "3.0.0",
            "info": {
               "title": "Vault API",
               "version": "1.0.0"
            }
        })json"};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    VaultClient client = createClient();

    const auto status = client.getOpenAPISpec();
    ASSERT_OK(status);

    const auto spec = status.getValue();
    ASSERT_TRUE(spec.hasField("openapi"));
    ASSERT_EQ(spec.getField("openapi").String(), "3.0.0");

    ASSERT_TRUE(spec.hasField("info"));
    const auto info = spec.getField("info").Obj();

    ASSERT_TRUE(info.hasField("title"));
    ASSERT_EQ(info.getField("title").String(), "Vault API");

    ASSERT_TRUE(info.hasField("version"));
    ASSERT_EQ(info.getField("version").String(), "1.0.0");
}

TEST_F(VaultClientTest, OpenAPISpec_ResponseWithRef) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};

    const MockHttpClient::Response response{200, {}, R"json({
            "openapi": "3.0.0",
            "info": {
               "title": "Vault API",
               "version": "1.0.0"
            },
            "paths": {
               "/some/path": {
                  "schema": {
                     "$ref": "#/components/schemas/SomeSchema"
                  }
               }
            }
        })json"};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    VaultClient client = createClient();

    const auto status = client.getOpenAPISpec();
    ASSERT_OK(status);

    const auto spec = status.getValue();

    ASSERT_TRUE(spec.hasField("openapi"));
    ASSERT_EQ(spec.getField("openapi").String(), "3.0.0");

    ASSERT_TRUE(spec.hasField("info"));
    const auto info = spec.getField("info").Obj();

    ASSERT_TRUE(info.hasField("title"));
    ASSERT_EQ(info.getField("title").String(), "Vault API");

    ASSERT_TRUE(info.hasField("version"));
    ASSERT_EQ(info.getField("version").String(), "1.0.0");

    ASSERT_TRUE(spec.hasField("paths"));
    const auto paths = spec.getField("paths").Obj();

    ASSERT_TRUE(paths.hasField("/some/path"));
    const auto somePath = paths.getField("/some/path").Obj();

    ASSERT_TRUE(somePath.hasField("schema"));
    const auto schema = somePath.getField("schema").Obj();

    // The '$ref' shall be replaced with '_ref'
    ASSERT_TRUE(schema.hasField("_ref"));
    const auto ref = schema.getField("_ref").String();
    ASSERT_EQ(ref, "#/components/schemas/SomeSchema");
}

TEST_F(VaultClientTest, OpenAPISpec_ErrorResponse) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};
    const MockHttpClient::Response response{400, {}, ""};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    VaultClient client = createClient();

    const auto status = client.getOpenAPISpec();
    ASSERT_NOT_OK(status);
    ASSERT_EQ(status.getStatus(), ErrorCodes::OperationFailed);
}

TEST_F(VaultClientTest, OpenAPISpec_InvalidResponse) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};

    // Response with an invalid json - missing '}' for the 'info' object
    const MockHttpClient::Response response{200, {}, R"json({
            "openapi": "3.0.0",
            "info": {
               "title": "Vault API",
               "version": "1.0.0"
        })json"};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    VaultClient client = createClient();

    const auto status = client.getOpenAPISpec();
    ASSERT_NOT_OK(status);
    ASSERT_EQ(status.getStatus(), ErrorCodes::OperationFailed);
}

TEST_F(VaultClientTest, OpenAPISpec_ValidResponseWithToken) {
    auto mock = std::make_unique<MockHttpClient>();
    const MockHttpClient::Request request{HttpClient::HttpMethod::kGET,
                                          getOpenAPISpecUrl(kTestHost, kTestPort)};
    const MockHttpClient::Response response{200, {}, R"json({
            "openapi": "3.0.0",
            "info": {
               "title": "Vault API",
               "version": "1.0.0"
            }
        })json"};

    mock->expect(request, response);

    setMockHttpClient(std::move(mock));

    // Set some test token. Unfortunately, there is no way to add an expectation for the headers
    // so just make sure the path when using token is also covered.
    VaultClient client = createClientWithToken("test_token");

    const auto status = client.getOpenAPISpec();
    ASSERT_OK(status);

    const auto spec = status.getValue();
    ASSERT_TRUE(spec.hasField("openapi"));
    ASSERT_EQ(spec.getField("openapi").String(), "3.0.0");

    ASSERT_TRUE(spec.hasField("info"));
    const auto info = spec.getField("info").Obj();

    ASSERT_TRUE(info.hasField("title"));
    ASSERT_EQ(info.getField("title").String(), "Vault API");

    ASSERT_TRUE(info.hasField("version"));
    ASSERT_EQ(info.getField("version").String(), "1.0.0");
}

}  // namespace
}  // namespace mongo::encryption
