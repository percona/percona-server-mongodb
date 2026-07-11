/**
 *    Copyright (C) 2025-present MongoDB, Inc.
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

#include "mongo/otel/traces/tracer_provider_service.h"

#include "mongo/util/static_immortal.h"

#include <chrono>
#include <utility>

namespace mongo::otel::traces {
namespace {

std::unique_ptr<TracerProviderService>& globalTracerProviderService() {
    static StaticImmortal<std::unique_ptr<TracerProviderService>> instance;
    return *instance;
}

}  // namespace

TracerProviderService* getGlobalTracerProviderService() {
    return globalTracerProviderService().get();
}

void setGlobalTracerProviderService(std::unique_ptr<TracerProviderService> service) {
    globalTracerProviderService() = std::move(service);
}

std::unique_ptr<TracerProviderService> swapGlobalTracerProviderServiceForTest(
    std::unique_ptr<TracerProviderService> newService) {
    return std::exchange(globalTracerProviderService(), std::move(newService));
}

void TracerProviderService::shutdown() {
    if (_enabled && _tracerProvider) {
        auto tracer = _tracerProvider->GetTracer("mongodb");
        tracer->Close(std::chrono::seconds{1});
        _tracerProvider = nullptr;
        _enabled = false;
    }
}

}  // namespace mongo::otel::traces
