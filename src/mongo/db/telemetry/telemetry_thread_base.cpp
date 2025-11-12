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

#include "mongo/db/telemetry/telemetry_thread_base.h"

#include <boost/filesystem.hpp>  // IWYU pragma: keep
#include <cstddef>
#include <fmt/format.h>  // IWYU pragma: keep
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/client.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameter.h"
#include "mongo/db/service_context.h"
#include "mongo/db/auth/sasl_options.h"
#include "mongo/db/ldap_options.h"
#ifdef PERCONA_OIDC_ENABLED
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#endif
#include "mongo/db/telemetry/telemetry_parameter_gen.h"
#include "mongo/db/telemetry/telemetry_path.h"
#include "mongo/logv2/log.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/duration.h"
#include "mongo/util/time_support.h"
#include "mongo/util/version.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {

constexpr StringData kParamName = "perconaTelemetry"_sd;

constexpr StringData kFalse = "false"_sd;
constexpr StringData kTrue = "true"_sd;


// We need this flag to filter out updates from server parameter which can arrive before global
// service context is set. In other words we need to avoid asserts from getGlobalServiceContext()
bool updatesEnabled = false;

// mutex to serialize external API calls and access to updatesEnabled
Mutex mutex = MONGO_MAKE_LATCH("TelemetryThread::mutex");

const auto getTelemetryThread =
    ServiceContext::declareDecoration<std::unique_ptr<TelemetryThreadBase>>();

// start telemetry thread if it is not running
void startTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThreadBase::get(serviceContext);
    if (telemetryThread == nullptr || !telemetryThread->running()) {
        invariant(TelemetryThreadBase::create != nullptr);
        auto telemetryThread = TelemetryThreadBase::create();
        telemetryThread->go();
        TelemetryThreadBase::set(serviceContext, std::move(telemetryThread));
    }
}

// stop telemetry thread if it is running
void stopTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThreadBase::get(serviceContext);
    if (telemetryThread != nullptr) {
        telemetryThread->shutdown();
        TelemetryThreadBase::set(serviceContext, {});
    }
}

bool isOIDCEnabled() {
#ifdef PERCONA_OIDC_ENABLED
    const auto config =
        ServerParameterSet::getNodeParameterSet()
            ->getIfExists<OidcIdentityProvidersServerParameter>("oidcIdentityProviders");
    if (config) {
        return !config->_data.empty();
    }
#endif

    return false;
}

bool isLDAPAuthorizationEnabled() {
    return !ldapGlobalParams.ldapQueryTemplate->empty();
}

bool isLDAPEnabled() {
    return !ldapGlobalParams.ldapServers->empty();
}

bool isAuthenticationMechanismEnabled(const std::string& mechanismName) {
    return std::find(saslGlobalParams.authenticationMechanisms.begin(),
                     saslGlobalParams.authenticationMechanisms.end(),
                     mechanismName) != saslGlobalParams.authenticationMechanisms.end();
}

bool isLDAPSaslAuthenticationEnabled() {
    return isAuthenticationMechanismEnabled("PLAIN");
}

bool isKerberosAuthenticationEnabled() {
    return isAuthenticationMechanismEnabled("GSSAPI");
}

bool isX509AuthenticationEnabled() {
    return isAuthenticationMechanismEnabled("MONGODB-X509");
}

}  // namespace


TelemetryThreadBase::TelemetryThreadBase()
    : BackgroundJob(false /* selfDelete */),
      _nextScrape(Date_t::now() + Seconds(perconaTelemetryGracePeriod)),
      _mutex(MONGO_MAKE_LATCH("TelemetryThread::_mutex")) {}

TelemetryThreadBase* TelemetryThreadBase::get(ServiceContext* serviceCtx) {
    return getTelemetryThread(serviceCtx).get();
}

void TelemetryThreadBase::set(ServiceContext* serviceCtx,
                              std::unique_ptr<TelemetryThreadBase> newTelemetryThread) {
    auto& telemetryThread = getTelemetryThread(serviceCtx);
    if (telemetryThread) {
        invariant(
            !telemetryThread->running(),
            "Tried to reset the TelemetryThread without shutting down the previous instance.");
    }

    telemetryThread = std::move(newTelemetryThread);
}

void TelemetryThreadBase::run() {
    const ThreadClient tc(name(), getGlobalServiceContext()->getService());
    LOGV2_DEBUG(29121, 1, "starting {name} thread", "name"_attr = name());

    if (auto status = _initParameters(tc->getServiceContext()); !status.isOK()) {
        LOGV2_ERROR(29133,
                    "Telemetry thread failed to initialize. Telemetry will be stopped",
                    "status"_attr = status);
        _shuttingDown.store(true);
    }

    while (!_shuttingDown.load()) {
        if (Date_t::now() >= _nextScrape) {
            // cleanup telemetry dir
            if (auto status = _cleanupTelemetryDir(); !status.isOK()) {
                LOGV2_WARNING(29132,
                              "Telemetry thread failed to cleanup telemetry directory ",
                              "status"_attr = status);
            }
            auto* serviceCtx = tc->getServiceContext();
            // create metrics file
            if (auto status = _writeMetrics(serviceCtx); !status.isOK()) {
                LOGV2_WARNING(
                    29131, "Telemetry thread failed to write metric file", "status"_attr = status);
            }
            // update nextScrape
            if (auto status = _advance(serviceCtx); !status.isOK()) {
                LOGV2_ERROR(29128,
                            "Telemetry thread failed to schedule the next telemetry scrape and "
                            "will be stopped",
                            "status"_attr = status);
                _shuttingDown.store(true);
                continue;
            }
        }

        {
            stdx::unique_lock<Latch> lock(_mutex);
            MONGO_IDLE_THREAD_BLOCK;
            _condvar.wait_until(lock, _nextScrape.toSystemTimePoint());
        }
    }
    LOGV2_DEBUG(29122, 1, "stopping {name} thread", "name"_attr = name());
}

void TelemetryThreadBase::shutdown() {
    _shuttingDown.store(true);
    {
        stdx::unique_lock<Latch> lock(_mutex);
        // Wake up the telemetry thread early, we do not want the shutdown
        // to wait for us too long.
        _condvar.notify_one();
    }
    wait();
}

// auxiliary function
boost::filesystem::path TelemetryThreadBase::sdPath(StringData sd) {
    return {sd.rawData(), sd.rawData() + sd.size()};  // NOLINT(*-pointer-arithmetic)
}

// auxiliary function
StringData TelemetryThreadBase::boolName(bool v) {
    return v ? kTrue : kFalse;
}

Status TelemetryThreadBase::_initParameters(ServiceContext* serviceContext) try {
    BSONObjBuilder pfx;
    pfx.append(kSource, _sourceName());
    {
        const auto& vii = VersionInfoInterface::instance();
        pfx.append(kPillarVersion, vii.version());
        pfx.append(kPerconaFeatures, vii.perconaFeatures());
    }

    // on first start both instance Id and internal Id are initialized to the same value
    // after some events like backup/restore, dbpath change or cleanup those two Ids may become
    // not equal --> this is intended behavior
    auto initialId = OID::gen();

    // load/create instance id
    if (auto status = _initInstanceId(initialId); !status.isOK()) {
        return status;
    }
    pfx.append(kDbInstanceId, _instid.toString());
    LOGV2_DEBUG(29123,
                1,
                "Initialized telemetry instance id: {db_instance_id}",
                "db_instance_id"_attr = _instid.toString());

    // init unique metric file suffix
    // must go after instance id initialization
    if (_metricFileSuffix.empty()) {
        _metricFileSuffix = _instid.toString();
    }

    // operation context is necessary for following operations
    auto opCtxObj = cc().makeOperationContext();
    auto* opCtx = opCtxObj.get();

    // load/create db id
    if (auto status = _initDbId(serviceContext, opCtx, initialId); !status.isOK()) {
        return status;
    }
    if (_dbid.isSet()) {
        pfx.append(kDbInternalId, _dbid.toString());
    }

    pfx.append(kOIDCEnabled, boolName(isOIDCEnabled()));
    pfx.append(kLDAPEnabled, boolName(isLDAPEnabled()));
    pfx.append(kLDAPAuthorizationEnabled, boolName(isLDAPAuthorizationEnabled()));
    pfx.append(kLDAPSaslAuthenticationEnabled, boolName(isLDAPSaslAuthenticationEnabled()));
    pfx.append(kKerberosAuthenticationEnabled, boolName(isKerberosAuthenticationEnabled()));
    pfx.append(kX509AuthenticationEnabled, boolName(isX509AuthenticationEnabled()));

    _prefix = pfx.obj();

    return Status::OK();
} catch (...) {
    return exceptionToStatus();
}

// advance nextScrape and store it into kTelemetryCollection
Status TelemetryThreadBase::_advance(ServiceContext* serviceContext) try {
    _nextScrape = Date_t::now() + Seconds(perconaTelemetryScrapeInterval);
    return _advancePersist(serviceContext);
} catch (...) {
    return exceptionToStatus();
}

// cleanup telemetry directory
Status TelemetryThreadBase::_cleanupTelemetryDir() try {
    namespace fs = boost::filesystem;
    const auto ts = Date_t::now().toMillisSinceEpoch() / 1000;
    const auto telePath = sdPath(getTelemetryPath());
    // We do not create any directories
    if (!fs::is_directory(telePath)) {
        return {ErrorCodes::NonExistentPath,
                fmt::format("telemetry directory doesn't exist or isn't a directory: {}",
                            getTelemetryPath())};
    }

    // clear outdated files
    auto suffix = fmt::format("-{}.json", _metricFileSuffix);
    const std::string jsonExt(".json");
    constexpr int perconaTelemetryHistoryOrphan = 60 * 60 * 24 * 7;
    for (auto const& dirEntry : fs::directory_iterator{telePath}) {
        if (fs::is_regular_file(dirEntry.status())) {
            auto s = dirEntry.path().filename().string();
            try {
                std::size_t pos = 0;
                const auto filets = std::stoll(s, &pos);
                if ((filets < ts - perconaTelemetryHistoryKeepInterval &&
                     s.substr(pos) == suffix) ||
                    (filets < ts - perconaTelemetryHistoryOrphan && s.ends_with(jsonExt))) {
                    fs::remove(dirEntry.path());
                }
            } catch (std::invalid_argument const&) {  // NOLINT(*-empty-catch)
                // possible exception from std::stoll
                // means file name does not match pattern of valid metrics file name
            } catch (std::out_of_range const&) {  // NOLINT(*-empty-catch)
                // possible exception from std::stoll
                // means file name does not match pattern of valid metrics file name
            } catch (const fs::filesystem_error& e) {
                LOGV2_DEBUG(29130,
                            1,
                            "Error removing file {file}: {errmsg}",
                            "file"_attr = dirEntry.path().string(),
                            "errmsg"_attr = e.what());
            }
        }
    }
    return Status::OK();
} catch (...) {
    return exceptionToStatus();
}

// write metrics file
Status TelemetryThreadBase::_writeMetrics(ServiceContext* serviceContext) try {
    namespace fs = boost::filesystem;
    const auto ts = Date_t::now().toMillisSinceEpoch() / 1000;
    const auto telePath = sdPath(getTelemetryPath());

    // dump new metrics file
    const auto tmpName = telePath / fmt::format("{}-{}.tmp", ts, _metricFileSuffix);
    LOGV2_DEBUG(29129, 1, "writing metrics file {path}", "path"_attr = tmpName.string());
    BSONObjBuilder builder(_prefix);

    builder.append(kUptime, std::to_string(time(nullptr) - serverGlobalParams.started));

    _appendMetrics(serviceContext, &builder);

    auto obj = builder.done();  // obj becomes invalid when builder goes out of scope
    std::ofstream ofs(tmpName);
    ofs << obj.jsonString(ExtendedCanonicalV2_0_0, 1 /* pretty */) << "\n";
    ofs.close();
    // set file permissions tp 660 to allow telemetry agent access
    fs::permissions(tmpName, fs::owner_read | fs::owner_write | fs::group_read | fs::group_write);
    fs::rename(tmpName, telePath / fmt::format("{}-{}.json", ts, _metricFileSuffix));
    return Status::OK();
} catch (...) {
    return exceptionToStatus();
}


std::unique_ptr<TelemetryThreadBase> (*TelemetryThreadBase::create)(){nullptr};
std::string TelemetryThreadBase::_metricFileSuffix;


void initPerconaTelemetryInternal(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    //  enable updates from server parameter
    updatesEnabled = true;
    // only create if telemetry is enabled
    if (ServerParameterSet::getNodeParameterSet()
            ->get<TelemetryParameter>(kParamName)
            ->_data.load()) {
        startTelemetryThread_inlock(serviceContext);
    }
}

void shutdownPerconaTelemetry(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    // we do not allow any updates during shutdown
    updatesEnabled = false;
    stopTelemetryThread_inlock(serviceContext);
}

void updatePerconaTelemetry(bool state) {
    stdx::unique_lock<Latch> lock(mutex);
    if (updatesEnabled) {
        if (state) {
            startTelemetryThread_inlock(getGlobalServiceContext());
        } else {
            stopTelemetryThread_inlock(getGlobalServiceContext());
        }
    }
}

}  // namespace mongo
