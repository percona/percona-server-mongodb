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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

#include "mongo/db/ldap/ldap_manager_impl.h"

#include <regex>

#include <poll.h>
#include <lber.h>

#include <fmt/format.h>
#include <sasl/sasl.h>

#include "mongo/bson/json.h"
#include "mongo/db/client.h"
#include "mongo/db/ldap_options.h"
#include "mongo/logv2/log.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/scopeguard.h"

namespace mongo {
namespace {

/* Called after a connection is established */
//typedef int (ldap_conn_add_f) LDAP_P(( LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr,
//	struct ldap_conncb *ctx ));
/* Called before a connection is closed */
//typedef void (ldap_conn_del_f) LDAP_P(( LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx ));

int cb_add(LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr,
           struct ldap_conncb *ctx );

void cb_del(LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx);

int rebindproc(LDAP* ld, const char* /* url */, ber_tag_t /* request */, ber_int_t /* msgid */, void* arg);

int cb_urllist_proc( LDAP *ld, LDAPURLDesc **urllist, LDAPURLDesc **url, void *params);

}
}

extern "C" {

struct interactionParameters {
    const char* realm;
    const char* dn;
    const char* pw;
    const char* userid;
};

static int interaction(unsigned flags, sasl_interact_t *interact, void *defaults) {
    interactionParameters *params = (interactionParameters*)defaults;
    const char *dflt = interact->defresult;

    switch (interact->id) {
    case SASL_CB_GETREALM:
        dflt = params->realm;
        break;
    case SASL_CB_AUTHNAME:
        dflt = params->dn;
        break;
    case SASL_CB_PASS:
        dflt = params->pw;
        break;
    case SASL_CB_USER:
        dflt = params->userid;
        break;
    }

    if (dflt && !*dflt)
        dflt = NULL;

    if (flags != LDAP_SASL_INTERACTIVE &&
        (dflt || interact->id == SASL_CB_USER)) {
        goto use_default;
    }

    if( flags == LDAP_SASL_QUIET ) {
        /* don't prompt */
        return LDAP_OTHER;
    }


use_default:
    interact->result = (dflt && *dflt) ? dflt : "";
    interact->len = std::strlen( (char*)interact->result );

    return LDAP_SUCCESS;
}

static int interactProc(LDAP *ld, unsigned flags, void *defaults, void *in) {
    sasl_interact_t *interact = (sasl_interact_t*)in;

    if (ld == NULL)
        return LDAP_PARAM_ERROR;

    while (interact->id != SASL_CB_LIST_END) {
        int rc = interaction( flags, interact, defaults );
        if (rc)
            return rc;
        interact++;
    }

    return LDAP_SUCCESS;
}

} // extern "C"

namespace mongo {

struct LDAPConnInfo {
    LDAP* conn;
    bool borrowed;
};


using namespace fmt::literals;

static LDAP* create_connection(void* connect_cb_arg = nullptr,
                               logv2::LogSeverity logSeverity = logv2::LogSeverity::Debug(1)) {
    LDAP* ldap;
    auto uri = ldapGlobalParams.ldapURIList();

    auto res = ldap_initialize(&ldap, uri.c_str());
    if (res != LDAP_SUCCESS) {
        LOGV2_SEVERITY(29088,
                       logSeverity,
                       "Cannot initialize LDAP structure for {uri} ; LDAP error: {err}",
                       "uri"_attr = uri,
                       "err"_attr = ldap_err2string(res));
        return nullptr;
    }

    if (!ldapGlobalParams.ldapFollowReferrals.load()) {
        LOGV2_DEBUG(29086, 2, "Disabling referrals");
        res = ldap_set_option(ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
        if (res != LDAP_OPT_SUCCESS) {
            LOGV2_SEVERITY(29089,
                           logSeverity,
                           "Cannot disable LDAP referrals; LDAP error: {err}",
                           "err"_attr = ldap_err2string(res));
            return nullptr;
        }
    }

    res = ldap_set_urllist_proc(ldap, cb_urllist_proc, nullptr);
    if (res != LDAP_OPT_SUCCESS) {
        LOGV2_SEVERITY(29089,
                       logSeverity,
                       "Cannot set LDAP URLlist callback procedure",
                       "err"_attr = ldap_err2string(res));
        return nullptr;
    }

    if (connect_cb_arg) {
        static ldap_conncb conncb;
        conncb.lc_add = cb_add;
        conncb.lc_del = cb_del;
        conncb.lc_arg = connect_cb_arg;
        res = ldap_set_option(ldap, LDAP_OPT_CONNECT_CB, &conncb);
        if (res != LDAP_OPT_SUCCESS) {
            LOGV2_SEVERITY(29089,
                           logSeverity,
                           "Cannot set LDAP connection callbacks; LDAP error: {err}",
                           "err"_attr = ldap_err2string(res));
            return nullptr;
        }
    }

    return ldap;
}

class LDAPManagerImpl::ConnectionPoller : public BackgroundJob {
public:
    ConnectionPoller(LDAPManagerImpl* manager)
        : _manager(manager) {}

    virtual std::string name() const override {
        return "LDAPConnectionPoller";
    }

    virtual void run() override {
        ThreadClient tc(name(), getGlobalServiceContext());
        LOGV2_DEBUG(29061, 1, "starting thread", "name"_attr = name());

        // poller thread will handle disconnection events
        while (!_shuttingDown.load()) {
            MONGO_IDLE_THREAD_BLOCK;
            std::vector<pollfd> fds;
            {
                stdx::unique_lock<Latch> lock{_mutex};
                _condvar.wait(lock, [this] { return !_poll_fds.empty() || _shuttingDown.load(); });

                fds.reserve(_poll_fds.size());
                for(auto fd: _poll_fds) {
                  if(fd.first < 0) continue;
                  pollfd pfd;
                  pfd.events = POLLPRI | POLLRDHUP;
                  pfd.revents = 0;
                  pfd.fd = fd.first;
                  fds.push_back(pfd);
                }
            }
            // if there are no descriptors that means server is shutting down
            if (fds.empty())
                continue;

            static const int poll_timeout = 1000; // milliseconds
            int poll_ret = poll(fds.data(), fds.size(), poll_timeout);
            if (poll_ret != 0) {
              LOGV2_DEBUG(29063, 2, "poll() return value is", "retval"_attr = poll_ret);
            }
            if (poll_ret < 0) {
                char const* errname = "<something unexpected>";
                switch (errno) {
                case EFAULT: errname = "EFAULT"; break;
                case EINTR: errname = "EINTR"; break;
                case EINVAL: errname = "EINVAL"; break;
                case ENOMEM: errname = "ENOMEM"; break;
                }
                LOGV2_DEBUG(29064, 2, "poll() error name", "errname"_attr = errname);
                //restart all LDAP connections... but why?
                {
                    stdx::unique_lock<Latch> lock{_mutex};
                    if(!_poll_fds.empty()) {
                        _poll_fds.clear();
                        //_manager->needReinit();
                    }
                }
            } else if (poll_ret > 0) {
                static struct {
                    int v;
                    char const* name;
                } flags[] = {
                    {POLLIN, "POLLIN"},
                    {POLLPRI, "POLLPRI"},
                    {POLLOUT, "POLLOUT"},
                    {POLLRDHUP, "POLLRDHUP"},
                    {POLLERR, "POLLERR"},
                    {POLLHUP, "POLLHUP"},
                    {POLLNVAL, "POLLNVAL"}
                };
                if (shouldLog(logv2::LogSeverity::Debug(2))) {
                    for (auto const& f: flags) {
                        for (auto const& fd: fds) {
                            if (fd.revents & f.v) {
                              LOGV2_DEBUG(29065, 2, "poll(): {event} event registered for {fd}", "event"_attr = f.name, "fd"_attr = fd.fd);
                            }
                        }
                    }
                }
                for (auto const& fd: fds) {
                    if (fd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
                        // need to restart LDAP connection
                        stdx::unique_lock<Latch> lock{_mutex};
                        if(_poll_fds[fd.fd].conn) {
                          ldap_unbind_ext(_poll_fds[fd.fd].conn, nullptr, nullptr);
                        }
                        _poll_fds.erase(fd.fd);
                        //_manager->needReinit();
                    }
                }
            }
        }
        LOGV2_DEBUG(29066, 1, "stopping thread", "name"_attr = name());
    }

    void start_poll(LDAP* ldap, int fd) {
        bool changed = false;
        {
            stdx::unique_lock<Latch> lock{_mutex};
            auto it = _poll_fds.find(fd);
            if(it == _poll_fds.end()) {
                _poll_fds.insert({fd, {ldap, true}});
                changed = true;
            }
        }
        if (changed) {
            _condvar.notify_one();
        }
    }
    void shutdown() {
        _shuttingDown.store(true);
        _condvar.notify_one();
        wait();
    }

    // requires holding _mutex
    LDAPConnInfo* find_free_slot() {
        for (auto& fd : _poll_fds) {
            if (!fd.second.borrowed) {
                return &fd.second;
            }
        }
        return nullptr;
    }

    LDAP* borrow_or_create() {
        {
            stdx::unique_lock<Latch> lock{_mutex};
            auto slot = find_free_slot();
            if (slot != nullptr) {
                slot->borrowed = true;
                return slot->conn;
            }

            if(static_cast<unsigned>(ldapGlobalParams.ldapConnectionPoolSizePerHost.load())
                    < _poll_fds.size()) {
                // pool is full, wait until we have a free slot
                _condvar_pool.wait(lock, [this]{ return find_free_slot() || _shuttingDown.load();});

                auto slot = find_free_slot();
                if (slot != nullptr) {
                    slot->borrowed = true;
                    return slot->conn;
                }

                // shutting down
                return nullptr;
            }
        }
        // no available connection, pool has space => create one
        // _poll_fds will be registered in the callback
        return create_connection(this);
    }

    void return_ldap_connection(LDAP* ldap) {
        bool found = false;
        {
            stdx::unique_lock<Latch> lock{_mutex};
            auto it = std::find_if(_poll_fds.begin(), _poll_fds.end(), [&](auto const& e) {
                return e.second.conn == ldap;
            });
            if (it != _poll_fds.end()) {
                it->second.borrowed = false;
                found = true;
            }
        }
        if (found) {
            _condvar_pool.notify_one();
        }
    }

private:
    std::map<int, LDAPConnInfo> _poll_fds;
    LDAPManagerImpl* _manager;
    AtomicWord<bool> _shuttingDown{false};
    // _mutex works in pair with _condvar and also protects _poll_fds
    Mutex _mutex = MONGO_MAKE_LATCH("LDAPUserCacheInvalidator::_mutex");
    stdx::condition_variable _condvar;
    stdx::condition_variable _condvar_pool;
};

namespace {

/* Called after a connection is established */
//typedef int (ldap_conn_add_f) LDAP_P(( LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr,
//	struct ldap_conncb *ctx ));
/* Called before a connection is closed */
//typedef void (ldap_conn_del_f) LDAP_P(( LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx ));

int cb_add(LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr,
           struct ldap_conncb *ctx ) {
    int fd = -1;
    ldap_get_option(ld, LDAP_OPT_DESC, &fd);
    LOGV2_DEBUG(29069, 2, "LDAP connect callback; file descriptor: {fd}", "fd"_attr = fd);
    static_cast<LDAPManagerImpl::ConnectionPoller*>(ctx->lc_arg)->start_poll(ld, fd);
    return LDAP_SUCCESS;
}

void cb_del(LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx) {
    LOGV2_DEBUG(29070, 2, "LDAP disconnect callback");
}

void cb_log(LDAP_CONST char* data) {
  LOGV2_DEBUG(29090, 2, "(LDAP debugging)", "msg"_attr = data);
}

int rebindproc(LDAP* ld, const char* /* url */, ber_tag_t /* request */, ber_int_t /* msgid */, void* arg) {

    const auto user = ldapGlobalParams.ldapQueryUser.get();
    const auto password = ldapGlobalParams.ldapQueryPassword.get();

    berval cred;
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = password.size();

    if (ldapGlobalParams.ldapBindMethod == "simple") {
        return ldap_sasl_bind_s(ld, const_cast<char*>(user.c_str()), LDAP_SASL_SIMPLE, &cred,
                                nullptr, nullptr, nullptr);
    } else if (ldapGlobalParams.ldapBindMethod == "sasl") {
        interactionParameters params;
        params.userid = const_cast<char*>(user.c_str());
        params.dn = const_cast<char*>(user.c_str());
        params.pw = const_cast<char*>(password.c_str());
        params.realm = nullptr;
        return ldap_sasl_interactive_bind_s(
                                            ld,
                                            nullptr,
                                            ldapGlobalParams.ldapBindSaslMechanisms.c_str(),
                                            nullptr,
                                            nullptr,
                                            LDAP_SASL_QUIET,
                                            interactProc,
                                            &params);
    } else {
      return LDAP_INAPPROPRIATE_AUTH;
    }
}

// example of this callback is in the OpenLDAP's
// servers/slapd/back-meta/bind.c (meta_back_default_urllist)
int cb_urllist_proc( LDAP *ld, LDAPURLDesc **urllist, LDAPURLDesc **url, void *params) {
    if (urllist == url)
        return LDAP_SUCCESS;

    LDAPURLDesc **urltail;
    for ( urltail = &(*url)->lud_next; *urltail; urltail = &(*urltail)->lud_next )
        /* count */ ;

    // all failed hosts go to the end of list
    *urltail = *urllist;
    // succeeded host becomes first
    *urllist = *url;
    // mark end of list
    *url = nullptr;

    return LDAP_SUCCESS;
}

}



LDAPManagerImpl::LDAPManagerImpl() = default;

LDAPManagerImpl::~LDAPManagerImpl() {
    if (_connPoller) {
        //log() << "Shutting down LDAP connection poller thread";
        _connPoller->shutdown();
        //log() << "Finished shutting down LDAP connection poller thread";
    }
}

void LDAPManagerImpl::return_search_connection(LDAP* ldap) {
  _connPoller->return_ldap_connection(ldap);
}

Status LDAPManagerImpl::initialize() {

    const int ldap_version = LDAP_VERSION3;
    int res = LDAP_OTHER;

    LOGV2_DEBUG(29084, 1, "Adjusting global LDAP settings");

    res = ldap_set_option(nullptr, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (res != LDAP_OPT_SUCCESS) {
        LOGV2_DEBUG(29089,
                    1,
                    "Cannot set LDAP version; LDAP error: {err}",
                    "err"_attr = ldap_err2string(res));
    }

    if (ldapGlobalParams.ldapDebug.load()) {
        static const unsigned short debug_any = 0xffff;
        res = ldap_set_option(nullptr, LDAP_OPT_DEBUG_LEVEL, &debug_any);
        if (res != LDAP_OPT_SUCCESS) {
            LOGV2_DEBUG(29089,
                        1,
                        "Cannot set LDAP log level; LDAP error: {err}",
                        "err"_attr = ldap_err2string(res));
        }
        ber_set_option(nullptr, LBER_OPT_LOG_PRINT_FN, reinterpret_cast<const void*>(cb_log));
    }

    return Status::OK();
}

// Cannot start threads from initialize() because initialize()
// is executed when thread starting is prohibited
void LDAPManagerImpl::start_threads() {
    if (!_connPoller) {
        _connPoller = std::make_unique<ConnectionPoller>(this);
        _connPoller->go();
    }
}

LDAP* LDAPManagerImpl::borrow_search_connection() {

    auto ldap = _connPoller->borrow_or_create();

    if(!ldap) {
      return ldap;
    }

    auto ret = LDAPbind(ldap,
                    ldapGlobalParams.ldapQueryUser.get(),
                    ldapGlobalParams.ldapQueryPassword.get());

    return ldap;
}

static void init_ldap_timeout(timeval* tv) {
    auto timeout = ldapGlobalParams.ldapTimeoutMS.load();
    tv->tv_sec = timeout / 1000;
    tv->tv_usec = (timeout % 1000) * 1000;
}

Status LDAPManagerImpl::execQuery(std::string& ldapurl, std::vector<std::string>& results) {

    auto ldap = borrow_search_connection();

    if(!ldap) {
        return Status(ErrorCodes::LDAPLibraryError,
                      "Failed to get an LDAP connection from the pool.");
    }

    timeval tv;
    init_ldap_timeout(&tv); // use ldapTimeoutMS
    LDAPMessage*answer = nullptr;
    LDAPURLDesc *ludp{nullptr};
    int res = ldap_url_parse(ldapurl.c_str(), &ludp);
    ON_BLOCK_EXIT([&] { ldap_free_urldesc(ludp); return_search_connection(ldap); });
    if (res != LDAP_SUCCESS) {
        return Status(ErrorCodes::LDAPLibraryError,
                      "Cannot parse LDAP URL: {}"_format(
                          ldap_err2string(res)));
    }

    // if attributes are not specified assume query returns set of entities (groups)
    const bool entitiesonly = !ludp->lud_attrs || !ludp->lud_attrs[0];

    LOGV2_DEBUG(29051, 1, "Parsing LDAP URL: {ldapurl}; dn: {dn}; scope: {scope}; filter: {filter}",
            "ldapurl"_attr = ldapurl,
            "scope"_attr = ludp->lud_scope,
            "dn"_attr = ludp->lud_dn ? ludp->lud_dn : "nullptr",
            "filter"_attr = ludp->lud_filter ? ludp->lud_filter : "nullptr");

    int retrycnt = 1;
    do {
        res = ldap_search_ext_s(ldap,
                ludp->lud_dn,
                ludp->lud_scope,
                ludp->lud_filter,
                ludp->lud_attrs,
                0, // attrsonly (0 => attrs and values)
                nullptr, nullptr, &tv, 0, &answer);
        if (res == LDAP_SUCCESS)
            break;
        if (retrycnt > 0) {
            ldap_msgfree(answer);
            LOGV2_ERROR(29072, "LDAP search failed with error",
                    "errstr"_attr = ldap_err2string(res));
            return_search_connection(ldap);
            ldap = borrow_search_connection();
            if (!ldap) {
                return Status(ErrorCodes::LDAPLibraryError,
                              "Failed to get an LDAP connection from the pool.");
            }
        }
    } while (retrycnt-- > 0);

    ON_BLOCK_EXIT([&] { ldap_msgfree(answer); });
    if (res != LDAP_SUCCESS) {
        return Status(ErrorCodes::LDAPLibraryError,
                      "LDAP search failed with error: {}"_format(
                          ldap_err2string(res)));
    }

    auto entry = ldap_first_entry(ldap, answer);
    while (entry) {
        if (entitiesonly) {
            auto dn = ldap_get_dn(ldap, entry);
            ON_BLOCK_EXIT([&] { ldap_memfree(dn); });
            if (!dn) {
                int ld_errno = 0;
                ldap_get_option(ldap, LDAP_OPT_RESULT_CODE, &ld_errno);
                return Status(ErrorCodes::LDAPLibraryError,
                              "Failed to get DN from LDAP query result: {}"_format(
                                  ldap_err2string(ld_errno)));
            }
            results.emplace_back(dn);
        } else {
            BerElement *ber = nullptr;
            auto attribute = ldap_first_attribute(ldap, entry, &ber);
            ON_BLOCK_EXIT([&] { ber_free(ber, 0); });
            while (attribute) {
                ON_BLOCK_EXIT([&] { ldap_memfree(attribute); });

                auto const values = ldap_get_values_len(ldap, entry, attribute);
                ON_BLOCK_EXIT([&] { ldap_value_free_len(values); });
                if (values) {
                    auto curval = values;
                    while (*curval) {
                        results.emplace_back((*curval)->bv_val, (*curval)->bv_len);
                        ++curval;
                    }
                }
                attribute = ldap_next_attribute(ldap, entry, ber);
            }
        }
        entry = ldap_next_entry(ldap, entry);
    }
    return Status::OK();
}

Status LDAPManagerImpl::mapUserToDN(const std::string& user, std::string& out) {
    //TODO: keep BSONArray somewhere is ldapGlobalParams (but consider multithreaded access)
    std::string mapping = ldapGlobalParams.ldapUserToDNMapping.get();

    //Parameter validator checks that mapping is valid array of objects
    //see validateLDAPUserToDNMapping function
    BSONArray bsonmapping{fromjson(mapping)};
    for (const auto& elt: bsonmapping) {
        auto step = elt.Obj();
        std::smatch sm;
        std::regex rex{step["match"].str()};
        if (std::regex_match(user, sm, rex)) {
            // user matched current regex
            BSONElement eltempl = step["substitution"];
            bool substitution = true;
            if (!eltempl) {
                // ldapQuery mode
                eltempl = step["ldapQuery"];
                substitution = false;
            }
            // format template
            {
                std::regex rex{R"(\{(\d+)\})"};
                std::string ss;
                const std::string stempl = eltempl.str();
                ss.reserve(stempl.length() * 2);
                std::sregex_iterator it{stempl.begin(), stempl.end(), rex};
                std::sregex_iterator end;
                auto suffix_len = stempl.length();
                for (; it != end; ++it) {
                    ss += it->prefix();
                    ss += sm[std::stol((*it)[1].str()) + 1].str();
                    suffix_len = it->suffix().length();
                }
                ss += stempl.substr(stempl.length() - suffix_len);
                out = std::move(ss);
            }
            // in substitution mode we are done - just return 'out'
            if (substitution)
                return Status::OK();
            // in ldapQuery mode we need to execute query and make decision based on query result
            auto ldapurl = fmt::format("ldap://{Servers}/{Query}",
                fmt::arg("Servers", "ldap.server"),
                fmt::arg("Query", out));
            std::vector<std::string> qresult;
            auto status = execQuery(ldapurl, qresult);
            if (!status.isOK())
                return status;
            // query succeeded only if we have single result
            // otherwise continue search
            if (qresult.size() == 1) {
                out = qresult[0];
                return Status::OK();
            }
        }
    }
    // we have no successful transformations, return error
    return Status(ErrorCodes::UserNotFound,
                  "Failed to map user '{}' to LDAP DN"_format(user));
}

Status LDAPManagerImpl::queryUserRoles(const UserName& userName, stdx::unordered_set<RoleName>& roles) {
    constexpr auto kAdmin = "admin"_sd;

    const std::string providedUser{userName.getUser()};
    std::string mappedUser;
    {
        auto mapRes = mapUserToDN(providedUser, mappedUser);
        if (!mapRes.isOK())
            return mapRes;
    }

    auto ldapurl = fmt::format("ldap://{Servers}/{Query}",
            fmt::arg("Servers", "ldap.server"),
            fmt::arg("Query", ldapGlobalParams.ldapQueryTemplate.get()));
    ldapurl = fmt::format(ldapurl,
            fmt::arg("USER", mappedUser),
            fmt::arg("PROVIDED_USER", providedUser));

    std::vector<std::string> qresult;
    auto status = execQuery(ldapurl, qresult);
    if (status.isOK()) {
        for (auto& dn: qresult) {
            roles.insert(RoleName{dn, kAdmin});
        }
    }
    return status;
}

Status LDAPbind(LDAP* ld, const char* usr, const char* psw) {
    if (ldapGlobalParams.ldapFollowReferrals.load()) {
      ldap_set_rebind_proc( ld, rebindproc, (void *)usr );
    }
    if (ldapGlobalParams.ldapBindMethod == "simple") {
        // ldap_simple_bind_s was deprecated in favor of ldap_sasl_bind_s
        berval cred;
        cred.bv_val = (char*)psw;
        cred.bv_len = std::strlen(psw);
        auto res = ldap_sasl_bind_s(ld, usr, LDAP_SASL_SIMPLE, &cred,
                               nullptr, nullptr, nullptr);
        if (res != LDAP_SUCCESS) {
            return Status(ErrorCodes::LDAPLibraryError,
                          "Failed to authenticate '{}' using simple bind; LDAP error: {}"_format(
                              usr, ldap_err2string(res)));
        }
    } else if (ldapGlobalParams.ldapBindMethod == "sasl") {
        interactionParameters params;
        params.userid = usr;
        params.dn = usr;
        params.pw = psw;
        params.realm = nullptr;
        auto res = ldap_sasl_interactive_bind_s(
                ld,
                nullptr,
                ldapGlobalParams.ldapBindSaslMechanisms.c_str(),
                nullptr,
                nullptr,
                LDAP_SASL_QUIET,
                interactProc,
                &params);
        if (res != LDAP_SUCCESS) {
            return Status(ErrorCodes::LDAPLibraryError,
                          "Failed to authenticate '{}' using sasl bind; LDAP error: {}"_format(
                              usr, ldap_err2string(res)));
        }
    } else {
        return Status(ErrorCodes::OperationFailed,
                      "Unknown bind method: {}"_format(ldapGlobalParams.ldapBindMethod));
    }
    return Status::OK();
}

Status LDAPbind(LDAP* ld, const std::string& usr, const std::string& psw) {
    return LDAPbind(ld, usr.c_str(), psw.c_str());
}

namespace {

ServiceContext::ConstructorActionRegisterer ldapServerConfigValidationRegisterer{
    "ldapServerConfigValidationRegisterer",
    {"CreateLDAPManager"},
    [](ServiceContext* svcCtx) {
        if (!ldapGlobalParams.ldapServers->empty()
            && ldapGlobalParams.ldapValidateLDAPServerConfig) {
            LDAP* ld = create_connection(nullptr, logv2::LogSeverity::Error());
            uassert(ErrorCodes::LDAPLibraryError,
                    "Failed to construct an LDAP connection",
                    ld != nullptr);
            ON_BLOCK_EXIT([ld]{ ldap_unbind_ext(ld, nullptr, nullptr); });
            uassertStatusOK(LDAPbind(ld,
                        ldapGlobalParams.ldapQueryUser.get(),
                        ldapGlobalParams.ldapQueryPassword.get()));

        }
    }
};

}  // namespace

}  // namespace mongo

