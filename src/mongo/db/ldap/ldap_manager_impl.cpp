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


#include "mongo/db/ldap/ldap_manager_impl.h"

#include <algorithm>
#include <map>
#include <regex>
#include <utility>
#include <vector>

#include <lber.h>
#include <poll.h>

#include <fmt/format.h>
#include <sasl/sasl.h>

#include "mongo/bson/json.h"
#include "mongo/db/client.h"
#include "mongo/db/ldap_options.h"
#include "mongo/logv2/log.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/scopeguard.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl


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

}  // namespace
}  // namespace mongo

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
        dflt = nullptr;

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

    if (ld == nullptr)
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
    LDAP* conn = nullptr;
    bool borrowed = false;

    void close() {
        invariant(!borrowed);
        if (conn) {
            ldap_unbind_ext(conn, nullptr, nullptr);
            conn = nullptr;
        }
    }

    // close if it is not borrowed
    void safe_close() {
        if (!borrowed) {
            close();
        }
    }
};


using namespace fmt::literals;

static LDAP* create_connection(void* connect_cb_arg = nullptr,
                               logv2::LogSeverity logSeverity = logv2::LogSeverity::Debug(1)) {
    LDAP* ldap = nullptr;
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
    explicit ConnectionPoller() = default;

    virtual std::string name() const override {
        return "LDAPConnectionPoller";
    }

    virtual void run() override {
        ThreadClient tc(name(), getGlobalServiceContext()->getService());
        LOGV2_DEBUG(29061, 1, "starting thread", "name"_attr = name());

        // poller thread will handle disconnection events
        while (!_shuttingDown.load()) {
            MONGO_IDLE_THREAD_BLOCK;
            std::vector<pollfd> fds;
            {
                stdx::unique_lock<Latch> lock{_mutex};
                _condvar.wait(lock, [this] { return !_poll_fds.empty() || _shuttingDown.load(); });

                fds.reserve(_poll_fds.size());
                for (auto& fd : _poll_fds) {
                    if (fd.first < 0)
                        continue;
                    pollfd pfd;
                    pfd.events = POLLPRI | POLLRDHUP;
                    pfd.revents = 0;
                    pfd.fd = fd.first;
                    fds.push_back(pfd);
                }
            }
            // if there are no descriptors that means server is shutting down
            // or we just closed some failed connections
            if (fds.empty())
                continue;

            bool notify_condvar_pool = false;
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
                LOGV2_WARNING(29064, "poll() error name", "errname"_attr = errname);
                //restart all LDAP connections... but why?
                {
                    stdx::unique_lock<Latch> lock{_mutex};
                    for (auto& fd : _poll_fds) {
                        fd.second.safe_close();
                    }
                    _poll_fds.clear();
                    notify_condvar_pool = true;
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
                if (shouldLog(MONGO_LOGV2_DEFAULT_COMPONENT, logv2::LogSeverity::Debug(2))) {
                    for (auto const& fd : fds) {
                        if (fd.revents == 0) {
                            continue;
                        }
                        for (auto const& f : flags) {
                            if (fd.revents & f.v) {
                                LOGV2_DEBUG(29065,
                                            2,
                                            "poll(): {event} event registered for {fd}",
                                            "event"_attr = f.name,
                                            "fd"_attr = fd.fd);
                            }
                        }
                    }
                }
                stdx::unique_lock<Latch> lock{_mutex};
                for (auto const& fd: fds) {
                    if (fd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
                        auto it = _poll_fds.find(fd.fd);
                        if (MONGO_unlikely(it == _poll_fds.end())) {
                            LOGV2_WARNING(
                                171200, "poll(): no connection found for fd", "fd"_attr = fd.fd);
                            continue;
                        }
                        it->second.safe_close();
                        _poll_fds.erase(it);
                        notify_condvar_pool = true;
                    }
                }
            }
            if (notify_condvar_pool) {
                _condvar_pool.notify_all();
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
                it = _poll_fds.insert({fd, {.conn = ldap, .borrowed = true}}).first;
                changed = true;
            } else if (it->second.conn != ldap) {
                // we have some connection corresponding to provided fd
                // we observed such connections in failed state (see PSMDB-1712)
                // let's replace it with the new one
                // we are going to overwrite it->second.conn with ldap
                // if it is borrowed then it will be unbind in return_ldap_connection()
                // otherwise close it here
                it->second.safe_close();
                it->second.conn = ldap;
                it->second.borrowed = true;
                changed = true;
            } else {
                LOGV2_WARNING(171201, "unexpected start of the same connection", "fd"_attr = fd);
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
        // create scope block to ensure that _mutex is released before call to create_connection
        {
            stdx::unique_lock<Latch> lock{_mutex};
            while (true) {
                if (_shuttingDown.load()) {
                    // return nullptr if shutdown is in progress
                    return nullptr;
                }
                if (auto* slot = find_free_slot()) {
                    invariant(slot->conn != nullptr);
                    slot->borrowed = true;
                    return slot->conn;
                }
                if (_poll_fds.size() <=
                    static_cast<unsigned>(ldapGlobalParams.ldapConnectionPoolSizePerHost.load())) {
                    // no available connection, pool has space => create new connection
                    break;
                }
                // wait for some connection returned from borrowed state
                // or killed after failure
                _condvar_pool.wait(lock);
            }
        }
        // LDAP connect callback will add entry to the _poll_fds
        return create_connection(this);
    }

    void return_ldap_connection(LDAP* ldap) {
        stdx::unique_lock<Latch> lock{_mutex};
        auto it = std::find_if(_poll_fds.begin(), _poll_fds.end(), [&](auto const& e) {
            return e.second.conn == ldap;
        });
        if (it == _poll_fds.end()) {
            // for this connection there was no cb_add call
            // or it was removed from _poll_fds by start_poll()'s logic
            // or it was removed from _poll_fds due to some event reported by poll()
            // unbind it here
            ldap_unbind_ext(ldap, nullptr, nullptr);
            return;
        }
        // returning connection which was not borrowed is an error
        invariant(it->second.borrowed);
        it->second.borrowed = false;
        // poller should be always notified here
        _condvar_pool.notify_one();
    }

private:
    std::map<int, LDAPConnInfo> _poll_fds;
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
        _connPoller = std::make_unique<ConnectionPoller>();
        _connPoller->go();
    }
}

LDAP* LDAPManagerImpl::borrow_search_connection() {

    auto* ldap = _connPoller->borrow_or_create();

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

Status LDAPManagerImpl::execQuery(const std::string& ldapurl,
                                  bool entitiesonly,
                                  std::vector<std::string>& results) {

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
    // 'ldap' should be captured by reference because its value can be changed as part of retry
    // logic below (search for 'borrow_search_connection' call)
    ON_BLOCK_EXIT([&, ludp] {
        ldap_free_urldesc(ludp);
        return_search_connection(ldap);
    });
    if (res != LDAP_SUCCESS) {
        return Status(ErrorCodes::LDAPLibraryError,
                      "Cannot parse LDAP URL: {}"_format(
                          ldap_err2string(res)));
    }

    // Special handling of 'DN' attribute
    // Some users provide 'DN' or 'dn' in the attributes part of query just to read
    // only distinguished names of the entries. There is no such attribute in the
    // LDAP server. To read entry's DN we have to use ldap_get_dn(). That is
    // exactly what we do when `entitiesonly` is true.
    // Ensure that `attributes` is nullptr in this case.
    auto attributes = ludp->lud_attrs;
    if (attributes && attributes[0] != nullptr && attributes[1] == nullptr) {  // single attribute?
        std::string attr{attributes[0]};
        if (attr == "DN" || attr == "dn") {
            attributes = nullptr;
        }
    }
    // if attributes are not specified assume query returns set of entities (groups)
    entitiesonly = entitiesonly || !attributes || !attributes[0];

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
                                attributes,
                                0,  // attrsonly (0 => attrs and values)
                                nullptr,
                                nullptr,
                                &tv,
                                0,
                                &answer);
        // Treat nullptr answer as an error. It is undocumented in which cases LDAP_SUCCESS can
        // be along with nullptr answer.
        if (res == LDAP_SUCCESS && answer != nullptr)
            break;
        if (retrycnt > 0) {
            if (res != LDAP_SUCCESS) {
                ldap_msgfree(answer);
                LOGV2_ERROR(
                    29072, "LDAP search failed with error", "errstr"_attr = ldap_err2string(res));
            } else {
                // res is LDAP_SUCCESS, answer is nullptr
                LOGV2_ERROR(29116, "LDAP search 'succeeded' but answer is nullptr");
            }
            return_search_connection(ldap);
            ldap = borrow_search_connection();
            if (!ldap) {
                return Status(ErrorCodes::LDAPLibraryError,
                              "Failed to get an LDAP connection from the pool.");
            }
        }
    } while (retrycnt-- > 0);

    ON_BLOCK_EXIT([=] { ldap_msgfree(answer); });
    if (res != LDAP_SUCCESS) {
        return Status(ErrorCodes::LDAPLibraryError,
                      "LDAP search failed with error: {}"_format(
                          ldap_err2string(res)));
    } else if (answer == nullptr) {
        return Status(ErrorCodes::LDAPLibraryError, "LDAP search failed to return non-null answer");
    }

    auto entry = ldap_first_entry(ldap, answer);
    while (entry) {
        if (entitiesonly) {
            auto dn = ldap_get_dn(ldap, entry);
            ON_BLOCK_EXIT([=] { ldap_memfree(dn); });
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
            ON_BLOCK_EXIT([=] { ber_free(ber, 0); });
            while (attribute) {
                ON_BLOCK_EXIT([=] { ldap_memfree(attribute); });

                auto const values = ldap_get_values_len(ldap, entry, attribute);
                ON_BLOCK_EXIT([=] { ldap_value_free_len(values); });
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

namespace {

std::string escapeForLDAPFilter(const std::string& str) {
    std::string result;
    result.reserve(str.size() * 2);
    for (auto c : str) {
        if (c == '\\') {
            result += "\\5c";
        } else if (c == '*') {
            result += "\\2a";
        } else if (c == '(') {
            result += "\\28";
        } else if (c == ')') {
            result += "\\29";
        } else if (c == '\0') {
            result += "\\00";
        } else {
            result += c;
        }
    }
    return result;
};

std::string escapeForLDAPURL(const std::string& str) {
    std::string result;
    result.reserve(str.size() * 2);
    for (auto c : str) {
        if (c == ' ') {
            result += "%20";
        } else if (c == '#') {
            result += "%23";
        } else if (c == '%') {
            result += "%25";
        } else if (c == '+') {
            result += "%2b";
        } else if (c == ',') {
            result += "%2c";
        } else if (c == ';') {
            result += "%3b";
        } else if (c == '<') {
            result += "%3c";
        } else if (c == '>') {
            result += "%3e";
        } else if (c == '?') {
            result += "%3f";
        } else if (c == '@') {
            result += "%40";
        } else if (c == '\\') {
            result += "%5c";
        } else if (c == '=') {
            result += "%3d";
        } else if (c == '/') {
            result += "%2f";
        } else {
            result += c;
        }
    }
    return result;
}

std::string escapeNoop(const std::string& str) {
    return str;
}

std::string escapeCombined(const std::string& str) {
    return escapeForLDAPURL(escapeForLDAPFilter(str));
}

// substitute {0}, {1}, ... in stempl with corresponding values from sm
std::string substituteFromMatch(const std::string& stempl,
                                const std::smatch& sm,
                                std::string (*escFn)(const std::string&) = escapeNoop) {
    static const std::regex rex{R"(\{(\d+)\})"};
    std::string ss;
    ss.reserve(stempl.length() * 2);
    std::sregex_iterator it{stempl.begin(), stempl.end(), rex};
    std::sregex_iterator end;
    auto suffix_len = stempl.length();
    for (; it != end; ++it) {
        ss += it->prefix();
        ss += escFn(sm[std::stol((*it)[1].str()) + 1].str());
        suffix_len = it->suffix().length();
    }
    ss += stempl.substr(stempl.length() - suffix_len);
    return ss;
}

}  // namespace

Status LDAPManagerImpl::mapUserToDN(const std::string& user, std::string& out) {
    // TODO: keep BSONArray somewhere in ldapGlobalParams (but consider multithreaded access)
    std::string mapping = ldapGlobalParams.ldapUserToDNMapping.get();

    // Parameter validator checks that mapping is valid array of objects
    // see validateLDAPUserToDNMapping function
    BSONArray bsonmapping{fromjson(mapping)};
    for (const auto& elt : bsonmapping) {
        auto step = elt.Obj();
        std::smatch sm;
        std::regex rex{step["match"].str()};
        if (std::regex_match(user, sm, rex)) {
            // user matched current regex
            BSONElement eltempl = step["substitution"];
            if (eltempl) {
                // substitution mode
                // we do not escape substituted values here because result value will be used as
                // {USER} and will be escaped there
                out = substituteFromMatch(eltempl.str(), sm);
                return Status::OK();
            }
            // ldapQuery mode
            std::string escapedQuery;
            eltempl = step["ldapQuery"];
            std::istringstream iss{eltempl.str()};
            std::string part;
            int partnum = 0;
            while (std::getline(iss, part, '?')) {
                if (partnum > 0) {
                    escapedQuery += '?';
                }
                if (partnum == 3) {
                    // ldap search filter should be escaped in a special way
                    escapedQuery += substituteFromMatch(part, sm, escapeCombined);
                } else {
                    escapedQuery += substituteFromMatch(part, sm, escapeForLDAPURL);
                }
                ++partnum;
            }

            // in ldapQuery mode we need to execute query and make decision based on query result
            auto ldapurl = fmt::format("ldap://{Servers}/{Query}",
                                       fmt::arg("Servers", "ldap.server"),
                                       fmt::arg("Query", escapedQuery));
            std::vector<std::string> qresult;
            auto status = execQuery(ldapurl, true, qresult);
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
    return {ErrorCodes::UserNotFound, "Failed to map user '{}' to LDAP DN"_format(user)};
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

    // avoid escaping in the loop
    const std::string mappedUserEscaped = escapeForLDAPURL(mappedUser);
    const std::string providedUserEscaped = escapeForLDAPURL(providedUser);
    const std::string mappedUserEscapedForFilter =
        escapeForLDAPURL(escapeForLDAPFilter(mappedUser));
    const std::string providedUserEscapedForFilter =
        escapeForLDAPURL(escapeForLDAPFilter(providedUser));

    // split query template into parts and replace placeholders in each part with escaped values
    std::string escapedQuery;
    std::istringstream iss{ldapGlobalParams.ldapQueryTemplate.get()};
    std::string part;
    int partnum = 0;
    while (std::getline(iss, part, '?')) {
        if (partnum > 0) {
            escapedQuery += '?';
        }
        if (partnum == 3) {
            // ldap search filter should be escaped in a special way
            escapedQuery += fmt::format(part,
                                        fmt::arg("USER", mappedUserEscapedForFilter),
                                        fmt::arg("PROVIDED_USER", providedUserEscapedForFilter));
        } else {
            escapedQuery += fmt::format(part,
                                        fmt::arg("USER", mappedUserEscaped),
                                        fmt::arg("PROVIDED_USER", providedUserEscaped));
        }
        ++partnum;
    }

    auto ldapurl = fmt::format("ldap://{Servers}/{Query}",
                               fmt::arg("Servers", "ldap.server"),
                               fmt::arg("Query", escapedQuery));

    std::vector<std::string> qresult;
    auto status = execQuery(ldapurl, false, qresult);
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

