/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/encryption/kmip_client.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>

#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/kmip_exchange.h"


namespace mongo::encryption {
// In theory, the code in this file must not depend on whether the Boost.Asio
// or the Standalone Asio is used as a backend networking library. The table
// below summaries namespace alias definitions for choosing an Asio flavor.
//
// |          Boost.Asio             |     Standalone Asio     |
// |---------------------------------|-------------------------|
// |  namespace net = boost::asio;   |  namespace net = asio;  |
// |  namespace sys = boost::system; |  namespace sys = std;   |
//
// @note The `sys` namespace alias must only be used for the symbols defined
// in the standard `system_error` header file or their counterparts from
// `boost/system.hpp`.
namespace net = boost::asio;
namespace sys = boost::system;

class KmipClient::Impl {
public:
    Impl(const std::string& host,
         const std::string& port,
         const std::string& serverCaFile,
         const std::string& clientCertificateFile,
         const std::string& clientCertificatePassword,
         std::chrono::milliseconds timeout);

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    Impl(Impl&&) = default;
    Impl& operator=(Impl&&) = default;

    std::string registerSymmetricKey(const Key& key);
    std::optional<Key> getSymmetricKey(const std::string& keyId);

private:
    static net::mutable_buffer buffer(detail::KmipExchange::Span s) noexcept;
    static void loadSystemCaCertificates(net::ssl::context& sslCtx);
    net::ssl::context createSslContext();

    void exchange(std::shared_ptr<detail::KmipExchange> exch);

    // aborts all outstanding operations
    void cancel();
    template <typename MemFn, typename... Args>
    void handle(MemFn memFn, const sys::error_code& ec, Args&&... args);
    void handleTimeout();
    void handleResolve(net::ip::tcp::resolver::results_type endpoints);
    void handleConnect();
    void handleTlsHandshake();
    void handleRequestWrite([[maybe_unused]] std::size_t transmittedByteCount);
    void handleResponseLengthRead([[maybe_unused]] std::size_t receivedByteCount);
    void handleResponseValueRead([[maybe_unused]] std::size_t receivedByteCount);
    void handleTlsShutdown(const sys::error_code& ec);

    std::string _host;
    std::string _port;
    std::string _serverCaFile;
    std::string _clientCertificateFile;
    std::string _clientCertificatePassword;
    std::chrono::milliseconds _timeout;

    net::io_context _ioCtx;
    net::steady_timer _timer;
    net::ip::tcp::resolver _resolver;
    net::ssl::context _sslCtx;
    std::unique_ptr<net::ssl::stream<net::ip::tcp::socket>> _socket;

    std::shared_ptr<detail::KmipExchange> _exch;
};


KmipClient::Impl::Impl(const std::string& host,
                       const std::string& port,
                       const std::string& serverCaFile,
                       const std::string& clientCertificateFile,
                       const std::string& clientCertificatePassword,
                       std::chrono::milliseconds timeout)
    : _host(host),
      _port(port),
      _serverCaFile(serverCaFile),
      _clientCertificateFile(clientCertificateFile),
      _clientCertificatePassword(clientCertificatePassword),
      _timeout(timeout),
      _ioCtx(),
      _timer(_ioCtx),
      _resolver(_ioCtx),
      _sslCtx(createSslContext()) {}


net::ssl::context KmipClient::Impl::createSslContext() {
    net::ssl::context sslCtx(net::ssl::context::tls_client);
    sslCtx.set_options(net::ssl::context::default_workarounds | net::ssl::context::single_dh_use);
    sslCtx.set_verify_mode(net::ssl::verify_peer | net::ssl::verify_fail_if_no_peer_cert);
    sslCtx.set_verify_callback(net::ssl::host_name_verification(_host));

    loadSystemCaCertificates(sslCtx);
    if (!_serverCaFile.empty()) {
        sslCtx.load_verify_file(_serverCaFile);
    }

    if (!_clientCertificatePassword.empty()) {
        sslCtx.set_password_callback(
            [this](std::size_t maxLength, net::ssl::context::password_purpose purpose) {
                return _clientCertificatePassword;
            });
    }
    sslCtx.use_private_key_file(_clientCertificateFile, net::ssl::context::pem);
    sslCtx.use_certificate_chain_file(_clientCertificateFile);

    return sslCtx;
}


void KmipClient::Impl::loadSystemCaCertificates(net::ssl::context& sslCtx) {
    namespace bfs = boost::filesystem;
    // @note The list of certificate files and directories is adopted from
    // [here](https://go.dev/src/crypto/x509/root_linux.go)
    static constexpr std::array<const char*, 6> certFiles = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem"
    };
    static constexpr std::array<const char*, 3> certDirs = {
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/system/etc/security/cacerts"
    };

    for (const auto& f : certFiles) {
        if (bfs::is_regular_file(bfs::path(f))) {
            sslCtx.load_verify_file(f);
            break;
        }
    }
    for (const auto& d : certDirs) {
        if (bfs::is_directory(bfs::path(d))) {
            sslCtx.add_verify_path(d);
        }
    }
}


net::mutable_buffer KmipClient::Impl::buffer(detail::KmipExchange::Span s) noexcept {
    return net::mutable_buffer(s.data(), s.size());
}

std::string KmipClient::Impl::registerSymmetricKey(const Key& key) {
    auto exch = std::make_shared<detail::KmipExchangeRegisterSymmetricKey>(key);
    exchange(exch);
    return exch->decodeKeyId();
}

std::optional<Key> KmipClient::Impl::getSymmetricKey(const std::string& keyId) {
    auto exch = std::make_shared<detail::KmipExchangeGetSymmetricKey>(keyId);
    exchange(exch);
    return exch->decodeKey();
}


void KmipClient::Impl::exchange(std::shared_ptr<detail::KmipExchange> exch) {
    _exch = exch;

    // The `ssl::stream` is not reusable, a fresh object is required for each
    // new connection. Since the copy assignment operator of the `ssl::stream`
    // is deleted and move assignment is absent at all, falling back to
    // `unique_ptr` is the only viable option.
    _socket = std::make_unique<net::ssl::stream<net::ip::tcp::socket>>(_ioCtx, _sslCtx);
    _ioCtx.restart();

    _timer.expires_after(_timeout);
    _timer.async_wait([this](const sys::error_code& ec) { handle(&Impl::handleTimeout, ec); });
    _resolver.async_resolve(
        _host,
        _port,
        [this](const sys::error_code& ec, net::ip::tcp::resolver::results_type endpoints) {
            handle(&Impl::handleResolve, ec, std::move(endpoints));
        });
    _ioCtx.run();

    _exch.reset();
}


void KmipClient::Impl::cancel() {
    _resolver.cancel();
    _timer.cancel();
    if (_socket->lowest_layer().is_open()) {
        _socket->lowest_layer().shutdown(net::ip::tcp::socket::shutdown_both);
        _socket->lowest_layer().close();
    }
}

template <typename MemFn, typename... Args>
void KmipClient::Impl::handle(MemFn memFn, const sys::error_code& ec, Args&&... args) {
    try {
        if (ec == net::error::operation_aborted) {
            return;
        }
        if (ec) {
            throw sys::system_error(ec);
        }
        std::invoke(memFn, *this, std::forward<Args>(args)...);
    } catch (...) {
        cancel();
        throw;
    }
}


void KmipClient::Impl::handleTimeout() {
    throw sys::system_error(sys::error_code(sys::errc::timed_out, sys::system_category()));
}

void KmipClient::Impl::handleResolve(net::ip::tcp::resolver::results_type endpoints) {
    _socket->lowest_layer().async_connect(
        endpoints.begin()->endpoint(),
        [this](const sys::error_code& ec) { handle(&Impl::handleConnect, ec); });
}

void KmipClient::Impl::handleConnect() {
    auto host_is_address = [](const std::string& host) {
        sys::error_code ec;
        [[maybe_unused]] net::ip::address address = net::ip::make_address(host, ec);
        return !ec;
    };
    // set up the SNI extension for the TLS handshake
    if (!host_is_address(_host) &&
        !::SSL_set_tlsext_host_name(_socket->native_handle(), _host.c_str())) {
        throw sys::system_error(sys::error_code(::ERR_get_error(), net::error::get_ssl_category()));
    }
    _socket->async_handshake(
        net::ssl::stream<net::ip::tcp::socket>::client,
        [this](const sys::error_code& ec) { handle(&Impl::handleTlsHandshake, ec); });
}

void KmipClient::Impl::handleTlsHandshake() {
    _exch->state(detail::KmipExchange::State::TransmittingRequest);
    net::async_write(*_socket,
                     buffer(_exch->span()),
                     [this](const sys::error_code& ec, std::size_t transmittedByteCount) {
                         handle(&Impl::handleRequestWrite, ec, transmittedByteCount);
                     });
}

void KmipClient::Impl::handleRequestWrite([[maybe_unused]] std::size_t transmittedByteCount) {
    _exch->state(detail::KmipExchange::State::ReceivingResponseLength);
    net::async_read(*_socket,
                    buffer(_exch->span()),
                    [this](const sys::error_code& ec, std::size_t receivedByteCount) {
                        handle(&Impl::handleResponseLengthRead, ec, receivedByteCount);
                    });
}

void KmipClient::Impl::handleResponseLengthRead([[maybe_unused]] std::size_t receivedByteCount) {
    _exch->state(detail::KmipExchange::State::ReceivingResponseValue);
    net::async_read(*_socket,
                    buffer(_exch->span()),
                    [this](const sys::error_code& ec, std::size_t receivedByteCount) {
                        handle(&Impl::handleResponseValueRead, ec, receivedByteCount);
                    });
}

void KmipClient::Impl::handleResponseValueRead([[maybe_unused]] std::size_t receivedByteCount) {
    _exch->state(detail::KmipExchange::State::ResponseReceived);

    _socket->async_shutdown([this](const sys::error_code& ec) {
        this->handleTlsShutdown(ec);
    });
}

void KmipClient::Impl::handleTlsShutdown(const sys::error_code& ec) {
    if (ec == net::error::operation_aborted) {
        return;
    }
    cancel();
    if (ec.category() == net::ssl::error::get_stream_category() &&
        ec.value() == net::ssl::error::stream_truncated) {
        // The server hasn't handled the TLS shutdown properly. Namely, instead
        // of replying with a close notify alert in response to the close-notify
        // alert sent to it by the KMIP client, it just has answered with a FIN
        // packet indicating it wanted to close the connection.
        // Since that non-standard behavior is quite widespread, the KMIP
        // client shouldn't report it as an error because it can't do anything
        // meaningful about that anyway. The client just concludes the
        // connection closing by sending a FIN-ACK packet in response to the
        // server's FIN. Technically, the latter has already been done by the
        // `cancel` member function above.
        return;
    }
    if (ec) {
        throw sys::system_error(ec);
    }
}

KmipClient::~KmipClient() = default;

KmipClient::KmipClient(KmipClient&&) = default;
KmipClient& KmipClient::operator=(KmipClient&&) = default;

KmipClient::KmipClient(const std::string& host,
                       const std::string& port,
                       const std::string& serverCaFile,
                       const std::string& clientCertificateFile,
                       const std::string& clientCertificatePassword,
                       std::chrono::milliseconds timeout)
    : _impl(std::make_unique<Impl>(
          host, port, serverCaFile, clientCertificateFile, clientCertificatePassword, timeout)) {}

std::string KmipClient::registerSymmetricKey(const Key& key) {
    return _impl->registerSymmetricKey(key);
}

std::optional<Key> KmipClient::getSymmetricKey(const std::string& keyId) {
    return _impl->getSymmetricKey(keyId);
}
}  // namespace mongo::encryption
