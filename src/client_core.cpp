// ==========================================================================
// FILE: client_core.cpp                      LAYER: engine (heart of the project)
//
// WHAT THIS FILE DOES
//   The client never chooses the algorithm; the server does. The client
//   only controls the MENU in its ClientHello. This file builds that menu
//   from a ClientConfig (one item on the menu = "forced") and runs one
//   handshake with OpenSSL. If the server can't accept the only option,
//   it answers with a handshake_failure alert.
//
// NAMESPACES
//   tlsf
//       Public functions of this file (apply_offer, run_handshake).
//   (anonymous namespace, inside tlsf)
//       Private helpers visible only in this file.
//
// PRIVATE HELPERS (anonymous namespace)
//   CtxPtr, SslPtr
//       unique_ptr aliases with custom deleters (SSL_CTX_free, SSL_free),
//       so OpenSSL objects are freed automatically on every return path.
//   bool is_ip_literal(const std::string& h)
//       True if h is an IPv4/IPv6 address. IPs must not be sent as SNI and
//       are matched against the certificate's IP entries, not DNS names.
//
// PUBLIC FUNCTIONS
//   std::string apply_offer(SSL_CTX* ctx, const ClientConfig& c)
//       WHERE FORCING HAPPENS. Copies the config into the context:
//         SSL_CTX_set_min/max_proto_version -> allowed TLS versions
//         SSL_CTX_set1_groups_list          -> supported_groups + key_share
//                                              (key share made for the FIRST group)
//         SSL_CTX_set1_sigalgs_list         -> signature_algorithms
//         SSL_CTX_set_ciphersuites          -> TLS 1.3 cipher_suites
//         SSL_CTX_set_cipher_list           -> TLS 1.2 cipher_suites
//       Returns "" on success, or why OUR OpenSSL rejected a name
//       (in which case nothing is sent to the server).
//
//   HandshakeResult run_handshake(const ClientConfig& c)
//       One full handshake, step by step:
//         1. create the client context (SSL_CTX)
//         2. apply_offer()                -> stop early if rejected locally
//         3. certificate checking: OS trust store or c.cafile
//         4. TCP connect (BIO_new_connect / BIO_do_connect)
//         5. create the connection (SSL), set SNI and the expected hostname
//         6. attach_trace()               -> record every handshake message
//         7. SSL_connect()                -> the whole handshake in one call
//         8. describe()                   -> what was agreed
//         9. optional request/response, then SSL_shutdown()
//
// USED BY
//   tls_client.cpp (one handshake), tls_probe.cpp (many handshakes),
//   inspect.cpp (reuses apply_offer for the dashboard).
// ==========================================================================

#include "client_core.hpp"
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <memory>

namespace tlsf
{

namespace
{
using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;

bool is_ip_literal(const std::string& h)
{
    unsigned char buf[16];
    return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
}
}

std::string apply_offer(SSL_CTX* ctx, const ClientConfig& c)
{
    auto reject = [](const std::string& what) {
        return "local OpenSSL does not support " + what + ": " + openssl_errors();
    };
    if (c.min_version && !SSL_CTX_set_min_proto_version(ctx, c.min_version))
        return reject("that minimum version");
    if (c.max_version && !SSL_CTX_set_max_proto_version(ctx, c.max_version))
        return reject("that maximum version");

    if (!c.groups.empty() && !SSL_CTX_set1_groups_list(ctx, c.groups.c_str()))
        return reject("groups '" + c.groups + "'");
    if (!c.sigalgs.empty() && !SSL_CTX_set1_sigalgs_list(ctx, c.sigalgs.c_str()))
        return reject("sigalgs '" + c.sigalgs + "'");
    if (!c.ciphersuites.empty() && !SSL_CTX_set_ciphersuites(ctx, c.ciphersuites.c_str()))
        return reject("TLS 1.3 ciphersuites '" + c.ciphersuites + "'");
    if (!c.cipher_list.empty() && !SSL_CTX_set_cipher_list(ctx, c.cipher_list.c_str()))
        return reject("TLS 1.2 cipher list '" + c.cipher_list + "'");
    return "";
}

HandshakeResult run_handshake(const ClientConfig& c)
{
    HandshakeResult r;
    ERR_clear_error();

    CtxPtr ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx) {
        r.error = "SSL_CTX_new: " + openssl_errors();
        return r;
    }

    std::string err = apply_offer(ctx.get(), c);
    if (!err.empty()) {
        r.rejected_locally = true;
        r.error = err;
        return r;
    }

    if (c.verify) {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        int ok = c.cafile.empty()
                     ? SSL_CTX_set_default_verify_paths(ctx.get())
                     : SSL_CTX_load_verify_locations(ctx.get(), c.cafile.c_str(), nullptr);
        if (!ok) {
            r.error = "cannot load trust store: " + openssl_errors();
            return r;
        }
    }

    BIO* bio = BIO_new_connect((c.host + ":" + c.port).c_str());
    if (!bio || BIO_do_connect(bio) <= 0) {
        r.error = "TCP connect to " + c.host + ":" + c.port + " failed: " + openssl_errors();
        BIO_free_all(bio);
        return r;
    }

    SslPtr ssl(SSL_new(ctx.get()), SSL_free);
    SSL_set_bio(ssl.get(), bio, bio);

    const std::string name = c.sni.empty() ? c.host : c.sni;
    if (!is_ip_literal(name)) SSL_set_tlsext_host_name(ssl.get(), name.c_str());
    if (c.verify) {
        if (is_ip_literal(name)) X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), name.c_str());
        else SSL_set1_host(ssl.get(), name.c_str());
    }

    attach_trace(ssl.get(), &r.trace);

    if (SSL_connect(ssl.get()) != 1) {
        r.error = "handshake failed: " + openssl_errors();
        long v = SSL_get_verify_result(ssl.get());
        if (v != X509_V_OK)
            r.error += std::string(" [certificate: ") + X509_verify_cert_error_string(v) + "]";
        return r;
    }

    r.ok = true;
    r.neg = describe(ssl.get());

    if (!c.request.empty()) {
        SSL_write(ssl.get(), c.request.data(), static_cast<int>(c.request.size()));
        char buf[4096];
        int n;
        while ((n = SSL_read(ssl.get(), buf, sizeof buf)) > 0) r.response.append(buf, n);
    }
    SSL_shutdown(ssl.get());
    return r;
}

}
