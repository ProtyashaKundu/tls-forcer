// ==========================================================================
// FILE: tls_server.cpp                       LAYER: program (test server)
//
// WHAT THIS PROGRAM DOES
//   A TLS server for safe local testing. For every connection it prints
//   what the client OFFERED next to what the server CHOSE. A browser that
//   opens https://localhost:4433/ gets the same report as a web page,
//   which shows the browser's real ClientHello (GREASE values included).
//     ./tls_server --port 4433 --cert certs/ecdsa.crt --key certs/ecdsa.key
//                  --cert certs/ed25519.crt --key certs/ed25519.key
//
// NAMESPACES
//   uses tlsf (via `using namespace tlsf;`).
//   (anonymous namespace)  Private helpers of this program.
//
// TYPES
//   struct Offer
//       The client's menu as readable strings: versions, cipher suites,
//       groups, key shares (with sizes), signature schemes. clear() resets it.
//
// FUNCTIONS (anonymous namespace)
//   u16(p)
//       Reads a big-endian 2-byte number.
//   u16_list(p, len, name_fn)
//       Decodes a length-prefixed list of code points into names using
//       the given naming function (group_id_name or sigalg_id_name).
//   client_hello_cb(ssl, alert, arg)
//       Registered with SSL_CTX_set_client_hello_cb. Runs as soon as the
//       ClientHello arrives, BEFORE the server decides, and records the
//       offered suites, supported_versions, supported_groups,
//       signature_algorithms and key_share entries into the Offer.
//   report(offer, negotiated, trace)
//       Builds the "CLIENT OFFERED / SERVER CHOSE" text block.
//   handle(ctx, client_bio, offer)
//       Serves one connection: 5-second receive timeout, SSL_accept()
//       (the server side of the handshake), print the report, answer an
//       HTTP GET with it, then shut down and free the connection.
//
//   int main(argc, argv)
//       Loads one or more certificate/key pairs (one per key type, so the
//       client's signature_algorithms decides which certificate is used),
//       sets the server's own groups/sigalgs/suites/versions, turns on
//       SSL_OP_CIPHER_SERVER_PREFERENCE unless --prefer client, registers
//       client_hello_cb, binds the port, ignores SIGPIPE, and loops forever
//       accepting connections.
// ==========================================================================

#include "tls_util.hpp"

#include <openssl/err.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <csignal>
#include <ctime>
#include <iostream>
#include <sstream>

using namespace tlsf;

namespace {

struct Offer
{
    std::vector<std::string> versions, ciphers, groups, key_shares, sigalgs;
    void clear()
    {
    	*this = Offer{};
    }
};

uint16_t u16(const unsigned char* p)
{
	return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

std::vector<std::string> u16_list(const unsigned char* p, size_t len,  std::string (*name)(uint16_t))
{
    std::vector<std::string> out;
    if (len < 2) return out;
    size_t n = std::min<size_t>(u16(p), len - 2);
    for (size_t i = 0; i + 1 < n; i += 2) out.push_back(name(u16(p + 2 + i)));
    return out;
}

int client_hello_cb(SSL* s, int* , void* arg)
{
    auto* o = static_cast<Offer*>(arg);
    const unsigned char* p;
    size_t len;

    len = SSL_client_hello_get0_ciphers(s, &p);
    for (size_t i = 0; i + 1 < len; i += 2)
    {
        uint16_t id = u16(p + i);
        if (is_grease(id))
        {
        	o->ciphers.push_back("GREASE");
        	continue;
        }
        const SSL_CIPHER* c = SSL_CIPHER_find(s, p + i);
        const char* nm = c ? SSL_CIPHER_standard_name(c) : nullptr;
        o->ciphers.push_back(nm ? nm : "unknown");
    }
    if (SSL_client_hello_get0_ext(s, 43, &p, &len) && len >= 1)
        for (size_t i = 1; i + 1 < len && i < 1u + p[0]; i += 2)
        {
            uint16_t v = u16(p + i);
            o->versions.push_back(v == 0x0304 ? "TLS1.3" : v == 0x0303 ? "TLS1.2"
                                  : is_grease(v) ? "GREASE" : "other");
        }
    if (SSL_client_hello_get0_ext(s, 10, &p, &len))
    	o->groups = u16_list(p, len, group_id_name);
    if (SSL_client_hello_get0_ext(s, 13, &p, &len))
    	o->sigalgs = u16_list(p, len, sigalg_id_name);
    if (SSL_client_hello_get0_ext(s, 51, &p, &len) && len >= 2)
    {
        size_t end = std::min<size_t>(2 + u16(p), len);
        for (size_t i = 2; i + 4 <= end;)
        {
            uint16_t g = u16(p + i), klen = u16(p + i + 2);
            o->key_shares.push_back(group_id_name(g) + " (" + std::to_string(klen) + " B)");
            i += 4 + klen;
        }
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

std::string report(const Offer& o, const Negotiated& n, const Trace& t)
{
    auto line = [](const std::string& k, const std::vector<std::string>& v)
    {
        return "  " + k + ": " + (v.empty() ? "(not sent)" : join(v, ", ")) + "\n";
    };
    std::ostringstream s;
    s << "CLIENT OFFERED\n"
      << line("versions         ", o.versions) << line("cipher suites    ", o.ciphers)
      << line("groups           ", o.groups) << line("key shares       ", o.key_shares)
      << line("signature schemes", o.sigalgs) << "\nSERVER CHOSE\n"
      << "  protocol         : " << n.version << "\n"
      << "  cipher suite     : " << n.cipher << "\n"
      << "  key exchange     : " << n.group << "\n"
      << "  server signed    : " << n.own_sig << "\n"
      << "  HelloRetryRequest: " << (t.hrr ? "yes" : "no") << "\n";
    return s.str();
}

void handle(SSL_CTX* ctx, BIO* cbio, Offer& offer)
{
    offer.clear();
    Trace trace;
    int fd = -1;
    BIO_get_fd(cbio, &fd);
    timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    SSL* ssl = SSL_new(ctx);
    SSL_set_bio(ssl, cbio, cbio);
    attach_trace(ssl, &trace);

    std::time_t now = std::time(nullptr);
    char ts[16];
    std::strftime(ts, sizeof ts, "%H:%M:%S", std::localtime(&now));
    std::cout << "\n[" << ts << "] connection\n";

    if (SSL_accept(ssl) != 1)
    {
        std::cout << "  handshake FAILED: " << openssl_errors() << "\n";
        if (!offer.groups.empty() || !offer.sigalgs.empty())
            std::cout << "  client had offered groups [" << join(offer.groups, ", ")
                      << "] sigalgs [" << join(offer.sigalgs, ", ") << "]\n";
        SSL_free(ssl);
        return;
    }
    Negotiated n = describe(ssl);
    std::string text = report(offer, n, trace);
    std::cout << text;

    char buf[4096];
    int r = SSL_read(ssl, buf, sizeof buf);
    if (r > 0 && std::string(buf, r).rfind("GET ", 0) == 0)
    {
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                           "Content-Length: " + std::to_string(text.size()) +
                           "\r\nConnection: close\r\n\r\n" + text;
        SSL_write(ssl, resp.data(), static_cast<int>(resp.size()));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ERR_clear_error();
}

}

int main(int argc, char** argv)
{
    Args a(argc, argv);
    auto certs = a.all("--cert"), keys = a.all("--key");
    if (certs.empty() || certs.size() != keys.size())
    {

	  std::cerr <<R"(usage: tls_server --cert C --key K [--cert C2 --key K2 ...] [options]
	  --port P               listen port (default 4433)
	  --groups LIST          groups the server accepts, in ITS preference order
	  --sigalgs LIST         signature schemes the server may use
	  --ciphersuites LIST    TLS 1.3 suites;  --cipher-list LIST for TLS 1.2
	  --prefer server|client whose order decides (default server)
	  --tls12 | --tls13      pin the protocol version
	  --provider NAME        load an OpenSSL provider (repeatable)
	Give one cert per key type (ECDSA, Ed25519, RSA ...); the server picks the one
	that matches the client's signature_algorithms.
	)";
      return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    try
    {
        load_providers(a.all("--provider"));
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        return 2;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    auto fail = [&](const std::string& what)
    {
        std::cerr << what << ": " << openssl_errors() << "\n";
        return 1;
    };
    for (size_t i = 0; i < certs.size(); ++i)
    {
        if (SSL_CTX_use_certificate_chain_file(ctx, certs[i].c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, keys[i].c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1)
            return fail("loading " + certs[i]);
    }
    if (a.flag("--tls12"))
    	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION), SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if (a.flag("--tls13"))
    	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    std::string g = a.get("--groups"), s = a.get("--sigalgs");
    std::string cs = a.get("--ciphersuites"), cl = a.get("--cipher-list");
    if (!g.empty() && !SSL_CTX_set1_groups_list(ctx, g.c_str()))
    	return fail("groups");
    if (!s.empty() && !SSL_CTX_set1_sigalgs_list(ctx, s.c_str()))
    	return fail("sigalgs");
    if (!cs.empty() && !SSL_CTX_set_ciphersuites(ctx, cs.c_str()))
      return fail("ciphersuites");
    if (!cl.empty() && !SSL_CTX_set_cipher_list(ctx, cl.c_str()))
    	return fail("cipher-list");

    bool server_pref = a.get("--prefer", "server") != "client";
    if (server_pref)
    	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    Offer offer;
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, &offer);

    std::string port = a.get("--port", "4433");
    BIO* acc = BIO_new_accept(port.c_str());
    BIO_set_bind_mode(acc, BIO_BIND_REUSEADDR);
    if (BIO_do_accept(acc) <= 0) return fail("bind to port " + port);

    std::cout << "Listening on :" << port << "  (preference: " << (server_pref ? "server" : "client")
              << ")\n  groups : " << (g.empty() ? "(default)" : g)
              << "\n  sigalgs: " << (s.empty() ? "(default)" : s) << "\n" << std::flush;

    for (;;)
    {
        if (BIO_do_accept(acc) <= 0)
        {
        	ERR_clear_error();
        	continue;
        }
        handle(ctx, BIO_pop(acc), offer);
        std::cout << std::flush;
    }
}
