// ==========================================================================
// FILE: client_core.hpp                      LAYER: engine (declarations)
//
// WHAT THIS FILE IS FOR
//   Declares the "order form" you fill in before a handshake and the
//   "receipt" you get back afterwards, plus the two engine functions.
//   Every program that runs a client handshake includes this file.
//
// NAMESPACE
//   tlsf
//       The project's own namespace ("tls-forcer"), so our names can't
//       clash with OpenSSL or the standard library.
//
// TYPES
//   struct ClientConfig  -- the order form
//       host, port      Where to connect (e.g. "google.com", "443").
//       sni             Name sent in the Server Name Indication extension;
//                       empty means "use host".
//       groups          Key-exchange groups to offer, colon-separated
//                       ("X25519", "X25519:P-256"). One entry = forced.
//       sigalgs         Signature schemes we accept ("ed25519", ...).
//       ciphersuites    TLS 1.3 cipher suites ("TLS_AES_128_GCM_SHA256").
//       cipher_list     TLS 1.2 cipher suites in OpenSSL naming.
//       min_version,
//       max_version     Allowed TLS versions (0 = no limit).
//       verify, cafile  Whether to check the certificate, and which CA to trust.
//       request         Optional bytes (e.g. an HTTP GET) to send afterwards.
//
//   struct HandshakeResult  -- the receipt
//       ok                Handshake completed.
//       rejected_locally  OUR OpenSSL refused the offer; nothing was sent.
//       error             Readable reason for any failure.
//       neg               What was negotiated (Negotiated, from tls_util).
//       trace             Every handshake message seen (Trace, from tls_util).
//       response          The server's reply to `request`, if any.
//
// FUNCTIONS (defined in client_core.cpp)
//   HandshakeResult run_handshake(const ClientConfig&)
//       Runs one complete client handshake and returns the receipt.
//   std::string apply_offer(SSL_CTX*, const ClientConfig&)
//       Writes the menu (versions, groups, sigalgs, suites) into an OpenSSL
//       context. Returns "" on success, or the reason OpenSSL refused.
// ==========================================================================

#pragma once
#include "tls_util.hpp"
#include <string>

namespace tlsf
{

struct ClientConfig
{
    std::string host = "localhost";
    std::string port = "4433";
    std::string sni;
    std::string groups;
    std::string sigalgs;
    std::string ciphersuites;
    std::string cipher_list;
    int min_version = 0;
    int max_version = 0;
    bool verify = true;
    std::string cafile;
    std::string request;
};

struct HandshakeResult
{
    bool ok = false;
    bool rejected_locally = false;
    std::string error;
    Negotiated neg;
    Trace trace;
    std::string response;
};

HandshakeResult run_handshake(const ClientConfig& cfg);

std::string apply_offer(SSL_CTX* ctx, const ClientConfig& cfg);

}
