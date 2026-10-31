// ==========================================================================
// FILE: tls_util.hpp                         LAYER: toolbox (declarations)
//
// WHAT THIS FILE IS FOR
//   Declares the shared helpers that make a handshake OBSERVABLE and
//   READABLE: number-to-name translators, the message recorder ("trace"),
//   the ClientHello/ServerHello parser, the negotiated-result reader,
//   and small utilities. Included by every other source file.
//
// NAMESPACE
//   tlsf   All toolbox types and functions.
//
// TYPES
//   struct TraceEvent   One recorded message: sent/received, record type
//                       (20 ChangeCipherSpec, 21 alert, 22 handshake),
//                       message type or alert code, HRR flag, size, time.
//   struct Trace        The whole recording: list of TraceEvents, number of
//                       ClientHellos, HRR flag, start time, raw copies
//                       of every ClientHello/ServerHello, and the derived
//                       secrets reported by OpenSSL's key-log callback
//                       (keylog, one SSLKEYLOGFILE-format line each).
//   struct KeyShare     One key share: group id, public-key size in bytes,
//                       and the public key itself as hex.
//   struct HelloInfo    A decoded ClientHello or ServerHello: suites, groups,
//                       sigalgs, versions, extensions, key shares, ALPN, SNI,
//                       and the 32-byte random as hex.
//   struct Negotiated   Final result: version, cipher, group, peer and own
//                       signature, and the IANA signature-scheme name.
//   class Args          Tiny command-line parser (flag, get, get_any, all).
//
// FUNCTIONS (defined in tls_util.cpp)
//   openssl_errors()          OpenSSL error queue -> one readable line.
//   group_id_name(id)         Named-group code point -> name (0x001d -> x25519).
//   sigalg_id_name(id)        Signature-scheme code point -> name.
//   cipher_id_name(id)        Cipher-suite id -> IANA name.
//   ext_name(id)              Extension type -> name (51 -> key_share).
//   handshake_type_name(t,h)  Message type -> name (2 + hrr -> HelloRetryRequest).
//   is_grease(id)             True for RFC 8701 GREASE values (0x?a?a).
//   load_providers(names)     Load OpenSSL providers, e.g. "oqsprovider".
//   attach_trace(ssl, trace)  Start recording every message AND every derived
//                             secret of a connection.
//   to_hex(p, n)              Bytes -> lowercase hex text.
//   parse_hello(bytes)        Decode a raw ClientHello/ServerHello.
//   describe(ssl)             Read what the finished handshake negotiated.
//   to_string(neg, trace)     Format the result for the terminal.
//   split(s, sep), join(v, sep)   String helpers.
// ==========================================================================

#pragma once
#include <openssl/ssl.h>
#include <chrono>
#include <cstdint>
#include <string>

#include <vector>

namespace tlsf {

std::string openssl_errors();

std::string group_id_name(uint16_t id);
std::string sigalg_id_name(uint16_t id);
bool is_grease(uint16_t id);

void load_providers(const std::vector<std::string>& names);

std::string cipher_id_name(uint16_t id);
std::string ext_name(uint16_t id);
std::string handshake_type_name(int type, bool hrr);

struct TraceEvent {
    bool sent;
    int content_type;
    int detail;
    bool hrr;
    size_t len;
    double t_ms;
};

struct Trace
{
    int client_hellos = 0;
    bool hrr = false;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    std::vector<TraceEvent> events;
    std::vector<std::vector<unsigned char>> hellos;
    std::vector<std::string> keylog;
};
void attach_trace(SSL* ssl, Trace* trace);
std::string to_hex(const unsigned char* p, size_t n);

struct KeyShare
{
    uint16_t group;
    size_t len;
    std::string hex;
};

struct HelloInfo {
    bool ok = false;
    bool client = false;
    bool hrr = false;
    std::vector<uint16_t> suites;
    std::vector<uint16_t> groups, sigalgs, versions, extensions;
    std::vector<KeyShare> key_shares;
    std::vector<std::string> alpn;
    std::string sni;
    std::string random;
    size_t length = 0;
};
HelloInfo parse_hello(const std::vector<unsigned char>& msg);

struct Negotiated {
    std::string version, cipher, group, peer_sig, own_sig;
    std::string peer_sig_iana;
};
Negotiated describe(SSL* ssl);
std::string to_string(const Negotiated& n, const Trace& t);

std::vector<std::string> split(const std::string& s, char sep);
std::string join(const std::vector<std::string>& v, const std::string& sep);

class Args {
public:
    Args(int argc, char** argv) : tok_(argv + 1, argv + argc) {}
    bool flag(const std::string& name) const;
    std::string get(const std::string& name, const std::string& def = "") const;
    std::string get_any(const std::vector<std::string>& names, const std::string& def = "") const;
    std::vector<std::string> all(const std::string& name) const;

private:
    std::vector<std::string> tok_;
};

}
