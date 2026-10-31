// ==========================================================================
// FILE: tls_client.cpp                       LAYER: program (command line)
//
// WHAT THIS PROGRAM DOES
//   Runs ONE handshake with a restricted ("forced") offer and prints what
//   the server chose, or why it failed.
//     ./tls_client --host google.com --group P-256 --sigalg ecdsa_secp256r1_sha256
//     ./tls_client --host google.com --sigalg ed25519        (server refuses)
//     ./tls_client --host google.com --groups ffdhe2048:X25519  (HelloRetryRequest)
//
// NAMESPACES
//   uses tlsf (via `using namespace tlsf;`). Defines nothing of its own.
//
// FUNCTIONS
//   static void usage()
//       Prints the help text (all flags) to stderr.
//   int main(int argc, char** argv)
//       1. Parses flags with Args; shows help if --host is missing.
//       2. Loads optional providers (--provider oqsprovider).
//       3. Fills a ClientConfig: host, port, sni, groups, sigalgs,
//          ciphersuites, cipher_list, cafile, --insecure, --tls12/--tls13,
//          and an optional HTTP GET (--get PATH).
//       4. Prints the menu that the ClientHello will offer.
//       5. Calls run_handshake() and prints:
//            "NOT SENT"  our OpenSSL refused the offer (nothing sent)
//            "FAILED"    the server refused, or network/certificate error
//            "Handshake OK" + negotiated version, cipher, group, signature,
//                        HelloRetryRequest yes/no, number of ClientHellos.
//       Exit codes: 0 success, 1 handshake failed, 2 wrong usage.
//      Optional key output:
//         --keys         print both randoms, both public key shares and every
//                        derived secret after a successful handshake.
//         --keylog FILE  append the secrets to FILE in SSLKEYLOGFILE format,
//                        so Wireshark can decrypt a capture of the session.
// ==========================================================================

#include "client_core.hpp"
#include <fstream>
#include <iostream>

using namespace tlsf;

static void usage()
{
    std::cerr <<
    R"(usage: tls_client --host H [--port P] [options]
  --group(s) LIST        key exchange groups, e.g. X25519 | P-256 | X25519MLKEM768
  --sigalg(s) LIST       signature schemes, e.g. ed25519 | ecdsa_secp256r1_sha256 | rsa_pss_rsae_sha256
  --ciphersuites LIST    TLS 1.3 suites, e.g. TLS_CHACHA20_POLY1305_SHA256
  --cipher-list LIST     TLS 1.2 suites, e.g. ECDHE-RSA-AES128-GCM-SHA256
  --tls12 | --tls13      pin the protocol version
  --sni NAME             SNI / name to verify (default: host)
  --cafile FILE          trust this CA (e.g. certs/ca.crt from gen_certs.sh)
  --insecure             skip certificate verification
  --get PATH             send "GET PATH" after the handshake and print the reply
  --provider NAME        load an OpenSSL provider (repeatable), e.g. oqsprovider
  --keys                 also print randoms, public key shares and derived secrets
  --keylog FILE          append the secrets to FILE (SSLKEYLOGFILE format, for Wireshark)
LIST is colon-separated. One entry = forced; several = offered in that order.
)";
}

int main(int argc, char** argv)
{
    Args a(argc, argv);
    if (a.flag("--help") || a.flag("-h") || a.get("--host").empty()) {
        usage();
        return 2;
    }
    try {
        load_providers(a.all("--provider"));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    ClientConfig c;
    c.host = a.get("--host");
    c.port = a.get("--port", "443");
    c.sni = a.get("--sni");
    c.groups = a.get_any({"--group", "--groups"});
    c.sigalgs = a.get_any({"--sigalg", "--sigalgs"});
    c.ciphersuites = a.get("--ciphersuites");
    c.cipher_list = a.get("--cipher-list");
    c.cafile = a.get("--cafile");
    c.verify = !a.flag("--insecure");
    if (a.flag("--tls12")) c.min_version = c.max_version = TLS1_2_VERSION;
    if (a.flag("--tls13")) c.min_version = c.max_version = TLS1_3_VERSION;
    std::string path = a.get("--get");
    if (!path.empty())
        c.request = "GET " + path + " HTTP/1.1\r\nHost: " + c.host + "\r\nConnection: close\r\n\r\n";

    auto show = [](const std::string& s) { return s.empty() ? std::string("(OpenSSL default)") : s; };
    std::cout << "ClientHello will offer:\n"
              << "  groups        : " << show(c.groups) << "\n"
              << "  sigalgs       : " << show(c.sigalgs) << "\n"
              << "  1.3 suites    : " << show(c.ciphersuites) << "\n"
              << "  1.2 suites    : " << show(c.cipher_list) << "\n\n";

    HandshakeResult r = run_handshake(c);
    if (!r.ok) {
        std::cout << (r.rejected_locally ? "NOT SENT" : "FAILED") << ": " << r.error << "\n";
        if (!r.rejected_locally)
            std::cout << "\nThe server refused everything we offered (or the network/cert failed).\n";
        return 1;
    }
    std::cout << "Handshake OK. Server chose:\n" << to_string(r.neg, r.trace);
    if (!r.response.empty()) std::cout << "\n--- server response ---\n" << r.response << "\n";

    if (a.flag("--keys")) {
        auto shorten = [](const std::string& hex) {
            return hex.size() <= 64 ? hex : hex.substr(0, 64) + "...";
        };
        std::cout << "\n--- keys of this handshake ---\n";
        for (const auto& raw : r.trace.hellos) {
            HelloInfo h = parse_hello(raw);
            if (!h.ok) continue;
            const char* who = h.client ? "client" : (h.hrr ? "retry " : "server");
            std::cout << "  " << who << " random  : " << h.random << "\n";
            for (const auto& k : h.key_shares)
                std::cout << "  " << who << " key share: " << group_id_name(k.group) << ", "
                          << k.len << " bytes, " << (k.hex.empty() ? "(none)" : shorten(k.hex)) << "\n";
        }
        for (const auto& line : r.trace.keylog) {
            auto x = line.find(' ');
            auto y = x == std::string::npos ? x : line.find(' ', x + 1);
            std::cout << "  " << line.substr(0, x) << "\n      "
                      << (y == std::string::npos ? line : line.substr(y + 1)) << "\n";
        }
    }
    std::string keylog_file = a.get("--keylog");
    if (!keylog_file.empty()) {
        std::ofstream f(keylog_file, std::ios::app);
        for (const auto& line : r.trace.keylog) f << line << "\n";
        std::cout << "\nWrote " << r.trace.keylog.size() << " secret line(s) to " << keylog_file << "\n";
    }
    return 0;
}
