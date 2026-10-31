// ==========================================================================
// FILE: tls_probe.cpp                        LAYER: program (command line)
//
// WHAT THIS PROGRAM DOES
//   Maps what a server accepts. One handshake reveals only ONE choice, so
//   this program offers each candidate ALONE, one handshake per candidate,
//   and records YES / NO / not supported locally. It then offers two
//   options in both orders to find out whose preference the server follows.
//     ./tls_probe --host google.com
//     ./tls_probe --host cloudflare.com --tls12
//
// NAMESPACES
//   uses tlsf (via `using namespace tlsf;`).
//   (anonymous namespace)  Private constants and helpers.
//
// CONSTANTS AND TYPES (anonymous namespace)
//   kDefaultGroups, kDefaultSigalgs, kDefaultSuites13
//       Candidate lists, including post-quantum names (ML-KEM, ML-DSA).
//   enum class Axis { Group, Sigalg, Suite }
//       Which part of the menu is being tested.
//
// FUNCTIONS (anonymous namespace)
//   base_config(args)
//       Starting ClientConfig: target from flags, certificate verification
//       off (we study negotiation, not trust), version pinned to TLS 1.3
//       (or TLS 1.2 with --tls12).
//   set_axis(config, axis, value)
//       Puts a value into the right menu field for that axis.
//   chosen(result, axis)
//       Reads back what the server picked for that axis.
//   probe_axis(args, axis, title, list)
//       The loop: for each candidate, force only that one, run_handshake(),
//       print "--" (our OpenSSL can't offer it), "NO" (server refused) or
//       "YES" + what was used (+ [HRR] if a retry happened).
//   preference_test(args, axis, title, x, y)
//       Offers "x:y" then "y:x". Same pick both times = SERVER preference;
//       pick follows our order = CLIENT preference.
//
//   int main(argc, argv)
//       Baseline handshake with OpenSSL's defaults, then probes groups,
//       signature schemes and TLS 1.3 suites, then the preference tests.
// ==========================================================================

#include "client_core.hpp"
#include <iomanip>
#include <iostream>

using namespace tlsf;

namespace
{

	const char* kDefaultGroups =
	    "X25519:X448:P-256:P-384:P-521:ffdhe2048:ffdhe3072:"
	    "X25519MLKEM768:SecP256r1MLKEM768:MLKEM512:MLKEM768:MLKEM1024";
	const char* kDefaultSigalgs =
	    "ed25519:ed448:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
	    "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_pss_sha256:rsa_pkcs1_sha256:"
	    "mldsa44:mldsa65:mldsa87";
	const char* kDefaultSuites13 =
	    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

	enum class Axis { Group, Sigalg, Suite };

	ClientConfig base_config(const Args& a)
	{
	    ClientConfig c;
	    c.host = a.get("--host");
	    c.port = a.get("--port", "443");
	    c.sni = a.get("--sni");
	    c.verify = false;
	    c.min_version = c.max_version = a.flag("--tls12") ? TLS1_2_VERSION : TLS1_3_VERSION;
	    return c;
	}

	void set_axis(ClientConfig& c, Axis axis, const std::string& v)
	{
	    if (axis == Axis::Group) c.groups = v;
	    if (axis == Axis::Sigalg) c.sigalgs = v;
	    if (axis == Axis::Suite) c.ciphersuites = v;
	}

	std::string chosen(const HandshakeResult& r, Axis axis)
	{
	    if (axis == Axis::Group) return r.neg.group;
	    if (axis == Axis::Sigalg) return r.neg.peer_sig;
	    return r.neg.cipher;
	}

	void probe_axis(const Args& a, Axis axis, const std::string& title, const std::string& list)
	{
	    std::cout << "\n== " << title << " (offering one at a time) ==\n";
	    for (const auto& item : split(list, ':'))
	    {
		  ClientConfig c = base_config(a);
		  set_axis(c, axis, item);
		  HandshakeResult r = run_handshake(c);
		  std::cout << "  " << std::left << std::setw(30) << item;
		  if (r.rejected_locally) std::cout << "--    not supported by local OpenSSL\n";
		  else if (!r.ok) std::cout << "NO    server refused\n";
		  else
		      std::cout << "YES   " << chosen(r, axis) << (r.trace.hrr ? "  [HRR]" : "") << "\n";
	    }
	}

	void preference_test(const Args& a, Axis axis, const std::string& title, const std::string& x, const std::string& y)
	{
	    ClientConfig c1 = base_config(a), c2 = base_config(a);
	    set_axis(c1, axis, x + ":" + y);
	    set_axis(c2, axis, y + ":" + x);
	    HandshakeResult r1 = run_handshake(c1), r2 = run_handshake(c2);
	    std::cout << "  " << std::left << std::setw(14) << title;
	    if (!r1.ok || !r2.ok)
	    {
		  std::cout << "inconclusive (server must accept both " << x << " and " << y << ")\n";
		  return;
	    }
	    std::string p1 = chosen(r1, axis), p2 = chosen(r2, axis);
	    std::cout << x << ":" << y << " -> " << p1 << "   |   " << y << ":" << x << " -> " << p2
		        << "   => " << (p1 == p2 ? "SERVER preference" : "CLIENT preference") << "\n";
	}

}

int main(int argc, char** argv) {
    Args a(argc, argv);
    if (a.get("--host").empty()) {
        std::cerr << "usage: tls_probe --host H [--port P] [--tls12] [--provider NAME]\n"
                     "                 [--groups LIST] [--sigalgs LIST] [--ciphersuites LIST]\n"
                     "                 [--pref-groups A:B] [--pref-suites A:B]\n";
        return 2;
    }
    try {
        load_providers(a.all("--provider"));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    HandshakeResult base = run_handshake(base_config(a));
    std::cout << "Target " << a.get("--host") << ":" << a.get("--port", "443") << "\n";
    if (!base.ok) {
        std::cout << "Baseline handshake failed: " << base.error << "\n";
        return 1;
    }
    std::cout << "\n== Baseline (OpenSSL default offer) ==\n" << to_string(base.neg, base.trace);

    probe_axis(a, Axis::Group, "Key exchange groups", a.get("--groups", kDefaultGroups));
    probe_axis(a, Axis::Sigalg, "Signature schemes", a.get("--sigalgs", kDefaultSigalgs));
    if (!a.flag("--tls12"))
        probe_axis(a, Axis::Suite, "TLS 1.3 cipher suites", a.get("--ciphersuites", kDefaultSuites13));

    std::cout << "\n== Whose preference wins? ==\n";
    auto pg = split(a.get("--pref-groups", "X25519:P-256"), ':');
    auto ps = split(a.get("--pref-suites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"), ':');
    if (pg.size() == 2) preference_test(a, Axis::Group, "groups", pg[0], pg[1]);
    if (ps.size() == 2 && !a.flag("--tls12")) preference_test(a, Axis::Suite, "suites", ps[0], ps[1]);
    std::cout << "  (group order also decides which key share is sent, so a group\n"
                 "   result can reflect 'server accepted the share it got'.)\n";
    return 0;
}
