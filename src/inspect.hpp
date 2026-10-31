// ==========================================================================
// FILE: inspect.hpp                          LAYER: engine for the dashboard (declarations)
//
// WHAT THIS FILE IS FOR
//   Declares the fully instrumented handshake used by the live dashboard:
//   it records timings, every message, parsed hellos and the certificate
//   chain, and converts everything to JSON for the browser.
//
// NAMESPACE
//   tlsf
//
// TYPES
//   struct InspectOptions
//       alpn              Protocols to offer like a browser ("h2", "http/1.1").
//       wait_for_tickets  Linger briefly after the handshake to catch
//                         NewSessionTicket messages.
//       timeout_ms        Upper limit for every network wait (default 6 s).
//   struct CertInfo
//       One certificate: subject, issuer, key type/curve or size, signature
//       algorithm, validity dates, first DNS names (sans) and their total.
//   struct InspectResult
//       Everything the dashboard shows: ok / rejected_locally / error,
//       host, port, resolved IP, DNS/TCP/TLS times, negotiated values,
//       chosen ALPN, the Trace, parsed hellos, certificate chain,
//       verification verdict, and a copy of the ClientConfig.
//
// FUNCTIONS (defined in inspect.cpp)
//   InspectResult inspect(const ClientConfig&, const InspectOptions& = {})
//       One timed, fully recorded handshake. Records the certificate
//       verdict instead of aborting, so a bad chain is still visible.
//   std::string to_json(const InspectResult&)
//       Converts the result to the JSON returned by /api/handshake.
// ==========================================================================

#pragma once

#include "client_core.hpp"

#include <string>
#include <vector>

namespace tlsf
{

	struct InspectOptions
	{
	    std::vector<std::string> alpn{"h2", "http/1.1"};
	    bool wait_for_tickets = true;
	    int timeout_ms = 6000;
	};

	struct CertInfo
	{
	    std::string subject, issuer, key, sigalg, not_before, not_after;
	    std::vector<std::string> sans;
	    size_t san_total = 0;
	};

	struct InspectResult
	{
	    bool ok = false;
	    bool rejected_locally = false;
	    std::string error;
	    std::string host, port, ip;
	    double dns_ms = 0, tcp_ms = 0, tls_ms = 0;
	    Negotiated neg;
	    std::string alpn;
	    Trace trace;
	    std::vector<HelloInfo> hellos;
	    std::vector<CertInfo> chain;
	    bool verify_ok = false;
	    std::string verify;
	    ClientConfig cfg;
	};

	InspectResult inspect(const ClientConfig& cfg, const InspectOptions& opt = {});
	std::string to_json(const InspectResult& r);

}
