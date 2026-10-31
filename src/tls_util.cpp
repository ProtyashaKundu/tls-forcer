// ==========================================================================
// FILE: tls_util.cpp                         LAYER: toolbox (implementation)
//
// WHAT THIS FILE DOES
//   Makes the handshake visible. OpenSSL performs the handshake; this file
//   records each message, decodes the hello messages byte by byte, spots
//   retries, translates wire numbers into names, and reports the result.
//
// NAMESPACES
//   tlsf
//       All public toolbox functions.
//   (anonymous namespace, inside tlsf)
//       The byte-parsing helpers used only by parse_hello().
//   file-static items (marked `static`)
//       hex16, kHrrRandom, msg_cb, nid_name, sig_desc: private to this file.
//
// ERRORS AND PROVIDERS
//   openssl_errors()
//       Pops every code from OpenSSL's per-thread error queue and joins
//       the text versions with "; ". Also empties the queue.
//   load_providers(names)
//       Loads "default" first (loading any provider disables the implicit
//       default one), then each requested provider such as oqsprovider.
//
// NAME TRANSLATION
//   hex16(id)                Format as "0x001d" when no name is known.
//   to_hex(p, n)             Any bytes -> lowercase hex (randoms, key shares).
//   is_grease(id)            GREASE pattern: both bytes equal, low nibble 0xA.
//   group_id_name(id)        Table: classic curves, FFDHE, ML-KEM and hybrids.
//   sigalg_id_name(id)       Table: ECDSA, RSA-PSS, RSA-PKCS1, EdDSA, ML-DSA.
//   cipher_id_name(id)       Asks OpenSSL (SSL_CIPHER_find) for the IANA name.
//   ext_name(id)             Table: extension numbers (0 SNI, 10 groups,
//                            13 sigalgs, 16 ALPN, 43 versions, 51 key_share).
//   handshake_type_name(t,h) Message type number -> name.
//
// RECORDING (THE WIRETAP)
//   kHrrRandom[32]
//       SHA-256("HelloRetryRequest") from RFC 8446 section 4.1.3. A ServerHello
//       whose random equals this value is really a HelloRetryRequest.
//   msg_cb(...)
//       Called by OpenSSL for every message. Keeps handshake, CCS and alert
//       records; stores direction, type, size and time; counts ClientHellos;
//       detects HRR by comparing bytes 6..37 with kHrrRandom (offset 6 =
//       type 1 + length 3 + legacy_version 2); copies raw hellos.
//   keylog_cb(ssl, line)
//       OpenSSL's key-log callback. Each time a secret is derived it hands
//       over one line "LABEL client_random secret" (the SSLKEYLOGFILE format
//       Wireshark reads). The line is stored in the Trace found through
//       SSL_get_app_data. TLS 1.3 gives five lines (handshake, traffic and
//       exporter secrets); TLS 1.2 gives one (CLIENT_RANDOM = master secret).
//   attach_trace(ssl, trace)
//       Registers msg_cb with SSL_set_msg_callback (the Trace as its arg),
//       stores the Trace as the connection's app data, and registers
//       keylog_cb on the connection's SSL_CTX.
//
// PARSING (anonymous namespace + parse_hello)
//   struct Reader
//       Cursor over bytes. need(k) checks bounds BEFORE reading; u8()/u16()
//       read big-endian values and advance.
//   u16_list(reader, out, one_byte_len)
//       Reads a length-prefixed list of 2-byte values.
//   parse_ext(hello, type, reader)
//       Decodes the extensions we care about: server_name, supported_groups,
//       signature_algorithms, ALPN, supported_versions, key_share
//       (ClientHello list; ServerHello single share; HRR group only).
//   parse_hello(bytes)
//       Decodes header, legacy_version, random (kept as hex; HRR check),
//       session id,
//       cipher suites (or chosen suite), compression, then each extension.
//
// READING THE RESULT
//   nid_name(nid)        OpenSSL NID -> short name ("SHA256").
//   sig_desc(ssl, peer)  Signature used by the peer (or us), e.g.
//                        "ECDSA + SHA256" (no hash shown for EdDSA).
//   describe(ssl)        Version, cipher, group (version-dependent API via
//                        #if for OpenSSL >= 3.2), signatures, and the IANA
//                        signature-scheme name used by the dashboard.
//   to_string(neg, trace)  Terminal output block used by the CLI tools.
//
// UTILITIES
//   split(s, sep), join(v, sep)
//       Split "a:b:c" into pieces (skipping empty ones) / join them back.
//   Args::flag, Args::get, Args::get_any, Args::all
//       Command-line parsing: presence of a flag, the value after a flag
//       (with default), the first of several aliases, every repeated value.
// ==========================================================================

#include "tls_util.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace tlsf {

std::string openssl_errors()
{
    std::string out;
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof buf);
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? "(no OpenSSL error recorded)" : out;
}

static std::string hex16(uint16_t id)
{
    std::ostringstream o;
    o << "0x" << std::hex << std::setw(4) << std::setfill('0') << id;
    return o.str();
}

std::string to_hex(const unsigned char* p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t k = 0; k < n; ++k) {
        out += digits[p[k] >> 4];
        out += digits[p[k] & 0x0f];
    }
    return out;
}

bool is_grease(uint16_t id)
{
    return (id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff);
}

std::string group_id_name(uint16_t id)
{
    static const std::map<uint16_t, const char*> names = {
        {0x0017, "secp256r1"},      {0x0018, "secp384r1"},
        {0x0019, "secp521r1"},      {0x001d, "x25519"},
        {0x001e, "x448"},           {0x0100, "ffdhe2048"},
        {0x0101, "ffdhe3072"},      {0x0102, "ffdhe4096"},
        {0x0103, "ffdhe6144"},      {0x0104, "ffdhe8192"},
        {0x0200, "MLKEM512"},       {0x0201, "MLKEM768"},
        {0x0202, "MLKEM1024"},      {0x11eb, "SecP256r1MLKEM768"},
        {0x11ec, "X25519MLKEM768"}, {0x11ed, "SecP384r1MLKEM1024"},
        {0x6399, "X25519Kyber768Draft00"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : hex16(id);
}

std::string sigalg_id_name(uint16_t id)
{
    static const std::map<uint16_t, const char*> names = {
        {0x0201, "rsa_pkcs1_sha1"},         {0x0203, "ecdsa_sha1"},
        {0x0202, "dsa_sha1"},               {0x0301, "rsa_sha224"},
        {0x0302, "dsa_sha224"},             {0x0303, "ecdsa_sha224"},
        {0x0402, "dsa_sha256"},             {0x0502, "dsa_sha384"},
        {0x0602, "dsa_sha512"},
        {0x0401, "rsa_pkcs1_sha256"},       {0x0501, "rsa_pkcs1_sha384"},
        {0x0601, "rsa_pkcs1_sha512"},       {0x0403, "ecdsa_secp256r1_sha256"},
        {0x0503, "ecdsa_secp384r1_sha384"}, {0x0603, "ecdsa_secp521r1_sha512"},
        {0x0804, "rsa_pss_rsae_sha256"},    {0x0805, "rsa_pss_rsae_sha384"},
        {0x0806, "rsa_pss_rsae_sha512"},    {0x0807, "ed25519"},
        {0x0808, "ed448"},                  {0x0809, "rsa_pss_pss_sha256"},
        {0x080a, "rsa_pss_pss_sha384"},     {0x080b, "rsa_pss_pss_sha512"},
        {0x0904, "mldsa44"},                {0x0905, "mldsa65"},
        {0x0906, "mldsa87"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : hex16(id);
}

void load_providers(const std::vector<std::string>& names) {
    if (names.empty()) return;
    if (!OSSL_PROVIDER_load(nullptr, "default"))
        throw std::runtime_error("cannot load default provider: " + openssl_errors());
    for (const auto& n : names)
        if (!OSSL_PROVIDER_load(nullptr, n.c_str()))
            throw std::runtime_error("cannot load provider '" + n + "': " + openssl_errors());
}

static const unsigned char kHrrRandom[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

static void msg_cb(int write_p, int , int content_type, const void* buf, size_t len, SSL* , void* arg)
{
    if (len < 1) return;
    if (content_type != SSL3_RT_HANDSHAKE && content_type != SSL3_RT_CHANGE_CIPHER_SPEC &&
        content_type != SSL3_RT_ALERT)
        return;
    auto* t = static_cast<Trace*>(arg);
    auto* p = static_cast<const unsigned char*>(buf);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t->t0).count();

    int detail = 0;
    bool hrr = false;
    if (content_type == SSL3_RT_HANDSHAKE) {
        detail = p[0];
        if (p[0] == SSL3_MT_CLIENT_HELLO) t->client_hellos++;
        if (p[0] == SSL3_MT_SERVER_HELLO && len >= 38 && std::memcmp(p + 6, kHrrRandom, 32) == 0)
            hrr = t->hrr = true;
        if (p[0] == SSL3_MT_CLIENT_HELLO || p[0] == SSL3_MT_SERVER_HELLO)
            t->hellos.emplace_back(p, p + len);
    }
    else if (content_type == SSL3_RT_ALERT && len >= 2)
    {
        detail = p[1];
    }
    t->events.push_back({write_p != 0, content_type, detail, hrr, len, ms});
}

std::string cipher_id_name(uint16_t id)
{
    if (is_grease(id)) return "GREASE";
    if (id == 0x00ff) return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    static SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    static SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    unsigned char b[2] = {static_cast<unsigned char>(id >> 8), static_cast<unsigned char>(id & 0xff)};
    if (const SSL_CIPHER* c = ssl ? SSL_CIPHER_find(ssl, b) : nullptr)
        if (const char* n = SSL_CIPHER_standard_name(c)) return n;
    return hex16(id);
}

std::string ext_name(uint16_t id)
{
    static const std::map<uint16_t, const char*> names = {
        {0, "server_name"},          {5, "status_request"},
        {10, "supported_groups"},    {11, "ec_point_formats"},
        {13, "signature_algorithms"},{16, "alpn"},
        {18, "signed_cert_timestamp"},{21, "padding"},
        {22, "encrypt_then_mac"},    {23, "extended_master_secret"},
        {27, "compress_certificate"},{35, "session_ticket"},
        {41, "pre_shared_key"},      {42, "early_data"},
        {43, "supported_versions"},  {44, "cookie"},
        {45, "psk_key_exchange_modes"},{49, "post_handshake_auth"},
        {50, "signature_algorithms_cert"},{51, "key_share"},
        {17513, "application_settings"},{65037, "encrypted_client_hello"},
        {65281, "renegotiation_info"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : std::to_string(id);
}

std::string handshake_type_name(int type, bool hrr) {
    switch (type) {
        case 1: return "ClientHello";
        case 2: return hrr ? "HelloRetryRequest" : "ServerHello";
        case 4: return "NewSessionTicket";
        case 8: return "EncryptedExtensions";
        case 11: return "Certificate";
        case 12: return "ServerKeyExchange";
        case 13: return "CertificateRequest";
        case 14: return "ServerHelloDone";
        case 15: return "CertificateVerify";
        case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        case 22: return "CertificateStatus";
        case 24: return "KeyUpdate";
        default: return "Handshake(" + std::to_string(type) + ")";
    }
}

namespace
{
	struct Reader
	{
	    const unsigned char* p;
	    size_t n, i = 0;
	    bool need(size_t k) const
	    {
	    	return i + k <= n;
	    }
	    uint8_t u8()
	    {
	    	return p[i++];
	    }
	    uint16_t u16()
	    {
	    	uint16_t v = static_cast<uint16_t>((p[i] << 8) | p[i + 1]); i += 2; return v;
	    }
	};

	void u16_list(Reader& e, std::vector<uint16_t>& out, bool one_byte_len) {
	    if (!e.need(one_byte_len ? 1 : 2)) return;
	    size_t len = one_byte_len ? e.u8() : e.u16();
	    size_t end = std::min(e.n, e.i + len);
	    while (e.i + 2 <= end) out.push_back(e.u16());
	}

	void parse_ext(HelloInfo& h, uint16_t type, Reader e) {
	    switch (type)
	    {
		  case 0:
		      if (e.need(5))
		       {
		          e.u16(); e.u8();
		          size_t l = e.u16();
		          if (e.need(l)) h.sni.assign(reinterpret_cast<const char*>(e.p + e.i), l);
			}
		      break;
		  case 10: u16_list(e, h.groups, false); break;
		  case 13: u16_list(e, h.sigalgs, false); break;
		  case 16:
		      if (e.need(2))
		      {
		          size_t list_len = e.u16();
		          size_t end = std::min(e.n, e.i + list_len);
		          while (e.i < end)
		          {
		              size_t l = e.u8();
		              if (e.i + l > end) break;
		              h.alpn.emplace_back(reinterpret_cast<const char*>(e.p + e.i), l);
		              e.i += l;
		          }
		      }
		      break;
		  case 43:
		      if (h.client) u16_list(e, h.versions, true);
		      else if (e.need(2)) h.versions.push_back(e.u16());
		      break;
		  case 51:
		      if (h.client)
		      {
		          if (!e.need(2)) break;
		          size_t list_len = e.u16();
		          size_t end = std::min(e.n, e.i + list_len);
		          while (e.i + 4 <= end) {
		              uint16_t g = e.u16();
		              size_t l = e.u16();
		              h.key_shares.push_back({g, l, e.need(l) ? to_hex(e.p + e.i, l) : std::string()});
		              e.i += l;
		          }
		      }
		      else if (e.need(2))
		      {
		          uint16_t g = e.u16();
		          size_t l = e.need(2) ? e.u16() : 0;
		          h.key_shares.push_back({g, l, e.need(l) ? to_hex(e.p + e.i, l) : std::string()});
		      }
		      break;
	    }
	}
	}

	HelloInfo parse_hello(const std::vector<unsigned char>& m)
	{
	    HelloInfo h;
	    h.length = m.size();
	    if (m.size() < 4 || (m[0] != 1 && m[0] != 2)) return h;
	    h.client = m[0] == 1;
	    size_t body = (static_cast<size_t>(m[1]) << 16) | (m[2] << 8) | m[3];
	    Reader r{m.data() + 4, std::min(body, m.size() - 4)};
	    if (!r.need(2 + 32 + 1)) return h;
	    r.i += 2;
	    if (!h.client && std::memcmp(r.p + r.i, kHrrRandom, 32) == 0) h.hrr = true;
	    h.random = to_hex(r.p + r.i, 32);
	    r.i += 32;
	    size_t sid = r.u8();
	    if (!r.need(sid)) return h;
	    r.i += sid;
	    if (h.client) {
		  if (!r.need(2)) return h;
		  size_t cl = r.u16();
		  if (!r.need(cl)) return h;
		  for (size_t k = 0; k + 1 < cl; k += 2)
		      h.suites.push_back(static_cast<uint16_t>((r.p[r.i + k] << 8) | r.p[r.i + k + 1]));
		  r.i += cl;
		  if (!r.need(1)) return h;
		  size_t comp = r.u8();
		  if (!r.need(comp)) return h;
		  r.i += comp;
	    } else {
		  if (!r.need(3)) return h;
		  h.suites.push_back(r.u16());
		  r.i += 1;
	    }
	    h.ok = true;
	    if (!r.need(2)) return h;
	    size_t ext_len = r.u16();
	    size_t end = std::min(r.n, r.i + ext_len);
	    while (r.i + 4 <= end) {
		  uint16_t t = r.u16();
		  size_t l = r.u16();
		  if (r.i + l > end) break;
		  h.extensions.push_back(t);
		  parse_ext(h, t, Reader{r.p + r.i, l});
		  r.i += l;
	    }
	    return h;
	}

	static void keylog_cb(const SSL* ssl, const char* line)
	{
	    auto* t = static_cast<Trace*>(SSL_get_app_data(ssl));
	    if (t && line) t->keylog.emplace_back(line);
	}

	void attach_trace(SSL* ssl, Trace* trace)
	{
	    SSL_set_msg_callback(ssl, msg_cb);
	    SSL_set_msg_callback_arg(ssl, trace);
	    SSL_set_app_data(ssl, trace);
	    SSL_CTX_set_keylog_callback(SSL_get_SSL_CTX(ssl), keylog_cb);
	}

	static std::string nid_name(int nid)
	{
	    if (nid == NID_undef) return "unknown";
	    const char* sn = OBJ_nid2sn(nid);
	    return sn ? sn : "nid:" + std::to_string(nid);
	}

	static std::string sig_desc(SSL* s, bool peer)
	{
	    int type = NID_undef, hash = NID_undef;
	    int ok = peer ? SSL_get_peer_signature_type_nid(s, &type)
		            : SSL_get_signature_type_nid(s, &type);
	    if (!ok) return "(none)";
	    if (peer) SSL_get_peer_signature_nid(s, &hash);
	    else SSL_get_signature_nid(s, &hash);
	    std::string r = type == EVP_PKEY_EC        ? "ECDSA"
		            : type == EVP_PKEY_RSA       ? "RSA-PKCS1"
		            : type == EVP_PKEY_RSA_PSS   ? "RSA-PSS"
		            : type == NID_rsassaPss      ? "RSA-PSS"
		            : type == EVP_PKEY_ED25519   ? "Ed25519"
		            : type == EVP_PKEY_ED448     ? "Ed448"
		                                         : nid_name(type);
	    if (hash != NID_undef && type != EVP_PKEY_ED25519 && type != EVP_PKEY_ED448)
		  r += " + " + nid_name(hash);
	    return r;
	}

	Negotiated describe(SSL* s)
	{
	    Negotiated n;
	    n.version = SSL_get_version(s);
	    n.cipher = SSL_CIPHER_standard_name(SSL_get_current_cipher(s));
	#if OPENSSL_VERSION_NUMBER >= 0x30200000L
	    const char* g = SSL_get0_group_name(s);
	    n.group = g ? g : "(none)";
	#else
	    int nid = SSL_get_negotiated_group(s);
	    if (nid == NID_undef) n.group = "(none)";
	    else if (nid & TLSEXT_nid_unknown) n.group = group_id_name(nid & 0xffff);
	    else n.group = nid_name(nid);
	#endif
	    n.peer_sig = sig_desc(s, true);
	    n.own_sig = sig_desc(s, false);

	    int type = NID_undef, hash = NID_undef;
	    if (SSL_get_peer_signature_type_nid(s, &type))
	    {
		  SSL_get_peer_signature_nid(s, &hash);
		  const char* h = hash == NID_sha256 ? "sha256" : hash == NID_sha384 ? "sha384"
		                : hash == NID_sha512 ? "sha512" : hash == NID_sha1 ? "sha1" : "";
		  if (type == EVP_PKEY_ED25519) n.peer_sig_iana = "ed25519";
		  else if (type == EVP_PKEY_ED448) n.peer_sig_iana = "ed448";
		  else if (type == EVP_PKEY_EC)
		      n.peer_sig_iana = hash == NID_sha256 ? "ecdsa_secp256r1_sha256"
		                      : hash == NID_sha384 ? "ecdsa_secp384r1_sha384"
		                      : hash == NID_sha512 ? "ecdsa_secp521r1_sha512" : "ecdsa_sha1";
		  else if (type == EVP_PKEY_RSA_PSS || type == NID_rsassaPss)
		      n.peer_sig_iana = std::string("rsa_pss_rsae_") + h;
		  else if (type == EVP_PKEY_RSA)
		      n.peer_sig_iana = std::string("rsa_pkcs1_") + h;
	    }
	    return n;
	}

	std::string to_string(const Negotiated& n, const Trace& t)
	{
	    std::ostringstream o;
	    o << "  protocol      : " << n.version << "\n"
		<< "  cipher suite  : " << n.cipher << "\n"
		<< "  key exchange  : " << n.group << "\n"
		<< "  peer signed   : " << n.peer_sig << "\n";
	    if (n.own_sig != "(none)") o << "  we signed     : " << n.own_sig << "\n";
	    o
		<< "  HelloRetryReq : " << (t.hrr ? "YES (first key share was rejected)" : "no")
		<< "\n"
		<< "  ClientHellos  : " << t.client_hellos << "\n";
	    return o.str();
	}

	std::vector<std::string> split(const std::string& s, char sep)
	{
	    std::vector<std::string> out;
	    std::string cur;
	    std::istringstream in(s);
	    while (std::getline(in, cur, sep))
		  if (!cur.empty()) out.push_back(cur);
	    return out;
	}

	std::string join(const std::vector<std::string>& v, const std::string& sep)
	{
	    std::string out;
	    for (size_t i = 0; i < v.size(); ++i) out += (i ? sep : "") + v[i];
	    return out;
	}

	bool Args::flag(const std::string& name) const
	{
	    for (const auto& t : tok_)
		  if (t == name) return true;
	    return false;
	}

	std::string Args::get(const std::string& name, const std::string& def) const
	{
	    for (size_t i = 0; i + 1 < tok_.size(); ++i)
		  if (tok_[i] == name) return tok_[i + 1];
	    return def;
	}

	std::string Args::get_any(const std::vector<std::string>& names, const std::string& def) const
	{
	    for (const auto& n : names)
	    {
		  std::string v = get(n);
		  if (!v.empty()) return v;
	    }
	    return def;
	}

	std::vector<std::string> Args::all(const std::string& name) const
	{
	    std::vector<std::string> out;
	    for (size_t i = 0; i + 1 < tok_.size(); ++i)
		  if (tok_[i] == name) out.push_back(tok_[i + 1]);
	    return out;
	}
}
