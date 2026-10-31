// ==========================================================================
// FILE: tls_dashboard.cpp                    LAYER: program (local web server + API)
//
// WHAT THIS PROGRAM DOES
//   A browser cannot run raw TLS handshakes or see handshake messages, so
//   this program does the real handshakes with OpenSSL and serves the
//   dashboard page plus a small JSON API. It listens on 127.0.0.1 only.
//     ./tls_dashboard            then open http://localhost:8088 in Chrome
//
// ENDPOINTS (all GET)
//   /                the dashboard page (embedded at build time)
//   /api/info        local OpenSSL version + which algorithms it can offer
//   /api/handshake   ?host=&port=&version=1.2|1.3&groups=&sigalgs=&suites=&ciphers=
//   /api/probe       ?host=&port=&axis=groups|sigalgs|suites13|suites12|pref
//
// NAMESPACES
//   uses tlsf (via `using namespace tlsf;`).
//   J                Short alias for tlsf::json.
//   (anonymous namespace)  Private types, lists and helpers below.
//
// TYPES AND DATA (anonymous namespace)
//   Query            std::map of URL parameters (key -> value).
//   kGroups, kSigalgs, kSuites13, kSuites12
//                    Candidate lists offered and probed by the dashboard.
//   enum class Kind  Group, Sigalg, Suite13 or Suite12.
//
// FUNCTIONS (anonymous namespace)
//   locally_supported(kind, name)
//       Can OUR OpenSSL put this name in a ClientHello? Used to grey out
//       post-quantum buttons on older OpenSSL.
//   url_decode(s), parse_query(qs), get(q, key, def)
//       Decode "%3A"/"+" and read URL parameters.
//   base_config(q)
//       Builds a ClientConfig; accepts "google.com", a full URL, or host:port.
//   api_info()       JSON: OpenSSL version + supported flag for every candidate.
//   api_handshake(q) Calls inspect() and returns to_json(); logs one line.
//   api_probe(q)     One handshake per candidate for the chosen axis, or the
//                    "who decides?" test (A:B vs B:A) when axis=pref.
//   send_all(fd, s)  Send everything, looping over partial sends.
//   respond(fd, code, type, body)
//                    Writes an HTTP/1.1 response by hand (Content-Length,
//                    no-store, Connection: close).
//   read_file(path)  Load a file (for --web live editing of the page).
//   handle(fd, web_file)
//                    Reads one request (3-second timeout), routes it to the
//                    page or an API function, and turns exceptions into a
//                    JSON error instead of crashing.
//
//   int main(argc, argv)
//       Ignores SIGPIPE, loads providers, binds 127.0.0.1:8088 (or --port),
//       then serves requests one at a time forever.
// ==========================================================================

#include "dashboard_html.hpp"
#include "inspect.hpp"
#include "json.hpp"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

using namespace tlsf;
namespace J = tlsf::json;

namespace {

using Query = std::map<std::string, std::string>;

const std::vector<std::string> kGroups = {
    "X25519", "X448", "P-256", "P-384", "P-521", "ffdhe2048", "ffdhe3072", "ffdhe4096",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024"};
const std::vector<std::string> kSigalgs = {
    "ed25519", "ed448", "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384", "mldsa44", "mldsa65", "mldsa87"};
const std::vector<std::string> kSuites13 = {
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256"};
const std::vector<std::string> kSuites12 = {
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256", "AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA"};

enum class Kind { Group, Sigalg, Suite13, Suite12 };

bool locally_supported(Kind k, const std::string& name) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    int ok = k == Kind::Group    ? SSL_CTX_set1_groups_list(ctx, name.c_str())
           : k == Kind::Sigalg   ? SSL_CTX_set1_sigalgs_list(ctx, name.c_str())
           : k == Kind::Suite13  ? SSL_CTX_set_ciphersuites(ctx, name.c_str())
                                 : SSL_CTX_set_cipher_list(ctx, name.c_str());
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ok == 1;
}

std::string url_decode(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') o += ' ';
        else if (s[i] == '%' && i + 2 < s.size()) {
            o += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else o += s[i];
    }
    return o;
}

Query parse_query(const std::string& qs) {
    Query q;
    for (const auto& kv : split(qs, '&')) {
        auto eq = kv.find('=');
        if (eq == std::string::npos) q[url_decode(kv)] = "";
        else q[url_decode(kv.substr(0, eq))] = url_decode(kv.substr(eq + 1));
    }
    return q;
}

std::string get(const Query& q, const std::string& k, const std::string& def = "") {
    auto it = q.find(k);
    return it == q.end() || it->second.empty() ? def : it->second;
}

ClientConfig base_config(const Query& q) {
    ClientConfig c;
    std::string h = get(q, "host", "google.com");
    if (auto p = h.find("://"); p != std::string::npos) h = h.substr(p + 3);
    if (auto p = h.find_first_of("/?#"); p != std::string::npos) h = h.substr(0, p);
    c.port = get(q, "port", "443");
    if (auto p = h.rfind(':'); p != std::string::npos && h.find(':') == p) {
        c.port = h.substr(p + 1);
        h = h.substr(0, p);
    }
    c.host = h;
    std::string v = get(q, "version");
    if (v == "1.2") c.min_version = c.max_version = TLS1_2_VERSION;
    if (v == "1.3") c.min_version = TLS1_3_VERSION;
    return c;
}

std::string api_info() {
    auto list = [](Kind k, const std::vector<std::string>& names) {
        return J::arr(names, [k](const std::string& n) {
            return J::obj({{"name", J::str(n)}, {"supported", J::boolean(locally_supported(k, n))}});
        });
    };
    return J::obj({{"openssl", J::str(OpenSSL_version(OPENSSL_VERSION))},
                   {"groups", list(Kind::Group, kGroups)},
                   {"sigalgs", list(Kind::Sigalg, kSigalgs)},
                   {"suites13", list(Kind::Suite13, kSuites13)},
                   {"suites12", list(Kind::Suite12, kSuites12)}});
}

std::string api_handshake(const Query& q) {
    ClientConfig c = base_config(q);
    c.groups = get(q, "groups");
    c.sigalgs = get(q, "sigalgs");
    c.ciphersuites = get(q, "suites");
    c.cipher_list = get(q, "ciphers");
    InspectResult r = inspect(c);
    std::cout << "  " << c.host << ":" << c.port << "  groups=" << (c.groups.empty() ? "default" : c.groups)
              << " sigalgs=" << (c.sigalgs.empty() ? "default" : c.sigalgs) << "  -> "
              << (r.ok ? r.neg.version + " " + r.neg.group + " " + r.neg.peer_sig : "FAILED") << "\n";
    return to_json(r);
}

std::string api_probe(const Query& q) {
    std::string axis = get(q, "axis", "groups");
    InspectOptions opt;
    opt.wait_for_tickets = false;

    if (axis == "pref") {
        struct Test { std::string what; Kind k; std::string a, b; };
        std::vector<Test> tests = {
            {"Cipher suite (TLS 1.3)", Kind::Suite13, "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
            {"Cipher suite (TLS 1.3)", Kind::Suite13, "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
            {"Key exchange group", Kind::Group, "X25519", "P-256"},
            {"Signature scheme", Kind::Sigalg, "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"},
        };
        std::vector<std::string> out;
        for (const auto& t : tests) {
            std::string picks[2];
            bool ok = true;
            for (int i = 0; i < 2; ++i) {
                ClientConfig c = base_config(q);
                std::string list = i == 0 ? t.a + ":" + t.b : t.b + ":" + t.a;
                if (t.k == Kind::Suite13) { c.ciphersuites = list; c.min_version = TLS1_3_VERSION; }
                if (t.k == Kind::Group) c.groups = list;
                if (t.k == Kind::Sigalg) c.sigalgs = list;
                InspectResult r = inspect(c, opt);
                ok = ok && r.ok;
                picks[i] = !r.ok ? "failed"
                         : t.k == Kind::Group  ? r.neg.group
                         : t.k == Kind::Sigalg ? r.neg.peer_sig_iana
                                               : r.neg.cipher;
            }
            std::string verdict = !ok ? "inconclusive" : picks[0] == picks[1] ? "server" : "client";
            out.push_back(J::obj({{"what", J::str(t.what)}, {"a", J::str(t.a)}, {"b", J::str(t.b)},
                                  {"ab", J::str(picks[0])}, {"ba", J::str(picks[1])},
                                  {"verdict", J::str(verdict)}}));
        }
        return J::obj({{"axis", J::str(axis)}, {"pref", J::arr(out)}});
    }

    Kind k = axis == "sigalgs" ? Kind::Sigalg : axis == "suites13" ? Kind::Suite13
           : axis == "suites12" ? Kind::Suite12 : Kind::Group;
    const auto& names = k == Kind::Sigalg ? kSigalgs : k == Kind::Suite13 ? kSuites13
                      : k == Kind::Suite12 ? kSuites12 : kGroups;
    std::vector<std::string> out;
    for (const auto& n : names) {
        std::string status, chosen;
        bool hrr = false;
        double ms = 0;
        if (!locally_supported(k, n)) {
            status = "local";
        } else {
            ClientConfig c = base_config(q);
            if (k == Kind::Group) c.groups = n;
            if (k == Kind::Sigalg) c.sigalgs = n;
            if (k == Kind::Suite13) { c.ciphersuites = n; c.min_version = TLS1_3_VERSION; c.max_version = 0; }
            if (k == Kind::Suite12) { c.cipher_list = n; c.min_version = c.max_version = TLS1_2_VERSION; }
            InspectResult r = inspect(c, opt);
            status = r.ok ? "ok" : "refused";
            hrr = r.trace.hrr;
            ms = r.tls_ms;
            if (r.ok) chosen = r.neg.version + " · " + r.neg.cipher + " · " + r.neg.group + " · " + r.neg.peer_sig;
            else chosen = r.error;
        }
        out.push_back(J::obj({{"item", J::str(n)}, {"status", J::str(status)}, {"detail", J::str(chosen)},
                              {"hrr", J::boolean(hrr)}, {"ms", J::num(ms)}}));
    }
    return J::obj({{"axis", J::str(axis)}, {"items", J::arr(out)}});
}

void send_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return;
        off += static_cast<size_t>(n);
    }
}

void respond(int fd, int code, const std::string& type, const std::string& body) {
    std::ostringstream h;
    h << "HTTP/1.1 " << code << (code == 200 ? " OK" : code == 204 ? " No Content" : " Not Found") << "\r\n"
      << "Content-Type: " << type << "\r\nContent-Length: " << body.size()
      << "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    send_all(fd, h.str() + body);
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void handle(int fd, const std::string& web_file) {
    timeval tv{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    std::string req;
    char buf[4096];
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        req.append(buf, static_cast<size_t>(n));
    }
    std::istringstream line(req.substr(0, req.find("\r\n")));
    std::string method, target;
    line >> method >> target;
    std::string path = target.substr(0, target.find('?'));
    Query q = target.find('?') == std::string::npos ? Query{} : parse_query(target.substr(target.find('?') + 1));

    try {
        if (path == "/" || path == "/index.html")
            respond(fd, 200, "text/html; charset=utf-8", web_file.empty() ? kDashboardHtml : read_file(web_file));
        else if (path == "/api/info") respond(fd, 200, "application/json", api_info());
        else if (path == "/api/handshake") respond(fd, 200, "application/json", api_handshake(q));
        else if (path == "/api/probe") respond(fd, 200, "application/json", api_probe(q));
        else if (path == "/favicon.ico") respond(fd, 204, "text/plain", "");
        else respond(fd, 404, "text/plain", "not found");
    } catch (const std::exception& e) {
        respond(fd, 200, "application/json", J::obj({{"ok", "false"}, {"error", J::str(e.what())}}));
    }
}

}

int main(int argc, char** argv) {
    Args a(argc, argv);
    if (a.flag("--help") || a.flag("-h")) {
        std::cerr << "usage: tls_dashboard [--port 8088] [--provider oqsprovider] [--web web/dashboard.html]\n"
                     "  --web FILE   serve the page from disk instead of the built-in copy (for editing)\n";
        return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    try {
        load_providers(a.all("--provider"));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    int port = std::stoi(a.get("--port", "8088"));
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 || listen(s, 32) < 0) {
        std::perror("bind/listen");
        return 1;
    }
    std::cout << "TLS dashboard (" << OpenSSL_version(OPENSSL_VERSION) << ")\n"
              << "Open  http://localhost:" << port << "  in Chrome.  Ctrl+C to stop.\n" << std::flush;

    std::string web_file = a.get("--web");
    for (;;) {
        int c = accept(s, nullptr, nullptr);
        if (c < 0) continue;
        handle(c, web_file);
        close(c);
        std::cout << std::flush;
    }
}
