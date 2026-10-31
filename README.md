# tls-forcer

A C++17 / OpenSSL 3 toolkit to explore **who decides** the key exchange and
signature in a TLS handshake, and how a client can *force* a choice.

The rule: the client **offers** a menu, the server **picks**. A client "forces"
an algorithm by offering exactly one; the server then either uses it or aborts.

| Program       | What it does |
|---------------|--------------|
| `tls_client`  | Handshake with a restricted offer (`--group X25519 --sigalg ed25519`) and print what was negotiated, including HelloRetryRequest detection |
| `tls_server`  | Server with configurable groups/sigalgs/suites and preference mode. Logs each ClientHello (offered) next to its own choice. Answers HTTP GET with that report, so you can point a browser at it |
| `tls_probe`   | Offers every group / signature scheme / suite one at a time to map what a server accepts, then flips list order to detect server- vs client-preference |
| `tls_dashboard` | **Live browser dashboard.** Runs real handshakes to any public server (google.com, youtube.com, …) and animates every message in Chrome |

## Build

```bash
sudo apt install build-essential cmake libssl-dev   # OpenSSL >= 3.0
cmake -S . -B build && cmake --build build -j
./scripts/gen_certs.sh certs                        # CA + ECDSA, Ed25519, RSA certs
```

macOS: `brew install openssl@3 cmake`, then
`cmake -S . -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`.
Homebrew ships OpenSSL 3.5+, which unlocks the post-quantum scenarios.

## Live dashboard (for demos)

```bash
./build/tls_dashboard            # then open http://localhost:8088 in Chrome
```

Chrome's JavaScript can't open raw TLS connections or see handshake messages,
so `tls_dashboard` does the real handshakes with OpenSSL on your machine and
serves the page plus a small JSON API on `127.0.0.1` only.

What the page shows for each handshake:
- **Sequence diagram**: every message with direction, size and timestamp, colour-coded
  plaintext / encrypted / HelloRetryRequest / alert / compat ChangeCipherSpec.
  Click any arrow for a plain-English explanation and its parsed contents
  (menu offered, key shares, chosen suite, certificate, signature).
- **Summary cards**: protocol, key exchange (with key-share sizes), signature, suite, cert key, round trips.
- **Offered → chosen**: the ClientHello menu with the server's picks highlighted.
- **Timing**: DNS / TCP / TLS, and TLS time as a multiple of the network round trip.
- **Certificate chain**: leaf → intermediates → root, verified against your OS trust store.
- **Probes**: which groups / signatures / suites the server accepts, and whether it
  follows its own or the client's preference order.
- **History**: every run in a table; click one to replay it.

**Step mode** (checkbox) reveals one message per click or <kbd>→</kbd>, so you can talk over each arrow.

### Suggested 5-minute talk track

1. **Browser-like default → google.com.** "The client sends a menu; Google picks. One round trip,
   and after ServerHello everything is encrypted, even the certificate."
2. **Force P-256.** Same flow, different key exchange: "the client restricted the menu to one item."
3. **Force Ed25519 (expect failure).** A two-message handshake: ClientHello, then `handshake_failure`.
   "Forcing is only a veto; you can't make Google support something."
4. **Trigger HelloRetryRequest.** The key share was guessed for ffdhe2048, Google asks for X25519,
   and it takes two round trips. Point at the timing card.
5. **TLS 1.2 (legacy)** on cloudflare.com: two round trips, certificate in the clear,
   ServerKeyExchange signed, ChangeCipherSpec that actually means something.
6. **Who decides?** probe: same pick in both orders means the server decides.
7. **Post-quantum hybrid** (OpenSSL 3.5+ or `--provider oqsprovider`): X25519MLKEM768 key shares
   are ~1.2 KB instead of 32 B. Look at the ClientHello size.

Tip: do one warm-up run before the talk so DNS is cached, and note that on corporate or
campus networks a TLS-inspecting proxy may sit in the middle. You'll then see the proxy's
certificate chain instead of Google's, which is itself a nice discussion point.

## Try it

```bash
# Server with three certs (it picks the one matching the client's sigalgs)
./build/tls_server --port 4433 \
  --cert certs/ecdsa.crt --key certs/ecdsa.key \
  --cert certs/ed25519.crt --key certs/ed25519.key \
  --cert certs/rsa.crt --key certs/rsa.key

# Force X25519 + Ed25519
./build/tls_client --host localhost --port 4433 --cafile certs/ca.crt \
  --group X25519 --sigalg ed25519

# Force something the server won't do -> handshake_failure alert
./build/tls_server --port 4434 --cert certs/ecdsa.crt --key certs/ecdsa.key --groups P-256
./build/tls_client --host localhost --port 4434 --cafile certs/ca.crt --group X448

# Trigger a HelloRetryRequest: key share goes for X448, server only takes P-256
./build/tls_client --host localhost --port 4434 --cafile certs/ca.crt --groups X448:P-256

# TLS 1.2: one suite name bundles KE + auth + cipher + MAC
./build/tls_client --host localhost --port 4433 --cafile certs/ca.crt \
  --tls12 --cipher-list ECDHE-RSA-AES256-GCM-SHA384

# Map any real server
./build/tls_probe --host cloudflare.com --port 443
```

**Browser demo:** run the server and open `https://localhost:4433/`
(accept the warning, or import `certs/ca.crt`). The page lists your browser's
ClientHello (GREASE values, hybrid PQ key shares if it sends them) and what the
server chose.

## What you'll observe

- **Forcing works only as a veto.** One offered option either gets used or causes a
  `handshake_failure` alert.
- **Signatures are tied to the certificate.** A server with a P-256 ECDSA cert
  refuses `ecdsa_secp384r1_sha384`, because in TLS 1.3 the curve is part of the scheme.
  `rsa_pkcs1_*` is refused in TLS 1.3 for CertificateVerify.
- **HelloRetryRequest** fires when none of the client's key shares is acceptable
  but another group in `supported_groups` is. Two ClientHellos, one extra round trip.
- **Preference:** `--prefer server` (`SSL_OP_CIPHER_SERVER_PREFERENCE`) decides the
  cipher suite. For groups, OpenSSL 3.0-3.4 accepts any key share the client already
  sent rather than forcing an HRR to get its favourite, so group order looks
  client-driven. OpenSSL 3.5 adds a richer group-list syntax (preference tuples and
  "send a key share for this" markers; see `SSL_CTX_set1_groups_list(3)`) to change that trade-off.

## Post-quantum

Nothing in the code is classical-only. Group and sigalg names pass straight to OpenSSL:

- **OpenSSL >= 3.5**: `X25519MLKEM768`, `MLKEM768`, `mldsa65` work natively;
  `gen_certs.sh` will also make an ML-DSA-65 cert.
- **OpenSSL 3.0-3.4**: build [oqs-provider](https://github.com/open-quantum-safe/oqs-provider)
  and add `--provider oqsprovider` to any program.

Good next step: time handshakes and record ClientHello/ServerHello sizes per
(group, sigalg) pair, classical vs hybrid vs pure PQ.

## Layout

```
src/tls_util.*      names for IANA code points, HRR detection, negotiated-param readout
src/client_core.*   one restricted handshake (shared by client and prober)
src/inspect.*       fully instrumented handshake -> JSON (message trace, hellos, cert chain, timing)
src/tls_dashboard.cpp  local HTTP server + /api/info, /api/handshake, /api/probe
web/dashboard.html  the dashboard page (embedded into the binary at build time;
                    run with --web web/dashboard.html to edit it without rebuilding)
src/tls_client.cpp  src/tls_server.cpp  src/tls_probe.cpp
scripts/gen_certs.sh
```

Only probe servers you own or have permission to test.
