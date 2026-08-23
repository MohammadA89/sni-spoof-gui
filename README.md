# SNI Spoofing Advance

A Windows desktop rewrite of [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) in Go — modern UI, automatic route selection, a much faster data path, and tooling to tell you *why* a config does or does not work.

![license](https://img.shields.io/badge/license-GPL--3.0-blue) ![platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey)

---

## What it does

It opens TCP paths that DPI has already waved through, and runs your own config over them.

Paste a `vless://` or `trojan://` link into the app and press connect. An embedded xray-core runs it, and every connection xray makes — including the REALITY handshake itself — is dialled through the spoofing engine.

```
browser ──▶ 127.0.0.1:10808 ──▶ embedded xray ──[spoofed TCP]──▶ your server
                socks/http        your config                     unchanged
```

The config is used **verbatim**. There is no address to rewrite and no local relay hop: the spoof is not a destination, it is a property of how connections are made.

**You still need a config.** This is not a VPN and it gives you no exit of its own — it makes an existing config reach a server that DPI would otherwise cut off.

### Relay mode

Turning **Settings → Built-in client** off gives you the older shape instead: a plain local listener that an external client is pointed at, carrying no protocol of its own.

```
v2rayN / Xray  ──TCP──▶  127.0.0.1:40443  ──[spoofed TCP]──▶  clean IP:443
   your config              this app                            Cloudflare edge
```

Here you point a client that already works at the local listener instead of the real server address and leave the rest of its config alone. Its TLS, its SNI and its proxy protocol all pass through unchanged.

### How the spoofing works

After the TCP handshake to a clean edge IP completes, a fake TLS ClientHello carrying an innocuous SNI is injected with a sequence number placed one payload **behind** the connection's real starting point:

```
seq = initial_seq + 1 - len(fake_record)
```

The injected segment therefore ends exactly where the peer's receive window begins, so not one byte of it falls inside the window.

- A **DPI box** reassembling the stream sees a ClientHello for a harmless name and classifies the flow on it.
- The **peer's TCP stack** sees an already-acknowledged range, discards the payload, and answers with a bare ACK.

The connection is untouched, and the client's real ClientHello follows on a flow that has already been judged.

---

## Install

Download from [Releases](../../releases):

- **`SNI-Spoofing-Advance-amd64-installer.exe`** — installer; puts everything in place and adds shortcuts.
- **`SNI-Spoofing-Advance-portable.zip`** — extract anywhere and run.

Requirements: Windows 10/11 x64, and **Administrator rights** — WinDivert installs a kernel driver, so the app asks for elevation on launch.

## Use

1. Launch the app. It asks for elevation, because WinDivert installs a kernel driver.
2. Open **Configs** and paste your links — one per line, or the body of a subscription. Pick one.
3. Press the big button.
4. Point your browser at `127.0.0.1:10808` (SOCKS) or `127.0.0.1:10809` (HTTP), or turn on **Settings → Set as the Windows proxy** and let it do that for you.

Those are v2rayN's default ports, so an existing browser setting keeps working unchanged.

Closing the window does not quit: the app goes to the tray and the connection keeps running. Use **Quit** in the tray menu to exit.

### Which configs work

`vless://` and `trojan://`, over raw/tcp, ws, grpc, httpupgrade, xhttp and mKCP, with TLS or REALITY.

A few things are rejected at import rather than at connect time, because the xray version embedded here removed them outright and a config relying on one cannot run at all:

| In the link | Why it is rejected |
|---|---|
| `type=http`, `h2`, `quic` | those transports were removed; the config needs an xhttp link |
| `security=reality` with ws or httpupgrade | REALITY only works over raw, xhttp and gRPC |
| `type=kcp` with `seed=` or `headerType=` | mKCP's seed and header disguise were removed |
| `allowInsecure=1` | removed; it is dropped and the config will fail certificate validation |

`vmess://` and `ss://` are not supported yet.

### Configs behind Cloudflare

If your config's server sits behind Cloudflare, tick **behind Cloudflare** on it. The connection then goes to a scanned clean edge IP while the config's own SNI travels unchanged — which is what the scanner below is for.

Without that tick the config is dialled at its own address, which is what you want for a server that is not fronted.

---

## Scanner

**Clean IP scan** samples the bundled Cloudflare ranges in two passes. The first measures plain TCP connect latency across hundreds of addresses at once. The second takes the fastest and puts a real spoofed TLS session through each. Both passes matter: sorting by latency alone will happily recommend an address that accepts the handshake and then resets every real session, so only a verified address is ranked first.

**Fake SNI scan** tries a list of innocuous names and reports how many attempts each carried. Which names get through is a property of your network, not of this tool, so it is measured rather than guessed. A name that works two times out of three is reported as failing — intermittent is worse than useless, because the failures surface later looking like an unrelated fault.

**Config check** answers the question in the section above.

---

## Reliability

**Auto mode** verifies several addresses at connect time and keeps the runners-up. **Failover** then uses them: three consecutive dial failures on the current route, with no success in between, and the tunnel moves to the next verified address without dropping the session. One failure is ignored — a single reset happens on a healthy path.

**The connection pool** keeps pre-warmed connections that have already paid the TCP handshake and the injection delay, so a client's connect returns essentially instantly instead of waiting two round trips. Entries are checked for liveness before handout and expire well before the edge would drop them.

---

## Diagnostics

Two console tools ship alongside the app. Both need an elevated prompt.

```bash
spooftest.exe -domain hcaptcha.com -n 5 -control
```

Needs no server of your own: it dials a clean edge, spoofs the handshake, and completes a real TLS session against a public domain that edge already serves. `-control` repeats the run *without* spoofing — **that comparison is the point**. If the control also succeeds, the path is not being filtered and the run proves nothing; try a destination that is actually blocked for you.

```bash
sniproxy.exe -edge 104.17.0.1 -fake-sni auth.vercel.com
```

The tunnel with no window. `-no-spoof` relays without injecting, which is the decisive test: **a config that fails both with and without spoofing is not failing because of the transport.**

---

## What changed from upstream

The reference implementation is correct, but leaves most of its performance on the table.

**The capture filter was the main bottleneck.** Upstream matches every TCP packet between the interface and the edge IP, so the entire data plane is dragged through user space one packet at a time, behind the GIL. Because this version synthesises the fake record from scratch rather than cloning the handshake ACK, it only ever needs to see the two SYN packets — so the filter is `tcp.Syn` only and no data packet leaves the kernel.

**Connection latency.** A cold connection pays two round trips plus the injection delay before it can carry a byte. The pool takes all of that off the critical path.

**`TCP_NODELAY` was never set.** Nagle could hold small writes for up to 40ms, which is ruinous for interactive traffic.

**A correctness bug in the relay.** Upstream closes both sockets when either direction ends, truncating whatever was still in flight the other way. This version half-closes the peer and lets the opposite direction drain.

Also added: auto route selection, failover, the scanner, a UI, tray and run-at-startup.

---

## Configuration

`config.json` sits next to the executable. An upstream `config.json` is detected and migrated automatically.

| Key | Meaning |
|---|---|
| `listener.host` / `port` | where clients connect; `127.0.0.1:40443` by default |
| `transport.edge_ips` | ranked clean IPs; the rest are failover targets |
| `transport.edge_domain` | a domain the edge serves, used by the scanner and health checks |
| `transport.fake_sni` | the name DPI sees |
| `transport.mode` | `fast` (SYN-only capture) or `safe` (also waits for the acknowledging ACK) |
| `transport.auto` | pick and verify the route at connect time |
| `transport.spoof` | turn injection off while still relaying, for A/B testing |
| `transport.inject_delay_ms` | wait after SYN-ACK so the OS handshake ACK goes first |
| `transport.port_low` / `port_high` | source port range bound for outgoing connections |
| `pool.*` | pre-warmed connection count and lifetime |

---

## Build from source

Needs Go 1.22+, Node 18+, [Wails v2](https://wails.io), and NSIS for the installer.

```bash
wails build -nsis
```

Then place `WinDivert.dll` and `WinDivert64.sys` in `build/bin/`. `build.sh` does the whole thing including the CLI tools.

```
main.go, app*.go         Wails desktop app and its bound API
tray.go                  notification-area icon and menu
cmd/sniproxy             headless tunnel
cmd/spooftest            transport diagnostic
internal/spoof           WinDivert capture, fake ClientHello, spoofing dialer
internal/pool            pre-warmed connections
internal/relay           bidirectional copy with proper half-close
internal/tunnel          listener, plus the failover router
internal/scanner         clean-IP scan, fake-SNI probe, config check
internal/autostart       run-at-login registry entry
internal/config          configuration and legacy migration
frontend                 React + TypeScript UI
```

---

## Troubleshooting

**"needs administrator"** — WinDivert installs a kernel driver. Run elevated; the installed build asks automatically.

**Connect fails immediately** — another instance may hold the listener port. Check nothing else is on `40443`.

**Everything resets** — run `sniproxy.exe -no-spoof`. If it still fails, the edge does not serve your config's domain; use **Scanner → Config check**.

**Scanner verifies nothing** — your `edge_domain` may not be served by the sampled addresses. Try a different one under Settings.

---

## Credits

- [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) — the original project. The ClientHello template and the wrong-sequence injection technique are its work.
- [WinDivert](https://github.com/basil00/WinDivert) by Basil00 — the packet capture driver, redistributed under LGPLv3.
- [Wails](https://wails.io), [uTLS](https://github.com/refraction-networking/utls), [divert-go](https://github.com/imgk/divert-go).

## License

[GPL-3.0](LICENSE), inherited from the upstream project.
