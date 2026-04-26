# TODO

Living list of work items, open questions, and design decisions still to be made. Prune as items get addressed.

## Open questions

Answers needed before implementing the remaining in-scope protocols (IPv6, ICMPv4/ICMPv6, IGMP, IPsec, QUIC):

1. **ICMPv4/v6 coverage.** "Commonly used" — propose: Echo (Request/Reply), Destination Unreachable, Time Exceeded, Redirect, Packet Too Big, Parameter Problem; plus NDP (RS / RA / NS / NA, types 133–136) and MLDv2 (Query type 130, Report type 143) for ICMPv6. Trim or extend? Each as a typed struct dispatched via a visitor (like TCP options), or one `IcmpPdu` exposing `(type, code, payload)`? If typed: option lists inside RA/NS parsed (prefix info, source LLA, MTU, …) or kept as raw bytes?
2. **IPv6 pseudo-header implementation.** In scope for TCP/UDP/ICMPv6 checksums over IPv6. Generalize the existing `ChecksumWords` / `Ipv4PseudoHeader` machinery across address families, or add an `Ipv6PseudoHeader` analogue alongside the v4 one with a small bit of duplication?
3. **`Ipv6Address` ergonomics.** Helpers like `is_link_local`, `is_multicast`, `multicast_scope`, `solicited_node_for`, …? Or stay minimal like `Ipv4Address` and let downstream code reach in via `.into_std()`?
4. **IGMP version and message coverage.** All three versions (v1/v2/v3 — RFC 1112 / 2236 / 3376), or just v3? Membership Query, Membership Report, and Leave Group variants — typed structs dispatched via a visitor, or a single PDU exposing `(type, group_address, payload)`?
5. **IPsec AH vs. ESP scope.** AH (RFC 4302) is integrity-only and fully cleartext. For ESP (RFC 4303), the body is encrypted — expose just the cleartext header (SPI, sequence number) and treat the body as opaque ciphertext, or leave hooks for callers to plug in an AEAD context? IKEv2 keying is application-layer — confirmed out of scope?
6. **QUIC packet types, variable-length fields, and header protection.** Cover long header (Initial / 0-RTT / Handshake / Retry / Version Negotiation) plus short header (1-RTT) — each as a typed struct, or a unified PDU? How to model variable-length connection IDs (up to 20 bytes) and the Initial token field — `ref_from_bytes_with_elems` accessors or raw byte ranges? Does the view expose the *header-protected* layout (caller unprotects packet number and the low 4 first-byte bits before reading) or require unprotection upfront?

Resolved:

- **IPv6 extension header walk strategy.** Pull-style iterator on `Ipv6Pdu` (`extension_headers() -> Ipv6ExtIter<'_>` yielding `Result<Ipv6ExtensionHeader<'_>, Ipv6PduError>`), with a `transport() -> Result<(InetProtocol, &[u8]), Ipv6PduError>` shortcut for the common "find the upper-layer header" case. A visitor adaptor can be added later if a consumer needs one.

Defaults that will be applied unless otherwise directed:

- `XxxPdu` / `XxxHeader` / `XxxHeaderFields` naming, per-module `XxxPduError` enums.
- No doc strings yet (matches current style — `missing_docs` lint is still off).
- Network-endian only; defer the planned native-endian variant.
- One commit per protocol.

## In-flight / staged work

- **IPv6, ICMPv4/ICMPv6, IGMP, IPsec (AH and ESP), QUIC packet headers.** Not started; pending answers above. (The earlier `icmp.rs` / `ipv6.rs` on a separate branch are abandoned — start fresh.)
- **`ChecksumWords` → `ChecksumBuilder` migration.** `ChecksumBuilder` in [src/proto/mod.rs](src/proto/mod.rs) is the newer API; `ChecksumWords` is still what every PDU actually calls.
- **Writing / building API.** Per the read/write asymmetry goal, a complete write/build API is TBD.
- **Optional `alloc` feature.** May be added later to support writing.
- **Native-endian variants for hot paths.** Markers at [src/proto/mod.rs:107](src/proto/mod.rs:107) and [src/proto/ipv4.rs:409](src/proto/ipv4.rs:409).

## Code-level TODOs

### Cross-cutting

- **Sealed trait bound for `T: ?Sized`** in `From<zerocopy::SizeError<...>> for XxxPduError` impls — [src/proto/arp.rs:248](src/proto/arp.rs:248), [src/proto/ethernet.rs:168](src/proto/ethernet.rs:168), [src/proto/ipv4.rs:474](src/proto/ipv4.rs:474), [src/proto/tcp.rs:565](src/proto/tcp.rs:565), [src/proto/udp.rs:120](src/proto/udp.rs:120).
- **"Half word at end" handling** in checksum-word views — [src/proto/ipv4.rs:111](src/proto/ipv4.rs:111), [src/proto/ipv4.rs:118](src/proto/ipv4.rs:118), [src/proto/ipv4.rs:125](src/proto/ipv4.rs:125), [src/proto/tcp.rs:76](src/proto/tcp.rs:76), [src/proto/tcp.rs:83](src/proto/tcp.rs:83), [src/proto/udp.rs:40](src/proto/udp.rs:40), [src/proto/udp.rs:48](src/proto/udp.rs:48).
- **Debug-print of options/payload** — [src/proto/ipv4.rs:76](src/proto/ipv4.rs:76), [src/proto/ipv4.rs:137](src/proto/ipv4.rs:137), [src/proto/tcp.rs:95](src/proto/tcp.rs:95), [src/proto/tcp.rs:121](src/proto/tcp.rs:121). `DataDebug` should also include a truncated slice excerpt: [src/proto/mod.rs:16](src/proto/mod.rs:16) (note: existing typo `TOOD` to fix).

### Per protocol

- **Ethernet** — Frame Check Sequence (CRC) support: [src/proto/ethernet.rs:56](src/proto/ethernet.rs:56).
- **IPv4** — revisit `as_mut_parts` split: [src/proto/ipv4.rs:54](src/proto/ipv4.rs:54).
- **TCP** — MD5 option ([src/proto/tcp.rs:320](src/proto/tcp.rs:320)); Multipath TCP option ([src/proto/tcp.rs:326](src/proto/tcp.rs:326)); check trailing data after EOL ([src/proto/tcp.rs:346](src/proto/tcp.rs:346)); bypass `TcpOptionHeader` to read length directly ([src/proto/tcp.rs:349](src/proto/tcp.rs:349)); SACK via `ref_from_bytes_with_elems` ([src/proto/tcp.rs:375](src/proto/tcp.rs:375)).

## Conventions and policies to settle

Decisions needed before or during the remaining protocol work; each becomes a short addition to `CLAUDE.md` once settled.

- **Sub-protocol type naming.** With ICMPv4 + ICMPv6 + QUIC packet variants in scope, decide a scheme: flat (`EchoRequest`), prefixed (`Icmpv4EchoRequest`), or module-scoped (`icmpv4::EchoRequest`). The `XxxPdu` / `XxxHeader` / `XxxHeaderFields` rule doesn't extend down to message types.
- **Writing-side API sketch.** One paragraph on intent — builder vs. `&mut Pdu` setters vs. checksum auto-update on commit — *before* reading-side decisions for IPv6/ICMP/QUIC silently constrain a future write API.
- **Per-module RFC anchor.** Each protocol module declares which RFCs it implements, including known updates and errata (e.g., ICMPv6 = RFC 4443 + RFC 4861 NDP + RFC 4884 + …). A short table in `CLAUDE.md`, or `//! Implements RFC NNNN [+ updates].` at the top of each module.
- **MSRV.** Pin a concrete minimum Rust version in `Cargo.toml`'s `rust-version` field (Edition 2024 already implies ≥ 1.85) and document in `CLAUDE.md`.
- **Layout invariants.** Decide whether to add `const _: () = assert!(size_of::<XxxHeaderFields>() == N);` per header struct as compile-time guards against accidental padding regressions.
- **Hot paths.** Enumerate which fields/operations the planned native-endian variant should target (TCP ports, IPv6 `next_header`, IPv4 destination address, …). Informs both the variant's scope and where benchmarks should focus once they exist.
- **`zerocopy` version and feature policy.** Document the upgrade posture across a future 0.9 / 1.0 transition and which optional features (`simd`, `alloc`, …) we'd opt into when.

## Repo housekeeping

- Enable `missing_docs` lint when doc coverage makes it tractable: [src/lib.rs:10](src/lib.rs:10).
- Fix `TOOD` typo: [src/proto/mod.rs:16](src/proto/mod.rs:16).
- Test corpus: `tests/data/` with hex-encoded golden packets per protocol (Ethernet frame, IPv4+TCP, IPv6+UDP with extension headers, ICMPv6 NDP RA, …) plus unit tests, doctests, and a fuzzing target.
- End-to-end annotated `examples/` walking from raw bytes through Ethernet → IPv4/IPv6 → TCP/UDP/ICMP, demonstrating the typical caller dispatch pattern (informs API ergonomics decisions).
- CI config: minimum is lints + clippy + fmt-check + multi-target build + MSRV check; aspirational is miri, cross-OS, fuzzing, release builds.
- Decide on `rust-toolchain.toml` (currently absent).
