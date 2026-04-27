# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`ipsuite` is a `no_std`, no-alloc Rust crate providing zero-copy view types for a targeted subset of the Internet Protocol Suite (Ethernet, ARP, IPv4, IPv6, ICMPv4, ICMPv6, IGMP, IPsec, TCP, UDP, QUIC headers). It is **work in progress** and pre-1.0 (`0.0.x`). The only runtime dependency is `zerocopy` (re-exported as `ipsuite::zerocopy` so downstream crates can pin the matching version). Edition 2024. Tri-licensed Apache-2.0 OR BSD-2-Clause OR MIT.

**Read alongside [TODO.md](TODO.md).** Open questions, in-flight and staged work, conventions still to settle, and per-file `// TODO` markers live there — `CLAUDE.md` describes the project as it stands; `TODO.md` describes what's still in motion.

## Commands

```sh
cargo build                  # default features (no_std, no alloc)
cargo build --features std   # opt-in std feature
cargo check --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt
cargo test                   # no tests exist yet
cargo test <name>            # run a single test once tests are added
```

There is no `rust-toolchain.toml`, no `rustfmt.toml`, no `clippy.toml`, no CI config, and no test/bench/examples directory yet.

## Design

The crate gives Rust code a safe, zero-cost way to read common network protocols off the wire. Reading — locating headers, decoding fields, walking option lists — is the dominant use case; mutation is supported (`from_bytes_mut`, `update_checksum`, …) but secondary. There is no parser, no serializer, no allocator: the caller owns a byte buffer (from a NIC, a socket, a pcap file, …) and the crate hands back typed views into it.

Both the safety and the efficiency of those views rest on Google's `zerocopy` crate. zerocopy's derives (`FromBytes`, `IntoBytes`, `KnownLayout`, `Immutable`, `Unaligned`) carry the proof that a `#[repr(C, packed)]` struct's bit pattern is valid for any input, so that obligation lives in a single audited dependency rather than spread across this codebase. Everything user-facing here is safe Rust; the only `unsafe` is inside zerocopy itself. The same machinery delivers efficiency: `&[u8]` becomes `&XxxPdu` via a length check and a pointer cast — no parsing, no copy, no allocation.

Target environments where these constraints pay off:

- **Kernel-side eBPF programs in Rust** (`aya-ebpf` — XDP, TC, cgroup BPF). The BPF VM has no heap, a 512-byte stack, no unwinding, and a verifier that wants every memory access proved in-bounds at static-analysis time. `XxxPdu::from_bytes(&[u8])` — one length check, then typed loads at compile-time-known offsets — is exactly the shape the verifier can reason about, and the lint guardrails (`indexing_slicing`, `unwrap_used`, `arithmetic_side_effects`) drag user code toward verifier-acceptable form, not just toward soundness.
- **Linux kernel modules in Rust** — same `no_std`/no-alloc constraint, same need for layout-checked typed access to skb data.
- **Embedded targets without a heap** — microcontrollers, hypervisor data paths, anywhere `alloc` isn't available.
- **smartNIC programmable data planes** and **DPDK-style userland** that opts out of `std` for cycle budget — `&Ipv4Pdu` over a shared-buffer offset is one memory load, no decode step.
- **Anywhere bytes come from a shared region** (AF_PACKET mmap ring, virtio-net descriptor, kernel skb, DMA ring, RDMA buffer) and the consumer wants typed access without a copy or wrapper.

Userspace `std` tooling (sniffers, packet generators, scanners) is also possible but isn't where the design constraints earn their keep — for that use case `pnet` is more mature and feature-rich.

The design goals, in priority order:

- **Cover a targeted subset of the Internet Protocol Suite.** Wire-format types for Ethernet, ARP, IPv4, IPv6, ICMPv4, ICMPv6, IGMP, IPsec (AH and ESP), TCP, UDP, and QUIC packet headers (long and short). Out of scope by design: SCTP, DCCP, UDP-Lite, tunneling encapsulations (GRE, VXLAN, MPLS), application-layer protocols, and the encrypted body of QUIC packets (handed off to a TLS/QUIC stack).
- **Read/write asymmetry.** Reading is the focus; mutation is supported (`from_bytes_mut`, `update_checksum`, …) but secondary, and a complete write/build API is TBD.
- **Consistent API across protocols.** Every protocol exposes the same shape: `XxxPdu` / `XxxHeader` / `XxxHeaderFields`, a per-module `XxxPduError` enum, and (where applicable) an iterator yielding enum variants for dynamic sections. Naming follows each protocol's spec — TCP options stay `TcpOption`s, IPv6 extension headers stay `Ipv6ExtensionHeader`s — even though the underlying walk shape is identical.
- **No `unsafe` in this crate.** All `unsafe` lives inside `zerocopy`.
- **No panics in the safe API.** Fallible operations return `Result`; the deny-listed lints (`indexing_slicing`, `unwrap_used`, `get_unwrap`) prevent hidden panics in code that doesn't look fallible at first glance.
- **Memory is directly mapped to data types — no copies, no parsing, no intermediate representation.** A `&[u8]` becomes a `&XxxPdu` via a length check and a pointer cast.
- **A thin layer the compiler can mostly remove.** No virtual dispatch, no boxing, no hidden allocations. Reading a field is a load plus (where applicable) a byte-swap.
- **Endianness is in the type system.** Every multi-byte wire field is a `network_endian::U16/U32/...`. Byte-order conversion happens once at the accessor, not scattered through call sites. A native-endian variant for hot paths is planned (see `// TODO: native byteorder` markers).
- **`no_std`, no `alloc` by default.** The crate must work in kernels, embedded targets, and userland alike. The only runtime dependency is zerocopy, which has the same posture. `std` is opt-in via the `std` feature; today it only toggles the `no_std` attribute. An `alloc` feature may be added later to support writing.
- **No I/O, no global state.** Buffers are caller-owned; the crate has no sockets, no pcap reader, no `static`s, no init. It composes with any packet source (libpcap, AF_PACKET, virtio-net, eBPF) and any concurrency model.
- **Errors are flat, allocation-free enums.** Each module's `XxxPduError` is a tiny enum, no `Box<dyn Error>`, no `String` — cheap to construct and propagate.
- **Const-friendly accessors and constants where possible.** Field accessors and well-known constants (`InetProtocol::TCP`, `HardwareType::ETHERNET`, …) are `const fn`, enabling compile-time matching and configuration.
- **The `zerocopy` re-export is part of the public API.** `pub use zerocopy;` in `lib.rs` lets downstream crates pin the matching version and exchange `FromBytes`/`IntoBytes` types across crate boundaries without version skew.

## Architecture

Every supported protocol lives in `src/proto/<proto>.rs` and is re-exported through `src/proto/mod.rs`. The shape is the same in each file — once you understand one, the others follow.

**The PDU pattern.** Each protocol defines an unsized `XxxPdu` struct: a fixed `XxxHeaderFields` (or `XxxHeader`) followed by an unsized `[u8]` tail for options/payload. All header structs are `#[repr(C, packed)]` and derive zerocopy's `FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned`. The crate is a thin reinterpretation layer over a caller-owned byte buffer — there is no parsing into owned data structures, no allocation, and no copy.

The standard surface on each PDU is:

- `from_bytes(&[u8]) -> Result<&Self, XxxPduError>` and `from_bytes_mut(&mut [u8]) -> Result<&mut Self, _>` — reinterpret a buffer.
- `as_parts(&self) -> Result<(&XxxHeader, &[u8]), _>` and `as_mut_parts(...)` — split into header + payload. For variable-length headers (IPv4 IHL, TCP data offset) this re-splits the underlying byte slice based on the length encoded in the fixed fields.
- For protocols with a checksum: `update_checksum(partial)` and `verify_checksum(partial)`.

**Endianness.** Every multi-byte wire field is a `zerocopy::network_endian::U16/U32/...`, never a raw `u16`. Several files carry `// TODO: native byteorder` markers — a planned native-endian variant for hot paths, not yet implemented. New protocol fields must use `network_endian` types.

**Checksums.** Centralized in `src/proto/mod.rs`:
- `Checksum` is the on-wire `network_endian::U16` newtype.
- `ChecksumBuilder` accumulates a one's-complement sum incrementally (used for pseudo-headers).
- `ChecksumWords<const WORDS: usize, const CKSUM: usize>` is a generic packed view over a header of `WORDS` u16 words with the checksum slot at index `CKSUM`. Each protocol with a checksum defines a `type XxxPduWords = ChecksumWords<{ Fields::WORDS }, IDX>;` (e.g. IPv4 uses `<{ Ipv4HeaderFields::WORDS }, 5>`, UDP uses `<_, 3>`, TCP uses `<_, 8>`). Update `update_checksum` to use `update_checksum_nonzero` for protocols (UDP) where 0 is reserved to mean "no checksum".

**TCP options use a visitor.** `TcpOptions::accept(&mut visitor)` walks the option list and dispatches to `TcpOptionsVisitor` callbacks. Add a new option by extending `TcpOptionKind`, the dispatch arm in `accept`, and a `visit_*` method on the trait.

**Errors.** Each module has its own flat `XxxPduError` enum (`BufferTooShort`, `InvalidChecksum`, `InvalidHeaderLength`, ...) plus two `From<zerocopy::SizeError<&[u8], _>>` / `<&mut [u8], _>` impls. The repeated pattern is intentionally marked `// TODO: sealed trait for T` — when extending, follow the same shape.

**Address types** (`MacAddress`, `Ipv4Address`, `Ipv6Address`) are `#[repr(transparent)]` over the byte array. IPv4/IPv6 expose `into_std()` / `from_std()` for `core::net::Ipv4Addr` / `Ipv6Addr` interop, plus `From` impls in both directions for owned and reference forms.

## Lint policy (load-bearing — read before editing)

`src/lib.rs` enables a large `#![deny(...)]` set covering both rustc and clippy. The notable ones that will catch you out:

- `clippy::indexing_slicing`, `clippy::unwrap_used`, `clippy::get_unwrap` — use `.get()`, `split_at_checked`, `?` everywhere; never `[i]`, `unwrap()`, `expect()`.
- `clippy::arithmetic_side_effects` — use `wrapping_*`, `checked_*`, `saturating_*` explicitly. Plain `+`, `-`, `*`, `>>` on integers will fail.
- `clippy::as_conversions`, `clippy::as_underscore` — no `as` casts. Use `From`/`TryFrom`/`.into()` where possible.
- `clippy::std_instead_of_core`, `clippy::alloc_instead_of_core` — import from `core::`, never `std::` or `alloc::` (the crate is `no_std`).
- `clippy::missing_inline_in_public_items` — every public function/method needs `#[inline]`. Apply uniformly, including to large or generic functions where the hint is effectively a no-op (the compiler ignores it for big bodies, and generic functions already expose their MIR to downstream crates). The annotation exists to satisfy the lint, not to claim "please inline me" — don't opt out with `#[expect]` per call site.
- `clippy::must_use_candidate` — pure getters returning a value need `#[must_use]`.
- `missing_copy_implementations`, `missing_debug_implementations` — derive or implement both for new public types.

When a deny rule genuinely cannot be satisfied (e.g. a `u16 as u32` widening for checksum math, or a const-generic-checked index), gate it with `#[expect(<lint>, reason = "...")]` (preferred) or `#[allow(<lint>, reason = "...")]` and write the reason. Look at existing call sites in `proto/mod.rs` and `proto/ipv4.rs` for the established phrasing.

When multiple lints fire on the same item, use one `#[expect(...)]` per lint, each with its own specific reason — never combine lints into a single attribute. Each lint represents a distinct concern and deserves its own justification (e.g. `as_conversions` is justified by *why we're using raw `as`*, while `cast_possible_truncation` is justified by *why losing bits is correct here*).

`missing_docs` is currently commented out (`// TODO: missing_docs`) — doc strings are welcome but not yet enforced.

## Repo state at time of writing

- `ChecksumBuilder` in `src/proto/mod.rs` is the newer API; the older `ChecksumWords` is still what every protocol PDU actually calls. Migration between the two is in flight.
