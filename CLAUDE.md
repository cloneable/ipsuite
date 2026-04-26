# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`ipsuite` is a `no_std`, no-alloc Rust crate providing zero-copy view types for the Internet Protocol Suite (Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP). It is **work in progress** and pre-1.0 (`0.0.x`). The only runtime dependency is `zerocopy` (re-exported as `ipsuite::zerocopy` so downstream crates can pin the matching version). Edition 2024. Tri-licensed Apache-2.0 OR BSD-2-Clause OR MIT.

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
- `clippy::missing_inline_in_public_items` — every public function/method needs `#[inline]`.
- `clippy::must_use_candidate` — pure getters returning a value need `#[must_use]`.
- `missing_copy_implementations`, `missing_debug_implementations` — derive or implement both for new public types.

When a deny rule genuinely cannot be satisfied (e.g. a `u16 as u32` widening for checksum math, or a const-generic-checked index), gate it with `#[expect(<lint>, reason = "...")]` (preferred) or `#[allow(<lint>, reason = "...")]` and write the reason. Look at existing call sites in `proto/mod.rs` and `proto/ipv4.rs` for the established phrasing.

`missing_docs` is currently commented out (`// TODO: missing_docs`) — doc strings are welcome but not yet enforced.

## Repo state at time of writing

- `ChecksumBuilder` in `src/proto/mod.rs` is the newer API; the older `ChecksumWords` is still what every protocol PDU actually calls. Migration between the two is in flight.
