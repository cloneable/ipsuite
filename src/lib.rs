#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unknown_lints)]
#![deny(renamed_and_removed_lints)]
#![deny(
    anonymous_parameters,
    deprecated_in_future,
    late_bound_lifetime_arguments,
    missing_copy_implementations,
    missing_debug_implementations,
    // TODO: missing_docs,
    path_statements,
    patterns_in_fns_without_body,
    rust_2018_idioms,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    unused_extern_crates,
    variant_size_differences
)]
#![deny(
    clippy::all,
    clippy::alloc_instead_of_core,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    clippy::correctness,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::double_must_use,
    clippy::get_unwrap,
    clippy::indexing_slicing,
    clippy::missing_inline_in_public_items,
    clippy::missing_safety_doc,
    clippy::must_use_candidate,
    clippy::must_use_unit,
    clippy::obfuscated_if_else,
    clippy::perf,
    clippy::print_stdout,
    clippy::return_self_not_must_use,
    clippy::semicolon_if_nothing_returned,
    clippy::std_instead_of_core,
    clippy::style,
    clippy::suspicious,
    clippy::todo,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unwrap_used,
    clippy::use_debug
)]

pub mod proto;

// Re-export the matching version of zerocopy.
#[doc(hidden)]
pub use zerocopy;
