# Bulletproofs

<img
 width="100%"
 src="https://user-images.githubusercontent.com/698/46373713-9cc40280-c643-11e8-9bfe-2b0586e40369.png"
/>

The fastest [Bulletproofs][bp_website] implementation ever, featuring
single and aggregated range proofs, strongly-typed multiparty
computation, and a programmable constraint system API for proving
arbitrary statements (under development).

This library implements Bulletproofs using [Ristretto][ristretto],
using the `ristretto255` implementation in
[`curve25519-dalek`][curve25519_dalek].  When using the [parallel
formulas][parallel_edwards] in the `curve25519-dalek` AVX2 backend, it
can verify 64-bit rangeproofs **approximately twice as fast** as the
original `libsecp256k1`-based Bulletproofs implementation.

This library provides implementations of:

* Single-party proofs of single or multiple ranges, using the
  aggregated rangeproof construction;

* Online multi-party computation for rangeproof aggregation between
  multiple parties, using [session types][session_type_blog] to
  statically enforce correct protocol flow;
  
* A programmable constraint system API for expressing rank-1
  constraint systems, and proving and verifying proofs of arbitrary
  statements (under development in the `circuit` branch);
  
* Online multi-party computation for aggregated circuit proofs
  (planned future work).
  
These proofs are implemented using [Merlin transcripts][doc_merlin],
allowing them to be arbitrarily composed with other proofs without
implementation changes.

## Documentation
  
The user-facing documentation for this functionality can be [found
here][doc_external].  In addition, the library *also* contains
extensive notes on how Bulletproofs work.  These notes can be found in
the library's [internal documentation][doc_internal]:

* how [Bulletproofs work][bp_notes];
* how [the range proof protocol works][rp_notes];
* how [the inner product proof protocol works][ipp_notes];
* how [the aggregation protocol works][agg_notes];
* how the Bulletproof circuit proofs work (under development);
* how the constraint system reduction works (under development);
* how the aggregated circuit proofs work (future work).

## Comparative Performance

The following table gives comparative timings for proving and
verification of a 64-bit rangeproof on an i7-7800X with Turbo Boost
disabled.  Times are in microseconds (lower is better), with the
relative speed compared to the fastest implementation.

| Implementation | Group            | Proving (μs) |       rel | Verification (μs) |       rel |
|----------------|------------------|-------------:|----------:|------------------:|----------:|
| ours (avx2)    | ristretto255     |         7300 | **1.00x** |              1040 | **1.00x** |
| ours (u64)     | ristretto255     |        11300 | **1.54x** |              1490 | **1.43x** |
| libsecp+endo   | secp256k1        |        14300 | **1.96x** |              1900 | **1.83x** |
| libsecp-endo   | secp256k1        |        16800 | **2.30x** |              2080 | **2.00x** |
| Monero         | ed25519 (unsafe) |        53300 | **7.30x** |              4810 | **4.63x** |

This crate also contains other benchmarks; see the *Benchmarks*
section below for details.

## WARNING

This code is still research-quality.  It is not (yet) suitable for
deployment.  The development roadmap can be found in the
[Milestones][gh_milestones] section of the [Github repo][gh_repo].

## Tests

Run tests with `cargo test`.

## Benchmarks

This crate uses [criterion.rs][criterion] for benchmarks.  Run
benchmarks with `cargo bench`.

## Features

The `avx2_backend` feature enables `curve25519-dalek`'s AVX2 backend,
which implements curve arithmetic using [parallel
formulas][parallel_edwards].  To use it for Bulletproofs, the
`target_cpu` must support AVX2:

```text
RUSTFLAGS="-C target_cpu=skylake" cargo bench --features "avx2_backend"
```

Skylake-X CPUs have double the AVX2 registers. To use them, try

```text
RUSTFLAGS="-C target_cpu=skylake-avx512" cargo bench --features "avx2_backend"
```

This prevents spills in the AVX2 parallel field multiplication code, but causes
worse code generation elsewhere ¯\\\_(ツ)\_/¯

## About

This is a research project sponsored by [Interstellar][interstellar],
developed by Henry de Valence, Cathie Yun, and Oleg Andreev.

[bp_website]: https://crypto.stanford.edu/bulletproofs/
[ristretto]: https://ristretto.group
[doc_merlin]: https://doc.dalek.rs/merlin/index.html
[doc_external]: https://doc.dalek.rs/bulletproofs/index.html
[doc_internal]: https://doc-internal.dalek.rs/bulletproofs/index.html
[bp_notes]: https://doc-internal.dalek.rs/bulletproofs/notes/index.html
[rp_notes]: https://doc-internal.dalek.rs/bulletproofs/range_proof/index.html
[ipp_notes]: https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html
[agg_notes]: https://doc-internal.dalek.rs/bulletproofs/notes/index.html#aggregated-range-proof
[criterion]: https://github.com/japaric/criterion.rs
[session_type_blog]: https://blog.chain.com/bulletproof-multi-party-computation-in-rust-with-session-types-b3da6e928d5d
[curve25519_dalek]: https://doc.dalek.rs/curve25519_dalek/index.html
[parallel_edwards]: https://medium.com/@hdevalence/accelerating-edwards-curve-arithmetic-with-parallel-formulas-ac12cf5015be
[gh_repo]: https://github.com/dalek-cryptography/bulletproofs/
[gh_milestones]: https://github.com/dalek-cryptography/bulletproofs/milestones
[interstellar]: https://interstellar.com/
