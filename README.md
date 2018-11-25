![alt text](https://github.com/eianio/zei/raw/master/zei_logo.png)

**Confidential Payments for Accounts**

Zei is a library to help manage an account system that hides transaction amounts.
It Implements Confidential Transactions that was first proposed by [Greg Maxwell](https://people.xiph.org/~greg/confidential_values.txt). It however utilizes [Bulletproofs by Benedikt et al.](https://eprint.iacr.org/2017/1066.pdf) for shorter Rangeproofs. Publickey encryption is utilized to reveal plaintext amounts & blinding factors to the reciever.
This implementation uses Pedersen Commitments and is vulnerable to account poisoning. 

# Internal
View [Protocol](https://github.com/eianio/zei/blob/master/PROTOCOL.md)






# Benchmarks


# Installation

To install, add the following to your project's `Cargo.toml`:

```toml
[dependencies.zei]
version = "0.0.1"
```

Then, in your library or executable source, add:

```rust
extern crate zei;
```

By default, `zei` builds against `curve25519-dalek`'s `u64_backend`
feature, which uses Rust's `i128` feature to achieve roughly double the speed as
the `u32_backend` feature.  When targetting 32-bit systems, however, you'll
likely want to compile with
 `cargo build --no-default-features --features="u32_backend"`.
If you're building for a machine with avx2 instructions, there's also the
experimental `avx2_backend`.  To use it, compile with
`RUSTFLAGS="-C target_cpu=native" cargo build --no-default-features --features="avx2_backend"`