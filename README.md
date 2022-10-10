![](https://tokei.rs/b1/github/FindoraNetwork/noah)
![GitHub top language](https://img.shields.io/github/languages/top/FindoraNetwork/noah)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/FindoraNetwork/noah)
![GitHub issues](https://img.shields.io/github/issues-raw/FindoraNetwork/noah)
![GitHub pull requests](https://img.shields.io/github/issues-pr-raw/FindoraNetwork/noah)
![License](https://img.shields.io/badge/license-BUSL--1.1-lightgreen)

## Noah: A Cryptographic Library for Privacy Assets

Noah is a Rust library that implements various cryptographic primitives for privacy assets. It implements two 
constructions:

- **Maxwell construction.** In 2015, a renowned blockchain developer Gregory Maxwell presented a construction of 
confidential transactions (CT) for a UTXO chain. We implemented it with:
   - Secp256k1 or Ed25519 for digital signatures
   - The Ristretto group over Curve25519 for Pedersen commitments
   - Bulletproofs over Curve25519 

- **Zerocash construction.** Improved over a prior protocol Zerocoin, the Zerocash construction, firstly proposed by 
Ben-Sasson, Chiesa, Garman, Green, Miers, Tromer, and Virza and improved subsequently by the Zcash 
Foundation and Electric Coin Company (ECC), is another privacy-preserving transfer protocol over a UTXO chain. We implemented it with:
   - Secp256k1 or Ed25519 (incoming) for digital signatures
   - An inhouse variant of TurboPlonk with various optimization tricks
   - The European technique for efficient memory in zk-SNARK, using the Anemoi-Jive hashes

## Licensing

The primary license for Noah is the Business Source License 1.1 (`BUSL-1.1`), see [`LICENSE`](./LICENSE).
