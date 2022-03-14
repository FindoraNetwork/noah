![](https://tokei.rs/b1/github/FindoraNetwork/zei)
![GitHub top language](https://img.shields.io/github/languages/top/FindoraNetwork/zei)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/FindoraNetwork/zei)
![GitHub issues](https://img.shields.io/github/issues-raw/FindoraNetwork/zei)
![GitHub pull requests](https://img.shields.io/github/issues-pr-raw/FindoraNetwork/zei)
![License](https://img.shields.io/badge/license-BUSL--1.1-lightgreen)

#**Zei: Findora's Cryptographic Library**

Zei is a library that provide tools to create and verify public transaction
with confidential data.

Support:

- Basic Cryptographic tools:
  - ElGamal Encryption in the exponent over generic groups.
  - A Naive Multisignature (concatenation of ed25519 signatures)
  - BLS multisignatures (not currently integrated with Xfr creation)
  - Hybrid Encryption using signature key
- Advanced Cryptographic tools:
  - Anonymous Credentials based on David Pointcheval and Olivier Sanders.
    Short Randomizable Signatures. CT RSA 2015. https://eprint.iacr.org/2015/525.pdf.
    It currently uses BLS12_381 as the underlying pairing
  - Confidential Anonymous Credential Reveal: Allows to encrypt credential attributes
    so that a verifier can check a credential signature without learning the attributes.
    This functionality allows for identity attributes tracking over a public ledger.
  - Chaum Pedersen proofs: Allows to prove in zero-knowledge that a set of Pedersen
    commitments open to the same value. Used in transfers to prove that the input confidential asset
    is the same as the output asset type.
  - Pedersen-ElGamal Equality Proofs: Allows to prove in zero-knowledge that the
    decryption of an Elgamal ciphertexts correctly opens a pedersen commitment.
    Use in transfers that allow tracking amounts and asset type without publicly
    revealing these values.
  - Dlog: Simple proof of knowlege of discrete logarithms over generic groups.
- Xfr multi-input multi-output UTXO transfers
  - Plain: XfrNote reveal amount and asset type
  - Confidential amount and/or asset type: XfrNote hides amount and/or asset type
  - AssetType mixing: Allows for multiple asset types in a confidential transaction
    Implemented via the Cloak protocol. Currently using Interstellar spacesuite prototype
  - Tracking policies: Allow tracking of amount, asset type, and/or identity
    of asset holders. That is, confidential Xfrs need to provide ciphertexts of
    amount/asset_type and/or identity and prove that this are correctly formed.

# Benchmarks

## Use the benchmarks

Benchmarks are available for XfrNote operations. To run them all:

```shell
cargo bench
```

The report is available at `target/criterion/report/index.html`.

To run a specific benchmark:

```shell
cargo bench --bench {xfr_batch | xfr_{note|body}_{noidtracking|idtracking}_{assettracking|noassettracking}_{singleasset|multiasset}}_{time|cycles}
```

For example to run the benchmark for xfr notes with identity tracking, and no asset tracking for a single asset, run:

```shell
cargo bench --bench xfr_note_idtracking_noassettracking_singleasset_time
```

The benchmarks involving batch verification can be run with:

```shell
cargo bench --bench xfr_note_batch_time
```

Note that not all the combinations are implemented yet. So far the benchmarks available are
(replace `time`by `cycles` if you want the # of cpu cycles instead of seconds):

- `xfr_note_noidtracking_noassettracking_singleasset_time`
- `xfr_note_idtracking_noassettracking_singleasset_time`
- `xfr_note_idtracking_assettracking_multiasset_time`
- `xfr_note_idtracking_assettracking_singleasset_time`
- `xfr_body_idtracking_assettracking_singleasset_time`
- `xfr_note_batch_time`

## Licensing

The primary license for Zei is the Business Source License 1.1 (`BUSL-1.1`), see [`LICENSE`](./LICENSE).
