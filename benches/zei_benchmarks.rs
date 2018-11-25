// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate schnorr;
extern crate rand;
extern crate blake2;

use criterion::Criterion;

mod zei_benches {
    use super::*;
    use schnorr::Keypair;
    //use schnorr::PublicKey;
    use schnorr::Signature;
    // use schnorr::verify_batch;
    use rand::thread_rng;
    use rand::ThreadRng;
    use blake2::Blake2b;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Schnorr signing", move |b| {
            b.iter(| | keypair.sign::<Blake2b, _>(&mut csprng, msg))
        });
    }


    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign::<Blake2b, _>(&mut csprng, msg);
        
        c.bench_function("Schnorr signature verification", move |b| {
                         b.iter(| | keypair.verify::<Blake2b>(msg, &sig))
        });
    }

    // fn verify_batch_signatures(c: &mut Criterion) {
    //     static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

    //     c.bench_function_over_inputs(
    //         "Ed25519 batch signature verification",
    //         |b, &&size| {
    //             let mut csprng: ThreadRng = thread_rng();
    //             let keypairs: Vec<Keypair> = (0..size).map(|_| Keypair::generate::<Sha512, _>(&mut csprng)).collect();
    //             let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    //             let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
    //             let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign::<Sha512>(&msg)).collect();
    //             let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

    //             b.iter(|| verify_batch::<Sha512>(&messages[..], &signatures[..], &public_keys[..]));
    //         },
    //         &BATCH_SIZES,
    //     );
    // }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Schnorr keypair generation", move |b| {
                         b.iter(| | Keypair::generate(&mut csprng))
        });
    }

    criterion_group!{
        name = zei_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            //verify_batch_signatures,
            key_generation,
    }
}

criterion_main!(
    zei_benches::zei_benches,
);