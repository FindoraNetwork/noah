use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use noah::{
    setup::BulletproofParams,
    xfr::{
        asset_record::AssetRecordType,
        batch_verify_xfr_notes, gen_xfr_note,
        sig::XfrKeyPair,
        structs::{AssetRecord, AssetRecordTemplate, AssetType, XfrAmount, XfrAssetType},
        verify_xfr_note, XfrNotePolicies,
    },
};
use noah_algebra::prelude::*;
use rand::{CryptoRng, RngCore};

const BATCHSIZE: [usize; 7] = [1, 2, 3, 6, 10, 20, 30];

// Measurement of the verification time, batch verification time, and XfrNote generation time of `NonConfidential_SingleAsset.`
fn bench_nonconfidential_single_asset(c: &mut Criterion) {
    let mut params = BulletproofParams::default();
    let inputs_template = [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];
    let outputs_template = [AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType; 6];

    verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template);
    for i in BATCHSIZE {
        batch_verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template, i);
    }
}

// Measurement of the verification time, batch verification time, and XfrNote generation time of `ConfidentialAmount_NonConfidentialAssetType_SingleAsset.`
fn bench_confidential_amount_nonconfidential_assettype_single_asset(c: &mut Criterion) {
    let mut params = BulletproofParams::default();
    let inputs_template = [AssetRecordType::ConfidentialAmount_NonConfidentialAssetType; 6];
    let outputs_template = [AssetRecordType::ConfidentialAmount_NonConfidentialAssetType; 6];

    verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template);
    for i in BATCHSIZE {
        batch_verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template, i);
    }
}

// Measurement of the verification time, batch verification time, and XfrNote generation time of `NonConfidentialAmount_ConfidentialAssetType_SingleAsset.`
fn bench_nonconfidential_amount_confidential_asset_type_single_asset(c: &mut Criterion) {
    let mut params = BulletproofParams::default();
    let inputs_template = [AssetRecordType::NonConfidentialAmount_ConfidentialAssetType; 6];
    let outputs_template = [AssetRecordType::NonConfidentialAmount_ConfidentialAssetType; 6];

    verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template);
    for i in BATCHSIZE {
        batch_verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template, i);
    }
}

// Measurement of the verification time, batch verification time, and XfrNote generation time of `Confidential_MultiAsset.`
fn bench_confidential_single_asset(c: &mut Criterion) {
    let mut params = BulletproofParams::default();
    let inputs_template = [AssetRecordType::ConfidentialAmount_ConfidentialAssetType; 6];
    let outputs_template = [AssetRecordType::ConfidentialAmount_ConfidentialAssetType; 6];

    verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template);
    for i in BATCHSIZE {
        batch_verify_single_asset_transfer(c, &mut params, &inputs_template, &outputs_template, i);
    }
}

// Measurement of the verification time, batch verification time, and XfrNote generation time of `Confidential_SingleAsset.`
fn bench_confidential_multi_asset(c: &mut Criterion) {
    let asset_record_type = AssetRecordType::ConfidentialAmount_ConfidentialAssetType;

    verify_multi_asset_transfer(c, asset_record_type);
    for i in BATCHSIZE {
        batch_verify_multi_asset_transfer(c, asset_record_type, i)
    }
}

// Measurement of the verification time, batch verification time, and XfrNote generation time of `NonConfidential_MultiAsset.`
fn bench_nonconfidential_multi_asset(c: &mut Criterion) {
    let asset_record_type = AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType;

    verify_multi_asset_transfer(c, asset_record_type);
    for i in BATCHSIZE {
        batch_verify_multi_asset_transfer(c, asset_record_type, i)
    }
}

criterion_group!(
    benches,
    bench_nonconfidential_single_asset,
    bench_confidential_amount_nonconfidential_assettype_single_asset,
    bench_nonconfidential_amount_confidential_asset_type_single_asset,
    bench_confidential_single_asset,
    bench_confidential_multi_asset,
    bench_nonconfidential_multi_asset
);
criterion_main!(benches);

fn verify_single_asset_transfer(
    c: &mut Criterion,
    params: &mut BulletproofParams,
    inputs_template: &[AssetRecordType],
    outputs_template: &[AssetRecordType],
) {
    let mut prng = test_rng();
    let asset_type = AssetType::from_identical_byte(0u8);

    let input_amount = 100u64 * outputs_template.len() as u64;
    let total_amount = input_amount * inputs_template.len() as u64;
    let output_amount = total_amount / outputs_template.len() as u64;
    assert_eq!(total_amount, output_amount * outputs_template.len() as u64);

    let inkeys = gen_key_pair_vec(inputs_template.len(), &mut prng);
    let inkeys_ref = inkeys.iter().collect_vec();
    let outkeys = gen_key_pair_vec(outputs_template.len(), &mut prng);

    let inputs = inputs_template
        .iter()
        .zip(inkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                input_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let outputs = outputs_template
        .iter()
        .zip(outkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                output_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let inputs_record = inputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, template).unwrap()
        })
        .collect_vec();
    let outputs_record = outputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap()
        })
        .collect_vec();

    let benchmark_id = XfrType::gen_id_from_inputs_outputs(&inputs_record, &outputs_record);
    let mut gen_xfr_note_group = c.benchmark_group("single_asset");
    gen_xfr_note_group.bench_function(format!("`{}_Gen_Xfr_Note`", benchmark_id), |b| {
        b.iter(|| {
            assert!(gen_xfr_note(
                &mut prng,
                inputs_record.as_slice(),
                outputs_record.as_slice(),
                &inkeys_ref,
            )
            .is_ok())
        });
    });
    gen_xfr_note_group.finish();

    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs_record.as_slice(),
        outputs_record.as_slice(),
        &inkeys_ref,
    )
    .unwrap();
    let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());

    let mut verify_xfr_note_group = c.benchmark_group("single_asset");
    verify_xfr_note_group.bench_function(format!("`{}_Verify_Xfr_Note`", benchmark_id), |b| {
        b.iter(|| {
            assert!(verify_xfr_note(&mut prng, params, &xfr_note, &policies.to_ref()).is_ok())
        });
    });
    verify_xfr_note_group.finish();
}

fn batch_verify_single_asset_transfer(
    c: &mut Criterion,
    params: &mut BulletproofParams,
    inputs_template: &[AssetRecordType],
    outputs_template: &[AssetRecordType],
    batch_size: usize,
) {
    let mut prng = test_rng();
    let asset_type = AssetType::from_identical_byte(0u8);

    let input_amount = 100u64 * outputs_template.len() as u64;
    let total_amount = input_amount * inputs_template.len() as u64;
    let output_amount = total_amount / outputs_template.len() as u64;
    assert_eq!(total_amount, output_amount * outputs_template.len() as u64);

    let inkeys = gen_key_pair_vec(inputs_template.len(), &mut prng);
    let inkeys_ref = inkeys.iter().collect_vec();
    let outkeys = gen_key_pair_vec(outputs_template.len(), &mut prng);

    let inputs = inputs_template
        .iter()
        .zip(inkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                input_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let outputs = outputs_template
        .iter()
        .zip(outkeys.iter())
        .map(|(asset_record_type, key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                output_amount,
                asset_type,
                *asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let inputs_record = inputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, template).unwrap()
        })
        .collect_vec();
    let outputs_record = outputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap()
        })
        .collect_vec();

    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs_record.as_slice(),
        outputs_record.as_slice(),
        &inkeys_ref,
    )
    .unwrap();

    let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
    let polices_ref = policies.to_ref();
    let policies = vec![&polices_ref; batch_size];
    let xfr_notes = vec![&xfr_note; batch_size];

    let benchmark_id = XfrType::gen_id_from_inputs_outputs(&inputs_record, &outputs_record);
    let mut batch_verify_group = c.benchmark_group("batch_verify_single_asset");
    batch_verify_group.sample_size(50);
    batch_verify_group.bench_function(
        format!("`{}` of batch size {}", benchmark_id, batch_size),
        |b| {
            b.iter(|| {
                assert!(batch_verify_xfr_notes(&mut prng, params, &xfr_notes, &policies).is_ok())
            });
        },
    );
    batch_verify_group.finish();
}

fn verify_multi_asset_transfer(c: &mut Criterion, asset_record_type: AssetRecordType) {
    let mut params = BulletproofParams::default();
    let mut prng = test_rng();
    let asset_type0 = AssetType::from_identical_byte(0u8);
    let asset_type1 = AssetType::from_identical_byte(1u8);
    let asset_type2 = AssetType::from_identical_byte(2u8);

    let inkeys = gen_key_pair_vec(6, &mut prng);
    let inkeys_ref = inkeys.iter().collect_vec();
    let input_amount = [
        (10u64, asset_type0),
        (10u64, asset_type1),
        (10u64, asset_type0),
        (10u64, asset_type1),
        (10u64, asset_type1),
        (10u64, asset_type2),
    ];

    let inputs = input_amount
        .iter()
        .zip(inkeys.iter())
        .map(|((amount, asset_type), key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                *amount,
                *asset_type,
                asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let out_keys = gen_key_pair_vec(6, &mut prng);

    let out_amount = [
        (30u64, asset_type1),
        (5u64, asset_type2),
        (1u64, asset_type2),
        (4u64, asset_type2),
        (0u64, asset_type0),
        (20u64, asset_type0),
    ];
    let outputs = out_amount
        .iter()
        .zip(out_keys.iter())
        .map(|((amount, asset_type), key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                *amount,
                *asset_type,
                asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let inputs_record = inputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, template).unwrap()
        })
        .collect_vec();
    let outputs_record = outputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap()
        })
        .collect_vec();

    let benchmark_id = XfrType::gen_id_from_inputs_outputs(&inputs_record, &outputs_record);
    let mut gen_xfr_note_group = c.benchmark_group("multi_asset");
    gen_xfr_note_group.bench_function(format!("`{}_Gen_Xfr_Note`", benchmark_id), |b| {
        b.iter(|| {
            assert!(gen_xfr_note(
                &mut prng,
                inputs_record.as_slice(),
                outputs_record.as_slice(),
                &inkeys_ref,
            )
            .is_ok())
        });
    });
    gen_xfr_note_group.finish();

    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs_record.as_slice(),
        outputs_record.as_slice(),
        &inkeys_ref,
    )
    .unwrap();
    let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());

    let mut verify_xfr_note_group = c.benchmark_group("multi_asset");
    verify_xfr_note_group.bench_function(format!("`{}_Verify_Xfr_Note`", benchmark_id), |b| {
        b.iter(|| {
            assert!(verify_xfr_note(&mut prng, &mut params, &xfr_note, &policies.to_ref()).is_ok())
        });
    });
    verify_xfr_note_group.finish();
}

fn batch_verify_multi_asset_transfer(
    c: &mut Criterion,
    asset_record_type: AssetRecordType,
    batch_size: usize,
) {
    let mut params = BulletproofParams::default();
    let mut prng = test_rng();
    let asset_type0 = AssetType::from_identical_byte(0u8);
    let asset_type1 = AssetType::from_identical_byte(1u8);
    let asset_type2 = AssetType::from_identical_byte(2u8);

    let inkeys = gen_key_pair_vec(6, &mut prng);
    let inkeys_ref = inkeys.iter().collect_vec();
    let input_amount = [
        (10u64, asset_type0),
        (10u64, asset_type1),
        (10u64, asset_type0),
        (10u64, asset_type1),
        (10u64, asset_type1),
        (10u64, asset_type2),
    ];

    let inputs = input_amount
        .iter()
        .zip(inkeys.iter())
        .map(|((amount, asset_type), key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                *amount,
                *asset_type,
                asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let out_keys = gen_key_pair_vec(6, &mut prng);

    let out_amount = [
        (30u64, asset_type1),
        (5u64, asset_type2),
        (1u64, asset_type2),
        (4u64, asset_type2),
        (0u64, asset_type0),
        (20u64, asset_type0),
    ];
    let outputs = out_amount
        .iter()
        .zip(out_keys.iter())
        .map(|((amount, asset_type), key_pair)| {
            AssetRecordTemplate::with_no_asset_tracing(
                *amount,
                *asset_type,
                asset_record_type,
                key_pair.pub_key,
            )
        })
        .collect_vec();

    let inputs_record = inputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, template).unwrap()
        })
        .collect_vec();
    let outputs_record = outputs
        .iter()
        .map(|template| {
            AssetRecord::from_template_no_identity_tracing(&mut prng, &template).unwrap()
        })
        .collect_vec();

    let xfr_note = gen_xfr_note(
        &mut prng,
        inputs_record.as_slice(),
        outputs_record.as_slice(),
        &inkeys_ref,
    )
    .unwrap();
    let policies = XfrNotePolicies::empty_policies(inputs.len(), outputs.len());
    let polices_ref = policies.to_ref();
    let policies = vec![&polices_ref; batch_size];
    let xfr_notes = vec![&xfr_note; batch_size];

    let benchmark_id = XfrType::gen_id_from_inputs_outputs(&inputs_record, &outputs_record);
    let mut batch_verify_xfr_note_group = c.benchmark_group("batch_verify_multi_asset");
    batch_verify_xfr_note_group.sample_size(30);
    batch_verify_xfr_note_group.bench_function(
        format!("`{}` of batch size {}", benchmark_id, batch_size),
        |b| {
            b.iter(|| {
                assert!(
                    batch_verify_xfr_notes(&mut prng, &mut params, &xfr_notes, &policies).is_ok()
                )
            });
        },
    );
    batch_verify_xfr_note_group.finish();
}

fn gen_key_pair_vec<R: CryptoRng + RngCore>(size: usize, prng: &mut R) -> Vec<XfrKeyPair> {
    let mut keys = vec![];
    for _i in 0..size {
        keys.push(XfrKeyPair::generate_secp256k1(prng));
    }
    keys
}

#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
enum XfrType {
    /// All inputs and outputs are revealed, and all have the same asset type.
    NonConfidential_SingleAsset,
    /// At least one input or output has a confidential amount, and all asset types are revealed.
    ConfidentialAmount_NonConfidentialAssetType_SingleAsset,
    /// At least one asset type is confidential, and all the amounts are revealed.
    NonConfidentialAmount_ConfidentialAssetType_SingleAsset,
    /// At least one input or output has both confidential amount and asset type.
    Confidential_SingleAsset,
    /// At least one input or output has confidential amount and asset type, and the transfer involves multiple asset types.
    Confidential_MultiAsset,
    /// All inputs and outputs reveal amounts and asset types.
    NonConfidential_MultiAsset,
}

impl XfrType {
    fn from_inputs_outputs(inputs_record: &[AssetRecord], outputs_record: &[AssetRecord]) -> Self {
        let mut multi_asset = false;
        let mut confidential_amount_nonconfidential_asset_type = false;
        let mut confidential_asset_type_nonconfidential_amount = false;
        let mut confidential_all = false;

        let asset_type = inputs_record[0].open_asset_record.asset_type;
        for record in inputs_record.iter().chain(outputs_record) {
            if asset_type != record.open_asset_record.asset_type {
                multi_asset = true;
            }
            let confidential_amount = matches!(
                record.open_asset_record.blind_asset_record.amount,
                XfrAmount::Confidential(_)
            );
            let confidential_asset_type = matches!(
                record.open_asset_record.blind_asset_record.asset_type,
                XfrAssetType::Confidential(_)
            );

            if confidential_amount && confidential_asset_type {
                confidential_all = true;
            } else if confidential_amount {
                confidential_amount_nonconfidential_asset_type = true;
            } else if confidential_asset_type {
                confidential_asset_type_nonconfidential_amount = true;
            }
        }
        if multi_asset {
            if confidential_all
                || confidential_amount_nonconfidential_asset_type
                || confidential_asset_type_nonconfidential_amount
            {
                return XfrType::Confidential_MultiAsset;
            } else {
                return XfrType::NonConfidential_MultiAsset;
            }
        }
        if confidential_all
            || (confidential_amount_nonconfidential_asset_type
                && confidential_asset_type_nonconfidential_amount)
        {
            XfrType::Confidential_SingleAsset
        } else if confidential_amount_nonconfidential_asset_type {
            XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset
        } else if confidential_asset_type_nonconfidential_amount {
            XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset
        } else {
            XfrType::NonConfidential_SingleAsset
        }
    }

    fn gen_id_from_inputs_outputs(
        inputs_record: &[AssetRecord],
        outputs_record: &[AssetRecord],
    ) -> String {
        let xfr_type = Self::from_inputs_outputs(inputs_record, outputs_record);
        match xfr_type {
            XfrType::NonConfidential_SingleAsset => "NonConfidential".to_string(),
            XfrType::ConfidentialAmount_NonConfidentialAssetType_SingleAsset => {
                "ConfidentialAmount_NonConfidentialAssetType".to_string()
            }
            XfrType::NonConfidentialAmount_ConfidentialAssetType_SingleAsset => {
                "NonConfidentialAmount_ConfidentialAssetType".to_string()
            }
            XfrType::Confidential_SingleAsset => "Confidential".to_string(),
            XfrType::Confidential_MultiAsset => "Confidential".to_string(),
            XfrType::NonConfidential_MultiAsset => "NonConfidential".to_string(),
        }
    }
}
