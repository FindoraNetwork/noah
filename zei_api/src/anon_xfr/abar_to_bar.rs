/*
       Zei library - 2022 Findora Foundation
*/


use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use ruc::*;

use algebra::{
    bls12_381::BLSScalar,
    groups::{Group, One, Scalar, ScalarArithmetic, Zero},
    jubjub::{JubjubPoint, JubjubScalar},
};
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use poly_iops::{
    commitments::kzg_poly_com::{
        KZGCommitmentScheme, KZGCommitmentSchemeBLS,
    },
    plonk::{
        plonk_setup::preprocess_prover,
        protocol::prover::{PlonkPf, prover, verifier},
        turbo_plonk_cs::{TurboPlonkConstraintSystem, VarIndex},
    },
};
use utils::errors::ZeiError;

use crate::anon_xfr::{
    circuits::{
        AccElemVars, add_merkle_path_variables, commit, compute_merkle_root, NullifierInputVars,
        nullify, PayerSecret, PayerSecretVars, TurboPlonkCS,
    },
    keys::{AXfrKeyPair, AXfrPubKey},
    nullifier, structs::{
        MTNode, MTPath, Nullifier,
        OpenAnonBlindAssetRecord,
    },
};
use crate::setup::{DEFAULT_BP_NUM_GENS, NodeParams, PublicParams, UserParams};
use crate::xfr::{
    asset_record::{
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        build_open_asset_record,
    },
    sig::XfrPublicKey,
    structs::{
        AssetRecordTemplate, BlindAssetRecord, OpenAssetRecord, OwnerMemo,
        TracerMemo,
    },
};

const SK_LEN: usize = 252;
// secret key size (in bits)
const COMMON_SEED: [u8; 32] = [0u8; 32];

const ABAR_TO_BAR_TRANSCRIPT: &[u8] = b"Abar to Bar Conversion";

pub type Abar2BarPlonkProof = PlonkPf<KZGCommitmentSchemeBLS>;

/*
       Conversion Body
*/
/// AbarToBarBody has the input, the output and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarBody {
    /// input ABARS being spent
    pub input: (Nullifier, AXfrPubKey),
    /// The new BAR to be created
    pub output: BlindAssetRecord,
    /// The ZKP for the conversion
    pub proof: ConvertAbarBarProof,
}

/// This function generates the AbarToBarBody from the Open ABARs, the receiver address and the signing
/// key pair.
#[allow(dead_code)]
pub fn gen_abar_to_bar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    input: OpenAnonBlindAssetRecord,
    input_keypair: AXfrKeyPair,
    address: XfrPublicKey,
) -> Result<(
    AbarToBarBody,
    AXfrKeyPair,
    (OpenAssetRecord, Vec<TracerMemo>, Option<OwnerMemo>),
)> {
    // 1. check input correctness
    if input.mt_leaf_info.is_none() || input_keypair.pub_key() != input.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    // 2. randomize input key pair with open_abar rand key
    let rand_input_keypair = input_keypair.randomize(&input.key_rand_factor);

    // 3. build input witness infos
    let diversifier = JubjubScalar::random(prng);
    let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
    let nullifier_and_signing_key = (
        nullifier(
            &rand_input_keypair,
            input.amount,
            &input.asset_type,
            mt_leaf_info.uid,
        ),
        rand_input_keypair.pub_key().randomize(&diversifier),
    );

    // 4. build proof
    let payers_secret = PayerSecret {
        sec_key: rand_input_keypair.get_secret_scalar(),
        diversifier,
        uid: mt_leaf_info.uid,
        amount: input.amount,
        asset_type: input.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: input.blind,
    };


    let pc_gens = RistrettoPedersenGens::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        input.amount,
        input.asset_type,
        NonConfidentialAmount_NonConfidentialAssetType,
        address.clone(),
    );
    let (oar, tracer_memos, owner_memo) =
        build_open_asset_record(prng, &pc_gens, &art, vec![]);

    let mut proof = abar_to_bar(prng, params, payers_secret).c(d!())?;
    let diversified_key_pair = rand_input_keypair.randomize(&diversifier);

    let mt_info_temp = input.mt_leaf_info.as_ref().unwrap();
    proof.merkle_root = mt_info_temp.root;
    proof.merkle_root_version = mt_info_temp.root_version;

    Ok((
        AbarToBarBody {
            input: nullifier_and_signing_key,
            output: oar.blind_asset_record.clone(),
            proof,
        },
        diversified_key_pair,
        (oar, tracer_memos, owner_memo),
    ))
}

// Verifies the body
#[allow(dead_code)]
pub fn verify_abar_to_bar_body(
    params: &NodeParams,
    body: &AbarToBarBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    verify_abar_to_bar(params, &body.input, &body.proof, merkle_root)
}

/*
       Conversion Proof
*/
/// ConvertAbarBarProof is a struct to hold various aspects of a ZKP to prove equality, spendability
/// and conversion of an ABAR to a BAR on the chain.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertAbarBarProof {
    // TODO: BLS Ristretto equality proof
    spending_plonk_proof: Abar2BarPlonkProof,
    merkle_root: BLSScalar,
    merkle_root_version: usize,
}

/// abar_to_bar functions generates the new BAR and the proof given the Open ABAR and the receiver
/// public key.
#[allow(dead_code)]
pub(crate) fn abar_to_bar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    input: PayerSecret,
) -> Result<ConvertAbarBarProof> {
    let spending_plonk_proof = prove_abar_to_bar(prng, params, input).c(d!())?;

    Ok(ConvertAbarBarProof {
        spending_plonk_proof,
        merkle_root: Default::default(),
        merkle_root_version: 0,
    })
}

/// Verifies the proof with the input and output
#[allow(dead_code)]
pub fn verify_abar_to_bar(
    params: &NodeParams,
    input: &(Nullifier, AXfrPubKey),
    proof: &ConvertAbarBarProof,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != proof.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let mut online_inputs = vec![];
    online_inputs.push(input.clone().0);
    online_inputs.push(input.clone().1.as_jubjub_point().get_x());
    online_inputs.push(input.clone().1.as_jubjub_point().get_y());
    online_inputs.push(merkle_root.clone());

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &proof.spending_plonk_proof,
    )
}

fn prove_abar_to_bar<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    payers_secret: PayerSecret,
) -> Result<Abar2BarPlonkProof> {

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_bar_cs(payers_secret);
    let witness = cs.get_and_clear_witness();

    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
        .c(d!(ZeiError::AXfrProofError))
}

///
///        User params for abar_to_bar
///
///
impl UserParams {
    pub fn abar_to_bar_params(tree_depth: usize) -> UserParams {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            diversifier: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let (cs, n_constraints) = build_abar_to_bar_cs(payer_secret);
        let pcs = KZGCommitmentScheme::new(
            n_constraints + 2,
            &mut ChaChaRng::from_seed([0u8; 32]),
        );

        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(DEFAULT_BP_NUM_GENS),
            pcs,
            cs,
            prover_params,
        }
    }
}

///
///        Constraint System for abar_to_bar
///
///
fn build_abar_to_bar_cs(payers_secret: PayerSecret) -> (TurboPlonkCS, usize) {
    let mut cs = TurboPlonkConstraintSystem::new();
    let payers_secrets = add_payers_secret(&mut cs, payers_secret);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from_u64(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    // prove knowledge of payer's secret key: pk = base^{sk}
    let (pk_var, pk_point) = cs.scalar_mul(base, payers_secrets.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();
    let pk_y = pk_var.get_y();

    // prove knowledge of diversifier: pk_sign = pk^{diversifier}
    let (pk_sign_var, _) =
        cs.var_base_scalar_mul(pk_var, pk_point, payers_secrets.diversifier, SK_LEN);

    // commitments
    let com_abar_in_var = commit(
        &mut cs,
        payers_secrets.blind,
        payers_secrets.amount,
        payers_secrets.asset_type,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_secrets.uid,
            payers_secrets.amount,
            zero_var,
            zero_var,
        ],
        pow_2_64,
        one,
        zero,
        zero,
    );
    let nullifier_input_vars = NullifierInputVars {
        uid_amount,
        asset_type: payers_secrets.asset_type,
        pub_key_x: pk_x,
        pub_key_y: pk_y,
    };
    let nullifier_var = nullify(&mut cs, payers_secrets.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_secrets.uid,
        commitment: com_abar_in_var,
        pub_key_x: pk_x,
        pub_key_y: pk_y,
    };
    let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payers_secrets.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // prepare public inputs variables
    cs.prepare_io_variable(nullifier_var);
    cs.prepare_io_point_variable(pk_sign_var);

    // prepare the publc input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

fn add_payers_secret(cs: &mut TurboPlonkCS, secret: PayerSecret) -> PayerSecretVars {
    let bls_sk = BLSScalar::from(&secret.sec_key);
    let bls_diversifier = BLSScalar::from(&secret.diversifier);
    let sec_key = cs.new_variable(bls_sk);
    let diversifier = cs.new_variable(bls_diversifier);
    let uid = cs.new_variable(BLSScalar::from_u64(secret.uid));
    let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
    let blind = cs.new_variable(secret.blind);
    let path = add_merkle_path_variables(cs, secret.path.clone());
    let asset_type = cs.new_variable(secret.asset_type);
    PayerSecretVars {
        sec_key,
        diversifier,
        uid,
        amount,
        asset_type,
        path,
        blind,
    }
}

mod tests {
    use std::sync::Arc;
    use std::thread;

    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    use accumulators::merkle_tree::PersistentMerkleTree;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use crypto::basics::hash::rescue::RescueInstance;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};

    use crate::anon_xfr::abar_to_bar::{gen_abar_to_bar_body, verify_abar_to_bar_body};
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecordBuilder};
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::sig::XfrKeyPair;
    use crate::xfr::structs::AssetType;

    #[test]
    fn test_abar_to_bar_conversion() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let params = UserParams::abar_to_bar_params(41);

        let recv = XfrKeyPair::generate(&mut prng);
        let sender = AXfrKeyPair::generate(&mut prng);
        let sender_dec_key = XSecretKey::new(&mut prng);

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "test_abar_to_bar_conversion_db".to_string(),
            0,
        )));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonBlindAssetRecordBuilder::new()
            .pub_key(sender.pub_key())
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .finalize(&mut prng, &XPublicKey::from(&sender_dec_key))
            .unwrap()
            .build()
            .unwrap();

        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();

        oabar.update_mt_leaf_info(MTLeafInfo {
            path: MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        siblings1: e.siblings1,
                        siblings2: e.siblings2,
                        is_left_child: e.is_left_child,
                        is_right_child: e.is_right_child,
                    })
                    .collect(),
            },
            root: proof.root,
            root_version: proof.root_version,
            uid: 0,
        });

        let (body, _, _) = gen_abar_to_bar_body(
            &mut prng,
            &params,
            oabar,
            sender,
            recv.pub_key,
        ).unwrap();

        let node_params = NodeParams::from(params);
        verify_abar_to_bar_body(
            &node_params,
            &body,
            &proof.root,
        ).unwrap();

    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero(),
        ])[0]
    }
}
