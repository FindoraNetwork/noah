use crate::anon_xfr::structs::Commitment;
use crate::keys::{KeyPair, PublicKey};
use crate::{
    anon_xfr::structs::{
        AccElemVars, AnonAssetRecord, AxfrOwnerMemo, MTPath, MerkleNodeVars, MerklePathVars,
        OpenAnonAssetRecord,
    },
    xfr::structs::{AssetType, ASSET_TYPE_LENGTH},
};
use noah_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    collections::HashMap,
    prelude::*,
};
use noah_crypto::basic::anemoi_jive::{
    AnemoiJive, AnemoiJive381, AnemoiVLHTrace, JiveTrace, ANEMOI_JIVE_381_SALTS,
};
use noah_plonk::{
    plonk::{
        constraint_system::{TurboCS, VarIndex},
        indexer::PlonkPf,
    },
    poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS,
};

/// Module for general-purpose anonymous payment.
pub mod abar_to_abar;
/// Module for converting anonymous assets to transparent assets.
pub mod abar_to_ar;
/// Module for converting anonymous assets to confidential assets.
pub mod abar_to_bar;
/// Module for designs related to address folding for ed25519.
pub mod address_folding_ed25519;
/// Module for designs related to address folding for secp256k1.
pub mod address_folding_secp256k1;
/// Module for converting transparent assets to anonymous assets.
pub mod ar_to_abar;
/// Module for converting confidential assets to anonymous assets.
pub mod bar_to_abar;
/// Module for shared structures.
pub mod structs;

/// The asset type for FRA.
const ASSET_TYPE_FRA: AssetType = AssetType([0; ASSET_TYPE_LENGTH]);
/// FRA as the token used to pay the fee.
pub const FEE_TYPE: AssetType = ASSET_TYPE_FRA;
/// A constant 2^{32}.
pub const TWO_POW_32: u64 = 1 << 32;

pub(crate) type TurboPlonkCS = TurboCS<BLSScalar>;

/// The Plonk proof type.
pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// Check that inputs have Merkle tree witness and matching key pair.
fn check_inputs(inputs: &[OpenAnonAssetRecord], keypair: &KeyPair) -> Result<()> {
    for input in inputs.iter() {
        if input.mt_leaf_info.is_none() || keypair.get_pk() != input.pub_key {
            return Err(eg!(NoahError::ParameterError));
        }
    }
    Ok(())
}

/// Check that for each asset type total input amount == total output amount
/// and for FRA, total input amount == total output amount + fees.
fn check_asset_amount(
    inputs: &[OpenAnonAssetRecord],
    outputs: &[OpenAnonAssetRecord],
    fee: u32,
) -> Result<()> {
    let fee_asset_type = FEE_TYPE;
    let mut balances = HashMap::new();

    for record in inputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x += record.amount as i128;
        } else {
            balances.insert(record.asset_type, record.amount as i128);
        }
    }

    for record in outputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x -= record.amount as i128;
        } else {
            balances.insert(record.asset_type, -(record.amount as i128));
        }
    }

    for (&asset_type, &sum) in balances.iter() {
        if asset_type != fee_asset_type {
            if sum != 0i128 {
                return Err(eg!(NoahError::XfrCreationAssetAmountError));
            }
        } else {
            if sum != fee.into() {
                return Err(eg!(NoahError::XfrCreationAssetAmountError));
            }
        }
    }

    Ok(())
}

/// Check that the Merkle roots in input asset records are the same
/// `inputs` is guaranteed to have at least one asset record.
fn check_roots(inputs: &[OpenAnonAssetRecord]) -> Result<()> {
    let root = inputs[0]
        .mt_leaf_info
        .as_ref()
        .c(d!(NoahError::ParameterError))?
        .root;
    for input in inputs.iter().skip(1) {
        if input
            .mt_leaf_info
            .as_ref()
            .c(d!(NoahError::ParameterError))?
            .root
            != root
        {
            return Err(eg!(NoahError::AXfrVerificationError));
        }
    }
    Ok(())
}

/// Parse the owner memo from bytes.
/// * `bytes` - the memo bytes.
/// * `key_pair` - the memo bytes.
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match the commitment.
/// Return Ok(amount, asset_type, blinding) otherwise.
pub fn parse_memo(
    bytes: &[u8],
    key_pair: &KeyPair,
    abar: &AnonAssetRecord,
) -> Result<(u64, AssetType, BLSScalar)> {
    if bytes.len() != 8 + ASSET_TYPE_LENGTH + BLS12_381_SCALAR_LEN {
        return Err(eg!(NoahError::ParameterError));
    }
    let amount = u8_le_slice_to_u64(&bytes[0..8]);
    let mut i = 8;
    let mut asset_type_array = [0u8; ASSET_TYPE_LENGTH];
    asset_type_array.copy_from_slice(&bytes[i..i + ASSET_TYPE_LENGTH]);
    let asset_type = AssetType(asset_type_array);
    i += ASSET_TYPE_LENGTH;
    let blind = BLSScalar::from_bytes(&bytes[i..i + BLS12_381_SCALAR_LEN])
        .c(d!(NoahError::ParameterError))?;

    let (expected_commitment, _) =
        commit(&key_pair.get_pk(), blind, amount, asset_type.as_scalar())?;
    if expected_commitment != abar.commitment {
        return Err(eg!(NoahError::CommitmentVerificationError));
    }

    Ok((amount, asset_type, blind))
}

/// Decrypts the owner memo.
/// * `memo` - Owner memo to decrypt
/// * `dec_key` - Decryption key
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match the commitment or public key.
/// Return Ok(amount, asset_type, blinding) otherwise.
pub fn decrypt_memo(
    memo: &AxfrOwnerMemo,
    key_pair: &KeyPair,
    abar: &AnonAssetRecord,
) -> Result<(u64, AssetType, BLSScalar)> {
    let plaintext = memo.decrypt(&key_pair.get_sk())?;
    parse_memo(&plaintext, key_pair, abar)
}

/// Compute the nullifier.
pub fn nullify(
    key_pair: &KeyPair,
    amount: u64,
    asset_type_scalar: BLSScalar,
    uid: u64,
) -> Result<(BLSScalar, AnemoiVLHTrace<BLSScalar, 2, 12>)> {
    let pub_key = key_pair.get_pk();

    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::from(1u32));
    let uid_shifted = BLSScalar::from(uid).mul(&pow_2_64);
    let uid_amount = uid_shifted.add(&BLSScalar::from(amount));

    let public_key_scalars = pub_key.to_bls_scalars()?;
    let secret_key_scalars = key_pair.get_sk().to_bls_scalars()?;

    let zero = BLSScalar::zero();

    let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
        zero,                  /* protocol version number */
        uid_amount,            /* uid and amount */
        asset_type_scalar,     /* asset type */
        zero,                  /* address format number */
        public_key_scalars[0], /* public key */
        public_key_scalars[1], /* public key */
        public_key_scalars[2], /* public key */
        secret_key_scalars[0], /* secret key */
        secret_key_scalars[1], /* secret key */
    ]);

    Ok((trace.output, trace))
}

/// Length of the amount allowed in anonymous assets.
pub(crate) const AMOUNT_LEN: usize = 64;

/// Depth of the Merkle Tree circuit.
pub const TREE_DEPTH: usize = 20;

/// Add the commitment constraints to the constraint system:
/// comm = hash(hash(blinding, amount, asset_type, 0), pubkey_x, 0, 0).
pub fn commit_in_cs(
    cs: &mut TurboPlonkCS,
    blinding_var: VarIndex,
    amount_var: VarIndex,
    asset_var: VarIndex,
    public_key_scalars: &[VarIndex; 3],
    trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
) -> VarIndex {
    let output_var = cs.new_variable(trace.output);
    let zero_var = cs.zero_var();

    cs.anemoi_variable_length_hash(
        trace,
        &[
            zero_var,
            blinding_var,
            amount_var,
            asset_var,
            zero_var,
            public_key_scalars[0],
            public_key_scalars[1],
            public_key_scalars[2],
        ],
        output_var,
    );
    output_var
}

/// Compute the record's amount||asset type||pub key commitment
pub fn commit(
    public_key: &PublicKey,
    blind: BLSScalar,
    amount: u64,
    asset_type_scalar: BLSScalar,
) -> Result<(Commitment, AnemoiVLHTrace<BLSScalar, 2, 12>)> {
    let zero = BLSScalar::zero();
    let public_key_scalars = public_key.to_bls_scalars()?;

    let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&[
        zero, /* protocol version number */
        blind,
        BLSScalar::from(amount),
        asset_type_scalar,
        zero,                  /* address format number */
        public_key_scalars[0], /* public key */
        public_key_scalars[1], /* public key */
        public_key_scalars[2], /* public key */
    ]);

    Ok((trace.output, trace))
}

/// Add the nullifier constraints to the constraint system.
pub(crate) fn nullify_in_cs(
    cs: &mut TurboPlonkCS,
    secret_key_scalars: &[VarIndex; 2],
    uid_amount: VarIndex,
    asset_type: VarIndex,
    public_key_scalars: &[VarIndex; 3],
    trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
) -> VarIndex {
    let output_var = cs.new_variable(trace.output);
    let zero_var = cs.zero_var();

    cs.anemoi_variable_length_hash(
        trace,
        &[
            zero_var,
            uid_amount,
            asset_type,
            zero_var,
            public_key_scalars[0],
            public_key_scalars[1],
            public_key_scalars[2],
            secret_key_scalars[0],
            secret_key_scalars[1],
        ],
        output_var,
    );
    output_var
}

/// Add the Merkle tree path constraints to the constraint system.
pub fn add_merkle_path_variables(cs: &mut TurboPlonkCS, path: MTPath) -> MerklePathVars {
    let path_vars: Vec<MerkleNodeVars> = path
        .nodes
        .into_iter()
        .map(|node| MerkleNodeVars {
            left: cs.new_variable(node.left),
            mid: cs.new_variable(node.mid),
            right: cs.new_variable(node.right),
            is_left_child: cs.new_variable(BLSScalar::from(node.is_left_child as u32)),
            is_mid_child: cs.new_variable(BLSScalar::from(node.is_mid_child as u32)),
            is_right_child: cs.new_variable(BLSScalar::from(node.is_right_child as u32)),
        })
        .collect();
    // Boolean-constrain `is_left_child` and `is_right_child`
    for node_var in path_vars.iter() {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        cs.push_add_selectors(zero, one, one, one);
        cs.push_mul_selectors(zero, zero);
        cs.push_constant_selector(one.neg());
        cs.push_ecc_selector(zero);
        cs.push_out_selector(zero);

        let zero_var = cs.zero_var();
        cs.wiring[0].push(zero_var);
        cs.wiring[1].push(node_var.is_left_child);
        cs.wiring[2].push(node_var.is_mid_child);
        cs.wiring[3].push(node_var.is_right_child);
        cs.wiring[4].push(zero_var);
        cs.finish_new_gate();

        cs.attach_boolean_constraint_to_gate();
    }

    MerklePathVars { nodes: path_vars }
}

/// Add the sorting constraints that arrange the positions of the sibling nodes.
/// If `node` is the left child of parent, output (`node`, `sib1`, `sib2`);
/// if `node` is the right child of parent, output (`sib1`, `sib2`, `node`);
/// otherwise, output (`sib1`, `node`, `sib2`).
fn check_merkle_tree_validity(
    cs: &mut TurboPlonkCS,
    present: VarIndex,
    left: VarIndex,
    mid: VarIndex,
    right: VarIndex,
    is_left_child: VarIndex,
    is_mid_child: VarIndex,
    is_right_child: VarIndex,
) {
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();

    let sum = if cs.witness[is_right_child].is_one() {
        zero
    } else {
        if cs.witness[is_left_child].is_one() {
            cs.witness[left]
        } else {
            cs.witness[mid]
        }
    };

    let sum_var = cs.new_variable(sum);

    cs.push_add_selectors(zero, zero, zero, zero);
    cs.push_mul_selectors(one, one);
    cs.push_constant_selector(zero);
    cs.push_ecc_selector(zero);
    cs.push_out_selector(one);

    cs.wiring[0].push(left);
    cs.wiring[1].push(is_left_child);
    cs.wiring[2].push(mid);
    cs.wiring[3].push(is_mid_child);
    cs.wiring[4].push(sum_var);
    cs.finish_new_gate();

    let zero_var = cs.zero_var();

    cs.push_add_selectors(zero, zero, one, zero);
    cs.push_mul_selectors(one, zero);
    cs.push_constant_selector(zero);
    cs.push_ecc_selector(zero);
    cs.push_out_selector(one);

    cs.wiring[0].push(right);
    cs.wiring[1].push(is_right_child);
    cs.wiring[2].push(sum_var);
    cs.wiring[3].push(zero_var);
    cs.wiring[4].push(present);
    cs.finish_new_gate();
}

/// Compute the Merkle tree root given the path information.
pub fn compute_merkle_root_variables(
    cs: &mut TurboPlonkCS,
    elem: AccElemVars,
    path_vars: &MerklePathVars,
    leaf_trace: &AnemoiVLHTrace<BLSScalar, 2, 12>,
    traces: &Vec<JiveTrace<BLSScalar, 2, 12>>,
) -> VarIndex {
    let (uid, commitment) = (elem.uid, elem.commitment);

    let mut node_var = cs.new_variable(leaf_trace.output);
    cs.anemoi_variable_length_hash(leaf_trace, &[uid, commitment], node_var);
    for (idx, (path_node, trace)) in path_vars.nodes.iter().zip(traces.iter()).enumerate() {
        check_merkle_tree_validity(
            cs,
            node_var,
            path_node.left,
            path_node.mid,
            path_node.right,
            path_node.is_left_child,
            path_node.is_mid_child,
            path_node.is_right_child,
        );
        node_var = cs.jive_crh(
            trace,
            &[path_node.left, path_node.mid, path_node.right],
            ANEMOI_JIVE_381_SALTS[idx],
        );
    }
    node_var
}
