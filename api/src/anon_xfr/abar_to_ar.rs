use crate::anon_xfr::circuits::{
    add_merkle_path_variables, commit, compute_merkle_root, nullify, AccElemVars,
    NullifierInputVars, PayerSecret, PayerSecretVars, TurboPlonkCS, SK_LEN,
};
use num_traits::{One, Zero};
use std::ops::Add;
use zei_algebra::bls12_381::BLSScalar;
use zei_algebra::jubjub::JubjubPoint;
use zei_algebra::traits::Group;
use zei_plonk::plonk::constraint_system::TurboConstraintSystem;
use zei_plonk::plonk::constraint_system::VarIndex;

///
///        Constraint System for abar_to_bar
///
///
pub fn build_abar_to_bar_cs(payers_secret: PayerSecret) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();
    let payers_secrets_vars = add_payers_secret(&mut cs, payers_secret);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    // prove knowledge of payer's secret key: pk = base^{sk}
    let pk_var = cs.scalar_mul(base, payers_secrets_vars.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();

    // commitments
    let com_abar_in_var = commit(
        &mut cs,
        payers_secrets_vars.blind,
        payers_secrets_vars.amount,
        payers_secrets_vars.asset_type,
        pk_x,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_secrets_vars.uid,
            payers_secrets_vars.amount,
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
        asset_type: payers_secrets_vars.asset_type,
        pub_key_x: pk_x,
    };
    let nullifier_var = nullify(&mut cs, payers_secrets_vars.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_secrets_vars.uid,
        commitment: com_abar_in_var,
    };
    let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payers_secrets_vars.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // prepare public inputs variables
    cs.prepare_io_variable(nullifier_var);

    // prepare the public input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_io_variable(payers_secrets_vars.amount);
    cs.prepare_io_variable(payers_secrets_vars.asset_type);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

fn add_payers_secret(cs: &mut TurboPlonkCS, secret: PayerSecret) -> PayerSecretVars {
    let bls_sk = BLSScalar::from(&secret.sec_key);
    let sec_key = cs.new_variable(bls_sk);
    let uid = cs.new_variable(BLSScalar::from(secret.uid));
    let amount = cs.new_variable(BLSScalar::from(secret.amount));
    let blind = cs.new_variable(secret.blind);
    let path = add_merkle_path_variables(cs, secret.path.clone());
    let asset_type = cs.new_variable(secret.asset_type);
    PayerSecretVars {
        sec_key,
        uid,
        amount,
        asset_type,
        path,
        blind,
    }
}
