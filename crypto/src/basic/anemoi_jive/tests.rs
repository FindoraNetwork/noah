use crate::basic::anemoi_jive::{AnemoiJive, AnemoiJive381, ApplicableMDSMatrix, MDSMatrix};
use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::new_bls12_381;
use noah_algebra::prelude::Scalar;
use num_traits::{One, Zero};

#[test]
fn test_jive() {
    type F = BLSScalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let res = AnemoiJive381::eval_jive(&input_x, &input_y);
    assert_eq!(
        res,
        new_bls12_381!(
            "40534080031161498828112599909199108154146698842441932527619782321134903095510"
        )
    );
}

#[test]
fn test_jive_flatten() {
    type F = BLSScalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let trace = AnemoiJive381::eval_jive_with_trace(&input_x, &input_y);

    // first round
    {
        let a_i_minus_1 = trace.input_x[0].clone();
        let b_i_minus_1 = trace.input_x[1].clone();
        let c_i_minus_1 = trace.input_y[0].clone();
        let d_i_minus_1 = trace.input_y[1].clone();

        let a_i = trace.intermediate_x_before_constant_additions[0][0].clone();
        let b_i = trace.intermediate_x_before_constant_additions[0][1].clone();
        let c_i = trace.intermediate_y_before_constant_additions[0][0].clone();
        let d_i = trace.intermediate_y_before_constant_additions[0][1].clone();

        let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
        let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
        let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
        let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

        let g = AnemoiJive381::GENERATOR;
        let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

        // equation 1
        let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
            + g * (d_i_minus_1 + g * c_i_minus_1 + prk_i_c).square();
        let right = a_i_minus_1 + g * b_i_minus_1 + prk_i_a;
        assert_eq!(left, right);

        // equation 2
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d).square();
        let right = g * a_i_minus_1 + g2 * b_i_minus_1 + prk_i_b;
        assert_eq!(left, right);

        // equation 3
        let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
            + g * c_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = b_i;
        assert_eq!(left, right);
    }

    // remaining rounds
    for r in 1..12 {
        let a_i_minus_1 = trace.intermediate_x_before_constant_additions[r - 1][0].clone();
        let b_i_minus_1 = trace.intermediate_x_before_constant_additions[r - 1][1].clone();
        let c_i_minus_1 = trace.intermediate_y_before_constant_additions[r - 1][0].clone();
        let d_i_minus_1 = trace.intermediate_y_before_constant_additions[r - 1][1].clone();

        let a_i = trace.intermediate_x_before_constant_additions[r][0].clone();
        let b_i = trace.intermediate_x_before_constant_additions[r][1].clone();
        let c_i = trace.intermediate_y_before_constant_additions[r][0].clone();
        let d_i = trace.intermediate_y_before_constant_additions[r][1].clone();

        let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
        let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
        let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
        let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

        let g = AnemoiJive381::GENERATOR;
        let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

        // equation 1
        let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
            + g * (d_i_minus_1 + g * c_i_minus_1 + prk_i_c).square();
        let right = a_i_minus_1 + g * b_i_minus_1 + prk_i_a;
        assert_eq!(left, right);

        // equation 2
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d).square();
        let right = g * a_i_minus_1 + g2 * b_i_minus_1 + prk_i_b;
        assert_eq!(left, right);

        // equation 3
        let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
            + g * c_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = b_i;
        assert_eq!(left, right);
    }
}

#[test]
fn test_anemoi_variable_length_hash() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let res = AnemoiJive381::eval_variable_length_hash(&input);
    assert_eq!(
        res,
        new_bls12_381!(
            "17913626440896376279858183231538520765146521393387279167163788217724133906091"
        )
    );
}

#[test]
fn test_anemoi_variable_length_hash_flatten() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let trace = AnemoiJive381::eval_variable_length_hash_with_trace(&input);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive381::MDS_MATRIX);

    if input.len() % (2 * 2 - 1) != 0 || input.is_empty() {
        input.push(F::one());
        if input.len() % (2 * 2 - 1) != 0 {
            input.extend_from_slice(&[F::zero()].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))));
        }
    }

    // after the previous step, the length of input must be multiplies of `2 * N - 1`.
    assert_eq!(input.len() % (2 * 2 - 1), 0);

    let mut x = [F::zero(); 2];
    let mut y = [F::zero(); 2];
    for (rr, chuck) in input.chunks_exact(2 * 2 - 1).enumerate() {
        for i in 0..2 {
            x[i] += &chuck[i];
        }
        for i in 0..(2 - 1) {
            y[i] += &chuck[2 + i];
        }

        assert_eq!(x, trace.before_permutation[rr].0);
        assert_eq!(y, trace.before_permutation[rr].1);

        // first round
        {
            let a_i_minus_1 = trace.before_permutation[rr].0[0].clone();
            let b_i_minus_1 = trace.before_permutation[rr].0[1].clone();
            let c_i_minus_1 = trace.before_permutation[rr].1[0].clone();
            let d_i_minus_1 = trace.before_permutation[rr].1[1].clone();

            let a_i = trace.intermediate_values_before_constant_additions[rr].0[0][0].clone();
            let b_i = trace.intermediate_values_before_constant_additions[rr].0[0][1].clone();
            let c_i = trace.intermediate_values_before_constant_additions[rr].1[0][0].clone();
            let d_i = trace.intermediate_values_before_constant_additions[rr].1[0][1].clone();

            let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

            let g = AnemoiJive381::GENERATOR;
            let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

            // equation 1
            let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
                + g * (d_i_minus_1 + g * c_i_minus_1 + prk_i_c).square();
            let right = a_i_minus_1 + g * b_i_minus_1 + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d).square();
            let right = g * a_i_minus_1 + g2 * b_i_minus_1 + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        // remaining rounds
        for r in 1..12 {
            let a_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].0[r - 1][0].clone();
            let b_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].0[r - 1][1].clone();
            let c_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].1[r - 1][0].clone();
            let d_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].1[r - 1][1].clone();

            let a_i = trace.intermediate_values_before_constant_additions[rr].0[r][0].clone();
            let b_i = trace.intermediate_values_before_constant_additions[rr].0[r][1].clone();
            let c_i = trace.intermediate_values_before_constant_additions[rr].1[r][0].clone();
            let d_i = trace.intermediate_values_before_constant_additions[rr].1[r][1].clone();

            let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

            let g = AnemoiJive381::GENERATOR;
            let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

            // equation 1
            let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
                + g * (d_i_minus_1 + g * c_i_minus_1 + prk_i_c).square();
            let right = a_i_minus_1 + g * b_i_minus_1 + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d).square();
            let right = g * a_i_minus_1 + g2 * b_i_minus_1 + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (d_i_minus_1 + g * c_i_minus_1 + prk_i_c - &c_i).pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        x = trace.intermediate_values_before_constant_additions[rr].0[12 - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[12 - 1].clone();
        mds.permute_in_place(&mut x, &mut y);

        assert_eq!(x, trace.after_permutation[rr].0);
        assert_eq!(y, trace.after_permutation[rr].1);
    }

    assert_eq!(trace.output, x[0]);
}
