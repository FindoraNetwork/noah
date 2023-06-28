#![allow(deprecated)]

use crate::anemoi_jive::bls12_381_deprecated::AnemoiJive381Deprecated;
use crate::anemoi_jive::{AnemoiJive, ApplicableMDSMatrix, MDSMatrix};
use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::new_bls12_381_fr;
use noah_algebra::prelude::Scalar;
use num_traits::{One, Zero};

#[test]
fn test_jive() {
    type F = BLSScalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let res = AnemoiJive381Deprecated::eval_jive(&input_x, &input_y);
    assert_eq!(
        res,
        new_bls12_381_fr!(
            "40534080031161498828112599909199108154146698842441932527619782321134903095510"
        )
    );
}

#[test]
fn test_jive_flatten() {
    type F = BLSScalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let trace = AnemoiJive381Deprecated::eval_jive_with_trace(&input_x, &input_y);

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

        let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
        let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
        let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
        let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

        let g = AnemoiJive381Deprecated::GENERATOR;
        let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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
            + AnemoiJive381Deprecated::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive381Deprecated::GENERATOR_INV;
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

        let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
        let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
        let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
        let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

        let g = AnemoiJive381Deprecated::GENERATOR;
        let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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
            + AnemoiJive381Deprecated::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive381Deprecated::GENERATOR_INV;
        let right = b_i;
        assert_eq!(left, right);
    }
}

#[test]
fn test_anemoi_variable_length_hash() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let res = AnemoiJive381Deprecated::eval_variable_length_hash(&input);
    assert_eq!(
        res,
        new_bls12_381_fr!(
            "17913626440896376279858183231538520765146521393387279167163788217724133906091"
        )
    );
}

#[test]
fn test_anemoi_variable_length_hash_flatten() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let trace = AnemoiJive381Deprecated::eval_variable_length_hash_with_trace(&input);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive381Deprecated::MDS_MATRIX);

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

            let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

            let g = AnemoiJive381Deprecated::GENERATOR;
            let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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
                + AnemoiJive381Deprecated::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381Deprecated::GENERATOR_INV;
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

            let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

            let g = AnemoiJive381Deprecated::GENERATOR;
            let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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
                + AnemoiJive381Deprecated::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381Deprecated::GENERATOR_INV;
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

#[test]
fn test_eval_stream_cipher() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let expect = vec![
        new_bls12_381_fr!(
            "17913626440896376279858183231538520765146521393387279167163788217724133906091"
        ),
        new_bls12_381_fr!(
            "10924245457851299776834230964411301097341144242601887717142622193318101873637"
        ),
        new_bls12_381_fr!(
            "6663276913883111708418423034586768363551398850143421296540382885186078060823"
        ),
        new_bls12_381_fr!(
            "128933536200405882247940224412197398867767114327852757460179676316357563269"
        ),
        new_bls12_381_fr!(
            "15258059505200652487595045292898459322384722588445714078850235188840375113869"
        ),
        new_bls12_381_fr!(
            "12414736053374635364289834327316238573924204459455623330533024897044327146967"
        ),
        new_bls12_381_fr!(
            "2350377255947715518656472684633767529020826112660644861786637039916779504126"
        ),
    ];

    let res = AnemoiJive381Deprecated::eval_stream_cipher(&input, 2);
    assert_eq!(res, expect[..2]);

    let res = AnemoiJive381Deprecated::eval_stream_cipher(&input, 4);
    assert_eq!(res, expect[..4]);

    let res = AnemoiJive381Deprecated::eval_stream_cipher(&input, 6);
    assert_eq!(res, expect[..6]);

    let res = AnemoiJive381Deprecated::eval_stream_cipher(&input, 7);
    assert_eq!(res, expect[..7]);
}

#[test]
fn test_eval_stream_cipher_flatten() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let output_len = 7;
    let mut output = Vec::with_capacity(output_len);

    let trace = AnemoiJive381Deprecated::eval_stream_cipher_with_trace(&input, output_len);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive381Deprecated::MDS_MATRIX);

    if input.len() % (2 * 2 - 1) != 0 || input.is_empty() {
        input.push(F::one());
        if input.len() % (2 * 2 - 1) != 0 {
            input.extend_from_slice(&[F::zero()].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))));
        }
    }

    // after the previous step, the length of input must be multiplies of `2 * N - 1`.
    assert_eq!(input.len() % (2 * 2 - 1), 0);

    let g = AnemoiJive381Deprecated::GENERATOR;
    let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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

            let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

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
                + AnemoiJive381Deprecated::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381Deprecated::GENERATOR_INV;
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

            let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                + AnemoiJive381Deprecated::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381Deprecated::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        x = trace.intermediate_values_before_constant_additions[rr].0[12 - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[12 - 1].clone();
        mds.permute_in_place(&mut x, &mut y);

        assert_eq!(x, trace.after_permutation[rr].0);
        assert_eq!(y, trace.after_permutation[rr].1);
    }

    if output_len <= 2 {
        output.extend_from_slice(&x[..output_len])
    } else if output_len > 2 && output_len <= (2 * 2 - 1) {
        output.extend_from_slice(&x);
        output.extend_from_slice(&y[..output_len - 2])
    } else if output_len > (2 * 2 - 1) {
        output.extend_from_slice(&x);
        output.extend_from_slice(&y[..2 - 1]);

        let absorbing_times = input.len() / (2 * 2 - 1);
        let squeezing_times = output_len / (2 * 2 - 1) - 1;
        let remaining = output_len % (2 * 2 - 1);

        for i in 0..squeezing_times {
            // first round
            {
                let a_i_minus_1 = trace.before_permutation[absorbing_times + i].0[0].clone();
                let b_i_minus_1 = trace.before_permutation[absorbing_times + i].0[1].clone();
                let c_i_minus_1 = trace.before_permutation[absorbing_times + i].1[0].clone();
                let d_i_minus_1 = trace.before_permutation[absorbing_times + i].1[1].clone();

                let a_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[0][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[0][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[0][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[0][1]
                    .clone();

                let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

                let g = AnemoiJive381Deprecated::GENERATOR;
                let g2 = AnemoiJive381Deprecated::GENERATOR_SQUARE_PLUS_ONE;

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
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            // remaining rounds
            for r in 1..12 {
                let a_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .0[r - 1][0]
                    .clone();
                let b_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .0[r - 1][1]
                    .clone();
                let c_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .1[r - 1][0]
                    .clone();
                let d_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .1[r - 1][1]
                    .clone();

                let a_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[r][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[r][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[r][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[r][1]
                    .clone();

                let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            x = trace.intermediate_values_before_constant_additions[absorbing_times + i].0[12 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions[absorbing_times + i].1[12 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);

            assert_eq!(x, trace.after_permutation[absorbing_times + i].0);
            assert_eq!(y, trace.after_permutation[absorbing_times + i].1);

            output.extend_from_slice(&x);
            output.extend_from_slice(&y[..2 - 1]);
        }

        if remaining > 0 {
            // first round
            {
                let a_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].0[0].clone();
                let b_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].0[1].clone();
                let c_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].1[0].clone();
                let d_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].1[1].clone();

                let a_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[0][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[0][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[0][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[0][1]
                    .clone();

                let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

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
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            // remaining rounds
            for r in 1..12 {
                let a_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r - 1][0]
                    .clone();
                let b_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r - 1][1]
                    .clone();
                let c_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r - 1][0]
                    .clone();
                let d_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r - 1][1]
                    .clone();

                let a_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r][1]
                    .clone();

                let prk_i_a = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive381Deprecated::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381Deprecated::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            x = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .0[12 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .1[12 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);

            assert_eq!(
                x,
                trace.after_permutation[absorbing_times + squeezing_times].0
            );
            assert_eq!(
                y,
                trace.after_permutation[absorbing_times + squeezing_times].1
            );

            let mut x = x.to_vec();
            x.extend_from_slice(&y);
            output.extend_from_slice(&x[..remaining]);
        }
    }

    assert_eq!(trace.output, output);
}
