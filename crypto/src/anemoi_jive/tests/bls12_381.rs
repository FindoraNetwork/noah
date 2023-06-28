use crate::anemoi_jive::{AnemoiJive, AnemoiJive381, ApplicableMDSMatrix, MDSMatrix};
use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::new_bls12_381_fr;
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
        new_bls12_381_fr!(
            "45018547993113695511310159143102784961329952206271403420845830569151420326272"
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
        let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c - &c_i)
            .pow(&[5u64])
            + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c).square();
        let right = (a_i_minus_1.double() + d_i_minus_1)
            + g * (b_i_minus_1.double() + c_i_minus_1)
            + prk_i_a;
        assert_eq!(left, right);

        // equation 2
        let left = (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
            - &d_i)
            .pow(&[5u64])
            + g * (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d)
                .square();
        let right = g * (a_i_minus_1.double() + d_i_minus_1)
            + g2 * (b_i_minus_1.double() + c_i_minus_1)
            + prk_i_b;
        assert_eq!(left, right);

        // equation 3
        let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c - &c_i)
            .pow(&[5u64])
            + g * c_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
            - &d_i)
            .pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = b_i;
        assert_eq!(left, right);
    }

    // remaining rounds
    for r in 1..14 {
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
        let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c - &c_i)
            .pow(&[5u64])
            + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c).square();
        let right = (a_i_minus_1.double() + d_i_minus_1)
            + g * (b_i_minus_1.double() + c_i_minus_1)
            + prk_i_a;
        assert_eq!(left, right);

        // equation 2
        let left = (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
            - &d_i)
            .pow(&[5u64])
            + g * (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d)
                .square();
        let right = g * (a_i_minus_1.double() + d_i_minus_1)
            + g2 * (b_i_minus_1.double() + c_i_minus_1)
            + prk_i_b;
        assert_eq!(left, right);

        // equation 3
        let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c - &c_i)
            .pow(&[5u64])
            + g * c_i.square()
            + AnemoiJive381::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
            - &d_i)
            .pow(&[5u64])
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
        new_bls12_381_fr!(
            "7830848294887414696381022027093413300527713153909388134276426354836053663987"
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
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        // remaining rounds
        for r in 1..14 {
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
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        x = trace.intermediate_values_before_constant_additions[rr].0[14 - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[14 - 1].clone();
        mds.permute_in_place(&mut x, &mut y);

        for i in 0..2 {
            y[i] += &x[i];
            x[i] += &y[i];
        }

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
            "7830848294887414696381022027093413300527713153909388134276426354836053663987"
        ),
        new_bls12_381_fr!(
            "39718337357015754204525412160624485783828919341185097737409482242868871066883"
        ),
        new_bls12_381_fr!(
            "32919998053167867145677867576341727448530524020140466775345284690713542630022"
        ),
        new_bls12_381_fr!(
            "21355344602851555876875473678888443136761700898552528727644796660895185212280"
        ),
        new_bls12_381_fr!(
            "2380777103437516138714325791159107789728998290300680844220012334954519953895"
        ),
        new_bls12_381_fr!(
            "24733137920634344608218187290069119488021695925907642303806761902641604365818"
        ),
        new_bls12_381_fr!(
            "13533344520307676848486661527015946441719055333423348649184858644460601650580"
        ),
    ];

    let res = AnemoiJive381::eval_stream_cipher(&input, 2);
    assert_eq!(res, expect[..2]);

    let res = AnemoiJive381::eval_stream_cipher(&input, 4);
    assert_eq!(res, expect[..4]);

    let res = AnemoiJive381::eval_stream_cipher(&input, 6);
    assert_eq!(res, expect[..6]);

    let res = AnemoiJive381::eval_stream_cipher(&input, 7);
    assert_eq!(res, expect[..7]);
}

#[test]
fn test_eval_stream_cipher_flatten() {
    type F = BLSScalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let output_len = 7;
    let mut output = Vec::with_capacity(output_len);

    let trace = AnemoiJive381::eval_stream_cipher_with_trace(&input, output_len);

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

    let g = AnemoiJive381::GENERATOR;
    let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

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

            // equation 1
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        // remaining rounds
        for r in 1..14 {
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

            // equation 1
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        x = trace.intermediate_values_before_constant_additions[rr].0[14 - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[14 - 1].clone();
        mds.permute_in_place(&mut x, &mut y);
        for i in 0..2 {
            y[i] += &x[i];
            x[i] += &y[i];
        }

        println!("{}", rr);

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

                let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

                let g = AnemoiJive381::GENERATOR;
                let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

                // equation 1
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                        .square();
                let right = (a_i_minus_1.double() + d_i_minus_1)
                    + g * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_a;
                assert_eq!(left, right);

                // equation 2
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * (g * (a_i_minus_1 + d_i_minus_1)
                            + g2 * (b_i_minus_1 + c_i_minus_1)
                            + prk_i_d)
                            .square();
                let right = g * (a_i_minus_1.double() + d_i_minus_1)
                    + g2 * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_b;
                assert_eq!(left, right);

                // equation 3
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * c_i.square()
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * d_i.square()
                        + AnemoiJive381::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            // remaining rounds
            for r in 1..14 {
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

                let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

                // equation 1
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                        .square();
                let right = (a_i_minus_1.double() + d_i_minus_1)
                    + g * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_a;
                assert_eq!(left, right);

                // equation 2
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * (g * (a_i_minus_1 + d_i_minus_1)
                            + g2 * (b_i_minus_1 + c_i_minus_1)
                            + prk_i_d)
                            .square();
                let right = g * (a_i_minus_1.double() + d_i_minus_1)
                    + g2 * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_b;
                assert_eq!(left, right);

                // equation 3
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * c_i.square()
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * d_i.square()
                        + AnemoiJive381::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            x = trace.intermediate_values_before_constant_additions[absorbing_times + i].0[14 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions[absorbing_times + i].1[14 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..2 {
                y[i] += &x[i];
                x[i] += &y[i];
            }

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

                let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

                // equation 1
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                        .square();
                let right = (a_i_minus_1.double() + d_i_minus_1)
                    + g * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_a;
                assert_eq!(left, right);

                // equation 2
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * (g * (a_i_minus_1 + d_i_minus_1)
                            + g2 * (b_i_minus_1 + c_i_minus_1)
                            + prk_i_d)
                            .square();
                let right = g * (a_i_minus_1.double() + d_i_minus_1)
                    + g2 * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_b;
                assert_eq!(left, right);

                // equation 3
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * c_i.square()
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * d_i.square()
                        + AnemoiJive381::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            // remaining rounds
            for r in 1..14 {
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

                let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

                // equation 1
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                        .square();
                let right = (a_i_minus_1.double() + d_i_minus_1)
                    + g * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_a;
                assert_eq!(left, right);

                // equation 2
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * (g * (a_i_minus_1 + d_i_minus_1)
                            + g2 * (b_i_minus_1 + c_i_minus_1)
                            + prk_i_d)
                            .square();
                let right = g * (a_i_minus_1.double() + d_i_minus_1)
                    + g2 * (b_i_minus_1.double() + c_i_minus_1)
                    + prk_i_b;
                assert_eq!(left, right);

                // equation 3
                let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                    - &c_i)
                    .pow(&[5u64])
                    + g * c_i.square()
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left =
                    (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                        - &d_i)
                        .pow(&[5u64])
                        + g * d_i.square()
                        + AnemoiJive381::GENERATOR_INV;
                let right = b_i;
                assert_eq!(left, right);
            }

            x = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .0[14 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .1[14 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..2 {
                y[i] += &x[i];
                x[i] += &y[i];
            }

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
