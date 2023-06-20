use noah_algebra::bn254::BN254Scalar;
use noah_algebra::new_bn254_fr;
use noah_algebra::prelude::*;
use crate::anemoi_jive::{AnemoiJive, AnemoiJive254, ApplicableMDSMatrix, MDSMatrix};

#[test]
fn test_jive() {
    type F = BN254Scalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let res = AnemoiJive254::eval_jive(&input_x, &input_y);
    assert_eq!(
        res,
        new_bn254_fr!(
            "4943267647232206949073797646335542245204764337438846335826219097147863697986"
        )
    );
}

#[test]
fn test_jive_flatten() {
    type F = BN254Scalar;

    let input_x = [F::from(1u64), F::from(2u64)];
    let input_y = [F::from(3u64), F::zero()];

    let trace = AnemoiJive254::eval_jive_with_trace(&input_x, &input_y);

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

        let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
        let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
        let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
        let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

        let g = AnemoiJive254::GENERATOR;
        let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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
            + AnemoiJive254::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive254::GENERATOR_INV;
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

        let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
        let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
        let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
        let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

        let g = AnemoiJive254::GENERATOR;
        let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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
            + AnemoiJive254::GENERATOR_INV;
        let right = a_i;
        assert_eq!(left, right);

        // equation 4
        let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
            + g * d_i.square()
            + AnemoiJive254::GENERATOR_INV;
        let right = b_i;
        assert_eq!(left, right);
    }
}

#[test]
fn test_anemoi_variable_length_hash() {
    type F = BN254Scalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let res = AnemoiJive254::eval_variable_length_hash(&input);
    assert_eq!(
        res,
        new_bn254_fr!(
            "16706364257817800548673017186489241656725336586107883980840303157196850580358"
        )
    );
}

#[test]
fn test_anemoi_variable_length_hash_flatten() {
    type F = BN254Scalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&input);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive254::MDS_MATRIX);

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

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

            let g = AnemoiJive254::GENERATOR;
            let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive254::GENERATOR_INV;
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

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

            let g = AnemoiJive254::GENERATOR;
            let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive254::GENERATOR_INV;
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
    type F = BN254Scalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let expect = vec![
        new_bn254_fr!(
            "16706364257817800548673017186489241656725336586107883980840303157196850580358"
        ),
        new_bn254_fr!(
            "4399937163466564766323458526417985706844732355423055654139649019518126738159"
        ),
        new_bn254_fr!(
            "213837770267453807588464580915855559718909685435888846079537205151688002342"
        ),
        new_bn254_fr!(
            "18658451962321902160038073778218175151134338235233366978192553356066617494686"
        ),
        new_bn254_fr!(
            "6493884631177761101597386483759104549854687778856929752210050083537037439897"
        ),
        new_bn254_fr!(
            "21468778687176795406630530305155921207729571934897494719056697520733285531465"
        ),
        new_bn254_fr!(
            "2373666107211948246291962048341057092521610488239495070620173844125370469127"
        ),
    ];

    let res = AnemoiJive254::eval_stream_cipher(&input, 2);
    assert_eq!(res, expect[..2]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 4);
    assert_eq!(res, expect[..4]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 6);
    assert_eq!(res, expect[..6]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 7);
    assert_eq!(res, expect[..7]);
}

#[test]
fn test_eval_stream_cipher_flatten() {
    type F = BN254Scalar;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let output_len = 7;
    let mut output = Vec::with_capacity(output_len);

    let trace = AnemoiJive254::eval_stream_cipher_with_trace(&input, output_len);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive254::MDS_MATRIX);

    if input.len() % (2 * 2 - 1) != 0 || input.is_empty() {
        input.push(F::one());
        if input.len() % (2 * 2 - 1) != 0 {
            input.extend_from_slice(&[F::zero()].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))));
        }
    }

    // after the previous step, the length of input must be multiplies of `2 * N - 1`.
    assert_eq!(input.len() % (2 * 2 - 1), 0);

    let g = AnemoiJive254::GENERATOR;
    let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

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
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive254::GENERATOR_INV;
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

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive254::GENERATOR_INV;
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

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

                let g = AnemoiJive254::GENERATOR;
                let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

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
                    + AnemoiJive254::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
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

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                    + AnemoiJive254::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
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

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

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
                    + AnemoiJive254::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
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

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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
                    + AnemoiJive254::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
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
