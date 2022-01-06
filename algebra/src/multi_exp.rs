/*
 * Based on dalek-cryptography/curve25519-dalek implementation of Pippenger algorithm for multi-exponentiations
 */
use crate::{
    errors::AlgebraError,
    groups::{scalar_to_radix_2_power_w, Group, Scalar}
};
use ruc::*;

pub fn pippenger<G: Group>(scalars: &[&G::S], elems: &[&G]) -> Result<G> {
    let size = scalars.len();

    if size == 0 {
        return Err(eg!(AlgebraError::ParameterError));
    }

    let w = if size < 500 {
        6
    } else if size < 800 {
        7
    } else {
        8
    };

    let two_power_w: usize = 1 << w;
    let digits_vec: Vec<Vec<i8>> = scalars
        .iter()
        .map(|s| scalar_to_radix_2_power_w::<G::S>(s, w))
        .collect();

    let mut digits_count = 0;
    for digits in digits_vec.iter() {
        if digits.len() > digits_count {
            digits_count = digits.len();
        }
    }

    // init all the buckets
    let mut buckets: Vec<_> = (0..two_power_w / 2).map(|_| G::get_identity()).collect();

    let mut cols = (0..digits_count).rev().map(|index| {
        // empty each bucket
        for b in buckets.iter_mut() {
            *b = G::get_identity();
        }
        for (digits, elem) in digits_vec.iter().zip(elems) {
            if index >= digits.len() {
                continue;
            }
            let digit = digits[index];
            if digit > 0 {
                let b_index = (digit - 1) as usize;
                buckets[b_index] = buckets[b_index].add(elem);
            }
            if digit < 0 {
                let b_index = (-(digit + 1)) as usize;
                buckets[b_index] = buckets[b_index].sub(elem);
            }
        }
        let mut intermediate_sum = buckets[buckets.len() - 1].clone();
        let mut sum = buckets[buckets.len() - 1].clone();
        for i in (0..buckets.len() - 1).rev() {
            intermediate_sum = intermediate_sum.add(&buckets[i]);
            sum = sum.add(&intermediate_sum);
        }
        sum
    });

    let two_power_w_int = Scalar::from_u64(two_power_w as u64);
    // This unwrap is safe as the list of scalars is non empty at this point.
    let hi_col = cols.next().unwrap();
    let res = cols.fold(hi_col, |total, p| total.mul(&two_power_w_int).add(&p));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::bls12_381::{BLSGt, BLSG1, BLSG2};
    use crate::groups::{Group, Scalar};
    use crate::ristretto::RistrettoPoint;

    #[test]
    fn test_multiexp_ristretto() {
        run_multiexp_test::<RistrettoPoint>();
    }
    #[test]
    fn test_multiexp_blsg1() {
        run_multiexp_test::<BLSG1>();
    }
    #[test]
    fn test_multiexp_blsg2() {
        run_multiexp_test::<BLSG2>();
    }
    #[test]
    fn test_multiexp_blsgt() {
        run_multiexp_test::<BLSGt>();
    }

    fn run_multiexp_test<G: Group>() {
        let g = G::vartime_multi_exp(&[], &[]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let zero = G::S::from_u32(0);
        let g = G::vartime_multi_exp(&[&zero], &[&g1]);
        assert_eq!(g, G::get_identity());

        let g1 = G::get_base();
        let one = Scalar::from_u32(1);
        let g = G::vartime_multi_exp(&[&one], &[&g1]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g1p = G::get_base();
        let one = Scalar::from_u32(1);
        let zero = Scalar::from_u32(0);
        let g = G::vartime_multi_exp(&[&one, &zero], &[&g1, &g1p]);
        assert_eq!(g, G::get_base());

        let g1 = G::get_base();
        let g2 = g1.add(&g1);
        let g3 = g1.mul(&Scalar::from_u32(500));
        let thousand = Scalar::from_u32(1000);
        let two = Scalar::from_u32(2);
        let three = Scalar::from_u32(3);
        let g = G::vartime_multi_exp(&[&thousand, &two, &three], &[&g1, &g2, &g3]);
        let expected = G::get_base().mul(&Scalar::from_u32(1000 + 4 + 1500));
        assert_eq!(g, expected);
    }
}
