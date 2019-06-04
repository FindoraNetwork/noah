use super::groups::{Scalar, Group};

/// I perform a vector matrix multiplication
pub(crate) fn group_linear_combination_rows<S: Scalar, G: Group<S>>(lc_scalars: &[S], matrix: &[Vec<G>]) -> Vec<G>{
    let mut result = vec![G::get_identity(); lc_scalars.len()];
    for (s,column) in lc_scalars.iter().zip(matrix){
        for j in 0..column.len(){
            result[j] = result[j].add(&column[j].mul(s));
        }
    }
    result
}

/// I perform a vector matrix multiplication
pub(crate) fn scalar_linear_combination_rows<S: Scalar>(lc_scalars: &[S], matrix: &[Vec<S>]) -> Vec<S>{
    let mut result = vec![S::from_u32(0u32); lc_scalars.len()];
    for (s,column) in lc_scalars.iter().zip(matrix){
        for j in 0..column.len(){
            result[j] = result[j].add(&column[j].mul(s));
        }
    }
    result
}