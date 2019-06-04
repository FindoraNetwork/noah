use super::groups::{Scalar, Group};

/// I perform a vector matrix multiplication
pub(crate) fn group_linear_combination_rows<S: Scalar, G: Group<S>>(lc_scalars: &[S], matrix: &[Vec<G>]) -> Vec<G>{
    if matrix.len() == 0 {
        return vec![];
    }
    let mut result = vec![G::get_identity(); matrix[0].len()];
    for (s, row) in lc_scalars.iter().zip(matrix){
        for j in 0..row.len(){
            result[j] = result[j].add(&row[j].mul(s));
        }
    }
    result
}

/// I perform a vector matrix multiplication
pub(crate) fn scalar_linear_combination_rows<S: Scalar>(lc_scalars: &[S], matrix: &[Vec<S>]) -> Vec<S>{
    if matrix.len() == 0 {
        return vec![];
    }
    let mut result = vec![S::from_u32(0u32); matrix[0].len()];
    for (s, row) in lc_scalars.iter().zip(matrix){
        for j in 0..row.len(){
            result[j] = result[j].add(&row[j].mul(s));
        }
    }
    result
}
