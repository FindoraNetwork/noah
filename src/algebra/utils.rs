use super::groups::{Group, Scalar};

/// I perform a vector matrix multiplication
pub(crate) fn group_linear_combination_rows<G: Group>(lc_scalars: &[G::ScalarField],
                                                                    matrix: &[Vec<G>])
                                                                    -> Vec<G> {
  if matrix.len() == 0 {
    return vec![];
  }
  let mut result = vec![G::get_identity(); matrix[0].len()];
  for (s, row) in lc_scalars.iter().zip(matrix) {
    for j in 0..row.len() {
      result[j] = result[j].add(&row[j].mul(s));
    }
  }
  result
}

