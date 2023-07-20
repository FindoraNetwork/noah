use noah_algebra::prelude::Scalar;

/// The MDS matrix
pub struct MDSMatrix<F: Scalar, const N: usize>(pub [[F; N]; N]);

impl<F: Scalar, const N: usize> Default for MDSMatrix<F, N> {
    fn default() -> Self {
        Self([[F::default(); N]; N])
    }
}

/// The trait for MDS matrix that can be used in Anemoi-Jive CRH.
pub trait ApplicableMDSMatrix<F: Scalar, const N: usize> {
    /// Construct the MDS matrix from the generator.
    fn from_generator(generator: &F) -> Self;

    /// Perform the permutation in place.
    fn permute_in_place(&self, x: &mut [F; N], y: &mut [F; N]);

    /// Perform the permutation and return the result.
    fn permute(&self, x: &[F; N], y: &[F; N]) -> ([F; N], [F; N]) {
        let mut x: [F; N] = *x;
        let mut y: [F; N] = *y;
        self.permute_in_place(&mut x, &mut y);
        (x, y)
    }
}

impl<F: Scalar> ApplicableMDSMatrix<F, 2> for MDSMatrix<F, 2> {
    fn from_generator(generator: &F) -> Self {
        // The matrix is:
        //     ⌈ 1     g       ⌉
        //     ⌊ g     g^2 + 1 ⌋
        Self([
            [F::one(), *generator],
            [*generator, generator.square().add(F::one())],
        ])
    }

    fn permute_in_place(&self, x: &mut [F; 2], y: &mut [F; 2]) {
        // Reminder: a different matrix is applied to x and y
        // The one for y has a simple word permutation.

        let old_x = *x;
        for (i, _x) in x.iter_mut().enumerate().take(2) {
            *_x = F::zero();
            for (j, ox) in old_x.iter().enumerate() {
                *_x += &(self.0[i][j] * ox);
            }
        }

        // y has a simple word permutation.
        let old_y = [y[1], y[0]];
        for (i, _y) in y.iter_mut().enumerate().take(2) {
            *_y = F::zero();
            for (j, oy) in old_y.iter().enumerate() {
                *_y += &(self.0[i][j] * oy);
            }
        }
    }
}
