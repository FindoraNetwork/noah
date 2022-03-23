// This files implements PLONK/turbo PLONK SNARK for PLONK constraint systems
// The standard constraint system for m variables and n constraints is specified by selector vectors q_L, q_R, q_O, q_M, and
// input indices vectors a,b,c, such that an input x\in \FF^{m} satisfies the constraint system if for all i\in [n]
// x_{a_i} * q_L[i] + x_{b_i} * q_R[i] + x_{a_i} * x_{b_i} * q_M[i]  =  x_{c_i} * q_O[i]
// Note that this allows to specify arithmetic circuits gates by setting q_M[i] = 1 for MUL gates and
// q_L[i] = q_R[i] = 1 for ADD gates. But it is more general, as other combination can be added. Moreover,
// additional selector polynomials can be added with little cost to support more complex gates (Turbo PLONK).

// PLONK encodes the selector vectors as polynomials of degree n over field \FF. In addition, the input witness
// is expanded to 3 vectors of length n, representing left, right, and output values of each gate.
// This expansion must form a predefined permutation in [3*n] that correctly maps each value with the wiring of the circuit (
// for example, the output of i-th gate must be the left input j-th gate).
// The expanded witness vector is also represented by a polynomials f1(X), f2(X) and f3(X) of degree n.
// All polynomials are interpolated at points {g^i} for g a generator of an order n group H (<g> = H).
// Then, the constraint system is satisfiable if for all i in {0..n-1}
// f1(g^i) * q_L(g^i) + f2(g^i) * q_R(g^i) + f2(g^i) * f3(g^i) * q_M(g^i)  = f2(g^i) * q_O(g^i)
// AND the evaluation values of f1,f2,f3 define the permutation derived from vectors a, b, c.

// Let k_1, k_2 and k_3 such that k_i * H, are distinct cosets of H. That is, for all x \in k_iH
// x\not \in k_j*H for i!=j \in {1,2,3}. Let \pi be a permutation over [3n], define polynomials $\pi_1, \pi_2, \pi_3$ such that
// \pi_j(g^s) = k_l g^t if \pi[(j-1)*n + s] = (l-1)*n + t. That is, s-th element in group j, is mapped to t-th element in group l, for k, l \in {1,2,3},
// and s,t in {0..n-1}. Meaning, for example if j = 1 and l = 2, the left input of the s-th gate is the same wire as the right input of t-th gate.

// For random field elements gamma, delta, interpolate polynomial \Sigma such that
//  - \Sigma(g^{i+1}) = \Sigma(g^i) * prod_{j=1}^3[(f_j(g^i) + gamma * k_j g^i + delta)/ (f_j(g^i) + gamma * \pi_j(g^i) + delta)],
// for i in [n], and using \Sigma(0) = 1, for the base case.
// Hence, if f1, f2, f3 do not satisfy the permutation, then \Sigma(g^n)\neq 1 with overwhelming probability.
// This check is implemented as follows:
// - Verifier needs to check
//   + \Sigma(1) = 1,
//   + \Sigma(g^{i+1})* prod_{j=1}^3(f_j(g^i) + gamma * \pi_j(g^i) + delta) - \Sigma(g^i)* prod_{j=1}^3(f_j(g^i) + gamma * k_j*g^i + delta) = 0 for all i
// Or equivalently, that for all X in H:
//   + (\Sigma(X) -1)*(X^n -1)(X -1) = 0
//   + \Sigma(g*X)* prod_{j=1}^3(f_j(X) + gamma * \pi_j(X) + delta) - \Sigma(X)* prod_{j=1}^3(f_j(X) + gamma * k_j*X + delta) = 0

// For a random element alpha, them, the verifier checks the following equation over every element of X:

// P(X) = f1(X) * q_L(X) + f2(X) * q_R(X) + f2(X) * f3(X) * q_M(X)  - f2(X) * q_O(X) +
// alpha * (\Sigma(g*X)* prod_{j=1}^3(f_j(X) + gamma * \pi_j(X) + delta) - \Sigma(X)* prod_{j=1}^3(f_j(X) + gamma * k_j*X + delta)) +
// alpha^2*(\Sigma(X) -1)*(X^n -1)(X -1) = 0

// To check this equation, the prover computes the quotient polynomial Q(X) = P(X) / (X^n -1), and convinces the verifier that
// P(X) - Q(X)*(X^n-1) = 0 for all X in the **field**. For this purpose, a random challenge \beta is sampled uniformly random in the field,
// and the verifier checks that P(\beta) - Q(\beta)/(\beta^n -1) = 0.

// Preprocessing:
// Verifier and prover deterministically samples a group H of order n, k1,k2,k3, and compute polynomials q_L, q_R, q_M, q_O, \pi_1, \pi_2, \pi_3.
// The verifier store a commitment representation to each of them.

// Online:
// 1. Prover uses extended witness to interpolate polynomials f1,f2,f3, commit to them, and append the commitments to the proof.
// 2. The random challenges \gamma and \delta are sampled.
// 3. Prover interpolate polynomial \Sigma. Commit to it, and append the commitment to the proof.
// 4. The random challenge \alpha is sampled.
// 5. Prover computes polynomials P(X) and Q(X). It splits Q(X) into 3 degree-n polynomials Q0, Q1, Q2, commits, and append the commitment to the proof.
// 6. The random challenge \beta is sampled.
// 7. Prover computes linearization polynomial L(X):
//  - L(X): f1(\beta) * q_L(X) + f2(\beta) * q_R(X) + f1(\beta) * f2(\beta) * q_M(X) - f3(\beta) * q_O(X) +
//        \alpha * \Sigma(X)* prod_{j=1}^3(f_j(\beta) + gamma * k_j*\beta + delta)) -
//        \alpha * (\Sigma(g*\beta)* prod_{j=2}^3(f_j(\beta) + gamma * \pi_j(\beta) + delta)*gamma*\pi_3(X) +
//        \alpha^2 * Sigma(X) (\beta^n - 1)/(\beta - 1)
// 8. Prover appends f1(\beta), f2(\beta), f3(\beta), \pi_1(\beta), \pi_2(\beta), L(\beta), \Sigma(beta*g) to the proof, together with a batch
// proof of the correctness of these values, including a proof for Q(\beta) = Q0(\beta) + \beta^{n} * Q1(\beta) + \beta^{2*n} * Q2(\beta).
// 9. Verifier computes element Q(\beta) = P(\beta)/(\beta^n -1) =
//   (L(\beta) -  \alpha * (\Sigma(g*\beta)* prod_{j=2}^3(f_j(\beta) + gamma * \pi_j(\beta) + delta)*f3(\beta + delta) -
//   (\beta^n - 1)/(\beta - 1))/ (\beta^n -1).
// 10. Verifier homomorphically derives commitment to L(X).
// 11. Verifier batch verify the eval proofs for f1(\beta), f2(\beta), f3(\beta), \pi_1(\beta), \pi_2(\beta), L(\beta), \Sigma(beta*g),
// Q(\beta) =  = Q0(\beta) + \beta^{n} * Q1(\beta) + \beta^{2*n} * Q2(\beta).

// Adding Zero-Knowledge:
//  - each fi polynomial is randomized by adding a blinding polynomial of degree 1 that vanishes on H: fi(X) -> (bi1 + X bi2) * (X^n - 1) + fi(X)
//  - Since \Sigma(X) is opened in two points, we blind it with a degree 2 polynomial \Sigma(X) -> (b1 + X * b2 + X^2 * b3) * (X^n - 1) + \Sigma(X)
// Since, random polynomial vanishes on H, it does not affect correctness nor soundness of the protocol.

pub(crate) mod helpers;

pub mod constraint_system;
pub mod errors;
pub mod prover;
pub mod setup;
pub mod transcript;
pub mod verifier;
