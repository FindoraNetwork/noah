// This files implements the rescue block cipher and hash function
// It provides a generic algorithm for any parameters and also a specific instance
// for the BLS12_381 scalar field for a sponge construction parameters rate: 3 and capacity: 1.
// Instances parameters are obtained from https://github.com/KULeuven-COSIC/Marvellous
// instance = Rescue(s,q,m,alpha), where s is the security parameter (eg s = 128,
// q is the prime field size, m is the sponge state size = rate + capacity, and alpha is the *desired*
// S-box exponent for rescue construction.

// The constant is now generated from commit b265d9a of
// https://github.com/KULeuven-COSIC/Marvellous

// Rescue algorithm:
// 1. pad the input with `capacity` 0s
// 2. Set the state as padded input + instance.initial_constants + key.
// 3. Call key scheduling algorithm to derive rounds keys K_r' and K_r. This can be done on each round too.
// 4. Execute N rounds of the form
//   - state_r' = instance.M * S-box-inv(state_{r-1}) + K_r', first step of round r
//   - state_r = instance.M * S-box(state_r') + K_r, second step of round r
//   where S-box(x_1,...,x_m) = (x_1^\alpha, ..., x_m^\alpha) and
//        S-box-inv(x_1,...,x_m) = (x_1^{1/\alpha}, ..., x_m^{1/\alpha})
// 5. return state_N

// Key scheduling: The round keys are computed as:
// 1. Derive key injection keys:
// - set key_injection_0 = C
// 2. Use Rescue rounds to compute the round keys.
// - Set the key as input, and key_injection as the round keys.
// - do:
//   - key_injection_r' = instance.K * key_injection_{r-1} + instance.C, where K (m x m matrix) and C (m-size vector)
//   - K_r'= instance.M * S-box-inv(K_{r-1}) + key_injection_r'
//   - key_injection_r = instance.K * key_injection_r' + instance.C
//   - K_r = instance.M * S-box(K_r') + key_injection_r, used in second step of round r

use zei_algebra::{bls12_381::BLSScalar, prelude::*, str::FromStr};

#[allow(non_snake_case)]
pub struct RescueInstance<S> {
    pub MDS: Vec<Vec<S>>, // m * m matrix, m = rate + capacity
    pub IC: Vec<S>,       // initial constant m vector
    pub C: Vec<S>,        // key scheduling constant m vector
    pub K: Vec<Vec<S>>,   // key scheduling constant m * m matrix
    pub rate: usize,
    pub capacity: usize,
    pub alpha: u64,
    pub alpha_inv: Vec<u64>,
    pub num_rounds: usize,
}

pub type RoundSubKey<S> = Vec<S>;
pub type RescueState<S> = Vec<S>;

impl<S: Scalar> RescueInstance<S> {
    pub fn num_rounds(&self) -> usize {
        self.num_rounds
    }

    pub fn state_size(&self) -> usize {
        self.rate + self.capacity
    }

    // Take input and produce an initial state by appending `capacity` zeros.
    fn pad_input_to_state_size(&self, input: &[S]) -> RescueState<S> {
        let mut r = input.to_vec();
        while r.len() != self.state_size() {
            r.push(S::zero());
        }
        r
    }

    /// Produces RESCUE round keys from `key`
    pub fn key_scheduling(&self, key: &[S]) -> Vec<RoundSubKey<S>> {
        let mut key_injection = self.IC.clone();
        let mut prev_key: Vec<S> = key
            .iter()
            .zip(key_injection.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        let mut keys = vec![prev_key.clone()];
        for i in 0..2 * self.num_rounds() {
            if i % 2 == 0 {
                Self::pow_vector(prev_key.as_mut_slice(), &self.alpha_inv);
            } else {
                Self::pow_vector(prev_key.as_mut_slice(), &[self.alpha]);
            }
            // 1. update key injection
            Self::linear_op(&self.K, key_injection.as_mut_slice(), &self.C);
            // 2. compute round key
            Self::linear_op(
                &self.MDS,
                prev_key.as_mut_slice(),
                key_injection.as_mut_slice(),
            );
            // 3. save key
            keys.push(prev_key.clone());
        }
        keys
    }

    /// Compute hash sampling the rounds' keys online
    pub fn rescue(&self, input: &[S]) -> RescueState<S> {
        assert_eq!(input.len(), self.state_size());

        // key_state = key + initial constants
        let mut key_state: Vec<S> = self.IC.clone();
        // key_injection = initial constants
        let mut key_injection = self.IC.clone();

        let padded_input = self.pad_input_to_state_size(input);
        // state = state + key_state
        let mut state = padded_input
            .iter()
            .zip(key_state.iter())
            .map(|(input, k0i)| input.add(k0i))
            .collect_vec();
        // N rounds divided in two parts forward S-box (even step) and backward S-box (forward step)
        for round in 0..2 * self.num_rounds {
            self.rescue_round(
                state.as_mut_slice(),
                key_state.as_mut_slice(),
                key_injection.as_mut_slice(),
                round,
            );
        }
        state
    }

    // Compute a rescue round, sampling the round keys online
    fn rescue_round(
        &self,
        state: &mut [S],
        key_state: &mut [S],
        key_injection: &mut [S],
        round: usize,
    ) {
        if round % 2 == 0 {
            Self::pow_vector(key_state, &self.alpha_inv);
            Self::pow_vector(state, &self.alpha_inv);
        } else {
            Self::pow_vector(key_state, &[self.alpha]);
            Self::pow_vector(state, &[self.alpha]);
        }

        Self::linear_op(&self.K, key_injection, &self.C);
        Self::linear_op(&self.MDS, key_state, key_injection);
        Self::linear_op(&self.MDS, state, key_state);
    }

    // helper function: compute r = M*r + c, where M is a square matrix and r and c are vectors. Result is stored in r.
    pub fn linear_op(matrix: &[Vec<S>], mul_assign_vector: &mut [S], add_vector: &[S]) {
        let mut aux_vec = add_vector.to_vec();
        // multiply matrix agains mul assign vector, result in aux_vec
        for (m_i, aux_i) in matrix.iter().zip(aux_vec.iter_mut()) {
            for (m_ij, v_j) in m_i.iter().zip(mul_assign_vector.iter()) {
                *aux_i = aux_i.add(&m_ij.mul(v_j));
            }
        }
        for (assign_i, aux_elem) in mul_assign_vector.iter_mut().zip(aux_vec) {
            *assign_i = aux_elem;
        }
    }

    fn pow_vector(vector: &mut [S], exponent: &[u64]) {
        for v in vector {
            *v = v.pow(exponent);
        }
    }
}

// # of rounds
const NR: usize = 12;

// MDS matrix
const M00: &str = "52435875175126190479447740508185965837690552500527637822603658699938581066864";
const M01: &str = "52435875175126190479447740508185965837690552500527637822603658699938534124913";
const M02: &str = "52435875175126190479447740508185965837690552500527637822603658699922104442063";
const M03: &str = "52435875175126190479447740508185965837690552500527637822603658694270581781713";

const M10: &str = "137200";
const M11: &str = "54762351";
const M12: &str = "19167800400";
const M13: &str = "6593435097550";

const M20: &str = "52435875175126190479447740508185965837690552500527637822603658699938581164563";
const M21: &str = "52435875175126190479447740508185965837690552500527637822603658699938573341713";
const M22: &str = "52435875175126190479447740508185965837690552500527637822603658699935841949364";
const M23: &str = "52435875175126190479447740508185965837690552500527637822603658698996613844913";

const M30: &str = "400";
const M31: &str = "140050";
const M32: &str = "48177200";
const M33: &str = "16531644851";

// constant matrix
const K00: &str = "20508694040621567351648110034447675442497630601368754313856884903339587777311";
const K01: &str = "21833126749675005420257511508741654628498211767962591705355382899857469438170";
const K02: &str = "10094259962876866855921243786568400951965635335279511958062644189442373357290";
const K03: &str = "19703017446530302026954081842172601421653728134317178448940156258115853425803";

const K10: &str = "10251498144790729877114984073212046753223574188577263253763854582885300616634";
const K11: &str = "23799697215770479455315980501436150478606639549341703710964277906023879274693";
const K12: &str = "3007859742890615231402252990001597094047140204544326329227026628202747223471";
const K13: &str = "28206680002640467010077105488518988050496606663258696654543362871739559141116";

const K20: &str = "3001386190657217866716811031197002190094834176598601007437349105366277408753";
const K21: &str = "3302832234223427084389235892793462946069958738751625733789554798277785616852";
const K22: &str = "33828191304584863092326289783666465913001308709873493077072772336792329272781";
const K23: &str = "39527082973012175895755035046102602497048600747962062191946750704586900696815";

const K30: &str = "28051483866417948291356906371063959987011977735069581088198413305545643762525";
const K31: &str = "940230548799789892304826428424685764994822279495712794369041189518965610982";
const K32: &str = "51086698257646416011541091115454938869982232807222651212625724712549497545484";
const K33: &str = "17476372527237931823914329908105757745889986759257828348803723712031461055028";

// initial constants
const IC0: &str = "23134431890904997735913685390433273947519177060544011867815065124418348995661";
const IC1: &str = "7910743581020883359489900822814213105822551758045258908574127548576902234202";
const IC2: &str = "6452335108146897903818881932868089947456740590166061243393158685187431809297";
const IC3: &str = "864592593827916191968939823230510547087468030011538620003456937932684270153";

// constants
const C0: &str = "47547237971610965741643776816276041546468880714675495834455049663798422970459";
const C1: &str = "10004118136888058764408398782965078987905732598601545000387602435395348015578";
const C2: &str = "41751554506863950612723183999266149980852802057217063263129581065630539355943";
const C3: &str = "28630474321717538333837377020183699597240697917209889448356171144508785456174";

// alpha^{-1} mod (q-1) = 20974350070050476191779096203274386335076221000211055129041463479975432473805;
// least significant u64limb first
const ALPHA_INV: [u64; 4] = [
    0x33333332CCCCCCCD,
    0x217F0E679998F199,
    0xE14A56699D73F002,
    0x2E5F0FBADD72321C,
];
const ALPHA: u64 = 5;

impl Default for RescueInstance<BLSScalar> {
    fn default() -> Self {
        Self::new()
    }
}

impl RescueInstance<BLSScalar> {
    pub fn new() -> Self {
        Self {
            MDS: vec![
                vec![
                    BLSScalar::from_str(M00).unwrap(),
                    BLSScalar::from_str(M01).unwrap(),
                    BLSScalar::from_str(M02).unwrap(),
                    BLSScalar::from_str(M03).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(M10).unwrap(),
                    BLSScalar::from_str(M11).unwrap(),
                    BLSScalar::from_str(M12).unwrap(),
                    BLSScalar::from_str(M13).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(M20).unwrap(),
                    BLSScalar::from_str(M21).unwrap(),
                    BLSScalar::from_str(M22).unwrap(),
                    BLSScalar::from_str(M23).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(M30).unwrap(),
                    BLSScalar::from_str(M31).unwrap(),
                    BLSScalar::from_str(M32).unwrap(),
                    BLSScalar::from_str(M33).unwrap(),
                ],
            ],
            IC: vec![
                BLSScalar::from_str(IC0).unwrap(),
                BLSScalar::from_str(IC1).unwrap(),
                BLSScalar::from_str(IC2).unwrap(),
                BLSScalar::from_str(IC3).unwrap(),
            ],
            C: vec![
                BLSScalar::from_str(C0).unwrap(),
                BLSScalar::from_str(C1).unwrap(),
                BLSScalar::from_str(C2).unwrap(),
                BLSScalar::from_str(C3).unwrap(),
            ],
            K: vec![
                vec![
                    BLSScalar::from_str(K00).unwrap(),
                    BLSScalar::from_str(K01).unwrap(),
                    BLSScalar::from_str(K02).unwrap(),
                    BLSScalar::from_str(K03).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(K10).unwrap(),
                    BLSScalar::from_str(K11).unwrap(),
                    BLSScalar::from_str(K12).unwrap(),
                    BLSScalar::from_str(K13).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(K20).unwrap(),
                    BLSScalar::from_str(K21).unwrap(),
                    BLSScalar::from_str(K22).unwrap(),
                    BLSScalar::from_str(K23).unwrap(),
                ],
                vec![
                    BLSScalar::from_str(K30).unwrap(),
                    BLSScalar::from_str(K31).unwrap(),
                    BLSScalar::from_str(K32).unwrap(),
                    BLSScalar::from_str(K33).unwrap(),
                ],
            ],
            rate: 3,
            capacity: 1,
            alpha: ALPHA,
            alpha_inv: ALPHA_INV.to_vec(),
            num_rounds: NR,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::basic::rescue::RescueInstance;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*, str::FromStr};

    // Hash output on zero inputs
    const H0: &str = "6038713180564719469093204954070454311200442976044511285254586065910759707410";
    const H1: &str =
        "34329261730165386599160041834212446483842299157433262004736471876736429833755";
    const H2: &str = "2862237230994348516440719507068326488024178021789155173222527361984277349895";
    const H3: &str =
        "43585057371572541667806316000947875129969521379933781949636379096285260817308";

    // A random input
    const IN0: &str =
        "42537060686398681068720905217220236844590933627861183801397355384184270218630";
    const IN1: &str =
        "12225154963254549867036423973370419579530821253177826398645943378468081695636";
    const IN2: &str =
        "24365514044908739860551540899404524528046031872121777535250238952975251078869";

    // Hash output on the random input
    const OUT0: &str =
        "35832061285584612018010978377396475516386148728568768102972061541748447218154";
    const OUT1: &str =
        "14982435907911263894119260171766443289460927159355495366027587674112560884509";
    const OUT2: &str =
        "45163412910076015540204938060153898258490893781185872331302937226715728232099";
    const OUT3: &str =
        "39714470008892548080624693423358217990644071107421276480773579042887134307768";

    #[test]
    fn test_rescue_hash() {
        let hash = RescueInstance::<BLSScalar>::new();
        let zero_vec = [
            BLSScalar::zero(),
            BLSScalar::zero(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ];
        let expected_output = vec![
            BLSScalar::from_str(H0).unwrap(),
            BLSScalar::from_str(H1).unwrap(),
            BLSScalar::from_str(H2).unwrap(),
            BLSScalar::from_str(H3).unwrap(),
        ];
        let hash_state = hash.rescue(&zero_vec);
        assert_eq!(hash_state, expected_output);

        // Use a random input
        let input_vec = [
            BLSScalar::from_str(IN0).unwrap(),
            BLSScalar::from_str(IN1).unwrap(),
            BLSScalar::from_str(IN2).unwrap(),
            BLSScalar::zero(),
        ];
        let expected_output = vec![
            BLSScalar::from_str(OUT0).unwrap(),
            BLSScalar::from_str(OUT1).unwrap(),
            BLSScalar::from_str(OUT2).unwrap(),
            BLSScalar::from_str(OUT3).unwrap(),
        ];
        let hash_state = hash.rescue(&input_vec);
        assert_eq!(hash_state, expected_output);
    }
}
