use algebra::bls12_381::BLSScalar;
use crate::basic_crypto::hash::rescue::RescueInstance;
use ff::PrimeField;
use pairing::bls12_381::Fr;

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
const K00: &str = "10251498144790729877114984073212046753223574188577263253763854582885300616634";
const K01: &str = "23799697215770479455315980501436150478606639549341703710964277906023879274693";
const K02: &str = "3007859742890615231402252990001597094047140204544326329227026628202747223471";
const K03: &str = "28206680002640467010077105488518988050496606663258696654543362871739559141116";

const K10: &str = "3001386190657217866716811031197002190094834176598601007437349105366277408753";
const K11: &str = "3302832234223427084389235892793462946069958738751625733789554798277785616852";
const K12: &str = "33828191304584863092326289783666465913001308709873493077072772336792329272781";
const K13: &str = "39527082973012175895755035046102602497048600747962062191946750704586900696815";

const K20: &str = "28051483866417948291356906371063959987011977735069581088198413305545643762525";
const K21: &str = "940230548799789892304826428424685764994822279495712794369041189518965610982";
const K22: &str = "51086698257646416011541091115454938869982232807222651212625724712549497545484";
const K23: &str = "17476372527237931823914329908105757745889986759257828348803723712031461055028";

const K30: &str = "23134431890904997735913685390433273947519177060544011867815065124418348995661";
const K31: &str = "7910743581020883359489900822814213105822551758045258908574127548576902234202";
const K32: &str = "6452335108146897903818881932868089947456740590166061243393158685187431809297";
const K33: &str = "864592593827916191968939823230510547087468030011538620003456937932684270153";

// initial constants
const IC0: &str = "20508694040621567351648110034447675442497630601368754313856884903339587777311";
const IC1: &str = "21833126749675005420257511508741654628498211767962591705355382899857469438170";
const IC2: &str = "10094259962876866855921243786568400951965635335279511958062644189442373357290";
const IC3: &str = "19703017446530302026954081842172601421653728134317178448940156258115853425803";

// constants
const C0: &str = "47547237971610965741643776816276041546468880714675495834455049663798422970459";
const C1: &str = "10004118136888058764408398782965078987905732598601545000387602435395348015578";
const C2: &str = "41751554506863950612723183999266149980852802057217063263129581065630539355943";
const C3: &str = "28630474321717538333837377020183699597240697917209889448356171144508785456174";

// alpha^{-1} mod (q-1) = 20974350070050476191779096203274386335076221000211055129041463479975432473805;
// least significant u64limb first
const ALPHA_INV: [u64; 4] = [0x33333332CCCCCCCD,
                             0x217F0E679998F199,
                             0xE14A56699D73F002,
                             0x2E5F0FBADD72321C];
const ALPHA: u64 = 5;

impl Default for RescueInstance<BLSScalar> {
  fn default() -> Self {
    Self::new()
  }
}

impl RescueInstance<BLSScalar> {
  pub fn new() -> Self {
    Self { MDS: vec![vec![BLSScalar(Fr::from_str(M00).unwrap()),
                          BLSScalar(Fr::from_str(M01).unwrap()),
                          BLSScalar(Fr::from_str(M02).unwrap()),
                          BLSScalar(Fr::from_str(M03).unwrap()),],
                     vec![BLSScalar(Fr::from_str(M10).unwrap()),
                          BLSScalar(Fr::from_str(M11).unwrap()),
                          BLSScalar(Fr::from_str(M12).unwrap()),
                          BLSScalar(Fr::from_str(M13).unwrap()),],
                     vec![BLSScalar(Fr::from_str(M20).unwrap()),
                          BLSScalar(Fr::from_str(M21).unwrap()),
                          BLSScalar(Fr::from_str(M22).unwrap()),
                          BLSScalar(Fr::from_str(M23).unwrap()),],
                     vec![BLSScalar(Fr::from_str(M30).unwrap()),
                          BLSScalar(Fr::from_str(M31).unwrap()),
                          BLSScalar(Fr::from_str(M32).unwrap()),
                          BLSScalar(Fr::from_str(M33).unwrap()),]],
           IC: vec![BLSScalar(Fr::from_str(IC0).unwrap()),
                    BLSScalar(Fr::from_str(IC1).unwrap()),
                    BLSScalar(Fr::from_str(IC2).unwrap()),
                    BLSScalar(Fr::from_str(IC3).unwrap())],
           C: vec![BLSScalar(Fr::from_str(C0).unwrap()),
                   BLSScalar(Fr::from_str(C1).unwrap()),
                   BLSScalar(Fr::from_str(C2).unwrap()),
                   BLSScalar(Fr::from_str(C3).unwrap())],
           K: vec![vec![BLSScalar(Fr::from_str(K00).unwrap()),
                        BLSScalar(Fr::from_str(K01).unwrap()),
                        BLSScalar(Fr::from_str(K02).unwrap()),
                        BLSScalar(Fr::from_str(K03).unwrap()),],
                   vec![BLSScalar(Fr::from_str(K10).unwrap()),
                        BLSScalar(Fr::from_str(K11).unwrap()),
                        BLSScalar(Fr::from_str(K12).unwrap()),
                        BLSScalar(Fr::from_str(K13).unwrap()),],
                   vec![BLSScalar(Fr::from_str(K20).unwrap()),
                        BLSScalar(Fr::from_str(K21).unwrap()),
                        BLSScalar(Fr::from_str(K22).unwrap()),
                        BLSScalar(Fr::from_str(K23).unwrap()),],
                   vec![BLSScalar(Fr::from_str(K30).unwrap()),
                        BLSScalar(Fr::from_str(K31).unwrap()),
                        BLSScalar(Fr::from_str(K32).unwrap()),
                        BLSScalar(Fr::from_str(K33).unwrap()),]],
           rate: 3,
           capacity: 1,
           alpha: ALPHA,
           alpha_inv: ALPHA_INV.to_vec(),
           num_rounds: NR }
  }
}

#[cfg(test)]
mod test {
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::Scalar;
  use crate::basic_crypto::hash::rescue::RescueInstance;
  use ff::PrimeField;
  use pairing::bls12_381::Fr;

  // Hash output on zero inputs
  const H0: &str = "52184923318241479436224725218017640784400243367974222506608059144773855444730";
  const H1: &str = "23924545064338269124873376581031651645568148251016144999367772947687143613745";
  const H2: &str = "30937566749535609217704187869132113621318968118976606215026201258864567472550";
  const H3: &str = "33406978843301229557750270276095078266402830316315171601608271834052086941647";

  // A random input
  const IN0: &str = "42537060686398681068720905217220236844590933627861183801397355384184270218630";
  const IN1: &str = "12225154963254549867036423973370419579530821253177826398645943378468081695636";
  const IN2: &str = "24365514044908739860551540899404524528046031872121777535250238952975251078869";

  // Hash output on the random input
  const OUT0: &str =
    "33261895114630295414206051695197432234566285696847519001039321113311865814651";
  const OUT1: &str =
    "19233611809197654557396381890472531106976529922405272563624094402076250523604";
  const OUT2: &str =
    "13022914755273627860455360268792907696154546465002100319274480859241273599340";
  const OUT3: &str =
    "11841671251183135941416472468814974558690471402623537939181412432991452533485";

  #[test]
  fn rescue_hash_consistency() {
    let hash = RescueInstance::<BLSScalar>::new();
    let zero_vec = [BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0)];
    let keys = hash.key_scheduling(&zero_vec);
    let hash_state = hash.rescue_with_round_keys(&zero_vec, &keys);

    let hash_state2 = hash.rescue_hash(&zero_vec);

    assert_eq!(hash_state, hash_state2);

    let hash_init_keys = hash.hash_init();
    assert_eq!(hash_init_keys, keys);

    // Use some non-zero seed and plaintext
    let seed = [BLSScalar::from_u32(17),
                BLSScalar::from_u32(212),
                BLSScalar::from_u32(131),
                BLSScalar::from_u32(5179)];
    let input_vec = [BLSScalar::from_u32(34121),
                     BLSScalar::from_u32(65179),
                     BLSScalar::from_u32(19189),
                     BLSScalar::from_u32(0)];
    let keys = hash.key_scheduling(&seed);
    let hash_state = hash.rescue_with_round_keys(&input_vec, &keys);
    let hash_state2 = hash.rescue(&input_vec, &seed);

    assert_eq!(hash_state, hash_state2);
  }

  #[test]
  fn test_rescue_hash() {
    let hash = RescueInstance::<BLSScalar>::new();
    let zero_vec = [BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0),
                    BLSScalar::from_u32(0)];
    let expected_output = vec![BLSScalar(Fr::from_str(H0).unwrap()),
                               BLSScalar(Fr::from_str(H1).unwrap()),
                               BLSScalar(Fr::from_str(H2).unwrap()),
                               BLSScalar(Fr::from_str(H3).unwrap())];
    let keys = hash.key_scheduling(&zero_vec);
    let hash_state = hash.rescue_with_round_keys(&zero_vec, &keys);
    let hash_state2 = hash.rescue_hash(&zero_vec);
    assert_eq!(hash_state, expected_output);
    assert_eq!(hash_state2, expected_output);

    // Use a random input
    let input_vec = [BLSScalar(Fr::from_str(IN0).unwrap()),
                     BLSScalar(Fr::from_str(IN1).unwrap()),
                     BLSScalar(Fr::from_str(IN2).unwrap()),
                     BLSScalar::from_u32(0)];
    let expected_output = vec![BLSScalar(Fr::from_str(OUT0).unwrap()),
                               BLSScalar(Fr::from_str(OUT1).unwrap()),
                               BLSScalar(Fr::from_str(OUT2).unwrap()),
                               BLSScalar(Fr::from_str(OUT3).unwrap()),];
    let keys = hash.key_scheduling(&zero_vec);
    let hash_state = hash.rescue_with_round_keys(&input_vec, &keys);
    let hash_state2 = hash.rescue_hash(&input_vec);
    assert_eq!(hash_state, expected_output);
    assert_eq!(hash_state2, expected_output);
  }
}
