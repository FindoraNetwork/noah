use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::new_bls12_381;
use noah_algebra::prelude::*;

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
        let mut x: [F; N] = x.clone();
        let mut y: [F; N] = y.clone();
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

        let old_x = x.clone();
        for i in 0..2 {
            x[i] = F::zero();
            for j in 0..2 {
                x[i] += &(self.0[i][j] * old_x[j]);
            }
        }

        // y has a simple word permutation.
        let old_y = [y[1], y[0]];
        for i in 0..2 {
            y[i] = F::zero();
            for j in 0..2 {
                y[i] += &(self.0[i][j] * old_y[j]);
            }
        }
    }
}

/// The structure for the trace of the Anemoi-Jive sponge hash function.
#[derive(Clone)]
pub struct AnemoiVLHTrace<F: Scalar, const N: usize, const NUM_ROUNDS: usize> {
    /// The input sequence.
    pub input: Vec<F>,
    /// The state before each permutation.
    pub before_permutation: Vec<([F; N], [F; N])>,
    /// The intermediate values for each permutation.
    pub intermediate_values_before_constant_additions:
        Vec<([[F; N]; NUM_ROUNDS], [[F; N]; NUM_ROUNDS])>,
    /// The state after each permutation.
    pub after_permutation: Vec<([F; N], [F; N])>,
    /// The output.
    pub output: F,
}

impl<F: Scalar, const N: usize, const NUM_ROUNDS: usize> Default
    for AnemoiVLHTrace<F, N, NUM_ROUNDS>
{
    fn default() -> Self {
        Self {
            input: vec![],
            before_permutation: vec![],
            intermediate_values_before_constant_additions: vec![],
            after_permutation: vec![],
            output: F::default(),
        }
    }
}

impl<F: Scalar, const N: usize, const NUM_ROUNDS: usize> noah_algebra::fmt::Debug
    for AnemoiVLHTrace<F, N, NUM_ROUNDS>
{
    fn fmt(&self, f: &mut noah_algebra::fmt::Formatter<'_>) -> noah_algebra::fmt::Result {
        f.write_str("input:\n")?;
        for (i, elem) in self.input.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }

        for r in 0..NUM_ROUNDS {
            f.write_fmt(format_args!("round {}:\n", r))?;

            f.write_str("\r before permutation:")?;

            for (i, elem) in self.before_permutation[r].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.before_permutation[r].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }

            f.write_str("\r intermediate permutation:")?;

            for (i, elem) in self.intermediate_values_before_constant_additions[r]
                .0
                .iter()
                .enumerate()
            {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.intermediate_values_before_constant_additions[r]
                .1
                .iter()
                .enumerate()
            {
                f.write_fmt(format_args!("\r\r y[{}] = {:?}\n", i, elem))?;
            }

            f.write_str("\r after permutation:")?;

            for (i, elem) in self.after_permutation[r].0.iter().enumerate() {
                f.write_fmt(format_args!("\r\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.after_permutation[r].1.iter().enumerate() {
                f.write_fmt(format_args!("\r \r y[{}] = {:?}\n", i, elem))?;
            }
        }

        f.write_fmt(format_args!("output = {:?}\n", self.output))
    }
}

/// The structure for the trace of the Anemio-Jive CRH.
#[derive(Clone, PartialEq)]
pub struct JiveTrace<F: Scalar, const N: usize, const NUM_ROUNDS: usize> {
    /// The first half of the input.
    pub input_x: [F; N],
    /// The second half of the input.
    pub input_y: [F; N],
    /// The first half of the intermediate values in the rounds.
    pub intermediate_x_before_constant_additions: [[F; N]; NUM_ROUNDS],
    /// The second half of the intermediate values in the rounds.
    pub intermediate_y_before_constant_additions: [[F; N]; NUM_ROUNDS],
    /// The first half of the final output (after the linear layer).
    pub final_x: [F; N],
    /// The second half of the final output (after the linear layer).
    pub final_y: [F; N],
    /// The output of the Jive CRH.
    pub output: F,
}

impl<F: Scalar, const N: usize, const NUM_ROUNDS: usize> Default for JiveTrace<F, N, NUM_ROUNDS> {
    fn default() -> Self {
        Self {
            input_x: [F::default(); N],
            input_y: [F::default(); N],
            intermediate_x_before_constant_additions: [[F::default(); N]; NUM_ROUNDS],
            intermediate_y_before_constant_additions: [[F::default(); N]; NUM_ROUNDS],
            final_x: [F::default(); N],
            final_y: [F::default(); N],
            output: F::default(),
        }
    }
}

impl<F: Scalar, const N: usize, const NUM_ROUNDS: usize> noah_algebra::fmt::Debug
    for JiveTrace<F, N, NUM_ROUNDS>
{
    fn fmt(&self, f: &mut noah_algebra::fmt::Formatter<'_>) -> noah_algebra::fmt::Result {
        f.write_str("input_x:\n")?;
        for (i, elem) in self.input_x.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }

        f.write_str("input_y:\n")?;
        for (i, elem) in self.input_y.iter().enumerate() {
            f.write_fmt(format_args!("\r y[{}] = {:?}\n", i, elem))?;
        }

        for r in 0..NUM_ROUNDS {
            f.write_fmt(format_args!("round {}:\n", r))?;

            for (i, elem) in self.intermediate_x_before_constant_additions[r]
                .iter()
                .enumerate()
            {
                f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
            }

            for (i, elem) in self.intermediate_y_before_constant_additions[r]
                .iter()
                .enumerate()
            {
                f.write_fmt(format_args!("\r y[{}] = {:?}\n", i, elem))?;
            }
        }

        f.write_str("final_x:\n")?;
        for (i, elem) in self.final_x.iter().enumerate() {
            f.write_fmt(format_args!("\r x[{}] = {:?}\n", i, elem))?;
        }

        f.write_str("final_y:\n")?;
        for (i, elem) in self.final_y.iter().enumerate() {
            f.write_fmt(format_args!("\r y[{}] = {:?}\n", i, elem))?;
        }

        f.write_fmt(format_args!("output: {:?}\n", self.output))
    }
}

/// The trait for the Anemoi-Jive parameters.
pub trait AnemoiJive<F: Scalar, const N: usize, const NUM_ROUNDS: usize>
where
    MDSMatrix<F, N>: ApplicableMDSMatrix<F, N>,
{
    /// The S-Box alpha value.
    const ALPHA: u32;

    /// The generator of the group.
    const GENERATOR: F;

    /// Delta, which is the inverse of the generator.
    const GENERATOR_INV: F;

    /// Used in the MDS. The square of the generator plus one.
    const GENERATOR_SQUARE_PLUS_ONE: F;

    /// The first group of the round keys.
    const ROUND_KEYS_X: [[F; N]; NUM_ROUNDS];

    /// The second group of the round keys.
    const ROUND_KEYS_Y: [[F; N]; NUM_ROUNDS];

    /// The first group of the round keys that have been preprocessed with the MDS.
    const PREPROCESSED_ROUND_KEYS_X: [[F; N]; NUM_ROUNDS];

    /// The second group of the round keys that have been preprocessed with the MDS.
    const PREPROCESSED_ROUND_KEYS_Y: [[F; N]; NUM_ROUNDS];

    /// The MDS matrix.
    const MDS_MATRIX: [[F; N]; N];

    /// Return the inverse of alpha over `r - 1`.
    fn get_alpha_inv() -> Vec<u64>;

    /// Eval the Anemoi sponge.
    fn eval_variable_length_hash(input: &[F]) -> F {
        let mut input = input.to_vec();

        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::one()
        } else {
            input.push(F::one());
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(
                    &[F::zero()].repeat(2 * N - 1 - (input.len() % (2 * N - 1))),
                );
            }

            F::zero()
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // initialize the internal state.
        let mut x = [F::zero(); N];
        let mut y = [F::zero(); N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            for r in 0..NUM_ROUNDS {
                for i in 0..N {
                    x[i] += &Self::ROUND_KEYS_X[r][i];
                    y[i] += &Self::ROUND_KEYS_Y[r][i];
                }
                mds.permute_in_place(&mut x, &mut y);
                for i in 0..N {
                    x[i] -= &(Self::GENERATOR * &(y[i].square()));
                    y[i] -= &x[i].pow(&alpha_inv);
                    x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
                }
            }
            mds.permute_in_place(&mut x, &mut y);
        }
        y[N - 1] += &sigma;
        // This step can be omitted since we only get one element.
        // For formality we keep it here.

        x[0]
    }

    /// Eval the Anemoi sponge and return the trace.
    fn eval_variable_length_hash_with_trace(input: &[F]) -> AnemoiVLHTrace<F, N, NUM_ROUNDS> {
        let mut trace = AnemoiVLHTrace::<F, N, NUM_ROUNDS>::default();

        let mut input = input.to_vec();
        trace.input = input.clone();

        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::one()
        } else {
            input.push(F::one());
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(
                    &[F::zero()].repeat(2 * N - 1 - (input.len() % (2 * N - 1))),
                );
            }

            F::zero()
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // initialize the internal state.
        let mut x = [F::zero(); N];
        let mut y = [F::zero(); N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            trace.before_permutation.push((x.clone(), y.clone()));

            let mut intermediate_values_before_constant_additions =
                ([[F::zero(); N]; NUM_ROUNDS], [[F::zero(); N]; NUM_ROUNDS]);
            for r in 0..NUM_ROUNDS {
                for i in 0..N {
                    x[i] += &Self::ROUND_KEYS_X[r][i];
                    y[i] += &Self::ROUND_KEYS_Y[r][i];
                }
                mds.permute_in_place(&mut x, &mut y);
                for i in 0..N {
                    x[i] -= &(Self::GENERATOR * &(y[i].square()));
                    y[i] -= &x[i].pow(&alpha_inv);
                    x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
                }

                intermediate_values_before_constant_additions.0[r] = x.clone();
                intermediate_values_before_constant_additions.1[r] = y.clone();
            }

            mds.permute_in_place(&mut x, &mut y);

            trace
                .intermediate_values_before_constant_additions
                .push(intermediate_values_before_constant_additions);

            trace.after_permutation.push((x.clone(), y.clone()));
        }
        y[N - 1] += &sigma;
        // This step can be omitted since we only get one element.
        // For formality we keep it here.

        trace.output = x[0];

        trace
    }

    /// Eval the Anemoi-Jive hash function and return the result.
    fn eval_jive(x: &[F; N], y: &[F; N]) -> F {
        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();
        let sum_before_perm: F = x.iter().sum::<F>() + y.iter().sum::<F>();
        let mut x = x.clone();
        let mut y = y.clone();
        for r in 0..NUM_ROUNDS {
            for i in 0..N {
                x[i] += &Self::ROUND_KEYS_X[r][i];
                y[i] += &Self::ROUND_KEYS_Y[r][i];
            }
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..N {
                x[i] -= &(Self::GENERATOR * &(y[i].square()));
                y[i] -= &x[i].pow(&alpha_inv);
                x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
            }
        }
        mds.permute_in_place(&mut x, &mut y);
        let sum_after_perm: F = x.iter().sum::<F>() + y.iter().sum::<F>();
        sum_before_perm + sum_after_perm
    }

    /// Eval the Anemoi-Jive hash function and return the trace of execution,
    /// which is to be used for creating the zero-knowledge proof.
    fn eval_jive_with_trace(x: &[F; N], y: &[F; N]) -> JiveTrace<F, N, NUM_ROUNDS> {
        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();
        let mut trace = JiveTrace::default();
        trace.input_x = x.clone();
        trace.input_y = y.clone();
        let mut x = x.clone();
        let mut y = y.clone();
        let sum_before_perm: F = x.iter().sum::<F>() + y.iter().sum::<F>();
        for r in 0..NUM_ROUNDS {
            for i in 0..N {
                x[i] += &Self::ROUND_KEYS_X[r][i];
                y[i] += &Self::ROUND_KEYS_Y[r][i];
            }
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..N {
                x[i] -= &(Self::GENERATOR * &(y[i].square()));
                y[i] -= &x[i].pow(&alpha_inv);
                x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
            }
            trace.intermediate_x_before_constant_additions[r] = x;
            trace.intermediate_y_before_constant_additions[r] = y;
        }
        mds.permute_in_place(&mut x, &mut y);
        trace.final_x = x;
        trace.final_y = y;
        let sum_after_perm: F = x.iter().sum::<F>() + y.iter().sum::<F>();
        trace.output = sum_before_perm + sum_after_perm;
        trace
    }
}

/// The salts for the Anemoi-Jive CRH over BLS12-381.
/// The salts are generated with the following code.
/// ```ignore
/// pub static PI_2: &str = "44288109756659334461284756482337867831652712\
/// 01909145648566923460348610454326648213393607260249141273";
/// pub static PI_3: &str = "72458700660631558817488152092096282925409171\
/// 53643678925903600113305305488204665213841469519415116094";
///
/// // Generate the salts
/// pub fn generate_salts<F: PrimeField>(generator: &F, alpha: u32, num: usize) -> Vec<F> {
///     let pi_2_biguint = BigUint::from_str(PI_2).unwrap();
///     let pi_3_biguint = BigUint::from_str(PI_3).unwrap();
///
///     let prime_biguint: BigUint = F::MODULUS.into();
///
///     let pi_f_2 = F::from(pi_2_biguint % &prime_biguint);
///     let pi_f_3 = F::from(pi_3_biguint % &prime_biguint);
///
///     let mut salts = Vec::<F>::new();
///
///     let mut pi_2_r = F::one();
///     for r in 0..num {
///         let mut pi_3_i = F::one();
///
///         let pow_alpha: F = (pi_2_r + pi_3_i).pow(&[alpha as u64]);
///         salts.push(*generator * pi_2_r.square() + pow_alpha);
///         pi_3_i *= pi_f_3;
///
///         pi_2_r *= pi_f_2;
///     }
///
///     salts
/// }
///
/// let salts = generate_salts::<ark_bls12_381::Fr>(&ark_bls12_381::Fr::from(7u64), 5u32, 64);
///
/// ```
pub const ANEMOI_JIVE_381_SALTS: [BLSScalar; 64] = [
    new_bls12_381!("6406215194479240286762731634835344236141886914605144794931128113894074089386"),
    new_bls12_381!("25560080366671527635336967422834298208909930660967190727048965370381122828324"),
    new_bls12_381!("50658439267116975037933099803088424427085069111100904739841927317887955508403"),
    new_bls12_381!("49202867374801348233366257521250211085729311964982431211168378339150325266596"),
    new_bls12_381!("39512762860131380300143104002628333366763410802467663674311566818148974565133"),
    new_bls12_381!("11876717497669986095596439982191006521736331858730684113164765237413845473944"),
    new_bls12_381!("35905493000702460707851319694883808822917434543549898626738506946150871324421"),
    new_bls12_381!("27186483893192137888367056646633699857046736175736979525890113166774163514623"),
    new_bls12_381!("17106901080657171059221588430697500200139148930560720708527494771434207741325"),
    new_bls12_381!("2947247105774581031713063065251521320329902750845167986294561654101405196807"),
    new_bls12_381!("51592079572413191872853358671431032085743619585916994428905417867123890278387"),
    new_bls12_381!("24816805674044088753437614576850034920688912721097761569100178771751601655270"),
    new_bls12_381!("18737304489188221477320550535667941529509106215289172413722189957955490476880"),
    new_bls12_381!("13208403487417056542747186342055085956605253382587954734743695712810536004854"),
    new_bls12_381!("22174026916692900500018984239981888364960054940583861997478529762257435881649"),
    new_bls12_381!("14277223701616846144752813397523985951727042947802894661372383492716148000958"),
    new_bls12_381!("38537729790878817151832254066940670734709071874829822789012367620206294295697"),
    new_bls12_381!("46429159945618798562266749928924897987650987233446873772298366545774012057031"),
    new_bls12_381!("49573185258004972705338141619067910819644923361360150569716410656138196617350"),
    new_bls12_381!("8808549100351786545270432628901850098657939587763329761465451280385563386019"),
    new_bls12_381!("47545884453564576395283966691168696006505461953304970106904616669538449617563"),
    new_bls12_381!("21482870545546346116520674895805037239909053292564410348875474566920600909715"),
    new_bls12_381!("33186690764244511345193651820558716649119982023617916307826540102554516472139"),
    new_bls12_381!("30350340353888399331126590000673687431830313888658096223457706922661233825688"),
    new_bls12_381!("3942545902701090087705826329290868532706337657003733728810633366482846729506"),
    new_bls12_381!("2082510624392818698732847366299654635857775777539656452414916165122403066195"),
    new_bls12_381!("51649334795838988372125488154003249393791640708325093419815644887794813309008"),
    new_bls12_381!("34887858772413423169834803418440531108993150189891335581819239064760286101455"),
    new_bls12_381!("48936583161825646569724419127726438460187933985953245447187452101796146735887"),
    new_bls12_381!("32642730579209546249308615043133770609665519724015393385939652278500890099536"),
    new_bls12_381!("13613672512975190978853575030239289621055291996871872964870881328315332173445"),
    new_bls12_381!("45857815948615754399416976418518399475658898258642746840125919814552021343539"),
    new_bls12_381!("27930434012335308503985612474694399710070769233460431210898055589039696617174"),
    new_bls12_381!("16082891484083197962298420031939300179737546889483404481270668239938925730519"),
    new_bls12_381!("32431358382254799316517534547310733442268246743646647830932614874662926374169"),
    new_bls12_381!("12001798800269343419894608733509428807939395673673182558768306347518155928368"),
    new_bls12_381!("19091998626622759830887219341787346217536406773488965115213063023260188150196"),
    new_bls12_381!("4061365125589423535263386040342356261325929153772201912893015669652043473651"),
    new_bls12_381!("42723069573372575409439879325916774325247419381280869222846543303609926685073"),
    new_bls12_381!("33411013226341788489531212408025099328807232565519108168173254434046156358114"),
    new_bls12_381!("22285215956726326717555645346885663035321379032235291157141463562680247858723"),
    new_bls12_381!("19100716338800473714612639247494110760560181407251931992121147800828314529681"),
    new_bls12_381!("37908871663584165335205509051952483202836179525323491895871954224141938867990"),
    new_bls12_381!("4271765406273011823704321421282739325904910283385044968295660170595223240215"),
    new_bls12_381!("50876843920929781237572991363935625089207791214968266941968601163581536883058"),
    new_bls12_381!("1177156943948505448921151255413373199132597755232043043050169936690894579252"),
    new_bls12_381!("51587349655410657129411563705348793062261635176459590250788447130472536465786"),
    new_bls12_381!("9219550859140898932258056590169454588152106345986798523391093622183609260757"),
    new_bls12_381!("50031287409312337488777320835097641243752192579702150358835452882985744695259"),
    new_bls12_381!("32873249177724826442701901791509764378077343046877699374690979165865248847923"),
    new_bls12_381!("16761444014354370430823854639861333789647902397513323110799773505932848409160"),
    new_bls12_381!("40185192398708244083559562678736292297196925796969428219679037536661994618983"),
    new_bls12_381!("27811697745704948617150508783769544237268384518115636221517802995039085883956"),
    new_bls12_381!("11836823182912063961934875161323318469855118006229360566507084183152286812991"),
    new_bls12_381!("52119247984727570142503947637528636360850027343934935965194199382704200721131"),
    new_bls12_381!("12061754451123296293631777903065177515680659949636535501781111345784880536267"),
    new_bls12_381!("43479045165837144162744599062941533175485374356835125667928524388351515117313"),
    new_bls12_381!("23103429557191913769940047466046366751339316644963955862724231703064129035334"),
    new_bls12_381!("254369426964247362468237865478019065502192043444834575103908764163406492126"),
    new_bls12_381!("48071597869367984847725917733368171763615703896109771496842923848158767414061"),
    new_bls12_381!("15055256968173980806767925613812067038912295204458123756113946263570286560712"),
    new_bls12_381!("45304830436629094174821131905656972358424981966498279424220949086434482388311"),
    new_bls12_381!("20011523849368630227591426012028344136556818717871466977616177645897908380509"),
    new_bls12_381!("20913680202770605374619314867123384851639737147442790410915664878667151333977"),
];

/// The structure that stores the parameters for the Anemoi-Jive hash function for BLS12-381.
pub struct AnemoiJive381;

impl AnemoiJive<BLSScalar, 2usize, 12usize> for AnemoiJive381 {
    const ALPHA: u32 = 7u32;
    const GENERATOR: BLSScalar = new_bls12_381!("7");
    const GENERATOR_INV: BLSScalar = new_bls12_381!(
        "14981678621464625851270783002338847382197300714436467949315331057125308909861"
    );
    const GENERATOR_SQUARE_PLUS_ONE: BLSScalar = new_bls12_381!("50");
    const ROUND_KEYS_X: [[BLSScalar; 2usize]; 12usize] = [
        [
            new_bls12_381!("39"),
            new_bls12_381!(
                "17756515227822460609684409997111995494590448775258437999344446424780281143353"
            ),
        ],
        [
            new_bls12_381!(
                "41362478282768062297187132445775312675360473883834860695283235286481594490621"
            ),
            new_bls12_381!(
                "3384073892082712848969991795331397937188893616190315628722966662742467187281"
            ),
        ],
        [
            new_bls12_381!(
                "9548818195234740988996233204400874453525674173109474205108603996010297049928"
            ),
            new_bls12_381!(
                "51311880822158488881090781617710146800056386303122657365679608608648067582435"
            ),
        ],
        [
            new_bls12_381!(
                "25365440569177822667580105183435418073995888230868180942004497015015045856900"
            ),
            new_bls12_381!(
                "29347609441914902330741511702270026847909178228078752565372729158237774700914"
            ),
        ],
        [
            new_bls12_381!(
                "34023498397393406644117994167986720327178154686105264833093891093045919619309"
            ),
            new_bls12_381!(
                "2339620320400167830454536231899316133967303509954474267430948538955691907104"
            ),
        ],
        [
            new_bls12_381!(
                "38816051319719761886041858113129205506758421478656182868737326994635468402951"
            ),
            new_bls12_381!(
                "27338042530319738113354246208426108832239651080023276643867223794985578055610"
            ),
        ],
        [
            new_bls12_381!(
                "35167418087531820804128377095512663922179887277669504047069913414630376083753"
            ),
            new_bls12_381!(
                "42192983528513372869128514327443204912824559545179630597589572656156258515752"
            ),
        ],
        [
            new_bls12_381!(
                "25885868839756469722325652387535232478219821850603640827385444642154834700231"
            ),
            new_bls12_381!(
                "42721818980548514490325424436763032046927347769153393863616095871384405840432"
            ),
        ],
        [
            new_bls12_381!(
                "8867588811641202981080659274007552529205713737251862066053445622305818871963"
            ),
            new_bls12_381!(
                "23473499332437056484066006746048591864129988909190267521144125882222313735740"
            ),
        ],
        [
            new_bls12_381!(
                "36439756010140137556111047750162544185710881404522379792044818039722752946048"
            ),
            new_bls12_381!(
                "16497366583607480604161417644040292299204496829635795525393416854929276060989"
            ),
        ],
        [
            new_bls12_381!(
                "7788624504122357216765350546787885309160020166693449889975992574536033007374"
            ),
            new_bls12_381!(
                "16727395967350522643500778393489915391834352737211416857240725807058479128000"
            ),
        ],
        [
            new_bls12_381!(
                "3134147137704626983201116226440762775442116005053282329971088789984415999550"
            ),
            new_bls12_381!(
                "46525506418681456193255596516104416743523037046982280449529426136392814992763"
            ),
        ],
    ];
    const ROUND_KEYS_Y: [[BLSScalar; 2usize]; 12usize] = [
        [
            new_bls12_381!(
                "14981678621464625851270783002338847382197300714436467949315331057125308909900"
            ),
            new_bls12_381!(
                "48720959343719104324739338388885839802998711550637402773896395605948383052052"
            ),
        ],
        [
            new_bls12_381!(
                "28253420209785428420233456008091632509255652343634529984400816700490470131093"
            ),
            new_bls12_381!(
                "6257781313532096835800460747082714697295034136932481743077166200794135826591"
            ),
        ],
        [
            new_bls12_381!(
                "51511939407083344002778208487678590135577660247075600880835916725469990319313"
            ),
            new_bls12_381!(
                "4386017178186728799761421274050927732938229436976005221436222062273391481632"
            ),
        ],
        [
            new_bls12_381!(
                "46291121544435738125248657675097664742296276807186696922340332893747842754587"
            ),
            new_bls12_381!(
                "13820180736478645172746469075181304604729976364812127548341524461074783412926"
            ),
        ],
        [
            new_bls12_381!(
                "3650460179273129580093806058710273018999560093475503119057680216309578390988"
            ),
            new_bls12_381!(
                "40385222771838099109662234020243831589690223478794847201235014486200724862134"
            ),
        ],
        [
            new_bls12_381!(
                "45802223370746268123059159806400152299867771061127345631244786118574025749328"
            ),
            new_bls12_381!(
                "50306980075778262214155693291132052551559962723436936231611301042966928400825"
            ),
        ],
        [
            new_bls12_381!(
                "11798621276624967315721748990709309216351696098813162382053396097866233042733"
            ),
            new_bls12_381!(
                "34806952212038537244506031612074847133207330427265785757809673463434908473570"
            ),
        ],
        [
            new_bls12_381!(
                "42372918959432199162670834641599336326433006968669415662488070504036922966492"
            ),
            new_bls12_381!(
                "22755759419530071315007011572076166983660942447634027701351681157370705921018"
            ),
        ],
        [
            new_bls12_381!(
                "52181371244193189669553521955614617990714056725501643636576377752669773323445"
            ),
            new_bls12_381!(
                "30334172084294870556875274308904688414158741457854908094300017436690480001547"
            ),
        ],
        [
            new_bls12_381!(
                "23791984554824031672195249524658580601428376029501889159059009332107176394097"
            ),
            new_bls12_381!(
                "19832360622723392584029764807971325641132953515557801717644226271356492507876"
            ),
        ],
        [
            new_bls12_381!(
                "33342520831620303764059548442834699069640109058400548818586964467754352720368"
            ),
            new_bls12_381!(
                "5828182614154296575131381170785760240834851189333374788484657124381010655319"
            ),
        ],
        [
            new_bls12_381!(
                "16791548253207744974576845515705461794133799104808996134617754018912057476556"
            ),
            new_bls12_381!(
                "23729797853490401568967730686618146850735129707152853256809050789424668284094"
            ),
        ],
    ];
    const PREPROCESSED_ROUND_KEYS_X: [[BLSScalar; 2usize]; 12usize] = [
        [
            new_bls12_381!(
                "19423856244504843308895388963412036786752036425753790350203807573584805634484"
            ),
            new_bls12_381!(
                "48851758589103982813056651724624321326473598754479694805563782039996758215715"
            ),
        ],
        [
            new_bls12_381!(
                "12615120352220861760529334504909132397992176696639432273740343225740283617075"
            ),
            new_bls12_381!(
                "39254041182502554693227592821509358885443577992138703722301710542985871322293"
            ),
        ],
        [
            new_bls12_381!(
                "1680857724460829800497520971070141190086510791274611006640253356976701835382"
            ),
            new_bls12_381!(
                "10642009718258107005125687907015169292971409341517296589557723407546399245596"
            ),
        ],
        [
            new_bls12_381!(
                "21055205962077377064979725066581742658597925825308897609198966322925144025246"
            ),
            new_bls12_381!(
                "19426425651077970347256365643784327945023001503658122361954517318898039324097"
            ),
        ],
        [
            new_bls12_381!(
                "50400840640194581457299747791281933264949279255786584705110530865735762969037"
            ),
            new_bls12_381!(
                "40530253751005095154866327721757053962468943297294740267582712399474545583285"
            ),
        ],
        [
            new_bls12_381!(
                "20438848331453166761730619539368103981673769036708568085393258759780190054169"
            ),
            new_bls12_381!(
                "13102355325113334007125361459444939190884376835400339773809059013631164881254"
            ),
        ],
        [
            new_bls12_381!(
                "15903051736368288011341534338499303285808489090761091294574969808092698586939"
            ),
            new_bls12_381!(
                "48642595332839007989623773680566396238102878179451994014407043912927986255299"
            ),
        ],
        [
            new_bls12_381!(
                "10323350652838928277917180395760661780567941231511570937076163542214188476177"
            ),
            new_bls12_381!(
                "10113523200168631476850206190715732835521831388679114777941923267006562804645"
            ),
        ],
        [
            new_bls12_381!(
                "15874458613322026931199484971789798065043978600000821246251350698046271468604"
            ),
            new_bls12_381!(
                "29722959275438864043566920532205246644056734108140740599696263368669051646942"
            ),
        ],
        [
            new_bls12_381!(
                "47049571745140120826345490242072658604761254210917672824591418624350523003945"
            ),
            new_bls12_381!(
                "31229117748831183511893406289433107506389961302893678361911395025751449981526"
            ),
        ],
        [
            new_bls12_381!(
                "20008645925323634762375318284845361376619384326118092245453755824068224534348"
            ),
            new_bls12_381!(
                "51916167094363585021232525371035513352788938018982786930209699175658888499410"
            ),
        ],
        [
            new_bls12_381!(
                "14197441017717677459303848790055884953960060330763418541055119545102633841813"
            ),
            new_bls12_381!(
                "41035843192452817449487057030123679745862354361270934591707945552234089516428"
            ),
        ],
    ];
    const PREPROCESSED_ROUND_KEYS_Y: [[BLSScalar; 2usize]; 12usize] = [
        [
            new_bls12_381!(
                "48720959343719104324739338388885839802998711550637402773896395605948383052326"
            ),
            new_bls12_381!(
                "41413142976741213247759708675423930977044966565732460430968148099132503169104"
            ),
        ],
        [
            new_bls12_381!(
                "46724097256651524339091431279166244749012943040791278166071907004411683190703"
            ),
            new_bls12_381!(
                "40706849955588955917187031913139550726202938626007650211282213531740765358936"
            ),
        ],
        [
            new_bls12_381!(
                "50354341977012993942522437638685263655838536163339384451665686940931836609745"
            ),
            new_bls12_381!(
                "36941207020290968244301088401173674862613545886757827284270114412422778295937"
            ),
        ],
        [
            new_bls12_381!(
                "23242780496771669172800629751749162774660599011953179069101902517678195587957"
            ),
            new_bls12_381!(
                "51682959496458850896509844412783906651848812389276036938242674417679468316747"
            ),
        ],
        [
            new_bls12_381!(
                "13502568851623815690871135923029776884996591632595731212035117300429192414537"
            ),
            new_bls12_381!(
                "45732566965513648936744017011732745376285149021117983780699842619375344108234"
            ),
        ],
        [
            new_bls12_381!(
                "3871417445118805719435628378631357786800492647634890892099192973415040354530"
            ),
            new_bls12_381!(
                "20466270311451717679660817948633690969780667094043944053335478232540727046525"
            ),
        ],
        [
            new_bls12_381!(
                "12525550798160927495662793530668079972288098117902646786976128748621377403675"
            ),
            new_bls12_381!(
                "47041601688625269305913563197199903184677830423604052068282638638277293683945"
            ),
        ],
        [
            new_bls12_381!(
                "4750941084798322577016411014155726242548676225154110403146222485997679579384"
            ),
            new_bls12_381!(
                "23193631377894266722337971232503454186583188044220550661907969206082098837667"
            ),
        ],
        [
            new_bls12_381!(
                "28552644567763864887615744440905253485323271032672948792109050805808824974071"
            ),
            new_bls12_381!(
                "42306382518035481965072771009207529037214743952101733890925098593577223403890"
            ),
        ],
        [
            new_bls12_381!(
                "29068626981113042851053289956023492338059928220488112363246315496290983713016"
            ),
            new_bls12_381!(
                "17528872722110569711777317184079163617085663570808124411368583006389737647157"
            ),
        ],
        [
            new_bls12_381!(
                "29482327734991661005757258237884790377553404596026665228178773598907154959843"
            ),
            new_bls12_381!(
                "29975314276057168886569394075284368361751731228476654125423744860350112701217"
            ),
        ],
        [
            new_bls12_381!(
                "36398885275692235432110168280184447734290618439760550553926011521931908250960"
            ),
            new_bls12_381!(
                "9404369307422440602109320936066766745715365680494660899081541172742509310711"
            ),
        ],
    ];
    const MDS_MATRIX: [[BLSScalar; 2usize]; 2usize] = [
        [new_bls12_381!("1"), new_bls12_381!("7")],
        [new_bls12_381!("7"), new_bls12_381!("50")],
    ];
    fn get_alpha_inv() -> Vec<u64> {
        vec![
            3689348813023923405u64,
            2413663763415232921u64,
            16233882818423549954u64,
            3341406743785779740u64,
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use noah_algebra::new_bls12_381;

    #[test]
    fn test_jive() {
        type F = BLSScalar;

        let input_x = [F::from(1u64), F::from(2u64)];
        let input_y = [F::from(3u64), F::zero()];

        let res = AnemoiJive381::eval_jive(&input_x, &input_y);
        assert_eq!(
            res,
            new_bls12_381!(
                "40534080031161498828112599909199108154146698842441932527619782321134903095510"
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
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                + g * d_i.square()
                + AnemoiJive381::GENERATOR_INV;
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

            let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

            let g = AnemoiJive381::GENERATOR;
            let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

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
                + AnemoiJive381::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
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
            new_bls12_381!(
                "17913626440896376279858183231538520765146521393387279167163788217724133906091"
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
                input.extend_from_slice(
                    &[F::zero()].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))),
                );
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
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
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

                let prk_i_a = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive381::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive381::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

                let g = AnemoiJive381::GENERATOR;
                let g2 = AnemoiJive381::GENERATOR_SQUARE_PLUS_ONE;

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
                    + AnemoiJive381::GENERATOR_INV;
                let right = a_i;
                assert_eq!(left, right);

                // equation 4
                let left = (g * d_i_minus_1 + g2 * c_i_minus_1 + prk_i_d - &d_i).pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive381::GENERATOR_INV;
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
}
