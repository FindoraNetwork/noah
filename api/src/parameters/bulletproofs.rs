use crate::parameters::params::{
    BULLET_PROOF_RANGE, DEFAULT_BP_NUM_GENS, MAX_CONFIDENTIAL_RECORD_NUMBER,
};
use crate::parameters::{
    BULLETPROOF_CURVE25519_URS, BULLETPROOF_SECQ256K1_URS, BULLETPROOF_ZORRO_URS,
};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use bulletproofs::BulletproofGens;
use noah_algebra::prelude::*;
use noah_algebra::secq256k1::Secq256k1BulletproofGens;
use noah_algebra::zorro::ZorroBulletproofGens;

/// The trait for Bulletproofs that can be used in Bulletproofs generators.
pub trait BulletproofURS {
    /// Load the URS for Bulletproofs.
    fn load() -> Result<Self>
    where
        Self: Sized;

    /// Increase the Bulletproofs URS on demand.
    fn increase_circuit_gens(&mut self, new_size: usize);
}

impl BulletproofURS for BulletproofParams {
    fn load() -> Result<BulletproofParams> {
        let urs = BULLETPROOF_CURVE25519_URS.c(d!(NoahError::MissingSRSError))?;

        let pp: BulletproofParams = bincode::deserialize(&urs)
            .c(d!(NoahError::DeserializationError))
            .unwrap();
        Ok(pp)
    }

    fn increase_circuit_gens(&mut self, new_size: usize) {
        self.bp_circuit_gens
            .increase_capacity(new_size.next_power_of_two());
    }
}

impl BulletproofURS for Secq256k1BulletproofGens {
    fn load() -> Result<Self> {
        let urs = BULLETPROOF_SECQ256K1_URS.c(d!(NoahError::MissingSRSError))?;

        let reader = ark_std::io::BufReader::new(urs);
        let bp_gens =
            Secq256k1BulletproofGens::deserialize_with_mode(reader, Compress::No, Validate::No)
                .c(d!(NoahError::DeserializationError))
                .unwrap();
        Ok(bp_gens)
    }

    fn increase_circuit_gens(&mut self, new_size: usize) {
        self.increase_capacity(new_size.next_power_of_two());
    }
}

impl BulletproofURS for ZorroBulletproofGens {
    fn load() -> Result<Self> {
        let urs = BULLETPROOF_ZORRO_URS.c(d!(NoahError::MissingSRSError))?;

        let reader = ark_std::io::BufReader::new(urs);
        let bp_gens =
            ZorroBulletproofGens::deserialize_with_mode(reader, Compress::No, Validate::No)
                .c(d!(NoahError::DeserializationError))
                .unwrap();
        Ok(bp_gens)
    }

    fn increase_circuit_gens(&mut self, new_size: usize) {
        self.increase_capacity(new_size.next_power_of_two());
    }
}

/// The Bulletproofs URS.
#[derive(Serialize, Deserialize)]
pub struct BulletproofParams {
    /// The Bulletproofs generators.
    pub bp_gens: BulletproofGens,
    /// The Bulletproofs circuit generators.
    pub bp_circuit_gens: BulletproofGens,
    /// The number of bits in the range proof.
    pub range_proof_bits: usize,
}

impl Default for BulletproofParams {
    fn default() -> Self {
        let range_generators =
            BulletproofGens::new(BULLET_PROOF_RANGE, MAX_CONFIDENTIAL_RECORD_NUMBER);
        let circuit_generators = BulletproofGens::new(DEFAULT_BP_NUM_GENS, 1);

        BulletproofParams {
            bp_gens: range_generators,
            bp_circuit_gens: circuit_generators,
            range_proof_bits: BULLET_PROOF_RANGE,
        }
    }
}
