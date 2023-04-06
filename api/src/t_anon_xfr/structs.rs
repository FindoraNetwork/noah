use noah_algebra::prelude::*;
use rand_core::{CryptoRng, RngCore};

use crate::keys::{PublicKey, SecretKey};

/// An auditor’s memo that accurately describes contents of the transactions.
#[derive(Clone, Default, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TAxfrAuditorMemo(Vec<u8>);

impl TAxfrAuditorMemo {
    /// Crate an encrypted memo using the public key.
    pub fn new<R: CryptoRng + RngCore>(
        prng: &mut R,
        pub_key: &PublicKey,
        msg: &[u8],
    ) -> Result<Self> {
        let ctext = pub_key.hybrid_encrypt(prng, msg)?;
        Ok(Self(ctext))
    }

    /// Decrypt a memo using the viewing key.
    pub fn decrypt(&self, secret_key: &SecretKey) -> Result<Vec<u8>> {
        secret_key.hybrid_decrypt(&self.0)
    }
}
