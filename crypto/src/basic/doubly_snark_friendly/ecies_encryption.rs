use noah_algebra::prelude::*;
use noah_algebra::traits::CurveGroup;

/// The encryption key is often also called public key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESEncryptionKey<G: CurveGroup>(pub G);

/// The decryption key is also often called secret key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESDecryptionKey<G: CurveGroup>(pub G::ScalarType);

/// The ciphertext.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESCiphertext<G: CurveGroup> {
    /// The Diffie-Hellman key exchange group element divided by the cofactor.
    pub dh_point_div_by_cofactor: G,
    /// the ciphertexts.
    pub ciphertext: Vec<G::BaseType>,
}

/// The plaintext.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESPlaintext<G: CurveGroup>(pub Vec<G::BaseType>);

/// The keypair for the ECIES encryption.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESKeyPair<G: CurveGroup> {
    /// The encryption key.
    pub(crate) encryption_key: ECIESEncryptionKey<G>,
    /// The decryption key.
    pub(crate) decryption_key: ECIESDecryptionKey<G>,
}

