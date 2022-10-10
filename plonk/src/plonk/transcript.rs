use crate::plonk::indexer::PlonkVerifierParams;
use crate::poly_commit::{pcs::ToBytes, transcript::PolyComTranscript};
use merlin::Transcript;
use noah_algebra::prelude::*;
use noah_algebra::traits::Domain;
use rand_chacha::ChaChaRng;

/// Initialize the transcript when compute PLONK proof.
pub(crate) fn transcript_init_plonk<C: ToBytes, F: Domain>(
    transcript: &mut Transcript,
    params: &PlonkVerifierParams<C, F>,
    pi_values: &[F],
    root: &F,
) {
    transcript.append_message(b"New Domain", b"PLONK");

    transcript.append_u64(b"CS size", params.cs_size as u64);
    transcript.append_message(b"field size", &F::get_field_size_le_bytes());
    for q in params.cm_q_vec.iter() {
        transcript.append_commitment(q);
    }
    for p in params.cm_s_vec.iter() {
        transcript.append_commitment(p);
    }
    transcript.append_field_elem(root);
    for generator in params.k.iter() {
        transcript.append_field_elem(generator);
    }
    for pi_value in pi_values.iter() {
        transcript.append_field_elem(pi_value);
    }
}

/// Return the challenge result.
pub(crate) fn transcript_get_challenge_field_elem<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
    label: &'static [u8],
) -> F {
    let mut buff = [0u8; 32];
    transcript.challenge_bytes(label, &mut buff);
    let mut prng = ChaChaRng::from_seed(buff);
    loop {
        let elem = F::random(&mut prng);
        // elem should not be root-of-unity
        if elem.pow(&[group_order as u64]) != F::one() {
            return elem;
        }
    }
}

/// Return the challenge result by label: "alpha".
pub(crate) fn transcript_get_plonk_challenge_alpha<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
) -> F {
    transcript_get_challenge_field_elem(transcript, group_order, b"alpha")
}

/// Return the challenge result by label: "zeta".
pub(crate) fn transcript_get_plonk_challenge_zeta<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
) -> F {
    transcript_get_challenge_field_elem(transcript, group_order, b"zeta")
}

/// Return the challenge result by label: "beta".
pub(crate) fn transcript_get_plonk_challenge_beta<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
) -> F {
    transcript_get_challenge_field_elem(transcript, group_order, b"beta")
}

/// Return the challenge result by label: "gamma".
pub(crate) fn transcript_get_plonk_challenge_gamma<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
) -> F {
    transcript_get_challenge_field_elem(transcript, group_order, b"gamma")
}

/// Return the challenge result by label: "u"
pub(crate) fn transcript_get_plonk_challenge_u<F: Scalar>(
    transcript: &mut Transcript,
    group_order: usize,
) -> F {
    transcript_get_challenge_field_elem(transcript, group_order, b"u")
}
