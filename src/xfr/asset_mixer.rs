use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
use bulletproofs_yoloproof::r1cs::{R1CSProof, Prover, Verifier};
use crate::errors::ZeiError;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit::{AllocatedValue, Value, cloak, CommittedValue, VerifierCommittable};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMixProof(pub(crate) R1CSProof);


impl PartialEq for AssetMixProof {
    fn eq(&self, other: &AssetMixProof) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for AssetMixProof {}


pub fn asset_mixer_proof(
    pc_gens: &bulletproofs_yoloproof::PedersenGens,
    bp_gens: &bulletproofs_yoloproof::BulletproofGens,
    inputs: &[(u64, Scalar, Scalar, Scalar)],
    outputs: &[(u64, Scalar, Scalar, Scalar)],
)-> Result<AssetMixProof, ZeiError>{

    let mut prover_transcript = Transcript::new(b"TransactionTest");
    let mut prover = Prover::new(pc_gens, &mut prover_transcript);

    let in_vars = allocate_values_prover(&mut prover, inputs);
    let out_vars = allocate_values_prover(&mut prover, outputs);

    cloak(&mut prover, in_vars, out_vars).map_err(|_| ZeiError::AssetMixerVerificationError)?;

    let proof = prover.prove(&bp_gens).map_err(|_| ZeiError::AssetMixerVerificationError)?;
    Ok(AssetMixProof(proof))
}

fn allocate_values_prover(prover: &mut Prover, data: &[(u64, Scalar, Scalar, Scalar)]) -> Vec<AllocatedValue>
{
    let mut allocated_values = vec![];
    for (amount, atype, blind_amount, blind_atype) in data.iter() {
        let value = Value {
            q: (*amount).into(),
            f: *atype,
        };
        let (_, amount_var) = prover.commit(value.q.into(), *blind_amount);
        let (_, asset_var) = prover.commit(value.f, *blind_atype);
        allocated_values.push(AllocatedValue{
            q: amount_var.clone(),
            f: asset_var.clone(),
            assignment: Some(value),
        });
    }
    allocated_values
}

fn allocate_commitments_verifier(verifier: &mut Verifier, commitments: &[(CompressedRistretto, CompressedRistretto)]) -> Vec<AllocatedValue>
{
    let mut values = vec![];
    for (amount_com, type_com) in commitments.iter() {
        let value = CommittedValue {
            q: *amount_com,
            f: *type_com,
        };
        values.push(value);
    }
    values.commit(verifier)
}


/// Verify
pub fn asset_mixer_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    inputs: &[(CompressedRistretto, CompressedRistretto)],
    outputs: &[(CompressedRistretto, CompressedRistretto)],
    proof: &AssetMixProof,
)-> Result<(), ZeiError>
{
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let in_coms = allocate_commitments_verifier(&mut verifier, inputs);
    let out_coms = allocate_commitments_verifier(&mut verifier, outputs);

    cloak(&mut verifier, in_coms, out_coms).map_err(|_| ZeiError::AssetMixerVerificationError)?;

    verifier.verify(&proof.0, pc_gens, bp_gens).map_err(|_| ZeiError::AssetMixerVerificationError)

}

#[cfg(test)]
mod test{
    use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn test_asset_mixer(){
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(10000,1);

        let input = [
            (60u64, Scalar::from(0u8), Scalar::from(10000u64), Scalar::from(200000u64)), //(amount, type, blind_amount, blind_type)
            (100u64, Scalar::from(2u8), Scalar::from(10001u64), Scalar::from(200001u64)), //(amount, type, blind_amount, blind_type)
            (10u64, Scalar::from(1u8), Scalar::from(10002u64), Scalar::from(200002u64)), //(amount, type, blind_amount, blind_type)
            (50u64, Scalar::from(2u8), Scalar::from(10003u64), Scalar::from(200003u64)), //(amount, type, blind_amount, blind_type)
            ];
        let output = [
            (40u64, Scalar::from(2u8), Scalar::from(10004u64), Scalar::from(200004u64)), //(amount, type, blind_amount, blind_type)
            (9u64, Scalar::from(1u8), Scalar::from(10005u64), Scalar::from(200005u64)), //(amount, type, blind_amount, blind_type)
            (1u64, Scalar::from(1u8), Scalar::from(10006u64), Scalar::from(200006u64)), //(amount, type, blind_amount, blind_type)
            (80u64, Scalar::from(2u8), Scalar::from(10007u64), Scalar::from(200007u64)), //(amount, type, blind_amount, blind_type)
            (50u64, Scalar::from(0u8), Scalar::from(10008u64), Scalar::from(200008u64)), //(amount, type, blind_amount, blind_type)
            (10u64, Scalar::from(0u8), Scalar::from(10009u64), Scalar::from(200009u64)), //(amount, type, blind_amount, blind_type)
            (30u64, Scalar::from(2u8), Scalar::from(10010u64), Scalar::from(200010u64)), //(amount, type, blind_amount, blind_type)
        ];


        let proof = super::asset_mixer_proof(&pc_gens, &bp_gens,&input, &output).unwrap();

        let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> = input.iter().map(|(amount, typ, blind_a, blind_typ)|
            (pc_gens.commit(Scalar::from(*amount),*blind_a).compress(), pc_gens.commit(*typ,*blind_typ).compress())).collect();
        let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> = output.iter().map(|(amount, typ, blind_a, blind_typ)|
            (pc_gens.commit(Scalar::from(*amount),*blind_a).compress(), pc_gens.commit(*typ,*blind_typ).compress())).collect();

        assert_eq!(Ok(()), super::asset_mixer_verify(&pc_gens, &bp_gens, &input_coms, &output_coms, &proof));
    }
}
