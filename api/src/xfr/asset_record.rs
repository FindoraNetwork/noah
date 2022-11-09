use crate::anon_creds::{
    ac_confidential_open_commitment, ACCommitmentKey, ACUserSecretKey, Attr, AttributeCiphertext,
    ConfidentialAC, Credential,
};
use crate::xfr::{
    sig::{XfrKeyPair, XfrPublicKey},
    structs::{
        AssetRecord, AssetRecordTemplate, AssetType, BlindAssetRecord, OpenAssetRecord, OwnerMemo,
        TracerMemo, TracingPolicies, XfrAmount, XfrAssetType,
    },
};
use noah_algebra::{
    prelude::*,
    ristretto::{PedersenCommitmentRistretto, RistrettoScalar},
};

/// AssetRecord confidentiality flags. Indicated if amount and/or asset type should be confidential.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum AssetRecordType {
    /// Transparent amount, confidential asset type.
    NonConfidentialAmount_ConfidentialAssetType,
    /// Confidential amount, transparent asset type.
    ConfidentialAmount_NonConfidentialAssetType,
    /// Confidential amount, confidential asset type.
    ConfidentialAmount_ConfidentialAssetType,
    /// Transparent amount, transparent asset type.
    NonConfidentialAmount_NonConfidentialAssetType,
}

impl AssetRecordType {
    /// Return flgas that indicate the level of confidentiality.
    /// Return `(true,_)` if amount is confidential,
    /// Return `(_, true)` if asset type is confidential,
    pub fn get_flags(self) -> (bool, bool) {
        // confidential amount, confidential asset type
        match self {
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType => (false, false),
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => (true, false),
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => (false, true),
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType => (true, true),
        }
    }

    /// Return if the amount is confidential.
    pub fn is_confidential_amount(self) -> bool {
        matches!(
            self,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType
                | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType
        )
    }

    /// Return if the asset type is confidential.
    pub fn is_confidential_asset_type(self) -> bool {
        matches!(
            self,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType
                | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType
        )
    }

    /// Return if both the amount and the asset type are confidential.
    pub fn is_confidential_amount_and_asset_type(self) -> bool {
        matches!(
            self,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType
        )
    }

    /// Compute the record type from the level of confidentiality.
    pub fn from_flags(conf_amt: bool, conf_type: bool) -> Self {
        match (conf_amt, conf_type) {
            (false, false) => AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            (true, false) => AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            (false, true) => AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            (true, true) => AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        }
    }
}

impl AssetRecord {
    /// Build a record input from OpenAssetRecord with no associated policy
    /// Important: It assumes that RecordInput will be used as an input and not as an output
    /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is None.
    pub fn from_open_asset_record_no_asset_tracing(oar: OpenAssetRecord) -> AssetRecord {
        AssetRecord {
            open_asset_record: oar,
            tracing_policies: TracingPolicies::new(),
            identity_proofs: Vec::new(),
            asset_tracers_memos: Vec::new(),
            owner_memo: None,
        }
    }

    /// Build a record input from OpenAssetRecord with an associated policy that has no identity tracing
    /// Important: It assumes that RecordInput will be used as an input and not as an output
    /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is be None.
    pub fn from_open_asset_record_with_asset_tracing_but_no_identity<R: CryptoRng + RngCore>(
        prng: &mut R,
        oar: OpenAssetRecord,
        asset_tracing_policies: TracingPolicies,
    ) -> Result<AssetRecord> {
        let mut memos = vec![];
        let mut identity_proofs = vec![];
        for asset_tracing_policy in asset_tracing_policies.get_policies().iter() {
            // 1. Check for inconsistency.
            if asset_tracing_policy.identity_tracing.is_some() {
                return Err(eg!(NoahError::ParameterError)); // should use from_open_asset_record_with_identity_tracing method
            }

            let (amount_info, asset_type_info) = if asset_tracing_policy.asset_tracing {
                let amount_info = match oar.get_record_type() {
                    AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
                    | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => None,
                    _ => {
                        let amount = u64_to_u32_pair(oar.amount);
                        Some((
                            amount.0,
                            amount.1,
                            &oar.amount_blinds.0,
                            &oar.amount_blinds.1,
                        ))
                    }
                };
                let asset_type_info = match oar.get_record_type() {
                    AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
                    | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => None,
                    _ => Some((&oar.asset_type, &oar.type_blind)),
                };
                (amount_info, asset_type_info)
            } else {
                (None, None)
            };
            let asset_tracer_memo = TracerMemo::new(
                prng,
                &asset_tracing_policy.enc_keys,
                amount_info,
                asset_type_info,
                &[],
            );
            memos.push(asset_tracer_memo);
            identity_proofs.push(None);
        }
        Ok(AssetRecord {
            open_asset_record: oar,
            tracing_policies: asset_tracing_policies,
            identity_proofs,
            asset_tracers_memos: memos,
            owner_memo: None,
        })
    }

    /// Build a record input from OpenAssetRecord with associated policies for asset *and* identity tracing
    /// Important: It assumes that RecordInput will be used as an input and not as an output
    /// since OpenAsset record was recovered from a BlindAsset record. This means owner_memo field is None.
    pub fn from_open_asset_record_with_tracing<R: CryptoRng + RngCore>(
        prng: &mut R,
        oar: OpenAssetRecord,
        asset_tracing_policies: TracingPolicies,
        credential_sec_key: &ACUserSecretKey,
        credential: &Credential,
        credential_commitment_key: &ACCommitmentKey,
    ) -> Result<AssetRecord> {
        let mut memos = vec![];
        let mut identity_proofs = vec![];
        for asset_tracing_policy in asset_tracing_policies.get_policies().iter() {
            // 1. Compute `tracer_memo`.
            let (amount_info, asset_type_info) = if asset_tracing_policy.asset_tracing {
                let amount_info = match oar.get_record_type() {
                    AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
                    | AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => None,
                    _ => {
                        let amount = u64_to_u32_pair(oar.amount);
                        Some((
                            amount.0,
                            amount.1,
                            &oar.amount_blinds.0,
                            &oar.amount_blinds.1,
                        ))
                    }
                };
                let asset_type_info = match oar.get_record_type() {
                    AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
                    | AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => None,
                    _ => Some((&oar.asset_type, &oar.type_blind)),
                };
                (amount_info, asset_type_info)
            } else {
                (None, None)
            };

            let (attrs_and_ctexts, proof) = match asset_tracing_policy.identity_tracing.as_ref() {
                Some(id_policy) => {
                    // 1. Check for inconsistency.
                    if credential.ipk != id_policy.cred_issuer_pub_key {
                        return Err(eg!(NoahError::ParameterError));
                    }
                    let open = ac_confidential_open_commitment(
                        prng,
                        credential_sec_key,
                        credential,
                        credential_commitment_key,
                        &asset_tracing_policy.enc_keys.attrs_enc_key,
                        id_policy.reveal_map.as_slice(),
                        &[],
                    )
                    .c(d!())?;
                    let attrs_ctext = open.cts;
                    let proof = open.pok;
                    let attrs = credential
                        .get_revealed_attributes(id_policy.reveal_map.as_slice())
                        .c(d!())?;
                    let attrs_and_ctexts: Vec<(Attr, AttributeCiphertext)> =
                        attrs.into_iter().zip(attrs_ctext).collect();

                    (attrs_and_ctexts, Some(proof))
                }
                None => (vec![], None),
            };
            let asset_tracer_memo = TracerMemo::new(
                prng,
                &asset_tracing_policy.enc_keys,
                amount_info,
                asset_type_info,
                &attrs_and_ctexts,
            );
            identity_proofs.push(proof);
            memos.push(asset_tracer_memo);
        }
        Ok(AssetRecord {
            open_asset_record: oar,
            tracing_policies: asset_tracing_policies,
            identity_proofs,
            asset_tracers_memos: memos,
            owner_memo: None,
        })
    }

    /// Create the asset record using a template, without identity tracing.
    pub fn from_template_no_identity_tracing<R: CryptoRng + RngCore>(
        prng: &mut R,
        template: &AssetRecordTemplate,
    ) -> Result<AssetRecord> {
        let empty_id_proofs_and_ctext = vec![(None, vec![]); template.asset_tracing_policies.len()];
        for policy in template.asset_tracing_policies.get_policies().iter() {
            if policy.identity_tracing.is_some() {
                return Err(eg!(NoahError::ParameterError));
            }
        }
        build_record_input_from_template(prng, &template, empty_id_proofs_and_ctext.as_slice())
            .c(d!())
    }

    /// Create the asset record using a template, with identity tracing.
    pub fn from_template_with_identity_tracing<R: CryptoRng + RngCore>(
        prng: &mut R,
        template: &AssetRecordTemplate,
        credential_user_sec_key: &ACUserSecretKey,
        credential: &Credential,
        credential_key: &ACCommitmentKey,
    ) -> Result<AssetRecord> {
        let mut id_proofs_and_attrs = Vec::with_capacity(template.asset_tracing_policies.len());
        for policy in template.asset_tracing_policies.get_policies().iter() {
            let (conf_id, attrs) = if let Some(reveal_policy) = policy.identity_tracing.as_ref() {
                (
                    Some(
                        ac_confidential_open_commitment(
                            prng,
                            credential_user_sec_key,
                            credential,
                            credential_key,
                            &policy.enc_keys.attrs_enc_key,
                            &reveal_policy.reveal_map,
                            &[],
                        )
                        .c(d!())?,
                    ),
                    credential
                        .get_revealed_attributes(reveal_policy.reveal_map.as_slice())
                        .c(d!())?,
                )
            } else {
                (None, vec![])
            };
            id_proofs_and_attrs.push((conf_id, attrs));
        }
        build_record_input_from_template(prng, &template, id_proofs_and_attrs.as_slice()).c(d!())
    }
}

impl AssetRecordTemplate {
    /// Create an `AssetRecordTemplate` with no associated asset tracing policy
    pub fn with_no_asset_tracing(
        amount: u64,
        asset_type: AssetType,
        asset_record_type: AssetRecordType,
        address: XfrPublicKey,
    ) -> AssetRecordTemplate {
        AssetRecordTemplate {
            amount,
            asset_type,
            public_key: address,
            asset_record_type,
            asset_tracing_policies: TracingPolicies::new(),
        }
    }

    /// Create an `AssetRecordTemplate` with asset tracing policies
    pub fn with_asset_tracing(
        amount: u64,
        asset_type: AssetType,
        asset_record_type: AssetRecordType,
        address: XfrPublicKey,
        policies: TracingPolicies,
    ) -> AssetRecordTemplate {
        let mut template = AssetRecordTemplate::with_no_asset_tracing(
            amount,
            asset_type,
            asset_record_type,
            address,
        );
        template.asset_tracing_policies = policies;
        template
    }
}

fn sample_blind_asset_record<R: CryptoRng + RngCore>(
    prng: &mut R,
    pc_gens: &PedersenCommitmentRistretto,
    asset_record: &AssetRecordTemplate,
    attrs_and_ctexts: Vec<Vec<(Attr, AttributeCiphertext)>>,
) -> (
    BlindAssetRecord,
    (RistrettoScalar, RistrettoScalar),
    RistrettoScalar,
    Vec<TracerMemo>,
    Option<OwnerMemo>,
) {
    let (xfr_amount, xfr_asset_type, amount_blinds, asset_type_blind, owner_memo) =
        match asset_record.asset_record_type {
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType => (
                XfrAmount::NonConfidential(asset_record.amount),
                XfrAssetType::NonConfidential(asset_record.asset_type),
                (RistrettoScalar::zero(), RistrettoScalar::zero()),
                RistrettoScalar::zero(),
                None,
            ),

            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => {
                let (owner_memo, amount_blinds) =
                    OwnerMemo::from_amount(prng, asset_record.amount, &asset_record.public_key)
                        .unwrap(); // safe unwrap

                (
                    XfrAmount::from_blinds(
                        &pc_gens,
                        asset_record.amount,
                        &amount_blinds.0,
                        &amount_blinds.1,
                    ),
                    XfrAssetType::NonConfidential(asset_record.asset_type),
                    amount_blinds,
                    RistrettoScalar::zero(),
                    Some(owner_memo),
                )
            }

            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => {
                let (owner_memo, asset_type_blind) = OwnerMemo::from_asset_type(
                    prng,
                    &asset_record.asset_type,
                    &asset_record.public_key,
                )
                .unwrap(); //safe unwrap

                (
                    XfrAmount::NonConfidential(asset_record.amount),
                    XfrAssetType::from_blind(&pc_gens, &asset_record.asset_type, &asset_type_blind),
                    (RistrettoScalar::zero(), RistrettoScalar::zero()),
                    asset_type_blind,
                    Some(owner_memo),
                )
            }

            AssetRecordType::ConfidentialAmount_ConfidentialAssetType => {
                let (owner_memo, amount_blinds, asset_type_blind) =
                    OwnerMemo::from_amount_and_asset_type(
                        prng,
                        asset_record.amount,
                        &asset_record.asset_type,
                        &asset_record.public_key,
                    )
                    .unwrap(); //safe unwrap
                (
                    XfrAmount::from_blinds(
                        &pc_gens,
                        asset_record.amount,
                        &amount_blinds.0,
                        &amount_blinds.1,
                    ),
                    XfrAssetType::from_blind(&pc_gens, &asset_record.asset_type, &asset_type_blind),
                    amount_blinds,
                    asset_type_blind,
                    Some(owner_memo),
                )
            }
        };
    let blind_asset_record = BlindAssetRecord {
        public_key: asset_record.public_key,
        amount: xfr_amount,
        asset_type: xfr_asset_type,
    };

    let mut tracer_memos = vec![];
    let tracing_policies = &asset_record.asset_tracing_policies.0;
    for (policy, attr_ctexts) in tracing_policies.iter().zip(attrs_and_ctexts) {
        let mut amount_info = None;
        let mut asset_type_info = None;
        if policy.asset_tracing {
            if asset_record.asset_record_type.is_confidential_amount() {
                let (amount_lo, amount_hi) = u64_to_u32_pair(asset_record.amount);
                amount_info = Some((amount_lo, amount_hi, &amount_blinds.0, &amount_blinds.1));
            }
            if asset_record.asset_record_type.is_confidential_asset_type() {
                asset_type_info = Some((&asset_record.asset_type, &asset_type_blind));
            }
        }
        let memo = TracerMemo::new(
            prng,
            &policy.enc_keys,
            amount_info,
            asset_type_info,
            &attr_ctexts,
        );
        tracer_memos.push(memo);
    }
    (
        blind_asset_record,
        amount_blinds,
        asset_type_blind,
        tracer_memos,
        owner_memo,
    )
}

/// Build open asset record from the template and identity attributes.
pub fn build_open_asset_record<R: CryptoRng + RngCore>(
    prng: &mut R,
    pc_gens: &PedersenCommitmentRistretto,
    asset_record: &AssetRecordTemplate,
    attrs_and_ctexts: Vec<Vec<(Attr, AttributeCiphertext)>>,
) -> (OpenAssetRecord, Vec<TracerMemo>, Option<OwnerMemo>) {
    let (blind_asset_record, amount_blinds, type_blind, asset_tracing_memos, owner_memo) =
        sample_blind_asset_record(prng, pc_gens, asset_record, attrs_and_ctexts);

    let open_asset_record = OpenAssetRecord {
        blind_asset_record,
        amount: asset_record.amount,
        amount_blinds,
        asset_type: asset_record.asset_type,
        type_blind,
    };

    (open_asset_record, asset_tracing_memos, owner_memo)
}

/// Build blind asset record from the template and identity attributes.
pub fn build_blind_asset_record<R: CryptoRng + RngCore>(
    prng: &mut R,
    pc_gens: &PedersenCommitmentRistretto,
    asset_record: &AssetRecordTemplate,
    attrs_and_ctexts: Vec<Vec<(Attr, AttributeCiphertext)>>,
) -> (BlindAssetRecord, Vec<TracerMemo>, Option<OwnerMemo>) {
    let (blind_asset_record, _, _, asset_tracing_memos, owner_memo) =
        sample_blind_asset_record(prng, pc_gens, asset_record, attrs_and_ctexts);

    (blind_asset_record, asset_tracing_memos, owner_memo)
}

/// Open a blind asset record to obtain the open asset record.
/// The caller needs to have the key to decrypt the owner memo if some fields are confidential.
pub fn open_blind_asset_record(
    input: &BlindAssetRecord,
    owner_memo: &Option<OwnerMemo>,
    keypair: &XfrKeyPair,
) -> Result<OpenAssetRecord> {
    let (amount, asset_type, amount_blinds, type_blind) = match input.get_record_type() {
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType => (
            input.amount.get_amount().c(d!(NoahError::ParameterError))?,
            input
                .asset_type
                .get_asset_type()
                .c(d!(NoahError::ParameterError))?,
            (RistrettoScalar::zero(), RistrettoScalar::zero()),
            RistrettoScalar::zero(),
        ),

        AssetRecordType::ConfidentialAmount_NonConfidentialAssetType => {
            let owner_memo = owner_memo.as_ref().c(d!(NoahError::ParameterError))?;
            let amount = owner_memo.decrypt_amount(&keypair).c(d!())?;
            let amount_blinds = owner_memo.derive_amount_blinds(&keypair).c(d!())?;
            (
                amount,
                input
                    .asset_type
                    .get_asset_type()
                    .c(d!(NoahError::ParameterError))?,
                amount_blinds,
                RistrettoScalar::zero(),
            )
        }

        AssetRecordType::NonConfidentialAmount_ConfidentialAssetType => {
            let owner_memo = owner_memo.as_ref().c(d!(NoahError::ParameterError))?;
            let asset_type = owner_memo.decrypt_asset_type(&keypair).c(d!())?;
            let asset_type_blind = owner_memo.derive_asset_type_blind(&keypair).c(d!())?;
            (
                input.amount.get_amount().c(d!(NoahError::ParameterError))?,
                asset_type,
                (RistrettoScalar::zero(), RistrettoScalar::zero()),
                asset_type_blind,
            )
        }

        AssetRecordType::ConfidentialAmount_ConfidentialAssetType => {
            let owner_memo = owner_memo.as_ref().c(d!(NoahError::ParameterError))?;
            let (amount, asset_type) =
                owner_memo.decrypt_amount_and_asset_type(&keypair).c(d!())?;
            let amount_blinds = owner_memo.derive_amount_blinds(&keypair).c(d!())?;
            let asset_type_blind = owner_memo.derive_asset_type_blind(&keypair).c(d!())?;

            (amount, asset_type, amount_blinds, asset_type_blind)
        }
    };

    Ok(OpenAssetRecord {
        blind_asset_record: input.clone(),
        amount,
        amount_blinds,
        asset_type,
        type_blind,
    })
}

/// Helper function to generate assemble asset record from templates.
fn build_record_input_from_template<R: CryptoRng + RngCore>(
    prng: &mut R,
    asset_record: &AssetRecordTemplate,
    identity_proofs_and_attrs: &[(Option<ConfidentialAC>, Vec<Attr>)],
) -> Result<AssetRecord> {
    if asset_record.asset_tracing_policies.len() != identity_proofs_and_attrs.len() {
        return Err(eg!(NoahError::ParameterError));
    }
    let pc_gens = PedersenCommitmentRistretto::default();
    let mut attrs_ctexts = vec![];
    let mut reveal_proofs = vec![];
    let tracing_policy = asset_record.asset_tracing_policies.get_policies();
    for (tracing_policy, id_proof_and_attrs) in
        tracing_policy.iter().zip(identity_proofs_and_attrs.iter())
    {
        if tracing_policy.identity_tracing.is_none() && id_proof_and_attrs.0.is_some() {
            return Err(eg!(NoahError::ParameterError));
        }
        let (attrs_and_ctexts, reveal_proof) = match id_proof_and_attrs {
            (None, _) => (vec![], None),
            (Some(conf_ac), attrs) => {
                let c = conf_ac.cts.clone();
                let p = conf_ac.pok.clone();
                let attrs_and_ctexts = attrs.iter().zip(c).map(|(a, c)| (*a, c)).collect();
                (attrs_and_ctexts, Some(p))
            }
        };
        attrs_ctexts.push(attrs_and_ctexts);
        reveal_proofs.push(reveal_proof);
    }
    let (open_asset_record, asset_tracing_memos, owner_memo) =
        build_open_asset_record(prng, &pc_gens, asset_record, attrs_ctexts);

    Ok(AssetRecord {
        open_asset_record,
        tracing_policies: asset_record.asset_tracing_policies.clone(),
        identity_proofs: reveal_proofs,
        asset_tracers_memos: asset_tracing_memos,
        owner_memo,
    })
}

#[cfg(test)]
mod test {
    use super::{build_blind_asset_record, build_open_asset_record, open_blind_asset_record};
    use crate::xfr::{
        asset_record::AssetRecordType,
        sig::XfrKeyPair,
        structs::{
            AssetRecordTemplate, AssetTracerKeyPair, AssetType, OpenAssetRecord, TracingPolicies,
            TracingPolicy, XfrAmount, XfrAssetType,
        },
        tests::{create_xfr, gen_key_pair_vec},
    };
    use noah_algebra::{
        prelude::*,
        ristretto::{PedersenCommitmentRistretto, RistrettoScalar},
        traits::PedersenCommitment,
    };

    fn do_test_build_open_asset_record(record_type: AssetRecordType, asset_tracing: bool) {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let amount = 100u64;
        let asset_type = AssetType::from_identical_byte(0u8);
        let keypair = XfrKeyPair::generate(&mut prng);
        let tracing_policy = match asset_tracing {
            true => {
                let tracer_keys = AssetTracerKeyPair::generate(&mut prng);
                let tracing_policies = TracingPolicies::from_policy(TracingPolicy {
                    enc_keys: tracer_keys.enc_key,
                    asset_tracing: true,
                    identity_tracing: None,
                });

                Some(tracing_policies)
            }
            false => None,
        };

        let asset_record = if asset_tracing {
            AssetRecordTemplate::with_asset_tracing(
                amount,
                asset_type,
                record_type,
                keypair.pub_key,
                tracing_policy.unwrap(),
            )
        } else {
            AssetRecordTemplate::with_no_asset_tracing(
                amount,
                asset_type,
                record_type,
                keypair.pub_key,
            )
        };

        let (open_ar, asset_tracer_memo, owner_memo) =
            build_open_asset_record(&mut prng, &pc_gens, &asset_record, vec![vec![]]);

        assert_eq!(amount, open_ar.amount);
        assert_eq!(asset_type, open_ar.asset_type);
        assert_eq!(&keypair.pub_key, &open_ar.blind_asset_record.public_key);

        let expected_bar_amount;
        let expected_bar_asset_type;

        let (confidential_amount, confidential_asset) = record_type.get_flags();
        if confidential_amount {
            let (low, high) = u64_to_u32_pair(amount);
            let commitment_low = pc_gens
                .commit(RistrettoScalar::from(low), open_ar.amount_blinds.0)
                .compress();
            let commitment_high = pc_gens
                .commit(RistrettoScalar::from(high), open_ar.amount_blinds.1)
                .compress();
            expected_bar_amount = XfrAmount::Confidential((commitment_low, commitment_high));
        } else {
            expected_bar_amount = XfrAmount::NonConfidential(amount)
            //expected_bar_lock_amount_none = true;
        }

        if confidential_asset {
            expected_bar_asset_type = XfrAssetType::Confidential(
                pc_gens
                    .commit(asset_record.asset_type.as_scalar(), open_ar.type_blind)
                    .compress(),
            );
        } else {
            expected_bar_asset_type = XfrAssetType::NonConfidential(asset_type);
            //expected_bar_lock_type_none = true;
        }
        assert_eq!(expected_bar_amount, open_ar.blind_asset_record.amount);

        assert_eq!(
            expected_bar_asset_type,
            open_ar.blind_asset_record.asset_type
        );
        assert_eq!(
            confidential_asset || confidential_amount,
            owner_memo.is_some()
        );

        let expected = if asset_tracing {
            if confidential_asset {
                assert!(asset_tracer_memo[0].lock_asset_type.is_some());
            }
            if confidential_amount {
                assert!(asset_tracer_memo[0].lock_amount.is_some())
            }
            1
        } else {
            0
        };
        assert_eq!(expected, asset_tracer_memo.len());
    }

    #[test]
    fn test_build_open_asset_record() {
        do_test_build_open_asset_record(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            false,
        );
        do_test_build_open_asset_record(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            true,
        );
        do_test_build_open_asset_record(
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            false,
        );
        do_test_build_open_asset_record(
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            true,
        );
        do_test_build_open_asset_record(
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            false,
        );
        do_test_build_open_asset_record(
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            true,
        );
        do_test_build_open_asset_record(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            false,
        );
        do_test_build_open_asset_record(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            true,
        );
    }

    fn do_test_open_asset_record(record_type: AssetRecordType) {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let asset_type = AssetType::from_identical_byte(1u8);

        let inkeys = gen_key_pair_vec(2, &mut prng);
        let outkeys = gen_key_pair_vec(1, &mut prng);

        let input_templates = [
            AssetRecordTemplate::with_no_asset_tracing(
                10u64,
                asset_type,
                record_type,
                inkeys[0].pub_key,
            ),
            AssetRecordTemplate::with_no_asset_tracing(
                20u64,
                asset_type,
                record_type,
                inkeys[1].pub_key,
            ),
        ];

        let output_templates = [AssetRecordTemplate::with_no_asset_tracing(
            30u64,
            asset_type,
            record_type,
            outkeys[0].pub_key,
        )];

        let (xfr_note, _, _) = create_xfr(
            &mut prng,
            &input_templates,
            &output_templates,
            inkeys.iter().collect_vec().as_slice(),
        );

        let key_pair = outkeys.get(0).unwrap();
        let open_ar = open_blind_asset_record(
            &xfr_note.body.outputs[0],
            &xfr_note.body.owners_memos[0],
            &key_pair,
        )
        .unwrap();

        assert_eq!(&open_ar.blind_asset_record, &xfr_note.body.outputs[0]);
        assert_eq!(open_ar.amount, 30u64);
        assert_eq!(open_ar.asset_type, AssetType::from_identical_byte(1u8));

        let (confidential_amount, confidential_asset) = record_type.get_flags();

        if confidential_amount {
            let (low, high) = u64_to_u32_pair(open_ar.amount);
            let commitment_low = pc_gens
                .commit(RistrettoScalar::from(low), open_ar.amount_blinds.0)
                .compress();
            let commitment_high = pc_gens
                .commit(RistrettoScalar::from(high), open_ar.amount_blinds.1)
                .compress();
            let derived_commitment = (commitment_low, commitment_high);
            assert_eq!(
                derived_commitment,
                open_ar.blind_asset_record.amount.get_commitments().unwrap()
            );
        }

        if confidential_asset {
            let derived_commitment = pc_gens
                .commit(open_ar.asset_type.as_scalar(), open_ar.type_blind)
                .compress();
            assert_eq!(
                derived_commitment,
                open_ar
                    .blind_asset_record
                    .asset_type
                    .get_commitment()
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_open_asset_record() {
        do_test_open_asset_record(AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType);
        do_test_open_asset_record(AssetRecordType::NonConfidentialAmount_ConfidentialAssetType);
        do_test_open_asset_record(AssetRecordType::ConfidentialAmount_NonConfidentialAssetType);
        do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType);
        do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType);
    }

    fn build_and_open_blind_record(record_type: AssetRecordType, amt: u64, asset_type: AssetType) {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let keypair = XfrKeyPair::generate(&mut prng);
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amt,
            asset_type,
            record_type,
            keypair.pub_key,
        );

        let (blind_rec, _asset_tracer_memo, owner_memo) =
            build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);

        let open_rec = open_blind_asset_record(&blind_rec, &owner_memo, &keypair).unwrap();

        assert_eq!(*open_rec.get_amount(), amt);
        assert_eq!(*open_rec.get_asset_type(), asset_type);

        let oar_bytes = serde_json::to_string(&open_rec).unwrap();
        let oar_de: OpenAssetRecord = serde_json::from_str(oar_bytes.as_str()).unwrap();
        assert_eq!(open_rec, oar_de);
    }

    #[test]
    fn test_build_and_open_blind_record() {
        let mut prng = test_rng();
        let asset_type: AssetType = AssetType(prng.gen());
        let amt: u64 = prng.gen();

        build_and_open_blind_record(
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
            amt,
            asset_type,
        );
        build_and_open_blind_record(
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            amt,
            asset_type,
        );
        build_and_open_blind_record(
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            amt,
            asset_type,
        );
        build_and_open_blind_record(
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            amt,
            asset_type,
        );
    }

    #[test]
    fn open_blind_asset_record_error() {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        let keypair = XfrKeyPair::generate(&mut prng);
        let asset_type: AssetType = AssetType(prng.gen());
        let amount = 10u64;
        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amount,
            asset_type,
            AssetRecordType::ConfidentialAmount_NonConfidentialAssetType,
            keypair.pub_key,
        );
        let (blind_rec, _asset_tracer_memo, owner_memo) =
            build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);

        let open_rec = open_blind_asset_record(&blind_rec, &owner_memo, &keypair);
        assert!(open_rec.is_ok(), "Open a just created asset record");
        let open_rec = open_blind_asset_record(&blind_rec, &None, &keypair);
        assert!(open_rec.is_err(), "Expect error as amount is confidential");

        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amount,
            asset_type,
            AssetRecordType::NonConfidentialAmount_ConfidentialAssetType,
            keypair.pub_key,
        );
        let (blind_rec, _asset_tracer_memo, owner_memo) =
            build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);

        let open_rec = open_blind_asset_record(&blind_rec, &owner_memo, &keypair);
        assert!(open_rec.is_ok(), "Open a just created asset record");
        let open_rec = open_blind_asset_record(&blind_rec, &None, &keypair);
        assert!(
            open_rec.is_err(),
            "Expect error as asset type is confidential"
        );

        let ar = AssetRecordTemplate::with_no_asset_tracing(
            amount,
            asset_type,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
            keypair.pub_key,
        );
        let (blind_rec, _asset_tracer_memo, owner_memo) =
            build_blind_asset_record(&mut prng, &pc_gens, &ar, vec![]);

        let open_rec = open_blind_asset_record(&blind_rec, &owner_memo, &keypair);
        assert!(open_rec.is_ok(), "Open a just created asset record");
        let open_rec = open_blind_asset_record(&blind_rec, &None, &keypair);
        assert!(
            open_rec.is_err(),
            "Expect error as asset type and amount are confidential"
        );
    }
}
