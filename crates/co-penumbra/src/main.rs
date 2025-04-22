use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::OptimizationGoal;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use decaf377::Fq;
use decaf377::Fr;
use decaf377_rdsa::SpendAuth;
use decaf377_rdsa::VerificationKey;
use penumbra_sdk_asset::asset;
use penumbra_sdk_asset::Balance;
use penumbra_sdk_asset::Value;
use penumbra_sdk_governance::DelegatorVoteCircuit;
use penumbra_sdk_governance::DelegatorVoteProofPrivate;
use penumbra_sdk_governance::DelegatorVoteProofPublic;
use penumbra_sdk_keys::keys::Bip44Path;
use penumbra_sdk_keys::keys::SeedPhrase;
use penumbra_sdk_keys::keys::SpendKey;
use penumbra_sdk_sct::Nullifier;
use penumbra_sdk_shielded_pool::output::OutputProofPrivate;
use penumbra_sdk_shielded_pool::output::OutputProofPublic;
use penumbra_sdk_shielded_pool::Note;
use penumbra_sdk_shielded_pool::OutputCircuit;
use penumbra_sdk_shielded_pool::SpendCircuit;
use penumbra_sdk_shielded_pool::SpendProofPrivate;
use penumbra_sdk_shielded_pool::SpendProofPublic;
use penumbra_sdk_tct::Tree;
use penumbra_sdk_tct::Witness;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

pub fn serialize_witness_and_matrices(
    circuit: impl ConstraintSynthesizer<Fq>,
) -> anyhow::Result<()> {
    let cs: ConstraintSystemRef<Fq> = ConstraintSystem::new_ref();

    // Set the optimization goal
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    // Synthesize the circuit.
    circuit.generate_constraints(cs.clone())?;

    cs.finalize();

    let witness_values = &cs.borrow().expect("can borrow").witness_assignment;
    let public_values = &cs.borrow().expect("can borrow").instance_assignment;

    let mut witness = File::create("witness.wtns")?;

    witness.write_all(b"wtns")?;
    witness.write_u32::<LittleEndian>(2)?; // version
    witness.write_u32::<LittleEndian>(2)?; // n_sections

    witness.write_u32::<LittleEndian>(0)?;
    witness.write_u64::<LittleEndian>(0)?;

    let modulus = Fq::MODULUS.to_bytes_le();
    witness.write_u32::<LittleEndian>(modulus.len() as u32)?;
    witness.write_all(&modulus)?;

    witness.write_u32::<LittleEndian>((witness_values.len() + public_values.len()) as u32)?;

    witness.write_u32::<LittleEndian>(0)?;
    witness.write_u64::<LittleEndian>(0)?;

    for v in public_values.iter().chain(witness_values) {
        v.serialize_with_mode(&witness, Compress::Yes)?;
    }

    let matrices = cs.to_matrices().expect("can gen matrices");
    let matrices_file = File::create("matrices.bin")?;
    (matrices.a, matrices.b, matrices.c).serialize_uncompressed(matrices_file)?;

    Ok(())
}

fn setup_spend() -> anyhow::Result<SpendCircuit> {
    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_sender = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_sender = sk_sender.full_viewing_key();
    let ivk_sender = fvk_sender.incoming();
    let (sender, _dtk_d) = ivk_sender.payment_address(0u32.into());

    let value_to_send = Value {
        amount: 1u64.into(),
        asset_id: asset::Cache::with_known_assets()
            .get_unit("upenumbra")
            .unwrap()
            .id(),
    };

    let note = Note::generate(&mut OsRng, &sender, value_to_send);
    let note_commitment = note.commit();
    let spend_auth_randomizer = Fr::rand(&mut OsRng);
    let rsk = sk_sender.spend_auth_key().randomize(&spend_auth_randomizer);
    let nk = *sk_sender.nullifier_key();
    let ak: VerificationKey<SpendAuth> = sk_sender.spend_auth_key().into();
    let mut sct = Tree::new();
    sct.insert(Witness::Keep, note_commitment).unwrap();
    let anchor = sct.root();
    let state_commitment_proof = sct.witness(note_commitment).unwrap();
    let v_blinding = Fr::rand(&mut OsRng);
    let balance_commitment = value_to_send.commit(v_blinding);
    let rk: VerificationKey<SpendAuth> = rsk.into();
    let nullifier = Nullifier::derive(&nk, 0.into(), &note_commitment);

    let public = SpendProofPublic {
        anchor,
        balance_commitment,
        nullifier,
        rk,
    };
    let private = SpendProofPrivate {
        state_commitment_proof,
        note,
        v_blinding,
        spend_auth_randomizer,
        ak,
        nk,
    };

    Ok(SpendCircuit::new(public, private))
}

fn setup_output() -> anyhow::Result<OutputCircuit> {
    let mut rng = OsRng;

    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_recipient = sk_recipient.full_viewing_key();
    let ivk_recipient = fvk_recipient.incoming();
    let (dest, _dtk_d) = ivk_recipient.payment_address(0u32.into());

    let value_to_send = Value {
        amount: 1u64.into(),
        asset_id: asset::Cache::with_known_assets()
            .get_unit("upenumbra")
            .unwrap()
            .id(),
    };
    let balance_blinding = Fr::rand(&mut OsRng);

    let note = Note::generate(&mut rng, &dest, value_to_send);
    let note_commitment = note.commit();
    let balance_commitment = (-Balance::from(value_to_send)).commit(balance_blinding);

    let public = OutputProofPublic {
        balance_commitment,
        note_commitment,
    };
    let private = OutputProofPrivate {
        note,
        balance_blinding,
    };

    Ok(OutputCircuit::new(public, private))
}

fn setup_delegator_vote() -> anyhow::Result<DelegatorVoteCircuit> {
    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_sender = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_sender = sk_sender.full_viewing_key();
    let ivk_sender = fvk_sender.incoming();
    let (sender, _dtk_d) = ivk_sender.payment_address(0u32.into());

    let value_to_send = Value {
        amount: 2u64.into(),
        asset_id: asset::Cache::with_known_assets()
            .get_unit("upenumbra")
            .unwrap()
            .id(),
    };

    let note = Note::generate(&mut OsRng, &sender, value_to_send);
    let note_commitment = note.commit();
    let spend_auth_randomizer = Fr::rand(&mut OsRng);
    let rsk = sk_sender.spend_auth_key().randomize(&spend_auth_randomizer);
    let nk = *sk_sender.nullifier_key();
    let ak: VerificationKey<SpendAuth> = sk_sender.spend_auth_key().into();
    let mut sct = Tree::new();

    sct.insert(Witness::Keep, note_commitment).unwrap();
    let anchor = sct.root();
    let state_commitment_proof = sct.witness(note_commitment).unwrap();
    sct.end_epoch().unwrap();

    let first_note_commitment = Note::generate(&mut OsRng, &sender, value_to_send).commit();
    sct.insert(Witness::Keep, first_note_commitment).unwrap();
    let start_position = sct.witness(first_note_commitment).unwrap().position();

    let balance_commitment = value_to_send.commit(Fr::from(0u64));
    let rk: VerificationKey<SpendAuth> = rsk.into();
    let nf = Nullifier::derive(&nk, state_commitment_proof.position(), &note_commitment);

    let public = DelegatorVoteProofPublic {
        anchor,
        balance_commitment,
        nullifier: nf,
        rk,
        start_position,
    };
    let private = DelegatorVoteProofPrivate {
        state_commitment_proof,
        note,
        v_blinding: Fr::from(0u64),
        spend_auth_randomizer,
        ak,
        nk,
    };

    Ok(DelegatorVoteCircuit::new(public, private))
}

fn main() -> anyhow::Result<()> {
    serialize_witness_and_matrices(setup_spend()?)?;
    // serialize_witness_and_matrices(setup_output()?)?;
    // serialize_witness_and_matrices(setup_delegator_vote()?)?;
    Ok(())
}
