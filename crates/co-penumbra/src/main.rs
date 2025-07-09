use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::ConstraintMatrices;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::OptimizationGoal;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use clap::Parser;
use decaf377::Fq;
use decaf377::Fr;
use decaf377_rdsa::SigningKey;
use decaf377_rdsa::SpendAuth;
use decaf377_rdsa::VerificationKey;
use penumbra_sdk_asset::asset;
use penumbra_sdk_asset::Balance;
use penumbra_sdk_asset::Value;
use penumbra_sdk_dex::swap::proof::SwapCircuit;
use penumbra_sdk_dex::swap::proof::{SwapProofPrivate, SwapProofPublic};
use penumbra_sdk_dex::swap_claim::SwapClaimCircuit;
use penumbra_sdk_dex::swap_claim::{SwapClaimProofPrivate, SwapClaimProofPublic};
use penumbra_sdk_dex::{swap::SwapPlaintext, BatchSwapOutputData, TradingPair};
use penumbra_sdk_fee::Fee;
use penumbra_sdk_governance::DelegatorVoteCircuit;
use penumbra_sdk_governance::DelegatorVoteProofPrivate;
use penumbra_sdk_governance::DelegatorVoteProofPublic;
use penumbra_sdk_keys::keys::Bip44Path;
use penumbra_sdk_keys::keys::SeedPhrase;
use penumbra_sdk_keys::keys::SpendKey;
use penumbra_sdk_num::Amount;
use penumbra_sdk_sct::Nullifier;
use penumbra_sdk_shielded_pool::output::OutputProofPrivate;
use penumbra_sdk_shielded_pool::output::OutputProofPublic;
use penumbra_sdk_shielded_pool::Note;
use penumbra_sdk_shielded_pool::NullifierDerivationProofPrivate;
use penumbra_sdk_shielded_pool::NullifierDerivationProofPublic;
use penumbra_sdk_shielded_pool::SpendProofPrivate;
use penumbra_sdk_shielded_pool::SpendProofPublic;
use penumbra_sdk_shielded_pool::{
    ConvertCircuit, NullifierDerivationCircuit, OutputCircuit, SpendCircuit,
};
use penumbra_sdk_stake::undelegate_claim::UndelegateClaimProofPrivate;
use penumbra_sdk_stake::undelegate_claim::UndelegateClaimProofPublic;
use penumbra_sdk_stake::{IdentityKey, Penalty, UnbondingToken};
use penumbra_sdk_tct::Tree;
use penumbra_sdk_tct::Witness;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;

// Compute the degree associated with a given circuit.
//
// This degree can then be used for both phases.
pub fn circuit_degree(circuit: &ConstraintMatrices<Fq>) -> anyhow::Result<usize> {
    let circuit_size = circuit.num_constraints + circuit.num_instance_variables;
    Radix2EvaluationDomain::<Fq>::compute_size_of_domain(circuit_size)
        .ok_or_else(|| anyhow::anyhow!("Circuit of size {} is too large", circuit_size))
}

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
    println!(
        "circuit degree = {} num_inputs = {}",
        circuit_degree(&matrices)?.ilog2(),
        matrices.num_instance_variables
    );

    let matrices_file = File::create("matrices.bin")?;
    (matrices.a, matrices.b, matrices.c).serialize_uncompressed(matrices_file)?;

    Ok(())
}

fn spend() -> anyhow::Result<SpendCircuit> {
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

fn output() -> anyhow::Result<OutputCircuit> {
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

fn delegator_vote() -> anyhow::Result<DelegatorVoteCircuit> {
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

fn swap() -> anyhow::Result<SwapCircuit> {
    let mut rng = OsRng;
    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_recipient = sk_recipient.full_viewing_key();
    let ivk_recipient = fvk_recipient.incoming();
    let (claim_address, _dtk_d) = ivk_recipient.payment_address(0u32.into());

    let gm = asset::Cache::with_known_assets().get_unit("gm").unwrap();
    let gn = asset::Cache::with_known_assets().get_unit("gn").unwrap();

    let trading_pair = TradingPair::new(gm.id(), gn.id());

    let delta_1 = Amount::from(100_000u64);
    let delta_2 = Amount::from(0u64);
    let fee = Fee::default();
    let fee_blinding = Fr::rand(&mut OsRng);

    let swap_plaintext =
        SwapPlaintext::new(&mut rng, trading_pair, delta_1, delta_2, fee, claim_address);
    let fee_commitment = swap_plaintext.claim_fee.commit(fee_blinding);
    let swap_commitment = swap_plaintext.swap_commitment();

    let value_1 = Value {
        amount: swap_plaintext.delta_1_i,
        asset_id: swap_plaintext.trading_pair.asset_1(),
    };
    let value_2 = Value {
        amount: swap_plaintext.delta_2_i,
        asset_id: swap_plaintext.trading_pair.asset_2(),
    };
    let value_fee = Value {
        amount: swap_plaintext.claim_fee.amount(),
        asset_id: swap_plaintext.claim_fee.asset_id(),
    };
    let mut balance = Balance::default();
    balance -= value_1;
    balance -= value_2;
    balance -= value_fee;
    let balance_commitment = balance.commit(fee_blinding);

    let public = SwapProofPublic {
        balance_commitment,
        swap_commitment,
        fee_commitment,
    };
    let private = SwapProofPrivate {
        fee_blinding,
        swap_plaintext,
    };

    Ok(SwapCircuit::new(public, private))
}

fn swap_claim() -> anyhow::Result<SwapClaimCircuit> {
    let mut rng = OsRng;
    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_recipient = sk_recipient.full_viewing_key();
    let ivk_recipient = fvk_recipient.incoming();
    let (claim_address, _dtk_d) = ivk_recipient.payment_address(0u32.into());
    let nk = *sk_recipient.nullifier_key();
    let ak = *fvk_recipient.spend_verification_key();

    let gm = asset::Cache::with_known_assets().get_unit("gm").unwrap();
    let gn = asset::Cache::with_known_assets().get_unit("gn").unwrap();
    let trading_pair = TradingPair::new(gm.id(), gn.id());

    let delta_1_i = Amount::from(2u64);
    let delta_2_i = Amount::from(0u64);
    let fee = Fee::default();

    let swap_plaintext = SwapPlaintext::new(
        &mut rng,
        trading_pair,
        delta_1_i,
        delta_2_i,
        fee,
        claim_address,
    );
    let claim_fee = swap_plaintext.clone().claim_fee;
    let mut sct = Tree::new();
    let swap_commitment = swap_plaintext.swap_commitment();
    sct.insert(Witness::Keep, swap_commitment).unwrap();
    let anchor = sct.root();
    let state_commitment_proof = sct.witness(swap_commitment).unwrap();
    let position = state_commitment_proof.position();
    let nullifier = Nullifier::derive(&nk, position, &swap_commitment);
    let epoch_duration = 20;
    let height = epoch_duration * position.epoch() + position.block();

    let output_data = BatchSwapOutputData {
        delta_1: Amount::from(100u64),
        delta_2: Amount::from(100u64),
        lambda_1: Amount::from(50u64),
        lambda_2: Amount::from(25u64),
        unfilled_1: Amount::from(23u64),
        unfilled_2: Amount::from(50u64),
        height: height.into(),
        trading_pair: swap_plaintext.trading_pair,
        sct_position_prefix: position,
    };
    let (lambda_1, lambda_2) = output_data.pro_rata_outputs((delta_1_i, delta_2_i));

    let (output_rseed_1, output_rseed_2) = swap_plaintext.output_rseeds();
    let note_blinding_1 = output_rseed_1.derive_note_blinding();
    let note_blinding_2 = output_rseed_2.derive_note_blinding();
    let (output_1_note, output_2_note) = swap_plaintext.output_notes(&output_data);
    let note_commitment_1 = output_1_note.commit();
    let note_commitment_2 = output_2_note.commit();

    let public = SwapClaimProofPublic {
        anchor,
        nullifier,
        claim_fee,
        output_data,
        note_commitment_1,
        note_commitment_2,
    };
    let private = SwapClaimProofPrivate {
        swap_plaintext,
        state_commitment_proof,
        ak,
        nk,
        lambda_1,
        lambda_2,
        note_blinding_1,
        note_blinding_2,
    };

    Ok(SwapClaimCircuit::new(public, private))
}

fn nullifier_derivation() -> anyhow::Result<NullifierDerivationCircuit> {
    let mut rng = OsRng;
    let seed_phrase = SeedPhrase::generate(OsRng);
    let sk_sender = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_sender = sk_sender.full_viewing_key();
    let ivk_sender = fvk_sender.incoming();
    let (sender, _dtk_d) = ivk_sender.payment_address(0u32.into());

    let value_to_send = Value {
        amount: 1u128.into(),
        asset_id: asset::Cache::with_known_assets()
            .get_unit("upenumbra")
            .unwrap()
            .id(),
    };

    let note = Note::generate(&mut rng, &sender, value_to_send);
    let note_commitment = note.commit();
    let nk = *sk_sender.nullifier_key();
    let mut sct = Tree::new();

    sct.insert(Witness::Keep, note_commitment).unwrap();
    let state_commitment_proof = sct.witness(note_commitment).unwrap();
    let position = state_commitment_proof.position();
    let nullifier = Nullifier::derive(&nk, state_commitment_proof.position(), &note_commitment);

    let public = NullifierDerivationProofPublic {
        position,
        note_commitment,
        nullifier,
    };
    let private = NullifierDerivationProofPrivate { nk };

    Ok(NullifierDerivationCircuit::new(public, private))
}

fn convert() -> anyhow::Result<ConvertCircuit> {
    let sk = SigningKey::new_from_field(Fr::from(1u8));
    let balance_blinding = Fr::from(1u8);
    let value1_amount = 1u64;
    let penalty_amount = 1u64;
    let validator_identity = IdentityKey(VerificationKey::from(&sk).into());
    let unbonding_amount = Amount::from(value1_amount);

    let start_height = 1;
    let unbonding_token = UnbondingToken::new(validator_identity, start_height);
    let unbonding_id = unbonding_token.id();
    let penalty = Penalty::from_bps_squared(penalty_amount);
    let balance = penalty.balance_for_claim(unbonding_id, unbonding_amount);
    let balance_commitment = balance.commit(balance_blinding);

    let public = UndelegateClaimProofPublic {
        balance_commitment,
        unbonding_id,
        penalty,
    };
    let private = UndelegateClaimProofPrivate {
        unbonding_amount,
        balance_blinding,
    };

    Ok(ConvertCircuit::new(public.into(), private.into()))
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    circuit: Circuit,
}

#[derive(Debug, clap::Subcommand)]
enum Circuit {
    Spend,
    Output,
    DelegatorVote,
    Swap,
    SwapClaim,
    NullifierDerivation,
    Convert,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.circuit {
        Circuit::Spend => serialize_witness_and_matrices(spend()?)?,
        Circuit::Output => serialize_witness_and_matrices(output()?)?,
        Circuit::DelegatorVote => serialize_witness_and_matrices(delegator_vote()?)?,
        Circuit::Swap => serialize_witness_and_matrices(swap()?)?,
        Circuit::SwapClaim => serialize_witness_and_matrices(swap_claim()?)?,
        Circuit::NullifierDerivation => serialize_witness_and_matrices(nullifier_derivation()?)?,
        Circuit::Convert => serialize_witness_and_matrices(convert()?)?,
    }
    Ok(())
}
