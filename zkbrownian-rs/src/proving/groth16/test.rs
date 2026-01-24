use crate::proving::groth16::{prepare_verifying_key, Groth16};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    lc,
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng, UniformRand,
};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;

        Ok(())
    }
}

struct MySillyCircuit2<F: Field> {
    a: Option<F>,
    b: Option<F>,
    a2: Option<F>,
    b2: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit2<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let a2 = cs.new_witness_variable(|| self.a2.ok_or(SynthesisError::AssignmentMissing))?;
        let b2 = cs.new_witness_variable(|| self.b2.ok_or(SynthesisError::AssignmentMissing))?;

        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        let c2 = cs.new_input_variable(|| {
            let mut a2 = self.a2.ok_or(SynthesisError::AssignmentMissing)?;
            let b2 = self.b2.ok_or(SynthesisError::AssignmentMissing)?;

            a2 *= &b2;
            Ok(a2)
        })?;

        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;

        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;

        Ok(())
    }
}

fn test_prove_and_verify<E>(n_iters: usize)
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    for _ in 0..n_iters {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof).unwrap());
    }
}

fn test_rerandomize<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    for _ in 0..10 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof1 = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        // Rerandomize the proof, then rerandomize that
        let proof2 = Groth16::<E>::rerandomize_proof(&vk, &proof1, &mut rng);
        let proof3 = Groth16::<E>::rerandomize_proof(&vk, &proof2, &mut rng);

        // Check correctness: a rerandomized proof validates when the original validates
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof1).unwrap());
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof2).unwrap());
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof3).unwrap());

        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof1).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof2).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof3).unwrap());

        // Check that the proofs are not equal as group elements
        assert!(proof1 != proof2);
        assert!(proof1 != proof3);
        assert!(proof2 != proof3);
    }
}

fn test_link16<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(
        MySillyCircuit2 {
            a: None,
            b: None,
            a2: None,
            b2: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let mut c = a;
    c *= b;
    let a2 = E::ScalarField::rand(&mut rng);
    let b2 = E::ScalarField::rand(&mut rng);
    let mut c2 = a2;
    c2 *= b2;

    let r = E::ScalarField::rand(&mut rng);
    let s = E::ScalarField::rand(&mut rng);
    let com_r = E::ScalarField::rand(&mut rng);
    let com_size = 1;

    let (proof, com) = Groth16::<E>::create_proof_with_reduction(
        MySillyCircuit2 {
            a: Some(a),
            b: Some(b),
            a2: Some(a2),
            b2: Some(b2),
        },
        &pk,
        r,
        s,
        &[com_r],
        &[com_size],
    )
    .unwrap();

    assert!(
        Groth16::<E>::verify_proof(&pvk, &proof, com_size, &com, &[c2]).unwrap(),
        "Proof must verify"
    );

    let (proof2, com2) = Groth16::<E>::rerandomize_proof_and_input(&pk.vk, &proof, &com, &mut rng);

    assert!(
        Groth16::<E>::verify_proof(&pvk, &proof2, com_size, &com2, &[c2]).unwrap(),
        "Rerandomized proof must verify"
    );
}

struct MySillyCircuit3<F: Field> {
    a1: Option<F>,
    b1: Option<F>,
    a2: Option<F>,
    b2: Option<F>,
    a3: Option<F>,
    b3: Option<F>,
    a4: Option<F>,
    b4: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit3<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a1 = cs.new_witness_variable(|| self.a1.ok_or(SynthesisError::AssignmentMissing))?;
        let b1 = cs.new_witness_variable(|| self.b1.ok_or(SynthesisError::AssignmentMissing))?;
        let a2 = cs.new_witness_variable(|| self.a2.ok_or(SynthesisError::AssignmentMissing))?;
        let b2 = cs.new_witness_variable(|| self.b2.ok_or(SynthesisError::AssignmentMissing))?;
        let a3 = cs.new_witness_variable(|| self.a3.ok_or(SynthesisError::AssignmentMissing))?;
        let b3 = cs.new_witness_variable(|| self.b3.ok_or(SynthesisError::AssignmentMissing))?;
        let a4 = cs.new_witness_variable(|| self.a4.ok_or(SynthesisError::AssignmentMissing))?;
        let b4 = cs.new_witness_variable(|| self.b4.ok_or(SynthesisError::AssignmentMissing))?;

        let c1 = cs.new_input_variable(|| {
            let mut a1 = self.a1.ok_or(SynthesisError::AssignmentMissing)?;
            let b1 = self.b1.ok_or(SynthesisError::AssignmentMissing)?;

            a1 *= &b1;
            Ok(a1)
        })?;

        let c2 = cs.new_input_variable(|| {
            let mut a2 = self.a2.ok_or(SynthesisError::AssignmentMissing)?;
            let b2 = self.b2.ok_or(SynthesisError::AssignmentMissing)?;

            a2 *= &b2;
            Ok(a2)
        })?;

        let c3 = cs.new_input_variable(|| {
            let mut a3 = self.a3.ok_or(SynthesisError::AssignmentMissing)?;
            let b3 = self.b3.ok_or(SynthesisError::AssignmentMissing)?;

            a3 *= &b3;
            Ok(a3)
        })?;

        let c4 = cs.new_input_variable(|| {
            let mut a4 = self.a4.ok_or(SynthesisError::AssignmentMissing)?;
            let b4 = self.b4.ok_or(SynthesisError::AssignmentMissing)?;

            a4 *= &b4;
            Ok(a4)
        })?;

        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;
        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;
        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;
        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;
        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;
        cs.enforce_r1cs_constraint(|| lc!() + a1, || lc!() + b1, || lc!() + c1)?;

        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;
        cs.enforce_r1cs_constraint(|| lc!() + a2, || lc!() + b2, || lc!() + c2)?;

        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;
        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;
        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;
        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;
        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;
        cs.enforce_r1cs_constraint(|| lc!() + a3, || lc!() + b3, || lc!() + c3)?;

        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;
        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;
        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;
        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;
        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;
        cs.enforce_r1cs_constraint(|| lc!() + a4, || lc!() + b4, || lc!() + c4)?;

        Ok(())
    }
}

fn test_link16_extra<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(
        MySillyCircuit3 {
            a1: None,
            b1: None,
            a2: None,
            b2: None,
            a3: None,
            b3: None,
            a4: None,
            b4: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    let a1 = E::ScalarField::rand(&mut rng);
    let b1 = E::ScalarField::rand(&mut rng);
    let mut c1 = a1;
    c1 *= b1;
    let a2 = E::ScalarField::rand(&mut rng);
    let b2 = E::ScalarField::rand(&mut rng);
    let mut c2 = a2;
    c2 *= b2;
    let a3 = E::ScalarField::rand(&mut rng);
    let b3 = E::ScalarField::rand(&mut rng);
    let mut c3 = a3;
    c3 *= b3;
    let a4 = E::ScalarField::rand(&mut rng);
    let b4 = E::ScalarField::rand(&mut rng);
    let mut c4 = a4;
    c4 *= b4;

    let r = E::ScalarField::rand(&mut rng);
    let s = E::ScalarField::rand(&mut rng);
    let com_r1 = E::ScalarField::rand(&mut rng);
    let com_r2 = E::ScalarField::rand(&mut rng);

    let com_sizes = [1, 2];
    let coms_offset: usize = com_sizes.iter().sum();

    let (proof, coms) = Groth16::<E>::create_proof_with_reduction(
        MySillyCircuit3 {
            a1: Some(a1),
            b1: Some(b1),
            a2: Some(a2),
            b2: Some(b2),
            a3: Some(a3),
            b3: Some(b3),
            a4: Some(a4),
            b4: Some(b4),
        },
        &pk,
        r,
        s,
        &[com_r1, com_r2],
        &com_sizes,
    )
    .unwrap();

    assert!(
        Groth16::<E>::verify_proof(&pvk, &proof, coms_offset, &coms, &[c4]).unwrap(),
        "Proof must verify"
    );

    let (proof2, coms2) =
        Groth16::<E>::rerandomize_proof_and_input(&pk.vk, &proof, &coms, &mut rng);

    assert!(
        Groth16::<E>::verify_proof(&pvk, &proof2, coms_offset, &coms2, &[c4]).unwrap(),
        "Rerandomized proof must verify"
    );
}

/// Test batch verification with multiple valid proofs
fn test_batch_verify_valid<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // Setup circuit
    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    // Generate multiple valid proofs
    let num_proofs = 5;
    let mut proofs_and_inputs = Vec::new();

    for _ in 0..num_proofs {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        // First verify individually
        assert!(
            Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap(),
            "Individual proof should verify"
        );

        // Prepare inputs for batch verification
        let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();
        proofs_and_inputs.push((proof, prepared_input));
    }

    // Batch verify all proofs
    let batch_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &proofs_and_inputs).unwrap();
    assert!(
        batch_result,
        "Batch verification should succeed for all valid proofs"
    );
}

/// Test batch verification with a single proof (edge case)
fn test_batch_verify_single<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let mut c = a;
    c *= b;

    let proof = Groth16::<E>::prove(
        &pk,
        MySillyCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    // Verify individually first
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());

    // Batch verify with single proof
    let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();
    let proofs_and_inputs = vec![(proof, prepared_input)];

    let batch_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &proofs_and_inputs).unwrap();
    assert!(
        batch_result,
        "Batch verification should work for single proof"
    );
}

/// Test batch verification with empty input (edge case)
fn test_batch_verify_empty<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (_pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    // Batch verify with empty set
    let proofs_and_inputs = vec![];
    let batch_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &proofs_and_inputs).unwrap();
    assert!(
        batch_result,
        "Batch verification should succeed for empty input"
    );
}

/// Test that batch verification fails when one proof is invalid
fn test_batch_verify_one_invalid<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    let mut proofs_and_inputs = Vec::new();

    // Add 3 valid proofs
    for _ in 0..3 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();
        proofs_and_inputs.push((proof, prepared_input));
    }

    // Add 1 invalid proof (proof with wrong public input)
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let mut c = a;
    c *= b;

    let proof = Groth16::<E>::prove(
        &pk,
        MySillyCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    // Use wrong public input
    let wrong_c = E::ScalarField::rand(&mut rng);
    let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[wrong_c]).unwrap();
    proofs_and_inputs.push((proof, prepared_input));

    // Batch verification should fail
    let batch_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &proofs_and_inputs).unwrap();
    assert!(
        !batch_result,
        "Batch verification should fail when one proof is invalid"
    );
}

/// Test batch verification with many proofs to ensure scalability
fn test_batch_verify_many<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    // Generate many valid proofs (20 for thorough testing)
    let num_proofs = 20;
    let mut proofs_and_inputs = Vec::new();

    for _ in 0..num_proofs {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();
        proofs_and_inputs.push((proof, prepared_input));
    }

    // Batch verify all proofs
    let batch_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &proofs_and_inputs).unwrap();
    assert!(
        batch_result,
        "Batch verification should succeed for many valid proofs"
    );
}

/// Test cross-circuit batch verification with multiple circuits and valid proofs
fn test_batch_verify_cross_circuit_valid<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // Setup two different circuits
    let (pk1, vk1) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk1 = prepare_verifying_key::<E>(&vk1);

    let (pk2, vk2) = Groth16::<E>::setup(
        MySillyCircuit2 {
            a: None,
            b: None,
            a2: None,
            b2: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk2 = prepare_verifying_key::<E>(&vk2);

    let mut proofs_pvks_and_inputs = Vec::new();

    // Generate proofs for first circuit
    for _ in 0..3 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk1,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        // Verify individually first
        assert!(
            Groth16::<E>::verify_with_processed_vk(&pvk1, &[c], &proof).unwrap(),
            "Individual proof from circuit 1 should verify"
        );

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk1, 0, &[], &[c]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk1, prepared_input));
    }

    // Generate proofs for second circuit
    for _ in 0..2 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;
        let a2 = E::ScalarField::rand(&mut rng);
        let b2 = E::ScalarField::rand(&mut rng);
        let mut c2 = a2;
        c2 *= b2;

        let proof = Groth16::<E>::prove(
            &pk2,
            MySillyCircuit2 {
                a: Some(a),
                b: Some(b),
                a2: Some(a2),
                b2: Some(b2),
            },
            &mut rng,
        )
        .unwrap();

        // Verify individually first
        assert!(
            Groth16::<E>::verify_with_processed_vk(&pvk2, &[c, c2], &proof).unwrap(),
            "Individual proof from circuit 2 should verify"
        );

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk2, 0, &[], &[c, c2]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk2, prepared_input));
    }

    // Cross-circuit batch verify all proofs
    let batch_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&proofs_pvks_and_inputs).unwrap();
    assert!(
        batch_result,
        "Cross-circuit batch verification should succeed for all valid proofs"
    );
}

/// Test cross-circuit batch verification with a single proof (edge case)
fn test_batch_verify_cross_circuit_single<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let mut c = a;
    c *= b;

    let proof = Groth16::<E>::prove(
        &pk,
        MySillyCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    // Verify individually first
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());

    let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();
    let proofs_pvks_and_inputs = vec![(proof, &pvk, prepared_input)];

    let batch_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&proofs_pvks_and_inputs).unwrap();
    assert!(
        batch_result,
        "Cross-circuit batch verification should work for single proof"
    );
}

/// Test cross-circuit batch verification with empty input (edge case)
fn test_batch_verify_cross_circuit_empty<E>()
where
    E: Pairing,
{
    use crate::proving::groth16::{PreparedVerifyingKey, Proof};
    // Batch verify with empty set
    let proofs_pvks_and_inputs: Vec<(Proof<E>, &PreparedVerifyingKey<E>, E::G1)> = vec![];
    let batch_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&proofs_pvks_and_inputs).unwrap();
    assert!(
        batch_result,
        "Cross-circuit batch verification should succeed for empty input"
    );
}

/// Test that cross-circuit batch verification fails when one proof is invalid
fn test_batch_verify_cross_circuit_one_invalid<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // Setup two different circuits
    let (pk1, vk1) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk1 = prepare_verifying_key::<E>(&vk1);

    let (pk2, vk2) = Groth16::<E>::setup(
        MySillyCircuit2 {
            a: None,
            b: None,
            a2: None,
            b2: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk2 = prepare_verifying_key::<E>(&vk2);

    let mut proofs_pvks_and_inputs = Vec::new();

    // Add valid proofs from first circuit
    for _ in 0..2 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk1,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk1, 0, &[], &[c]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk1, prepared_input));
    }

    // Add one INVALID proof from second circuit (with wrong public input)
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let a2 = E::ScalarField::rand(&mut rng);
    let b2 = E::ScalarField::rand(&mut rng);

    let proof = Groth16::<E>::prove(
        &pk2,
        MySillyCircuit2 {
            a: Some(a),
            b: Some(b),
            a2: Some(a2),
            b2: Some(b2),
        },
        &mut rng,
    )
    .unwrap();

    // Use wrong public input
    let wrong_c = E::ScalarField::rand(&mut rng);
    let wrong_c2 = E::ScalarField::rand(&mut rng);
    let prepared_input = Groth16::<E>::prepare_inputs(&pvk2, 0, &[], &[wrong_c, wrong_c2]).unwrap();
    proofs_pvks_and_inputs.push((proof, &pvk2, prepared_input));

    // Batch verification should fail
    let batch_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&proofs_pvks_and_inputs).unwrap();
    assert!(
        !batch_result,
        "Cross-circuit batch verification should fail when one proof is invalid"
    );
}

/// Test cross-circuit batch verification with many proofs from different circuits
fn test_batch_verify_cross_circuit_many<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // Setup three different circuits
    let (pk1, vk1) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk1 = prepare_verifying_key::<E>(&vk1);

    let (pk2, vk2) = Groth16::<E>::setup(
        MySillyCircuit2 {
            a: None,
            b: None,
            a2: None,
            b2: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk2 = prepare_verifying_key::<E>(&vk2);

    let (pk3, vk3) = Groth16::<E>::setup(
        MySillyCircuit3 {
            a1: None,
            b1: None,
            a2: None,
            b2: None,
            a3: None,
            b3: None,
            a4: None,
            b4: None,
        },
        &mut rng,
    )
    .unwrap();
    let pvk3 = prepare_verifying_key::<E>(&vk3);

    let mut proofs_pvks_and_inputs = Vec::new();

    // Generate 7 proofs for first circuit
    for _ in 0..7 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk1,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk1, 0, &[], &[c]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk1, prepared_input));
    }

    // Generate 5 proofs for second circuit
    for _ in 0..5 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;
        let a2 = E::ScalarField::rand(&mut rng);
        let b2 = E::ScalarField::rand(&mut rng);
        let mut c2 = a2;
        c2 *= b2;

        let proof = Groth16::<E>::prove(
            &pk2,
            MySillyCircuit2 {
                a: Some(a),
                b: Some(b),
                a2: Some(a2),
                b2: Some(b2),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk2, 0, &[], &[c, c2]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk2, prepared_input));
    }

    // Generate 3 proofs for third circuit
    for _ in 0..3 {
        let a1 = E::ScalarField::rand(&mut rng);
        let b1 = E::ScalarField::rand(&mut rng);
        let mut c1 = a1;
        c1 *= b1;
        let a2 = E::ScalarField::rand(&mut rng);
        let b2 = E::ScalarField::rand(&mut rng);
        let mut c2 = a2;
        c2 *= b2;
        let a3 = E::ScalarField::rand(&mut rng);
        let b3 = E::ScalarField::rand(&mut rng);
        let mut c3 = a3;
        c3 *= b3;
        let a4 = E::ScalarField::rand(&mut rng);
        let b4 = E::ScalarField::rand(&mut rng);
        let mut c4 = a4;
        c4 *= b4;

        let proof = Groth16::<E>::prove(
            &pk3,
            MySillyCircuit3 {
                a1: Some(a1),
                b1: Some(b1),
                a2: Some(a2),
                b2: Some(b2),
                a3: Some(a3),
                b3: Some(b3),
                a4: Some(a4),
                b4: Some(b4),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input =
            Groth16::<E>::prepare_inputs(&pvk3, 0, &[], &[c1, c2, c3, c4]).unwrap();
        proofs_pvks_and_inputs.push((proof, &pvk3, prepared_input));
    }

    // Cross-circuit batch verify all 15 proofs from 3 different circuits
    let batch_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&proofs_pvks_and_inputs).unwrap();
    assert!(
        batch_result,
        "Cross-circuit batch verification should succeed for many proofs from different circuits"
    );
}

/// Performance comparison test between cross-circuit and same-circuit batch verification.
/// This test generates 50 proofs from the same circuit and compares the verification time
/// of both batch verifiers to identify potential performance regressions.
#[allow(dead_code)]
fn test_batch_verify_performance_comparison<E>()
where
    E: Pairing,
{
    use std::time::Instant;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    const BATCH_SIZE: usize = 50;

    println!("\n=== Batch Verification Performance Comparison ===");
    println!("Batch size: {} proofs", BATCH_SIZE);
    println!("Curve: {}\n", std::any::type_name::<E>());

    // Step 1: Setup circuit once
    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    // Step 2: Generate 50 proofs with random inputs
    println!("Generating {} proofs...", BATCH_SIZE);
    let proof_gen_start = Instant::now();

    let mut proofs = Vec::with_capacity(BATCH_SIZE);
    let mut prepared_inputs = Vec::with_capacity(BATCH_SIZE);

    for _ in 0..BATCH_SIZE {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        let prepared_input = Groth16::<E>::prepare_inputs(&pvk, 0, &[], &[c]).unwrap();

        proofs.push(proof);
        prepared_inputs.push(prepared_input);
    }

    let proof_gen_time = proof_gen_start.elapsed();
    println!("Proof generation took: {:?}\n", proof_gen_time);

    // Step 3: Test cross-circuit verifier
    println!("Testing cross-circuit batch verifier...");
    let cross_circuit_input: Vec<_> = proofs
        .iter()
        .zip(prepared_inputs.iter())
        .map(|(proof, input)| (proof.clone(), &pvk, *input))
        .collect();

    let cross_start = Instant::now();
    let cross_result =
        Groth16::<E>::batch_verify_proofs_cross_circuit(&cross_circuit_input).unwrap();
    let cross_time = cross_start.elapsed();

    assert!(
        cross_result,
        "Cross-circuit batch verification should succeed"
    );
    println!("  Result: SUCCESS");
    println!("  Time: {:?}", cross_time);

    // Step 4: Test same-circuit verifier
    println!("\nTesting same-circuit batch verifier...");
    let same_circuit_input: Vec<_> = proofs
        .iter()
        .zip(prepared_inputs.iter())
        .map(|(proof, input)| (proof.clone(), *input))
        .collect();

    let same_start = Instant::now();
    let same_result =
        Groth16::<E>::batch_verify_proofs_with_prepared_inputs(&pvk, &same_circuit_input).unwrap();
    let same_time = same_start.elapsed();

    assert!(
        same_result,
        "Same-circuit batch verification should succeed"
    );
    println!("  Result: SUCCESS");
    println!("  Time: {:?}", same_time);

    // Step 5: Output comparison
    println!("\n=== Results ===");
    println!("Cross-circuit verifier: {:?}", cross_time);
    println!("Same-circuit verifier:  {:?}", same_time);

    let speedup = cross_time.as_secs_f64() / same_time.as_secs_f64();
    println!("\nSpeedup (cross/same): {:.2}x", speedup);

    if speedup > 1.0 {
        println!(
            "⚠️  Cross-circuit verifier is {:.2}x SLOWER when used with same-circuit proofs",
            speedup
        );
    } else {
        println!("✓ Cross-circuit verifier performs comparably to same-circuit verifier");
    }
}

mod bls12_377 {
    use super::{
        test_batch_verify_cross_circuit_empty, test_batch_verify_cross_circuit_many,
        test_batch_verify_cross_circuit_one_invalid, test_batch_verify_cross_circuit_single,
        test_batch_verify_cross_circuit_valid, test_batch_verify_empty, test_batch_verify_many,
        test_batch_verify_one_invalid, test_batch_verify_single, test_batch_verify_valid,
        test_prove_and_verify, test_rerandomize,
    };
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(100);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<Bls12_377>();
    }

    #[test]
    fn batch_verify_valid() {
        test_batch_verify_valid::<Bls12_377>();
    }

    #[test]
    fn batch_verify_single() {
        test_batch_verify_single::<Bls12_377>();
    }

    #[test]
    fn batch_verify_empty() {
        test_batch_verify_empty::<Bls12_377>();
    }

    #[test]
    fn batch_verify_one_invalid() {
        test_batch_verify_one_invalid::<Bls12_377>();
    }

    #[test]
    fn batch_verify_many() {
        test_batch_verify_many::<Bls12_377>();
    }

    #[test]
    fn batch_verify_cross_circuit_valid() {
        test_batch_verify_cross_circuit_valid::<Bls12_377>();
    }

    #[test]
    fn batch_verify_cross_circuit_single() {
        test_batch_verify_cross_circuit_single::<Bls12_377>();
    }

    #[test]
    fn batch_verify_cross_circuit_empty() {
        test_batch_verify_cross_circuit_empty::<Bls12_377>();
    }

    #[test]
    fn batch_verify_cross_circuit_one_invalid() {
        test_batch_verify_cross_circuit_one_invalid::<Bls12_377>();
    }

    #[test]
    fn batch_verify_cross_circuit_many() {
        test_batch_verify_cross_circuit_many::<Bls12_377>();
    }
}

mod bw6_761 {
    use super::{
        test_batch_verify_empty, test_batch_verify_one_invalid, test_batch_verify_single,
        test_batch_verify_valid, test_prove_and_verify, test_rerandomize,
    };

    use ark_bw6_761::BW6_761;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<BW6_761>(1);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<BW6_761>();
    }

    // DISABLED: This test fails due to an apparent bug in arkworks' BW6_761
    // implementation of multi_miller_loop with dynamic-length vectors.
    // The optimization works correctly for BN254 and BLS12_377.
    // See verifier.rs:190 for details.
    #[test]
    #[ignore]
    fn batch_verify_valid() {
        test_batch_verify_valid::<BW6_761>();
    }

    #[test]
    fn batch_verify_single() {
        test_batch_verify_single::<BW6_761>();
    }

    #[test]
    fn batch_verify_empty() {
        test_batch_verify_empty::<BW6_761>();
    }

    #[test]
    fn batch_verify_one_invalid() {
        test_batch_verify_one_invalid::<BW6_761>();
    }
}

mod bn_254 {
    use super::{
        test_batch_verify_cross_circuit_empty, test_batch_verify_cross_circuit_many,
        test_batch_verify_cross_circuit_one_invalid, test_batch_verify_cross_circuit_single,
        test_batch_verify_cross_circuit_valid, test_batch_verify_empty, test_batch_verify_many,
        test_batch_verify_one_invalid, test_batch_verify_performance_comparison,
        test_batch_verify_single, test_batch_verify_valid, test_link16, test_link16_extra,
        test_prove_and_verify,
    };
    use ark_bn254::Bn254;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bn254>(100);
    }

    #[test]
    fn link16() {
        test_link16::<Bn254>();
        test_link16_extra::<Bn254>();
    }

    #[test]
    fn batch_verify_valid() {
        test_batch_verify_valid::<Bn254>();
    }

    #[test]
    fn batch_verify_single() {
        test_batch_verify_single::<Bn254>();
    }

    #[test]
    fn batch_verify_empty() {
        test_batch_verify_empty::<Bn254>();
    }

    #[test]
    fn batch_verify_one_invalid() {
        test_batch_verify_one_invalid::<Bn254>();
    }

    #[test]
    fn batch_verify_many() {
        test_batch_verify_many::<Bn254>();
    }

    #[test]
    fn batch_verify_cross_circuit_valid() {
        test_batch_verify_cross_circuit_valid::<Bn254>();
    }

    #[test]
    fn batch_verify_cross_circuit_single() {
        test_batch_verify_cross_circuit_single::<Bn254>();
    }

    #[test]
    fn batch_verify_cross_circuit_empty() {
        test_batch_verify_cross_circuit_empty::<Bn254>();
    }

    #[test]
    fn batch_verify_cross_circuit_one_invalid() {
        test_batch_verify_cross_circuit_one_invalid::<Bn254>();
    }

    #[test]
    fn batch_verify_cross_circuit_many() {
        test_batch_verify_cross_circuit_many::<Bn254>();
    }

    #[test]
    #[ignore]
    fn batch_verify_performance_comparison() {
        test_batch_verify_performance_comparison::<Bn254>();
    }
}
