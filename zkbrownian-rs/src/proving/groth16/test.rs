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
        com_r,
        com_size,
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

mod bls12_377 {
    use super::{test_prove_and_verify, test_rerandomize};
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(100);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<Bls12_377>();
    }
}

mod bw6_761 {
    use super::{test_prove_and_verify, test_rerandomize};

    use ark_bw6_761::BW6_761;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<BW6_761>(1);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<BW6_761>();
    }
}

mod bn_254 {
    use super::{test_link16, test_prove_and_verify};
    use ark_bn254::Bn254;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bn254>(100);
    }

    #[test]
    fn link16() {
        test_link16::<Bn254>();
    }
}
