use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};

use crate::proving::groth16::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::gr1cs::Result as R1CSResult;

use core::ops::{AddAssign, Neg};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`],
    /// wrt the prepared verification key `pvk` and instance public inputs.
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        coms_offset: usize,
        public_input_coms: &[E::G1],
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<E::G1> {
        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();

        if coms_offset > 0 {
            for com in public_input_coms.iter() {
                g_ic.add_assign(com);
            }
        }

        for (i, b) in public_inputs
            .iter()
            .zip(pvk.vk.gamma_abc_g1.iter().skip(1 + coms_offset))
        {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk` and prepared public inputs. This should be preferred over
    /// [`verify_proof`] if the instance's public inputs are
    /// known in advance.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        let qap = E::multi_miller_loop(
            [
                <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                prepared_inputs.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );

        let test = E::final_exponentiation(qap).unwrap();

        Ok(test.0 == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key
    /// `pvk`, with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        coms_offset: usize,
        public_inputs_coms: &[E::G1],
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs =
            Self::prepare_inputs(pvk, coms_offset, public_inputs_coms, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }

    /// Batch verify multiple Groth16 proofs against the same prepared verification key.
    ///
    /// This uses random linear combination to batch multiple pairing checks into a single one.
    /// Given proofs π_1, ..., π_n, we sample random coefficients α_1, ..., α_n and verify:
    /// e(∑ αᵢ·Aᵢ, ∑ αᵢ·Bᵢ) = e(α·g₁, β·g₂) · e(∑ αᵢ·prepared_inputsᵢ, -γ·g₂) · e(∑ αᵢ·Cᵢ, -δ·g₂)
    ///
    /// # Arguments
    /// * `pvk` - Prepared verification key (same for all proofs)
    /// * `proofs_and_inputs` - Vec of (proof, prepared_inputs) pairs
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` otherwise
    pub fn batch_verify_proofs_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proofs_and_inputs: &[(Proof<E>, E::G1)],
    ) -> R1CSResult<bool> {
        use ark_std::rand::thread_rng;

        if proofs_and_inputs.is_empty() {
            return Ok(true);
        }

        // For single proof, use regular verification
        if proofs_and_inputs.len() == 1 {
            return Self::verify_proof_with_prepared_inputs(
                pvk,
                &proofs_and_inputs[0].0,
                &proofs_and_inputs[0].1,
            );
        }

        let mut rng = thread_rng();
        let mut random_coeffs = Vec::with_capacity(proofs_and_inputs.len());
        for _ in 0..proofs_and_inputs.len() {
            random_coeffs.push(E::ScalarField::rand(&mut rng));
        }

        // Optimized batch verification using k+2 pairings instead of 3k pairings
        // The verification equation is:
        // e(α, β)^(∑ rᵢ) = ∏ e(rᵢ·Aᵢ, Bᵢ) · ∏ e(rᵢ·inputsᵢ, γ) · ∏ e(rᵢ·Cᵢ, δ)
        //
        // We rearrange to:
        // e(α, β)^(∑ rᵢ) · e(∑ rᵢ·inputsᵢ, -γ) · e(∑ rᵢ·Cᵢ, -δ) = ∏ e(rᵢ·Aᵢ, Bᵢ)
        //
        // This requires:
        // - k pairings for e(rᵢ·Aᵢ, Bᵢ) (one per proof)
        // - 2 pairings for the combined inputs and C terms
        // Total: k + 2 pairings (vs 3k in the naive approach)

        use ark_ec::VariableBaseMSM;

        // Compute ∑ rᵢ for the alpha_beta term
        let sum_coeffs = random_coeffs
            .iter()
            .fold(E::ScalarField::zero(), |acc, r| acc + r);

        // Compute ∑ rᵢ·inputsᵢ using MSM
        let input_points: Vec<_> = proofs_and_inputs
            .iter()
            .map(|(_, inp)| inp.into_affine())
            .collect();
        let combined_inputs = E::G1::msm(&input_points, &random_coeffs)
            .map_err(|_| ark_relations::gr1cs::SynthesisError::Unsatisfiable)?;

        // Compute ∑ rᵢ·Cᵢ using MSM
        let c_points: Vec<_> = proofs_and_inputs.iter().map(|(p, _)| p.c).collect();
        let combined_c = E::G1::msm(&c_points, &random_coeffs)
            .map_err(|_| ark_relations::gr1cs::SynthesisError::Unsatisfiable)?;

        // Prepare all G1 elements: [rᵢ·A₁, rᵢ·A₂, ..., rᵢ·Aₖ, ∑rᵢ·inputsᵢ, ∑rᵢ·Cᵢ]
        let mut g1_elements = Vec::with_capacity(proofs_and_inputs.len() + 2);

        for ((proof, _), coeff) in proofs_and_inputs.iter().zip(random_coeffs.iter()) {
            let scaled_a = proof
                .a
                .into_group()
                .mul_bigint(coeff.into_bigint())
                .into_affine();
            g1_elements.push(<E::G1Affine as Into<E::G1Prepared>>::into(scaled_a));
        }

        g1_elements.push(<E::G1Affine as Into<E::G1Prepared>>::into(
            combined_inputs.into_affine(),
        ));
        g1_elements.push(<E::G1Affine as Into<E::G1Prepared>>::into(
            combined_c.into_affine(),
        ));

        // Prepare all G2 elements: [B₁, B₂, ..., Bₖ, -γ, -δ]
        let mut g2_elements = Vec::with_capacity(proofs_and_inputs.len() + 2);

        for (proof, _) in proofs_and_inputs.iter() {
            g2_elements.push(<E::G2Affine as Into<E::G2Prepared>>::into(proof.b));
        }

        g2_elements.push(pvk.gamma_g2_neg_pc.clone());
        g2_elements.push(pvk.delta_g2_neg_pc.clone());

        // Perform single multi_miller_loop with k+2 pairings
        // This is significantly more efficient than k separate miller_loop calls
        // NOTE: There appears to be a bug in arkworks' BW6_761 curve implementation
        // where this fails for batches > 1 proof. Works correctly for BN254 and BLS12_377.
        let ml_result = E::multi_miller_loop(g1_elements, g2_elements);

        let test = E::final_exponentiation(ml_result).unwrap();

        // The right hand side should be e(α, β)^(∑ rᵢ)
        let expected = pvk.alpha_g1_beta_g2.pow(sum_coeffs.into_bigint());

        Ok(test.0 == expected)
    }
}
