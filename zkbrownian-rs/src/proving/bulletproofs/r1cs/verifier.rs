#![allow(non_snake_case)]

use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_std::{One, UniformRand, Zero};
use core::borrow::BorrowMut;
use core::mem;
use merlin::Transcript;

use super::constraint_system::{
    ConstraintSystem, RandomizableConstraintSystem, RandomizedConstraintSystem,
};
use super::linear_combination::{LinearCombination, Variable};
use super::proof::R1CSProof;

use crate::proving::bulletproofs::errors::R1CSError;
use crate::proving::bulletproofs::generators::{BulletproofGens, PedersenGens};
use crate::proving::bulletproofs::r1cs::Metrics;
use crate::proving::bulletproofs::transcript::TranscriptProtocol;

use super::op_splits;

/// A [`ConstraintSystem`] implementation for use by the verifier.
///
/// The verifier adds high-level variable commitments to the transcript,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the verifying code calls `verify`
/// which consumes the `Verifier` instance, samples random challenges
/// that instantiate the randomized constraints, and verifies the proof.
pub struct Verifier<T: BorrowMut<Transcript>, C: AffineRepr> {
    transcript: T,
    constraints: Vec<LinearCombination<C::ScalarField>>,

    vec_comms: Vec<(C, usize)>,

    /// Records the number of low-level variables allocated in the
    /// constraint system.
    ///
    /// Because the `VerifierCS` only keeps the constraints
    /// themselves, it doesn't record the assignments (they're all
    /// `Missing`), so the `num_vars` isn't kept implicitly in the
    /// variable assignments.
    num_vars: usize,
    V: Vec<C>,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    /// After that, the option will flip to None and additional calls to `randomize_constraints`
    /// will invoke closures immediately.
    #[allow(clippy::type_complexity)]
    deferred_constraints:
        Vec<Box<dyn FnOnce(&mut RandomizingVerifier<T, C>) -> Result<(), R1CSError>>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Verifier in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingVerifier<T: BorrowMut<Transcript>, C: AffineRepr> {
    verifier: Verifier<T, C>,
}

impl<T: BorrowMut<Transcript>, C: AffineRepr> ConstraintSystem<C::ScalarField> for Verifier<T, C> {
    fn transcript(&mut self) -> &mut Transcript {
        self.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        mut left: LinearCombination<C::ScalarField>,
        mut right: LinearCombination<C::ScalarField>,
    ) -> (
        Variable<C::ScalarField>,
        Variable<C::ScalarField>,
        Variable<C::ScalarField>,
    ) {
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        // Constrain l,r,o:
        left.terms.push((l_var, -C::ScalarField::one()));
        right.terms.push((r_var, -C::ScalarField::one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(
        &mut self,
        _: Option<C::ScalarField>,
    ) -> Result<Variable<C::ScalarField>, R1CSError> {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        _: Option<(C::ScalarField, C::ScalarField)>,
    ) -> Result<
        (
            Variable<C::ScalarField>,
            Variable<C::ScalarField>,
            Variable<C::ScalarField>,
        ),
        R1CSError,
    > {
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        Ok((l_var, r_var, o_var))
    }

    fn metrics(&self) -> Metrics {
        Metrics {
            multipliers: self.num_vars,
            constraints: self.constraints.len() + self.deferred_constraints.len(),
            phase_one_constraints: self.constraints.len(),
            phase_two_constraints: self.deferred_constraints.len(),
        }
    }

    fn constrain(&mut self, lc: LinearCombination<C::ScalarField>) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination
        // evals to 0 for prover, etc).
        self.constraints.push(lc);
    }
}

impl<T: BorrowMut<Transcript>, C: AffineRepr> RandomizableConstraintSystem<C::ScalarField>
    for Verifier<T, C>
{
    type RandomizedCS = RandomizingVerifier<T, C>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + FnOnce(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<T: BorrowMut<Transcript>, C: AffineRepr> ConstraintSystem<C::ScalarField>
    for RandomizingVerifier<T, C>
{
    fn transcript(&mut self) -> &mut Transcript {
        self.verifier.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        left: LinearCombination<C::ScalarField>,
        right: LinearCombination<C::ScalarField>,
    ) -> (
        Variable<C::ScalarField>,
        Variable<C::ScalarField>,
        Variable<C::ScalarField>,
    ) {
        self.verifier.multiply(left, right)
    }

    fn allocate(
        &mut self,
        assignment: Option<C::ScalarField>,
    ) -> Result<Variable<C::ScalarField>, R1CSError> {
        self.verifier.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(C::ScalarField, C::ScalarField)>,
    ) -> Result<
        (
            Variable<C::ScalarField>,
            Variable<C::ScalarField>,
            Variable<C::ScalarField>,
        ),
        R1CSError,
    > {
        self.verifier.allocate_multiplier(input_assignments)
    }

    fn metrics(&self) -> Metrics {
        self.verifier.metrics()
    }

    fn constrain(&mut self, lc: LinearCombination<C::ScalarField>) {
        self.verifier.constrain(lc)
    }
}

impl<T: BorrowMut<Transcript>, C: AffineRepr> RandomizedConstraintSystem<C::ScalarField>
    for RandomizingVerifier<T, C>
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> C::ScalarField {
        self.verifier
            .transcript
            .borrow_mut()
            .challenge_scalar::<C>(label)
    }
}

impl<T: BorrowMut<Transcript>, C: AffineRepr> Verifier<T, C> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `VerifierCS` holds onto the `&mut Transcript` until it consumes
    /// itself during [`VerifierCS::verify`], releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `VerifierCS` before proving is complete.
    ///
    /// The `commitments` parameter is a list of Pedersen commitments
    /// to the external variables for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by [`ConstraintSystem::challenge_scalar`] are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a tuple `(cs, vars)`.
    ///
    /// The first element is the newly constructed constraint system.
    ///
    /// The second element is a list of [`Variable`]s corresponding to
    /// the external inputs, which can be used to form constraints.
    pub fn new(mut transcript: T) -> Self {
        transcript.borrow_mut().r1cs_domain_sep();

        Verifier {
            vec_comms: Vec::new(),
            transcript,
            num_vars: 0,
            V: Vec::new(),
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    pub fn size(&self) -> usize {
        let mut n = self.num_vars;
        for (_, dim) in self.vec_comms.iter() {
            n = std::cmp::max(*dim, n)
        }
        n
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `commitment` parameter is a Pedersen commitment
    /// to the external variable for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by [`ConstraintSystem::challenge_scalar`] are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment (as a compressed Ristretto point),
    /// and a [`Variable`] corresponding to it, which can be used to form constraints.
    pub fn commit(&mut self, commitment: C) -> Variable<C::ScalarField> {
        let i = self.V.len();
        self.V.push(commitment);

        // Add the commitment to the transcript.
        self.transcript.borrow_mut().append_point(b"V", &commitment);

        Variable::Committed(i)
    }

    pub fn commit_vec(&mut self, dimension: usize, comm: C) -> Vec<Variable<C::ScalarField>> {
        // allocate next index for vector commitment
        let comm_idx = self.vec_comms.len();

        // add the commitment to the transcript.
        self.transcript.borrow_mut().append_point(b"V", &comm);

        // add to list of commitments
        self.vec_comms.push((comm, dimension));

        // create variables for all the addressable coordinates
        (0..dimension)
            .map(|i| Variable::VectorCommit(comm_idx, i))
            .collect()
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV, wc)
    /// ```
    /// where `w{L,R,O}` is \\( z \cdot z^Q \cdot W_{L,R,O} \\).
    ///
    /// This has the same logic as `ProverCS::flattened_constraints()`
    /// but also computes the constant terms (which the prover skips
    /// because they're not needed to construct the proof).
    #[allow(clippy::type_complexity)]
    fn flattened_constraints(
        &mut self,
        z: &C::ScalarField,
    ) -> (
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<Vec<C::ScalarField>>,
        C::ScalarField,
    ) {
        let n = self.num_vars;
        let m = self.V.len();

        let mut wL = vec![C::ScalarField::zero(); n];
        let mut wR = vec![C::ScalarField::zero(); n];
        let mut wO = vec![C::ScalarField::zero(); n];
        let mut wV = vec![C::ScalarField::zero(); m];
        let mut wc = C::ScalarField::zero();

        let mut wVCs = Vec::with_capacity(self.vec_comms.len());
        for (_, dim) in self.vec_comms.iter() {
            wVCs.push(vec![C::ScalarField::zero(); *dim]);
        }

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        wL[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        wR[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        wO[*i] += exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        wV[*i] -= exp_z * coeff;
                    }
                    Variable::VectorCommit(j, i) => {
                        // j : index of commitment
                        // i : coordinate with-in commitment
                        wVCs[*j][*i] += exp_z * coeff;
                    }
                    Variable::One(_) => {
                        wc -= exp_z * coeff;
                    }
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV, wVCs, wc)
    }

    /// Calls all remembered callbacks with an API that
    /// allows generating challenge scalars.
    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        // Clear the pending multiplier (if any) because it was committed into A_L/A_R/S.
        self.pending_multiplier = None;

        if self.deferred_constraints.is_empty() {
            self.transcript.borrow_mut().r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.borrow_mut().r1cs_2phase_domain_sep();
            // Note: the wrapper could've used &mut instead of ownership,
            // but specifying lifetimes for boxed closures is not going to be nice,
            // so we move the self into wrapper and then move it back out afterwards.
            let mut callbacks = mem::take(&mut self.deferred_constraints);
            let mut wrapped_self = RandomizingVerifier { verifier: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.verifier)
        }
    }

    /// Consume this `VerifierCS` and attempt to verify the supplied `proof`.
    /// The `pc_gens` and `bp_gens` are generators for Pedersen commitments and
    /// Bulletproofs vector commitments, respectively.  The
    /// [`BulletproofGens`] should have `gens_capacity` greater than
    /// the number of multiplication constraints that will eventually
    /// be added into the constraint system.
    pub fn verify(
        self,
        proof: &R1CSProof<C>,
        pc_gens: &PedersenGens<C>,
        bp_gens: &BulletproofGens<C>,
    ) -> Result<(), R1CSError> {
        let verification_tuple = self.verification_scalars_and_points(proof)?;
        let padded_n = (verification_tuple.proof_independent_scalars.len() - 2) / 2;

        // We are performing a single-party circuit proof, so party index is 0.
        let gens = bp_gens.share(0);

        if bp_gens.gens_capacity < padded_n {
            return Err(R1CSError::InvalidGeneratorsLength);
        }

        use std::iter;
        let fixed_points = iter::once(pc_gens.B)
            .chain(iter::once(pc_gens.B_blinding))
            .chain(gens.G(padded_n).copied())
            .chain(gens.H(padded_n).copied());

        let mega_check: C::Group = C::Group::msm_unchecked(
            verification_tuple
                .proof_dependent_points
                .into_iter()
                .chain(fixed_points)
                .collect::<Vec<_>>()
                .as_slice(),
            verification_tuple
                .proof_dependent_scalars
                .into_iter()
                .chain(verification_tuple.proof_independent_scalars)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        if !mega_check.is_zero() {
            return Err(R1CSError::VerificationError);
        }

        Ok(())
    }

    /// Compute verification scalars and points with an internally-generated random `r` scalar.
    pub fn verification_scalars_and_points(
        self,
        proof: &R1CSProof<C>,
    ) -> Result<VerificationTuple<C>, R1CSError> {
        let mut rng = rand::thread_rng();
        let r = C::ScalarField::rand(&mut rng);
        self.verification_scalars_and_points_impl(proof, r)
    }

    /// Compute verification scalars and points with a caller-provided `r` scalar.
    /// This is useful when the host needs to reproduce the exact same scalars
    /// as the guest (e.g. for hash commitment verification).
    pub fn verification_scalars_and_points_with_r(
        self,
        proof: &R1CSProof<C>,
        r: C::ScalarField,
    ) -> Result<VerificationTuple<C>, R1CSError> {
        self.verification_scalars_and_points_impl(proof, r)
    }

    fn verification_scalars_and_points_impl(
        mut self,
        proof: &R1CSProof<C>,
        r: C::ScalarField,
    ) -> Result<VerificationTuple<C>, R1CSError> {
        // pad
        while self.size() > self.num_vars {
            self.allocate_multiplier(None)?;
        }

        let n1 = self.size();

        // Commit a length _suffix_ for the number of high-level variables.
        // We cannot do this in advance because user can commit variables one-by-one,
        // but this suffix provides safe disambiguation because each variable
        // is prefixed with a separate label.
        let transcript = self.transcript.borrow_mut();
        transcript.append_u64(b"m", self.V.len() as u64);

        // number of commitments
        let ncomm = self.vec_comms.len();

        // op_degree = 2 + 2 * floor(#comm / 2)
        let op_degree = 2 + 2 * (ncomm / 2);
        let t_poly_deg = 2 * (op_degree + 1);
        let ops = op_splits(op_degree);

        #[cfg(debug_assertions)]
        {
            println!("op_degree = {}", op_degree);
            println!("t_poly_deg = {}", t_poly_deg);
            println!("ops = {:?}", &ops);
        }

        let op_aLaR = ops[0];
        let op_aO = ops[1];
        let op_vec = &ops[2..];

        debug_assert_eq!(t_poly_deg + 1, proof.T.len());

        transcript.validate_and_append_point(b"A_I1", &proof.A_I1)?;
        transcript.validate_and_append_point(b"A_O1", &proof.A_O1)?;
        transcript.validate_and_append_point(b"S1", &proof.S1)?;

        // Process the remaining constraints.
        self = self.create_randomized_constraints()?;

        let n = self.size();

        let transcript = self.transcript.borrow_mut();

        // Linear proof implementation doesn't require power-of-2 padding
        let n2 = n - n1;

        use crate::proving::bulletproofs::inner_product_proof::inner_product;
        use crate::proving::bulletproofs::util;
        use std::iter;

        // These points are the identity in the 1-phase unrandomized case.
        transcript.append_point(b"A_I2", &proof.A_I2);
        transcript.append_point(b"A_O2", &proof.A_O2);
        transcript.append_point(b"S2", &proof.S2);

        let y = transcript.challenge_scalar::<C>(b"y");
        let z = transcript.challenge_scalar::<C>(b"z");

        let transcript = self.transcript.borrow_mut();
        for d in 0..t_poly_deg + 1 {
            if d == op_degree {
                continue;
            }
            // println!("{}", &proof.T[d]);
            transcript.validate_and_append_point(util::T_LABELS[d], &proof.T[d])?;
        }

        let u = transcript.challenge_scalar::<C>(b"u");
        let x = transcript.challenge_scalar::<C>(b"x");

        #[cfg(debug_assertions)]
        println!("verifier: x = {}", x);

        // compute powers for vector commitments
        // they are assigned the lowest powers and therefore the coefficients
        // in the combination are correspondingly assigned the highest powers

        // precompute x powers
        let mut xs: Vec<C::ScalarField> = vec![C::ScalarField::zero(); t_poly_deg + 1];
        let mut rxs: Vec<C::ScalarField> = vec![C::ScalarField::zero(); t_poly_deg + 1];
        xs[0] = C::ScalarField::one();
        rxs[0] = r;
        for i in 1..xs.len() {
            xs[i] = xs[i - 1] * x;
            rxs[i] = rxs[i - 1] * x;
        }

        transcript.append_scalar::<C>(b"t_x", &proof.t_x);
        transcript.append_scalar::<C>(b"t_x_blinding", &proof.t_x_blinding);
        transcript.append_scalar::<C>(b"e_blinding", &proof.e_blinding);

        let w = transcript.challenge_scalar::<C>(b"w");

        let (wL, wR, wO, wV, wVCs, wc) = self.flattened_constraints(&z);

        #[cfg(debug_assertions)]
        println!("verifier wVCs = {:?}", &wVCs);

        // Linear proof: use l_vec and r_vec directly (no IPP verification)
        let l_vec = &proof.l_vec;
        let r_vec = &proof.r_vec;

        // Verify that the vectors have the correct length
        if l_vec.len() != n || r_vec.len() != n {
            return Err(R1CSError::VerificationError);
        }

        // Compute the inner product of l_vec and r_vec
        let ab = inner_product(l_vec, r_vec);

        let y_inv = y.inverse().unwrap();
        let y_inv_vec = util::exp_iter(y_inv)
            .take(n)
            .collect::<Vec<C::ScalarField>>();

        let yneg_wR = wR
            .into_iter()
            .zip(y_inv_vec.iter())
            .map(|(wRi, exp_y_inv)| wRi * exp_y_inv)
            .collect::<Vec<C::ScalarField>>();

        let delta = inner_product(&yneg_wR[0..self.num_vars], &wL);

        let u_for_g =
            std::iter::repeat_n(C::ScalarField::one(), n1).chain(std::iter::repeat_n(u, n2));

        let mut u_for_h = u_for_g.clone();

        debug_assert_eq!(op_aLaR.0, op_aLaR.1);
        let xwR = xs[op_aLaR.0];

        // Linear verification: compute g_scalars directly from l_vec
        let g_scalars = yneg_wR
            .iter()
            .zip(u_for_g)
            .zip(l_vec.iter())
            .map(|((yneg_wRi, u_or_1), l_i)| u_or_1 * (xwR * yneg_wRi - l_i));

        // r(x)
        let mut h_scalars = Vec::with_capacity(n);
        {
            let mut wL = wL.into_iter();
            let mut wO = wO.into_iter();
            let mut y_inv_vec = y_inv_vec.into_iter();

            for (i, r_i) in r_vec.iter().enumerate().take(n) {
                let y_inv = y_inv_vec.next().unwrap();
                let u_or_1 = u_for_h.next().unwrap();

                let wLi = wL.next().unwrap_or_default();
                let wOi = wO.next().unwrap_or_default();

                // compute right polynomial combination
                let mut comb = C::ScalarField::zero();
                {
                    // special terms
                    comb += xs[op_aLaR.1] * wLi;
                    comb += xs[op_aO.1] * wOi;

                    // add terms for vector commitments (higher degrees).
                    for j in 0..wVCs.len() {
                        let wVCji = wVCs[j].get(i).copied().unwrap_or_default();
                        comb += xs[op_vec[j].1] * wVCji;
                    }
                }

                // y^{-n} o (w_O + w_L * x + w_VCi * x^2)
                // Linear verification: use r_i directly instead of b * s_i
                let res = u_or_1 * (y_inv * (comb - r_i) - C::ScalarField::one());

                h_scalars.push(res);
            }
        }

        debug_assert_eq!(proof.T[op_degree], C::zero());
        debug_assert_eq!(proof.T.len(), t_poly_deg + 1);

        // homomorphically evaluate t polynomial at x
        let mut T_points = vec![];
        let mut T_scalars = vec![];
        for (d, _rx) in rxs.iter().enumerate().take(t_poly_deg + 1) {
            if d == op_degree {
                continue;
            }
            #[cfg(debug_assertions)]
            {
                println!("T[{}]: {} {}", d, proof.T[d].clone(), _rx);
            }
            T_points.push(proof.T[d]);
            T_scalars.push(rxs[d]);
        }

        debug_assert!(ncomm == 0 || proof.A_I2 == C::zero());
        debug_assert!(ncomm == 0 || proof.A_O2 == C::zero());
        debug_assert!(ncomm == 0 || proof.S2 == C::zero());

        let xI = xs[op_aLaR.0];
        let xO = xs[op_aO.0];
        let xS = xs[op_degree + 1];

        let vscalar = (0..ncomm).map(|j| xs[op_vec[j].0]);
        let vcomm = self.vec_comms.iter().copied().map(|(comm, _)| comm);

        let proof_points = vcomm
            .chain(iter::once(proof.A_I1))
            .chain(iter::once(proof.A_O1))
            .chain(iter::once(proof.S1))
            .chain(iter::once(proof.A_I2))
            .chain(iter::once(proof.A_O2))
            .chain(iter::once(proof.S2))
            .chain(self.V.iter().copied())
            .chain(T_points.iter().copied())
            .collect();

        let proof_scalars = vscalar
            .chain(iter::once(xI)) // A_I1
            .chain(iter::once(xO)) // A_O1
            .chain(iter::once(xS)) // S1
            .chain(iter::once(xI * u)) // A_I2
            .chain(iter::once(xO * u)) // A_O2
            .chain(iter::once(xS * u)) // S2
            .chain(wV.iter().map(|wVi| *wVi * rxs[op_degree])) // V : at op-degree
            .chain(T_scalars.iter().copied()) // T_points
            .collect::<Vec<_>>();

        let fixed_point_scalars: Vec<C::ScalarField> =
            iter::once(w * (proof.t_x - ab) + r * (xs[op_degree] * (wc + delta) - proof.t_x)) // B : shift (wc + delta) to the right power
                .chain(iter::once(-proof.e_blinding - r * proof.t_x_blinding)) // B_blinding
                .chain(g_scalars) // G
                .chain(h_scalars) // H
                .collect::<Vec<_>>();

        Ok(VerificationTuple {
            proof_dependent_points: proof_points,
            proof_dependent_scalars: proof_scalars,
            proof_independent_scalars: fixed_point_scalars,
        })
    }
}

pub struct VerificationTuple<C: AffineRepr> {
    pub proof_dependent_points: Vec<C>,
    pub proof_dependent_scalars: Vec<C::ScalarField>,
    pub proof_independent_scalars: Vec<C::ScalarField>,
}

/// Combine verification tuples using externally-provided random scalars,
/// returning the combined scalars without performing MSM.
///
/// The first tuple is used as-is (unscaled). Each subsequent tuple's scalars
/// are multiplied by the corresponding element from `batch_random_scalars`.
/// Therefore `batch_random_scalars` should have length `verification_tuples.len() - 1`.
///
/// Returns `(proof_points, proof_scalars, fixed_scalars, padded_n)`.
#[allow(clippy::type_complexity)]
pub fn batch_combine_scalars<C: AffineRepr>(
    verification_tuples: Vec<VerificationTuple<C>>,
    batch_random_scalars: &[C::ScalarField],
) -> (Vec<C>, Vec<C::ScalarField>, Vec<C::ScalarField>, usize) {
    let mut ver_iter = verification_tuples.into_iter();
    let vt = ver_iter.next().unwrap();
    let (mut proof_points, mut proof_scalars, mut fixed_scalars) = (
        vt.proof_dependent_points,
        vt.proof_dependent_scalars,
        vt.proof_independent_scalars,
    );
    let padded_n = (fixed_scalars.len() - 2) / 2;

    for (vt, random_scalar) in ver_iter.zip(batch_random_scalars.iter()) {
        proof_points.extend(vt.proof_dependent_points);
        proof_scalars.extend(
            vt.proof_dependent_scalars
                .into_iter()
                .map(|s| s * random_scalar),
        );
        for (acc, s) in fixed_scalars
            .iter_mut()
            .zip(vt.proof_independent_scalars.iter())
        {
            *acc += *s * random_scalar;
        }
    }

    (proof_points, proof_scalars, fixed_scalars, padded_n)
}

pub fn batch_verify<C: AffineRepr>(
    verification_tuples: Vec<VerificationTuple<C>>,
    pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>,
) -> Result<(), R1CSError> {
    let mut rng = rand::thread_rng();
    let mut ver_iter = verification_tuples.into_iter();
    let vt = ver_iter.next().unwrap();
    let (mut proof_points, mut proof_point_scalars, mut linear_combination) = (
        vt.proof_dependent_points,
        vt.proof_dependent_scalars,
        vt.proof_independent_scalars,
    );
    let padded_n = (linear_combination.len() - 2) / 2;

    for mut vt in ver_iter {
        proof_points.append(&mut vt.proof_dependent_points);

        // Sample random scalar
        let random_scalar = C::ScalarField::rand(&mut rng);

        // Multiply all scalars
        let ps = vt
            .proof_dependent_scalars
            .into_iter()
            .map(|s| s * random_scalar);
        let fps = vt
            .proof_independent_scalars
            .into_iter()
            .map(|s| s * random_scalar);

        proof_point_scalars.append(&mut ps.collect());
        linear_combination = linear_combination
            .iter()
            .zip(fps)
            .map(|(a, b)| *a + b)
            .collect()
    }

    // We are performing a single-party circuit proof, so party index is 0.
    let gens = bp_gens.share(0);

    if bp_gens.gens_capacity < padded_n {
        return Err(R1CSError::InvalidGeneratorsLength);
    }

    use std::iter;
    let fixed_points = iter::once(pc_gens.B)
        .chain(iter::once(pc_gens.B_blinding))
        .chain(gens.G(padded_n).copied())
        .chain(gens.H(padded_n).copied());

    let mega_check: C::Group = C::Group::msm_unchecked(
        proof_points
            .into_iter()
            .chain(fixed_points)
            .collect::<Vec<_>>()
            .as_slice(),
        proof_point_scalars
            .into_iter()
            .chain(linear_combination)
            .collect::<Vec<_>>()
            .as_slice(),
    );

    if !mega_check.is_zero() {
        return Err(R1CSError::VerificationError);
    }

    Ok(())
}

/// Parallelized batch verification using rayon for concurrent scalar multiplications.
///
/// This function performs the same verification as `batch_verify` but parallelizes
/// the scalar multiplication operations across verification tuples using rayon.
pub fn batch_verify_parallel<C>(
    verification_tuples: Vec<VerificationTuple<C>>,
    pc_gens: &PedersenGens<C>,
    bp_gens: &BulletproofGens<C>,
) -> Result<(), R1CSError>
where
    C: AffineRepr + Send + Sync,
    C::ScalarField: Send + Sync,
{
    use rayon::prelude::*;

    if verification_tuples.is_empty() {
        return Err(R1CSError::VerificationError);
    }

    let mut rng = rand::thread_rng();

    // Pre-generate random scalars for all tuples (except the first one which doesn't need scaling)
    let random_scalars: Vec<C::ScalarField> = (0..verification_tuples.len() - 1)
        .map(|_| C::ScalarField::rand(&mut rng))
        .collect();

    // Extract the first tuple to initialize accumulators
    let mut ver_iter = verification_tuples.into_iter();
    let first_vt = ver_iter.next().unwrap();
    let padded_n = (first_vt.proof_independent_scalars.len() - 2) / 2;

    // Collect remaining tuples
    let remaining_tuples: Vec<_> = ver_iter.collect();

    // Process all remaining tuples in parallel
    let processed_tuples: Vec<_> = remaining_tuples
        .into_par_iter()
        .zip(random_scalars.par_iter())
        .map(|(vt, &random_scalar)| {
            // Multiply all scalars by the random scalar in parallel
            let scaled_proof_scalars: Vec<_> = vt
                .proof_dependent_scalars
                .par_iter()
                .map(|s| *s * random_scalar)
                .collect();

            let scaled_independent_scalars: Vec<_> = vt
                .proof_independent_scalars
                .par_iter()
                .map(|s| *s * random_scalar)
                .collect();

            (
                vt.proof_dependent_points,
                scaled_proof_scalars,
                scaled_independent_scalars,
            )
        })
        .collect();

    // Sequential aggregation phase (this is cheap - just collecting vectors)
    let mut proof_points = first_vt.proof_dependent_points;
    let mut proof_point_scalars = first_vt.proof_dependent_scalars;
    let mut linear_combination = first_vt.proof_independent_scalars;

    for (mut points, mut scalars, independent_scalars) in processed_tuples {
        proof_points.append(&mut points);
        proof_point_scalars.append(&mut scalars);

        // Add to linear combination
        linear_combination = linear_combination
            .par_iter()
            .zip(independent_scalars.par_iter())
            .map(|(a, b)| *a + *b)
            .collect();
    }

    // We are performing a single-party circuit proof, so party index is 0.
    let gens = bp_gens.share(0);

    if bp_gens.gens_capacity < padded_n {
        return Err(R1CSError::InvalidGeneratorsLength);
    }

    use std::iter;
    let fixed_points = iter::once(pc_gens.B)
        .chain(iter::once(pc_gens.B_blinding))
        .chain(gens.G(padded_n).copied())
        .chain(gens.H(padded_n).copied());

    let mega_check: C::Group = C::Group::msm_unchecked(
        proof_points
            .into_iter()
            .chain(fixed_points)
            .collect::<Vec<_>>()
            .as_slice(),
        proof_point_scalars
            .into_iter()
            .chain(linear_combination)
            .collect::<Vec<_>>()
            .as_slice(),
    );

    if !mega_check.is_zero() {
        return Err(R1CSError::VerificationError);
    }

    Ok(())
}
