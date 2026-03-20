//! Minimal constraint system reimplementation for the SP1 guest.
//!
//! This mirrors the verifier's constraint system from zkbrownian's bulletproofs
//! but only tracks the constraint structure (variables and linear combinations).
//! No group operations are performed — only bookkeeping to compute
//! `flattened_constraints(z)`.

use bls12_381::Scalar;

/// Variable types matching zkbrownian's Variable enum.
#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub enum Variable {
    VectorCommit(usize, usize),
    Committed(usize),
    MultiplierLeft(usize),
    MultiplierRight(usize),
    MultiplierOutput(usize),
    One,
}

/// A linear combination of variables with scalar coefficients.
#[derive(Clone, Debug, Default)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, Scalar)>,
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> Self {
        LinearCombination {
            terms: vec![(v, Scalar::one())],
        }
    }
}

impl From<Scalar> for LinearCombination {
    fn from(c: Scalar) -> Self {
        LinearCombination {
            terms: vec![(Variable::One, c)],
        }
    }
}

impl LinearCombination {
    #[allow(dead_code)]
    pub fn scalar_mul(self, scalar: Scalar) -> Self {
        LinearCombination {
            terms: self
                .terms
                .into_iter()
                .map(|(var, coeff)| (var, coeff * scalar))
                .collect(),
        }
    }
}

impl std::ops::Add for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.terms.extend(rhs.terms);
        self
    }
}

impl std::ops::Add<Variable> for LinearCombination {
    type Output = Self;
    fn add(self, rhs: Variable) -> Self {
        self + LinearCombination::from(rhs)
    }
}

impl std::ops::Sub for LinearCombination {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        self.terms
            .extend(rhs.terms.into_iter().map(|(v, c)| (v, -c)));
        self
    }
}

impl std::ops::Sub<Variable> for LinearCombination {
    type Output = Self;
    fn sub(self, rhs: Variable) -> Self {
        self - LinearCombination::from(rhs)
    }
}

impl std::ops::Sub<Scalar> for LinearCombination {
    type Output = Self;
    fn sub(self, rhs: Scalar) -> Self {
        self - LinearCombination::from(rhs)
    }
}

impl std::ops::Add<Scalar> for LinearCombination {
    type Output = Self;
    fn add(self, rhs: Scalar) -> Self {
        self + LinearCombination::from(rhs)
    }
}

impl std::ops::Neg for LinearCombination {
    type Output = Self;
    fn neg(mut self) -> Self {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s;
        }
        self
    }
}

impl std::ops::Mul<Scalar> for LinearCombination {
    type Output = Self;
    fn mul(mut self, rhs: Scalar) -> Self {
        for (_, s) in self.terms.iter_mut() {
            *s *= rhs;
        }
        self
    }
}

/// Minimal verifier constraint system.
/// Mirrors the structure of zkbrownian's Verifier but without transcript or group ops.
#[derive(Default)]
pub struct VerifierCS {
    pub constraints: Vec<LinearCombination>,
    pub num_vars: usize,
    pub num_committed: usize,
    pub vec_comms: Vec<usize>, // just dimensions
    pending_multiplier: Option<usize>,
}

impl VerifierCS {
    pub fn new() -> Self {
        VerifierCS {
            constraints: Vec::new(),
            num_vars: 0,
            num_committed: 0,
            vec_comms: Vec::new(),
            pending_multiplier: None,
        }
    }

    pub fn size(&self) -> usize {
        let mut n = self.num_vars;
        for dim in &self.vec_comms {
            n = std::cmp::max(*dim, n);
        }
        n
    }

    /// Allocate and constrain a multiplication gate: left * right = out.
    /// Returns (left_var, right_var, out_var).
    pub fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let var = self.num_vars;
        self.num_vars += 1;

        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        left.terms.push((l_var, -Scalar::one()));
        right.terms.push((r_var, -Scalar::one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    /// Allocate a single variable (pairs up into multiplier slots).
    pub fn allocate(&mut self) -> Variable {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Variable::MultiplierLeft(i)
            }
            Some(i) => {
                self.pending_multiplier = None;
                Variable::MultiplierRight(i)
            }
        }
    }

    /// Allocate a committed (high-level) variable.
    #[allow(dead_code)]
    pub fn allocate_committed(&mut self, value: Option<Scalar>) -> Variable {
        let _ = value; // verifier ignores values
        let i = self.num_committed;
        self.num_committed += 1;
        Variable::Committed(i)
    }

    /// Allocate a full multiplier triple.
    pub fn allocate_multiplier(&mut self) -> (Variable, Variable, Variable) {
        let var = self.num_vars;
        self.num_vars += 1;
        (
            Variable::MultiplierLeft(var),
            Variable::MultiplierRight(var),
            Variable::MultiplierOutput(var),
        )
    }

    /// Add a constraint: lc = 0.
    pub fn constrain(&mut self, lc: LinearCombination) {
        self.constraints.push(lc);
    }

    /// Clear pending multiplier (called between phases).
    pub fn clear_pending(&mut self) {
        self.pending_multiplier = None;
    }

    /// Flatten constraints at challenge point z.
    /// Returns (wL, wR, wO, wV, wVCs, wc) matching zkbrownian's verifier.
    #[allow(non_snake_case, clippy::type_complexity)]
    pub fn flattened_constraints(
        &self,
        z: &Scalar,
    ) -> (
        Vec<Scalar>,
        Vec<Scalar>,
        Vec<Scalar>,
        Vec<Scalar>,
        Vec<Vec<Scalar>>,
        Scalar,
    ) {
        let n = self.num_vars;
        let m = self.num_committed;

        let mut wL = vec![Scalar::zero(); n];
        let mut wR = vec![Scalar::zero(); n];
        let mut wO = vec![Scalar::zero(); n];
        let mut wV = vec![Scalar::zero(); m];
        let mut wc = Scalar::zero();

        let mut wVCs: Vec<Vec<Scalar>> = self
            .vec_comms
            .iter()
            .map(|dim| vec![Scalar::zero(); *dim])
            .collect();

        let mut exp_z = *z;
        for lc in &self.constraints {
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
                        wVCs[*j][*i] += exp_z * coeff;
                    }
                    Variable::One => {
                        wc -= exp_z * coeff;
                    }
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV, wVCs, wc)
    }
}
