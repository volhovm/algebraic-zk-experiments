//! Direct flattened constraint computation without building LinearCombination objects.
//!
//! Replaces VerifierCS + re_randomize + flattened_constraints with a single-pass
//! computation that directly accumulates z^k * coeff into wL/wR/wO/wc arrays.

#![allow(non_snake_case, clippy::too_many_arguments)]

use bls12_381::Scalar;

pub const WINDOW_ELEMS: usize = 8; // 1 << 3

/// 3-bit lookup table with N rows of 8 elements each.
#[derive(Copy, Clone, Debug)]
pub struct Lookup3Bit<const N: usize> {
    pub elems: [[Scalar; WINDOW_ELEMS]; N],
}

/// Which side of a multiplier slot a variable occupies.
#[derive(Copy, Clone, Debug)]
pub enum SimpleVar {
    Left(usize),
    Right(usize),
}

/// Reference to a point coordinate's linear combination.
/// Either a simple variable or a lookup result (5-term expression).
#[derive(Copy, Clone, Debug)]
enum CoordRef<'a> {
    Simple(SimpleVar),
    Lookup {
        base_var: usize,
        row: usize,
        table: &'a Lookup3Bit<2>,
    },
}

/// Accumulates flattened constraint terms directly into wL/wR/wO/wc arrays.
struct DirectFlattener<'a> {
    wL: &'a mut [Scalar],
    wR: &'a mut [Scalar],
    wO: &'a mut [Scalar],
    wc: &'a mut Scalar,
    z_power: Scalar,
    z: Scalar,
    num_vars: usize,
    pending: Option<usize>,
}

impl<'a> DirectFlattener<'a> {
    // --- Emit helpers ---

    #[inline(always)]
    fn emit_l(&mut self, idx: usize, coeff: Scalar) {
        self.wL[idx] += self.z_power * coeff;
    }

    #[inline(always)]
    fn emit_r(&mut self, idx: usize, coeff: Scalar) {
        self.wR[idx] += self.z_power * coeff;
    }

    #[inline(always)]
    fn emit_o(&mut self, idx: usize, coeff: Scalar) {
        self.wO[idx] += self.z_power * coeff;
    }

    /// Emit a Variable::One term. Convention: wc -= z_power * coeff.
    #[inline(always)]
    fn emit_c(&mut self, coeff: Scalar) {
        *self.wc -= self.z_power * coeff;
    }

    #[inline(always)]
    fn emit_simple(&mut self, var: SimpleVar, coeff: Scalar) {
        match var {
            SimpleVar::Left(i) => self.emit_l(i, coeff),
            SimpleVar::Right(i) => self.emit_r(i, coeff),
        }
    }

    /// Advance to the next constraint (multiply z_power by z).
    #[inline(always)]
    fn advance(&mut self) {
        self.z_power *= self.z;
    }

    // --- Allocation helpers ---

    /// Allocate a multiplier triple (like VerifierCS::allocate_multiplier).
    fn alloc_mult(&mut self) -> usize {
        let v = self.num_vars;
        self.num_vars += 1;
        v
    }

    /// Allocate a single variable (like VerifierCS::allocate).
    /// Pairs consecutive calls into multiplier slots.
    fn allocate(&mut self) -> SimpleVar {
        match self.pending {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending = Some(i);
                SimpleVar::Left(i)
            }
            Some(i) => {
                self.pending = None;
                SimpleVar::Right(i)
            }
        }
    }

    // --- Expression emission ---

    /// Emit the f_right expression terms for single_membership.
    ///
    /// f_right(sa, s1, s2, u) where sa=MO(lb), s1=ML(lb), s2=MR(lb):
    ///   MO(lb): -u[0] + u[2] + u[4] - u[6]
    ///   MR(lb): u[0] - u[4]
    ///   ML(lb): u[0] - u[2]
    ///   One:    -u[0]
    fn emit_f_right(&mut self, lb: usize, u: &[Scalar; 8], sign: Scalar) {
        self.emit_o(lb, sign * (-u[0] + u[2] + u[4] - u[6]));
        self.emit_r(lb, sign * (u[0] - u[4]));
        self.emit_l(lb, sign * (u[0] - u[2]));
        self.emit_c(sign * (-u[0]));
    }

    /// Emit the f_full expression terms for single_membership (right arg of multiply).
    ///
    /// f_full = f_right + f_left_extra, where:
    ///   MO(lb): -u[0]+u[2]+u[4]-u[6] + u[1]-u[3]-u[5]+u[7]
    ///   MR(lb): u[0]-u[4] - u[1]+u[5]
    ///   ML(lb): u[0]-u[2] - u[1]+u[3]
    ///   One:    -u[0] + u[1]
    fn emit_f_full(&mut self, lb: usize, u: &[Scalar; 8], sign: Scalar) {
        self.emit_o(
            lb,
            sign * (-u[0] + u[2] + u[4] - u[6] + u[1] - u[3] - u[5] + u[7]),
        );
        self.emit_r(lb, sign * (u[0] - u[4] - u[1] + u[5]));
        self.emit_l(lb, sign * (u[0] - u[2] - u[1] + u[3]));
        self.emit_c(sign * (-u[0] + u[1]));
    }

    /// Emit the lookup result terms: MO(sm_var) - f_right.
    ///
    /// The single_membership result for row r is:
    ///   MO(lb+4+r): +1
    ///   MO(lb): u[0]-u[2]-u[4]+u[6]  (negated f_right)
    ///   MR(lb): -u[0]+u[4]
    ///   ML(lb): -u[0]+u[2]
    ///   One:    u[0]
    fn emit_lookup_result(&mut self, lb: usize, row: usize, table: &Lookup3Bit<2>, sign: Scalar) {
        let u = &table.elems[row];
        let sm_var = lb + 4 + row;
        self.emit_o(sm_var, sign);
        // -f_right with sign → emit_f_right with -sign
        self.emit_f_right(lb, u, -sign);
    }

    /// Emit terms from a CoordRef with given sign multiplier.
    fn emit_coord(&mut self, coord: &CoordRef, sign: Scalar) {
        match coord {
            CoordRef::Simple(v) => self.emit_simple(*v, sign),
            CoordRef::Lookup {
                base_var,
                row,
                table,
            } => {
                self.emit_lookup_result(*base_var, *row, table, sign);
            }
        }
    }

    // --- Gadget constraint emission ---

    /// Emit the 12 constraints from one lookup() call.
    /// Returns the base_var (the first allocate_multiplier's index).
    fn flatten_lookup(&mut self, table: &Lookup3Bit<2>) -> usize {
        let one = Scalar::one();
        let neg = -one;

        // allocate_multiplier for (b1=ML(lb), b2=MR(lb), ba=MO(lb))
        let lb = self.alloc_mult();
        // bit(): allocate_multiplier for (bit=ML(bv), bit_inv=MR(bv), zero=MO(bv))
        let bv = self.alloc_mult();

        // C0: bit_inv - bit + 1 = 0
        //     (MR(bv), 1), (ML(bv), -1), (One, 1)
        self.emit_r(bv, one);
        self.emit_l(bv, neg);
        self.emit_c(one);
        self.advance();

        // C1: MO(bv) = 0  [zero product]
        self.emit_o(bv, one);
        self.advance();

        // is_bit(b1 = ML(lb)):
        //   multiply(b1, b1-1) → var ib1
        let ib1 = self.alloc_mult();

        // C2: ML(lb) - ML(ib1) = 0  [left of multiply]
        self.emit_l(lb, one);
        self.emit_l(ib1, neg);
        self.advance();

        // C3: ML(lb) - 1 - MR(ib1) = 0  [right of multiply]
        self.emit_l(lb, one);
        self.emit_c(neg);
        self.emit_r(ib1, neg);
        self.advance();

        // C4: MO(ib1) = 0
        self.emit_o(ib1, one);
        self.advance();

        // is_bit(b2 = MR(lb)):
        //   multiply(b2, b2-1) → var ib2
        let ib2 = self.alloc_mult();

        // C5: MR(lb) - ML(ib2) = 0
        self.emit_r(lb, one);
        self.emit_l(ib2, neg);
        self.advance();

        // C6: MR(lb) - 1 - MR(ib2) = 0
        self.emit_r(lb, one);
        self.emit_c(neg);
        self.emit_r(ib2, neg);
        self.advance();

        // C7: MO(ib2) = 0
        self.emit_o(ib2, one);
        self.advance();

        // single_membership for each row (C8-C11):
        //   multiply(s0=ML(bv), f_full_row) → var sm_row
        for row in 0..2 {
            let sm = self.alloc_mult();

            // ML(bv) - ML(sm) = 0  [left of multiply]
            self.emit_l(bv, one);
            self.emit_l(sm, neg);
            self.advance();

            // f_full_row - MR(sm) = 0  [right of multiply]
            self.emit_f_full(lb, &table.elems[row], one);
            self.emit_r(sm, neg);
            self.advance();
        }

        lb
    }

    /// Emit the 9 constraints from incomplete_curve_addition.
    ///
    /// Constraints:
    /// 1. multiply(delta, x_r - x_l): 2 constraints
    /// 2. constrain(MO(mv1) - (y_r - y_l)): 1 constraint
    /// 3. multiply(delta, x_o - x_l): 2 constraints
    /// 4. constrain(MO(mv2) + y_o + y_l): 1 constraint
    /// 5. multiply(delta, delta): 2 constraints
    /// 6. constrain(x_o + x_r + x_l - MO(mv3)): 1 constraint
    fn flatten_incomplete_curve_add(
        &mut self,
        x_l: &CoordRef,
        y_l: &CoordRef,
        x_r: &CoordRef,
        y_r: &CoordRef,
        x_o: &CoordRef,
        y_o: &CoordRef,
    ) {
        let one = Scalar::one();
        let neg = -one;

        let delta = self.allocate();

        // multiply(delta, x_r - x_l) → mv1
        let mv1 = self.alloc_mult();

        // C_left: delta - ML(mv1) = 0
        self.emit_simple(delta, one);
        self.emit_l(mv1, neg);
        self.advance();

        // C_right: (x_r - x_l) - MR(mv1) = 0
        self.emit_coord(x_r, one);
        self.emit_coord(x_l, neg);
        self.emit_r(mv1, neg);
        self.advance();

        // constrain: MO(mv1) - (y_r - y_l) = 0
        //          = MO(mv1) - y_r + y_l = 0
        self.emit_o(mv1, one);
        self.emit_coord(y_r, neg);
        self.emit_coord(y_l, one);
        self.advance();

        // multiply(delta, x_o - x_l) → mv2
        let mv2 = self.alloc_mult();

        // C_left: delta - ML(mv2) = 0
        self.emit_simple(delta, one);
        self.emit_l(mv2, neg);
        self.advance();

        // C_right: (x_o - x_l) - MR(mv2) = 0
        self.emit_coord(x_o, one);
        self.emit_coord(x_l, neg);
        self.emit_r(mv2, neg);
        self.advance();

        // constrain: MO(mv2) - (-y_o - y_l) = 0
        //          = MO(mv2) + y_o + y_l = 0
        self.emit_o(mv2, one);
        self.emit_coord(y_o, one);
        self.emit_coord(y_l, one);
        self.advance();

        // multiply(delta, delta) → mv3
        let mv3 = self.alloc_mult();

        // C_left: delta - ML(mv3) = 0
        self.emit_simple(delta, one);
        self.emit_l(mv3, neg);
        self.advance();

        // C_right: delta - MR(mv3) = 0
        self.emit_simple(delta, one);
        self.emit_r(mv3, neg);
        self.advance();

        // constrain: x_o + x_r + x_l - MO(mv3) = 0
        self.emit_coord(x_o, one);
        self.emit_coord(x_r, one);
        self.emit_coord(x_l, one);
        self.emit_o(mv3, neg);
        self.advance();
    }

    /// Emit the 12 constraints from checked_curve_addition.
    ///
    /// = not_zero(x_l - x_r) (3 constraints) + incomplete_curve_addition (9 constraints)
    fn flatten_checked_curve_add(
        &mut self,
        x_l: &CoordRef,
        y_l: &CoordRef,
        x_r: &CoordRef,
        y_r: &CoordRef,
        x_o: &CoordRef,
        y_o: &CoordRef,
    ) {
        let one = Scalar::one();
        let neg = -one;

        // x_l_minus_x_r_inv = allocate()
        let x_inv = self.allocate();

        // not_zero(x_l - x_r, x_inv):
        //   multiply(x_l - x_r, x_inv) → nz_var
        let nz_var = self.alloc_mult();

        // C_left: (x_l - x_r) - ML(nz_var) = 0
        self.emit_coord(x_l, one);
        self.emit_coord(x_r, neg);
        self.emit_l(nz_var, neg);
        self.advance();

        // C_right: x_inv - MR(nz_var) = 0
        self.emit_simple(x_inv, one);
        self.emit_r(nz_var, neg);
        self.advance();

        // constrain: MO(nz_var) - 1 = 0
        self.emit_o(nz_var, one);
        self.emit_c(neg);
        self.advance();

        // Then incomplete_curve_addition
        self.flatten_incomplete_curve_add(x_l, y_l, x_r, y_r, x_o, y_o);
    }

    /// Emit all constraints for one re_randomize call.
    ///
    /// Parameters: variable indices for the commitment point (input/output).
    fn flatten_re_randomize(
        &mut self,
        tables: &[Lookup3Bit<2>],
        commit_x: SimpleVar,
        commit_y: SimpleVar,
        commit_x_tilde: SimpleVar,
        commit_y_tilde: SimpleVar,
    ) {
        let m = 85; // 252/3 + 1 = 85 windows

        let mut prev_acc_x = SimpleVar::Left(0); // placeholder, set after i=1
        let mut prev_acc_y = SimpleVar::Left(0);

        for i in 1..=m {
            let table = &tables[i - 1];

            // Lookup
            let lb = self.flatten_lookup(table);

            // Allocate accumulator variables
            let acc_x = self.allocate();
            let acc_y = self.allocate();

            if i > 1 {
                let x_l = CoordRef::Simple(prev_acc_x);
                let y_l = CoordRef::Simple(prev_acc_y);
                let x_r = CoordRef::Lookup {
                    base_var: lb,
                    row: 0,
                    table,
                };
                let y_r = CoordRef::Lookup {
                    base_var: lb,
                    row: 1,
                    table,
                };
                let x_o = CoordRef::Simple(acc_x);
                let y_o = CoordRef::Simple(acc_y);

                if i == m {
                    self.flatten_checked_curve_add(&x_l, &y_l, &x_r, &y_r, &x_o, &y_o);
                } else {
                    self.flatten_incomplete_curve_add(&x_l, &y_l, &x_r, &y_r, &x_o, &y_o);
                }
            }

            prev_acc_x = acc_x;
            prev_acc_y = acc_y;
        }

        // Final checked_curve_addition: commitment + R_m = commitment_tilde
        let x_l = CoordRef::Simple(commit_x);
        let y_l = CoordRef::Simple(commit_y);
        let x_r = CoordRef::Simple(prev_acc_x);
        let y_r = CoordRef::Simple(prev_acc_y);
        let x_o = CoordRef::Simple(commit_x_tilde);
        let y_o = CoordRef::Simple(commit_y_tilde);

        self.flatten_checked_curve_add(&x_l, &y_l, &x_r, &y_r, &x_o, &y_o);
    }
}

/// Directly compute flattened constraints (wL, wR, wO, wc) without
/// building LinearCombination objects.
///
/// Replicates the exact constraint structure of:
/// 1. Four allocate() calls for commitment #1
/// 2. re_randomize #1
/// 3. Four allocate() calls for commitment #2
/// 4. re_randomize #2
/// 5. Padding (no-op for this circuit)
///
/// Returns (wL, wR, wO, wc) and the total number of variables (n).
pub fn compute_flattened_direct(
    z: &Scalar,
    tables: &[Lookup3Bit<2>],
) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar, usize) {
    // Allocate generously; we'll truncate to actual num_vars at the end.
    let max_n = 2048;
    let mut wL = vec![Scalar::zero(); max_n];
    let mut wR = vec![Scalar::zero(); max_n];
    let mut wO = vec![Scalar::zero(); max_n];
    let mut wc = Scalar::zero();

    let mut f = DirectFlattener {
        wL: &mut wL,
        wR: &mut wR,
        wO: &mut wO,
        wc: &mut wc,
        z_power: *z, // z^1 for constraint 0
        z: *z,
        num_vars: 0,
        pending: None,
    };

    // First commitment: 4 allocate() → 2 multiplier slots
    let c1_x = f.allocate(); // ML(0)
    let c1_y = f.allocate(); // MR(0)
    let c1_x_tilde = f.allocate(); // ML(1)
    let c1_y_tilde = f.allocate(); // MR(1)

    // First re_randomize
    f.flatten_re_randomize(tables, c1_x, c1_y, c1_x_tilde, c1_y_tilde);

    // Second commitment: 4 allocate() → depends on pending state
    let c2_x = f.allocate();
    let c2_y = f.allocate();
    let c2_x_tilde = f.allocate();
    let c2_y_tilde = f.allocate();

    // Second re_randomize
    f.flatten_re_randomize(tables, c2_x, c2_y, c2_x_tilde, c2_y_tilde);

    let n = f.num_vars;

    // Truncate to actual size
    wL.truncate(n);
    wR.truncate(n);
    wO.truncate(n);

    (wL, wR, wO, wc, n)
}
