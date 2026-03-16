//! In-field curve arithmetic constraints, reimplemented for bls12_381::Scalar.
//! Mirrors zkbrownian's src/proving/relations/curve.rs.

use crate::constraint_system::{LinearCombination, Variable, VerifierCS};

/// Parameters for curve point addition constraint.
pub struct CurveAddition {
    pub x_l: LinearCombination,
    pub y_l: LinearCombination,
    pub x_r: LinearCombination,
    pub y_r: LinearCombination,
    pub x_o: LinearCombination,
    pub y_o: LinearCombination,
}

/// Enforce incomplete curve addition: (x_o, y_o) = (x_l, y_l) + (x_r, y_r)
/// Allocates a delta (slope) variable. Verifier provides no witness.
pub fn incomplete_curve_addition(cs: &mut VerifierCS, prms: &CurveAddition) {
    let delta_var = cs.allocate();
    let delta_lc = LinearCombination::from(delta_var);

    // delta * (x_r - x_l) = y_r - y_l
    let (_, _, delta_x_r_x_l) = cs.multiply(delta_lc.clone(), prms.x_r.clone() - prms.x_l.clone());
    cs.constrain(LinearCombination::from(delta_x_r_x_l) - (prms.y_r.clone() - prms.y_l.clone()));

    // delta * (x_o - x_l) = -y_o - y_l
    let (_, _, delta_x_o_x_l) = cs.multiply(delta_lc.clone(), prms.x_o.clone() - prms.x_l.clone());
    cs.constrain(LinearCombination::from(delta_x_o_x_l) - (-prms.y_o.clone() - prms.y_l.clone()));

    // delta^2 = x_o + x_r + x_l
    let (_, _, delta2) = cs.multiply(delta_lc.clone(), delta_lc);
    cs.constrain(
        prms.x_o.clone() + prms.x_r.clone() + prms.x_l.clone() - LinearCombination::from(delta2),
    );
}

/// Enforce x_l != x_r (via inverse witness) then do incomplete curve addition.
pub fn checked_curve_addition(cs: &mut VerifierCS, prms: &CurveAddition) {
    let x_l_minus_x_r_inv_var = cs.allocate();
    let x_l_minus_x_r_inv_lc = LinearCombination::from(x_l_minus_x_r_inv_var);
    // not_zero: v * v_inv = 1
    not_zero(
        cs,
        prms.x_l.clone() - prms.x_r.clone(),
        x_l_minus_x_r_inv_lc,
    );
    incomplete_curve_addition(cs, prms);
}

/// Enforce v != 0: v * v_inv = 1.
fn not_zero(cs: &mut VerifierCS, v: LinearCombination, v_inv: LinearCombination) {
    let (_, _, one) = cs.multiply(v, v_inv);
    cs.constrain(LinearCombination::from(one) - LinearCombination::from(Variable::One));
}
