//! Re-randomization constraint gadget, reimplemented for bls12_381::Scalar.
//! Mirrors zkbrownian's src/proving/relations/rerandomize.rs (verifier side).
//!
//! The verifier doesn't know the randomness, so all witnesses are None.
//! We only build the constraint structure.

use crate::constraint_system::{LinearCombination, Variable, VerifierCS};
use crate::relations::curve::{checked_curve_addition, incomplete_curve_addition, CurveAddition};
use crate::relations::lookup::{lookup, Lookup3Bit};

/// JubjubConfig ScalarField MODULUS_BIT_SIZE = 252
/// But we need the BLS12-381 scalar field's modulus bit size for the tables,
/// which is what the JubjubConfig::ScalarField has (252 bits).
/// Actually the scalar field of Jubjub (ed on bls12-381) is 252 bits.
const JUBJUB_SCALAR_MODULUS_BITS: usize = 252;

/// Re-randomize constraint gadget (verifier side).
///
/// Builds the same constraints as zkbrownian's `re_randomize` function
/// when called with `randomness = None` (verifier mode).
///
/// # Parameters
/// - `cs`: the constraint system
/// - `tables`: lookup tables for windowed scalar multiplication
/// - `commitment_x`: LC for the input point's x-coordinate
/// - `commitment_y`: LC for the input point's y-coordinate
/// - `commitment_x_tilde`: LC for the output point's x-coordinate
/// - `commitment_y_tilde`: LC for the output point's y-coordinate
pub fn re_randomize(
    cs: &mut VerifierCS,
    tables: &[Lookup3Bit<2>],
    commitment_x: LinearCombination,
    commitment_y: LinearCombination,
    commitment_x_tilde: LinearCombination,
    commitment_y_tilde: LinearCombination,
) {
    let lambda = JUBJUB_SCALAR_MODULUS_BITS;
    let m = lambda / 3 + 1;

    let mut acc_i_minus_1_x_lc: LinearCombination = LinearCombination::from(Variable::One);
    let mut acc_i_minus_1_y_lc: LinearCombination = LinearCombination::from(Variable::One);

    for i in 1..m + 1 {
        let table = &tables[i - 1];

        let [x_table, y_table] = lookup(cs, table);

        // Allocate accumulated coordinates
        let acc_i_x_var = cs.allocate();
        let acc_i_y_var = cs.allocate();
        let acc_i_x_lc = LinearCombination::from(acc_i_x_var);
        let acc_i_y_lc = LinearCombination::from(acc_i_y_var);

        if i > 1 {
            let prms = CurveAddition {
                x_l: acc_i_minus_1_x_lc.clone(),
                y_l: acc_i_minus_1_y_lc.clone(),
                x_r: x_table,
                y_r: y_table,
                x_o: acc_i_x_lc.clone(),
                y_o: acc_i_y_lc.clone(),
            };
            if i == m {
                // checked addition for the last window
                checked_curve_addition(cs, &prms);
            } else {
                // incomplete addition for intermediate windows
                incomplete_curve_addition(cs, &prms);
            }
        }

        acc_i_minus_1_x_lc = acc_i_x_lc;
        acc_i_minus_1_y_lc = acc_i_y_lc;
    }

    // Final addition: (commitment) + R_m = (commitment_tilde)
    let prms = CurveAddition {
        x_l: commitment_x,
        y_l: commitment_y,
        x_r: acc_i_minus_1_x_lc,
        y_r: acc_i_minus_1_y_lc,
        x_o: commitment_x_tilde,
        y_o: commitment_y_tilde,
    };
    checked_curve_addition(cs, &prms);
}
