//! 3-bit lookup table gadget, reimplemented for bls12_381::Scalar.
//! Mirrors zkbrownian's src/proving/relations/lookup.rs.

use bls12_381::Scalar;

use crate::constraint_system::{LinearCombination, Variable, VerifierCS};

pub const WINDOW_SIZE: usize = 3;
pub const WINDOW_ELEMS: usize = 1 << WINDOW_SIZE;

/// 3-bit lookup table with N rows of 8 elements each.
#[derive(Copy, Clone, Debug)]
pub struct Lookup3Bit<const N: usize> {
    pub elems: [[Scalar; WINDOW_ELEMS]; N],
}

pub fn is_bit(cs: &mut VerifierCS, var: LinearCombination) {
    let (_, _, zero) = cs.multiply(var.clone(), var - Scalar::one());
    cs.constrain(LinearCombination::from(zero));
}

fn bit(cs: &mut VerifierCS) -> Variable {
    // Verifier: allocate_multiplier with no assignment
    let (bit, bit_inv, zero) = cs.allocate_multiplier();

    // check bit_inv = bit - 1
    cs.constrain(LinearCombination::from(bit_inv) - (LinearCombination::from(bit) - Scalar::one()));

    // check product is zero
    cs.constrain(LinearCombination::from(zero));

    bit
}

fn single_membership(
    cs: &mut VerifierCS,
    u: &[Scalar; WINDOW_ELEMS],
    sa: LinearCombination,
    s0: LinearCombination,
    s1: LinearCombination,
    s2: LinearCombination,
) -> LinearCombination {
    // left side
    let (_, _, left) = cs.multiply(s0, {
        let f = -(sa.clone() * u[0]) + (s2.clone() * u[0]) + (s1.clone() * u[0]) - u[0]
            + (sa.clone() * u[2]);
        let f = f - (s1.clone() * u[2]) + (sa.clone() * u[4])
            - (s2.clone() * u[4])
            - (sa.clone() * u[6]);
        let f = f + (sa.clone() * u[1]) - (s2.clone() * u[1]) - (s1.clone() * u[1]) + u[1]
            - (sa.clone() * u[3]);
        f + (s1.clone() * u[3]) - (sa.clone() * u[5]) + (s2.clone() * u[5]) + (sa.clone() * u[7])
    });

    // right side
    let right = -(sa.clone() * u[0]) + (s2.clone() * u[0]) + (s1.clone() * u[0]) - u[0]
        + (sa.clone() * u[2]);
    let right = right - (s1 * u[2]) + (sa.clone() * u[4]) - (s2 * u[4]) - (sa * u[6]);

    // sum is the element
    LinearCombination::from(left) - right
}

/// Perform a 3-bit lookup (verifier side: no witness).
/// Returns N linear combinations representing the looked-up values.
pub fn lookup<const N: usize>(
    cs: &mut VerifierCS,
    table: &Lookup3Bit<N>,
) -> [LinearCombination; N] {
    // allocate multiplier for b1 * b2
    let (b1, b2, ba) = cs.allocate_multiplier();

    // allocate b0 as a bit
    let b0 = bit(cs);
    is_bit(cs, LinearCombination::from(b1));
    is_bit(cs, LinearCombination::from(b2));

    // enforce membership
    let mut res: Vec<LinearCombination> = Vec::with_capacity(N);
    for i in 0..N {
        res.push(single_membership(
            cs,
            &table.elems[i],
            LinearCombination::from(ba),
            LinearCombination::from(b0),
            LinearCombination::from(b1),
            LinearCombination::from(b2),
        ));
    }

    res.try_into()
        .unwrap_or_else(|_| panic!("Wrong number of lookup results"))
}
