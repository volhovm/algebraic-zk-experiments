//! Type aliases and scalar conversion utilities for bls12_381::Scalar.

use bls12_381::Scalar;

/// Convert 32 bytes (little-endian) to a Scalar.
/// The bytes must represent a valid field element.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    // bls12_381::Scalar::from_bytes expects little-endian 32-byte encoding
    let opt = Scalar::from_bytes(bytes);
    if bool::from(opt.is_some()) {
        opt.unwrap()
    } else {
        panic!("Invalid scalar bytes");
    }
}

/// Convert a Scalar to 32 bytes (little-endian).
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// Compute the inner product of two scalar vectors.
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "inner_product: length mismatch");
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

/// Iterator that yields successive powers of a scalar: 1, x, x^2, x^3, ...
pub struct ScalarExp {
    x: Scalar,
    next: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        let current = self.next;
        self.next *= self.x;
        Some(current)
    }
}

/// Return an iterator of powers of `x`: 1, x, x^2, ...
pub fn exp_iter(x: Scalar) -> ScalarExp {
    ScalarExp {
        x,
        next: Scalar::one(),
    }
}

/// Compute the inverse of a scalar (panics if zero).
pub fn scalar_inverse(s: &Scalar) -> Scalar {
    let inv = s.invert();
    if bool::from(inv.is_some()) {
        inv.unwrap()
    } else {
        panic!("Cannot invert zero scalar");
    }
}
