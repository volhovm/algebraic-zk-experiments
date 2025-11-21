//! Generator pre-generation for cryptographic operations
//!
//! Pre-generates random generators G_i (in G1) and H_i (in G2)
//! as required by the protocol specification

use crate::types::{G1Point, G2Point};
use ark_ec::{CurveGroup, Group};
use ark_bls12_381::{G1Projective, G2Projective};
use ark_std::UniformRand;
use rand::Rng;

/// Generate N random generators in G1
pub fn generate_g1_generators<R: Rng>(rng: &mut R, count: usize) -> Vec<G1Point> {
    (0..count)
        .map(|_| G1Projective::rand(rng).into_affine())
        .collect()
}

/// Generate N random generators in G2
pub fn generate_g2_generators<R: Rng>(rng: &mut R, count: usize) -> Vec<G2Point> {
    (0..count)
        .map(|_| G2Projective::rand(rng).into_affine())
        .collect()
}

/// Standard generators
pub struct Generators {
    /// Base generator for G1 (standard curve generator)
    pub g1_base: G1Point,
    /// Base generator for G2 (standard curve generator)
    pub g2_base: G2Point,
    /// Additional G1 generators: G_1, G_2, G_3, ...
    pub g1_generators: Vec<G1Point>,
    /// Additional G2 generators: H, H_1, H_2, ...
    pub g2_generators: Vec<G2Point>,
}

impl Generators {
    /// Generate standard generators for the protocol
    ///
    /// # Arguments
    /// * `num_g1` - Number of additional G1 generators needed
    /// * `num_g2` - Number of additional G2 generators needed
    pub fn generate<R: Rng>(rng: &mut R, num_g1: usize, num_g2: usize) -> Self {
        Self {
            g1_base: G1Projective::generator().into_affine(),
            g2_base: G2Projective::generator().into_affine(),
            g1_generators: generate_g1_generators(rng, num_g1),
            g2_generators: generate_g2_generators(rng, num_g2),
        }
    }

    /// Get a specific G1 generator by index
    pub fn g1(&self, index: usize) -> Option<&G1Point> {
        if index == 0 {
            Some(&self.g1_base)
        } else {
            self.g1_generators.get(index - 1)
        }
    }

    /// Get a specific G2 generator by index
    pub fn g2(&self, index: usize) -> Option<&G2Point> {
        if index == 0 {
            Some(&self.g2_base)
        } else {
            self.g2_generators.get(index - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_generate_g1_generators() {
        let mut rng = thread_rng();
        let gens = generate_g1_generators(&mut rng, 5);
        assert_eq!(gens.len(), 5);

        // Check they're all different
        for i in 0..gens.len() {
            for j in (i + 1)..gens.len() {
                assert_ne!(gens[i], gens[j]);
            }
        }
    }

    #[test]
    fn test_generate_g2_generators() {
        let mut rng = thread_rng();
        let gens = generate_g2_generators(&mut rng, 5);
        assert_eq!(gens.len(), 5);

        // Check they're all different
        for i in 0..gens.len() {
            for j in (i + 1)..gens.len() {
                assert_ne!(gens[i], gens[j]);
            }
        }
    }

    #[test]
    fn test_generators_struct() {
        let mut rng = thread_rng();
        let generators = Generators::generate(&mut rng, 10, 10);

        // Check base generators
        assert_eq!(generators.g1_base, G1Projective::generator().into_affine());
        assert_eq!(generators.g2_base, G2Projective::generator().into_affine());

        // Check indexing
        assert_eq!(generators.g1(0).unwrap(), &generators.g1_base);
        assert_eq!(generators.g2(0).unwrap(), &generators.g2_base);

        assert!(generators.g1(1).is_some());
        assert!(generators.g2(1).is_some());
    }
}
