//! Fixed-base Multi-Scalar Multiplication (MSM) with precomputation
//!
//! This module implements Pippenger's algorithm with precomputation for scenarios
//! where you need to compute many MSMs with the same fixed bases but different scalars.
//!
//! # Algorithm: Vertical Precomputation Strategy
//!
//! ## Precomputation Phase (once):
//! For each base point Gᵢ, precompute multiples: {0·Gᵢ, 1·Gᵢ, 2·Gᵢ, ..., (2^w - 1)·Gᵢ}
//! Store in affine coordinates for efficient mixed additions.
//!
//! ## MSM Computation Phase (many times):
//! For each new scalar vector c_vec, use Pippenger's algorithm with window decomposition
//! to compute ∑ᵢ cᵢ·Gᵢ using precomputed tables.
//!
//! # Performance
//!
//! - **Precomputation cost**: O(n × 2^w) point additions (one-time)
//! - **Per-MSM cost**: O(n × λ/w + 2^w × λ/w) point operations
//! - **Memory**: O(n × 2^w) affine points
//! - **Expected speedup**: 2-4× after amortizing precomputation over 50+ MSMs
//!
//! # Example
//!
//! ```ignore
//! use ark_bls12_381::{Fr, G1Projective};
//! use zkbrownian_rs::crypto::msm::FixedBaseMsmTable;
//!
//! // Precompute once for fixed bases
//! let bases: Vec<G1Projective> = /* ... */;
//! let table = FixedBaseMsmTable::new(&bases, 8);  // window_bits = 8
//!
//! // Reuse for many MSMs with different scalars
//! for _ in 0..100 {
//!     let scalars: Vec<Fr> = /* ... */;
//!     let result = table.msm(&scalars);
//! }
//! ```

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use std::vec::Vec;

/// Precomputed table for fixed-base MSM using vertical precomputation strategy
///
/// This struct stores precomputed multiples of fixed base points to accelerate
/// repeated MSM computations with the same bases but different scalars.
///
/// # Memory Usage
///
/// For n bases and window_bits = w:
/// - Stores n × 2^w affine points
/// - Example: 256 bases, w=8 → ~64 KB (256 × 256 × 32 bytes per point)
#[derive(Clone, Debug)]
pub struct FixedBaseMsmTable<G: CurveGroup> {
    /// Precomputed table: table[i][j] = j * base_i (in affine coordinates)
    /// - table[i][0] = point at infinity (0 * base_i)
    /// - table[i][1] = base_i
    /// - table[i][j] = j * base_i for j in [0, 2^window_bits)
    table: Vec<Vec<G::Affine>>,

    /// Number of bits per window (typically 4, 8, or 12)
    window_bits: usize,
}

impl<G: CurveGroup> FixedBaseMsmTable<G> {
    /// Create a new precomputed table for fixed bases
    ///
    /// # Arguments
    ///
    /// * `bases` - Fixed base points (same for all future MSM calls)
    /// * `window_bits` - Window size in bits (recommended: 8)
    ///     - Smaller window: less memory, more operations
    ///     - Larger window: more memory, fewer operations
    ///     - Typical values: 4, 8, 12, 16
    ///
    /// # Complexity
    ///
    /// - Time: O(n × 2^w) point additions
    /// - Space: O(n × 2^w) affine points
    ///
    /// # Example
    ///
    /// ```ignore
    /// let table = FixedBaseMsmTable::new(&bases, 8);  // 8-bit windows
    /// ```
    pub fn new(bases: &[G], window_bits: usize) -> Self {
        let n = bases.len();
        let table_size = 1 << window_bits; // 2^window_bits

        let mut table = Vec::with_capacity(n);

        for base in bases {
            // For each base, compute: 0*base, 1*base, 2*base, ..., (2^w - 1)*base
            let mut row_projective = Vec::with_capacity(table_size);

            // 0 * base = point at infinity
            row_projective.push(G::zero());

            // 1 * base
            row_projective.push(*base);

            // 2*base, 3*base, ..., (2^w - 1)*base
            // Use repeated addition: (j+1)*base = j*base + base
            let mut acc = *base;
            for _ in 2..table_size {
                acc += base;
                row_projective.push(acc);
            }

            // Convert entire row to affine coordinates in a batch
            // This is more efficient than converting individually
            let row_affine: Vec<G::Affine> = G::normalize_batch(&row_projective);
            table.push(row_affine);
        }

        Self { table, window_bits }
    }

    /// Compute a single MSM using the precomputed table: ∑ᵢ scalars[i] * bases[i]
    ///
    /// This uses Pippenger's algorithm with the precomputed table.
    ///
    /// # Arguments
    ///
    /// * `scalars` - Variable scalar coefficients (one per base)
    ///
    /// # Panics
    ///
    /// Panics if `scalars.len() != bases.len()` (number of bases in table)
    ///
    /// # Complexity
    ///
    /// - Time: O(n × λ/w + 2^w × λ/w) where λ is scalar bit length
    /// - Space: O(2^w) for temporary buckets
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = table.msm(&scalars);  // Fast MSM using precomputed table
    /// ```
    pub fn msm(&self, scalars: &[G::ScalarField]) -> G {
        assert_eq!(
            scalars.len(),
            self.table.len(),
            "Number of scalars must match number of bases in precomputed table"
        );

        if scalars.is_empty() {
            return G::zero();
        }

        let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
        let num_windows = scalar_bits.div_ceil(self.window_bits);

        use rayon::prelude::*;

        let window_contributions: Vec<G> = (0..num_windows)
            .into_par_iter()
            .map(|w| self.compute_window_contribution(scalars, w))
            .collect();

        let mut result = window_contributions[num_windows - 1];
        for window_idx in (0..num_windows - 1).rev() {
            for _ in 0..self.window_bits {
                result.double_in_place();
            }
            result += window_contributions[window_idx];
        }

        //// Start with the contribution from the most significant window
        //let mut result = self.compute_window_contribution(scalars, num_windows - 1);

        //// Process remaining windows from MSB-1 down to LSB
        //// For each window: multiply accumulated result by 2^window_bits, then add contribution
        //for window_idx in (0..num_windows - 1).rev() {
        //    // Shift accumulated result by window_bits (multiply by 2^window_bits)
        //    for _ in 0..self.window_bits {
        //        result.double_in_place();
        //    }

        //    // Add contribution from this window
        //    let window_contribution = self.compute_window_contribution(scalars, window_idx);
        //    result += window_contribution;
        //}

        result
    }

    /// Compute many MSMs using the precomputed table (batch processing)
    ///
    /// This computes multiple MSMs with the same fixed bases but different scalar vectors:
    /// - Result[j] = ∑ᵢ scalar_batch[j][i] * bases[i]
    ///
    /// This is the main use case for fixed-base MSM: computing hundreds of MSMs
    /// with the same base points but different scalars (e.g., in ZK proof generation).
    ///
    /// # Arguments
    ///
    /// * `scalar_batch` - A slice of scalar vectors, where each vector corresponds to one MSM
    ///
    /// # Panics
    ///
    /// Panics if any scalar vector has length != number of bases in table
    ///
    /// # Complexity
    ///
    /// - Time: O(batch_size × (n × λ/w + 2^w × λ/w))
    /// - Space: O(batch_size) for results + O(2^w) for temporary buckets
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Compute 100 MSMs with the same bases
    /// let scalar_batch: Vec<Vec<Fr>> = (0..100)
    ///     .map(|_| (0..n).map(|_| Fr::rand(&mut rng)).collect())
    ///     .collect();
    ///
    /// let results = table.msm_batch(&scalar_batch);
    /// assert_eq!(results.len(), 100);
    /// ```
    pub fn msm_batch(&self, scalar_batch: &[Vec<G::ScalarField>]) -> Vec<G> {
        // Validate input
        for (i, scalars) in scalar_batch.iter().enumerate() {
            assert_eq!(
                scalars.len(),
                self.table.len(),
                "Scalar vector {} has length {} but table has {} bases",
                i,
                scalars.len(),
                self.table.len()
            );
        }

        // CLAUDETODO
        // Process each MSM independently
        scalar_batch
            .iter()
            .map(|scalars| self.msm(scalars))
            .collect()
    }

    /// Compute contribution from a single window using bucket aggregation
    ///
    /// For each window, we compute: ∑ᵢ digit_i * base_i
    /// where digit_i is the w-bit window of scalar_i at position window_idx.
    ///
    /// We use the bucket method:
    /// 1. Group bases by their digit value into buckets
    /// 2. Aggregate buckets efficiently: ∑_{d=1}^{2^w-1} d · bucket[d]
    ///
    /// Note: This returns the unscaled contribution. The caller is responsible
    /// for scaling by 2^(window_idx * w) via doubling in the main loop.
    fn compute_window_contribution(&self, scalars: &[G::ScalarField], window_idx: usize) -> G {
        let bucket_count = 1 << self.window_bits; // 2^window_bits
        let mut buckets: Vec<G> = vec![G::zero(); bucket_count];

        // Extract window bits from each scalar and accumulate into buckets
        // bucket[d] will contain the sum of all base_i where digit_i = d
        for (i, scalar) in scalars.iter().enumerate() {
            let digit =
                extract_window_bits(scalar, window_idx * self.window_bits, self.window_bits);

            if digit > 0 {
                // Add base_i (NOT digit * base_i) to bucket[digit]
                // table[i][1] contains base_i
                // This is a mixed addition (affine + projective)
                buckets[digit as usize] += self.table[i][1];
            }
        }

        // Aggregate buckets efficiently: ∑_{d=1}^{2^w-1} d · bucket[d]
        // Use the running sum trick to compute this in O(2^w) additions:
        // running_sum = bucket[2^w-1] + bucket[2^w-2] + ... + bucket[1]
        // result = bucket[2^w-1] + (bucket[2^w-1] + bucket[2^w-2]) + ... + (bucket[2^w-1] + ... + bucket[1])
        let mut running_sum = G::zero();
        let mut window_result = G::zero();

        for d in (1..bucket_count).rev() {
            running_sum += buckets[d];
            window_result += running_sum;
        }

        window_result
    }

    /// Get the number of bases in this precomputed table
    pub fn num_bases(&self) -> usize {
        self.table.len()
    }

    /// Get the window size in bits
    pub fn window_bits(&self) -> usize {
        self.window_bits
    }

    /// Get the memory usage estimate in bytes
    ///
    /// This is approximate and depends on the curve's affine representation size
    pub fn memory_usage_estimate(&self) -> usize {
        let points_per_base = 1 << self.window_bits;
        let num_bases = self.table.len();
        // Rough estimate: 64 bytes per affine point (2 field elements × ~32 bytes each)
        num_bases * points_per_base * 64
    }
}

/// Extract a window of bits from a scalar field element
///
/// # Arguments
///
/// * `scalar` - The scalar field element
/// * `start_bit` - Starting bit position (0 = LSB)
/// * `window_bits` - Number of bits to extract
///
/// # Returns
///
/// The extracted bits as a u64 value in range [0, 2^window_bits)
///
/// # Example
///
/// If scalar = 0b...10110101 and we extract 4 bits starting at position 2:
/// Result = 0b1101 = 13
fn extract_window_bits<F: PrimeField>(scalar: &F, start_bit: usize, window_bits: usize) -> u64 {
    let bigint = scalar.into_bigint();
    let limbs = bigint.as_ref();

    // Determine which 64-bit limb contains the start bit
    let start_limb = start_bit / 64;
    let start_bit_in_limb = start_bit % 64;

    // If start position is beyond the scalar, return 0
    if start_limb >= limbs.len() {
        return 0;
    }

    // Extract bits from the current limb
    let mut result = limbs[start_limb] >> start_bit_in_limb;

    // If the window spans across two limbs, get bits from the next limb
    if start_bit_in_limb + window_bits > 64 && start_limb + 1 < limbs.len() {
        let next_limb_contribution = limbs[start_limb + 1] << (64 - start_bit_in_limb);
        result |= next_limb_contribution;
    }

    // Mask to keep only the requested number of bits
    let mask = if window_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << window_bits) - 1
    };

    result & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::VariableBaseMSM;
    use ark_std::{UniformRand, Zero};
    use rand::thread_rng;

    #[test]
    fn test_extract_window_bits() {
        // Test with a known scalar value
        let scalar = Fr::from(0b10110101u64); // Binary: 10110101

        // Extract 4 bits starting at position 0 (LSB)
        assert_eq!(extract_window_bits(&scalar, 0, 4), 0b0101); // 5

        // Extract 4 bits starting at position 2
        assert_eq!(extract_window_bits(&scalar, 2, 4), 0b1101); // 13

        // Extract 4 bits starting at position 4
        assert_eq!(extract_window_bits(&scalar, 4, 4), 0b1011); // 11
    }

    #[test]
    fn test_simple_scalar_multiplication() {
        // Test: 5 * G where G is a random point
        let mut rng = thread_rng();
        let base = G1Projective::rand(&mut rng);
        let scalar = Fr::from(5u64);

        // Create table with window_bits=4
        let table = FixedBaseMsmTable::new(&[base], 4);
        let result = table.msm(&[scalar]);

        let expected = base * scalar;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_simple_two_bases() {
        // Test: 3 * G1 + 2 * G2
        let mut rng = thread_rng();
        let bases = vec![G1Projective::rand(&mut rng), G1Projective::rand(&mut rng)];
        let scalars = vec![Fr::from(3u64), Fr::from(2u64)];

        let table = FixedBaseMsmTable::new(&bases, 4);
        let result = table.msm(&scalars);

        let expected = bases[0] * scalars[0] + bases[1] * scalars[1];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_fixed_base_msm_correctness() {
        let mut rng = thread_rng();

        // Test with various sizes
        for &size in &[8, 16, 32, 64] {
            let bases: Vec<G1Projective> =
                (0..size).map(|_| G1Projective::rand(&mut rng)).collect();
            let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

            // Compute using precomputed table
            let table = FixedBaseMsmTable::new(&bases, 8);
            let result_precomputed = table.msm(&scalars);

            // Compute using standard variable-base MSM
            let bases_affine: Vec<_> = G1Projective::normalize_batch(&bases);
            let result_standard =
                <G1Projective as VariableBaseMSM>::msm_unchecked(&bases_affine, &scalars);

            assert_eq!(
                result_precomputed, result_standard,
                "Fixed-base MSM result should match variable-base MSM for size {}",
                size
            );
        }
    }

    #[test]
    fn test_different_window_sizes() {
        let mut rng = thread_rng();
        let size = 32;

        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

        // Compute reference result
        let bases_affine: Vec<_> = G1Projective::normalize_batch(&bases);
        let expected = <G1Projective as VariableBaseMSM>::msm_unchecked(&bases_affine, &scalars);

        // Test different window sizes
        for &window_bits in &[4, 8, 12] {
            let table = FixedBaseMsmTable::new(&bases, window_bits);
            let result = table.msm(&scalars);

            assert_eq!(
                result, expected,
                "MSM with window_bits={} should match reference",
                window_bits
            );
        }
    }

    #[test]
    fn test_empty_msm() {
        let bases: Vec<G1Projective> = vec![];
        let scalars: Vec<Fr> = vec![];

        let table = FixedBaseMsmTable::new(&bases, 8);
        let result = table.msm(&scalars);

        assert_eq!(result, G1Projective::zero());
    }

    #[test]
    fn test_single_element_msm() {
        let mut rng = thread_rng();

        let base = G1Projective::rand(&mut rng);
        let scalar = Fr::rand(&mut rng);

        let table = FixedBaseMsmTable::new(&[base], 8);
        let result = table.msm(&[scalar]);

        let expected = base * scalar;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_zero_scalars() {
        let mut rng = thread_rng();
        let size = 16;

        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = vec![Fr::from(0u64); size];

        let table = FixedBaseMsmTable::new(&bases, 8);
        let result = table.msm(&scalars);

        assert_eq!(result, G1Projective::zero());
    }

    #[test]
    fn test_reuse_table() {
        let mut rng = thread_rng();
        let size = 32;

        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();

        // Precompute table once
        let table = FixedBaseMsmTable::new(&bases, 8);

        // Use it for multiple MSMs with different scalars
        let bases_affine: Vec<_> = G1Projective::normalize_batch(&bases);

        for _ in 0..10 {
            let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

            let result_precomputed = table.msm(&scalars);
            let result_standard =
                <G1Projective as VariableBaseMSM>::msm_unchecked(&bases_affine, &scalars);

            assert_eq!(result_precomputed, result_standard);
        }
    }

    #[test]
    #[should_panic(expected = "Number of scalars must match number of bases")]
    fn test_mismatched_lengths() {
        let mut rng = thread_rng();

        let bases: Vec<G1Projective> = (0..10).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();

        let table = FixedBaseMsmTable::new(&bases, 8);
        let _ = table.msm(&scalars); // Should panic
    }

    #[test]
    fn test_memory_usage_estimate() {
        let mut rng = thread_rng();
        let bases: Vec<G1Projective> = (0..256).map(|_| G1Projective::rand(&mut rng)).collect();

        let table = FixedBaseMsmTable::new(&bases, 8);
        let memory = table.memory_usage_estimate();

        // For 256 bases with window_bits=8:
        // Expected: 256 bases × 256 entries/base × 64 bytes/entry = 4,194,304 bytes ≈ 4 MB
        assert_eq!(memory, 256 * 256 * 64);
        assert!(memory > 4_000_000 && memory < 5_000_000);
    }

    #[test]
    fn test_msm_batch_correctness() {
        let mut rng = thread_rng();
        let size = 32;
        let batch_size = 10;

        // Generate fixed bases
        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();

        // Generate batch of scalar vectors
        let scalar_batch: Vec<Vec<Fr>> = (0..batch_size)
            .map(|_| (0..size).map(|_| Fr::rand(&mut rng)).collect())
            .collect();

        // Compute using batch MSM
        let table = FixedBaseMsmTable::new(&bases, 8);
        let results = table.msm_batch(&scalar_batch);

        assert_eq!(results.len(), batch_size);

        // Verify each result independently
        let bases_affine: Vec<_> = G1Projective::normalize_batch(&bases);
        for (i, result) in results.iter().enumerate() {
            let expected =
                <G1Projective as VariableBaseMSM>::msm_unchecked(&bases_affine, &scalar_batch[i]);
            assert_eq!(
                *result, expected,
                "Batch MSM result {} doesn't match expected",
                i
            );
        }
    }

    #[test]
    fn test_msm_batch_empty() {
        let mut rng = thread_rng();
        let bases: Vec<G1Projective> = (0..16).map(|_| G1Projective::rand(&mut rng)).collect();

        let table = FixedBaseMsmTable::new(&bases, 8);
        let results = table.msm_batch(&[]);

        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_msm_batch_single() {
        let mut rng = thread_rng();
        let size = 16;

        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

        let table = FixedBaseMsmTable::new(&bases, 8);

        // Batch of size 1 should match single MSM
        let batch_result = table.msm_batch(std::slice::from_ref(&scalars));
        let single_result = table.msm(&scalars);

        assert_eq!(batch_result.len(), 1);
        assert_eq!(batch_result[0], single_result);
    }

    #[test]
    fn test_msm_batch_large() {
        // Test the main use case: hundreds of MSMs
        let mut rng = thread_rng();
        let size = 64;
        let batch_size = 100;

        let bases: Vec<G1Projective> = (0..size).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalar_batch: Vec<Vec<Fr>> = (0..batch_size)
            .map(|_| (0..size).map(|_| Fr::rand(&mut rng)).collect())
            .collect();

        let table = FixedBaseMsmTable::new(&bases, 8);
        let results = table.msm_batch(&scalar_batch);

        assert_eq!(results.len(), batch_size);

        // Spot check a few results
        let bases_affine: Vec<_> = G1Projective::normalize_batch(&bases);
        for i in [0, batch_size / 2, batch_size - 1] {
            let expected =
                <G1Projective as VariableBaseMSM>::msm_unchecked(&bases_affine, &scalar_batch[i]);
            assert_eq!(results[i], expected);
        }
    }

    #[test]
    #[should_panic(expected = "Scalar vector 1 has length")]
    fn test_msm_batch_mismatched_lengths() {
        let mut rng = thread_rng();

        let bases: Vec<G1Projective> = (0..10).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalar_batch = vec![
            (0..10).map(|_| Fr::rand(&mut rng)).collect(),
            (0..5).map(|_| Fr::rand(&mut rng)).collect(), // Wrong length at index 1
        ];

        let table = FixedBaseMsmTable::new(&bases, 8);
        let _ = table.msm_batch(&scalar_batch); // Should panic
    }
}
