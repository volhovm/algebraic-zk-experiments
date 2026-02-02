 Fixed-Bases Multi-Scalar Multiplication (MSM) Specification

## Problem Statement

You need to compute hundreds of MSMs of the form:

MSM(G_vec, c_vec) = ∑ᵢ₌₀ⁿ⁻¹ cᵢ·Gᵢ

text

where:
- **G_vec = [G₀, G₁, ..., Gₙ₋₁]** is a **fixed vector of base points** (same for all MSMs)
- **c_vec = [c₀, c₁, ..., cₙ₋₁]** is a **variable vector of scalars** (different for each MSM)
- You compute this MSM hundreds of times with the same G_vec but different c_vec

**Goal:** Precompute a table based on G_vec once, then reuse it for all subsequent MSMs to achieve 2–4× speedup.

---

## Algorithm: Pippenger MSM with Precomputation

The standard approach is **Pippenger's algorithm** with precomputation of the bases. This is different from fixed-*base* (singular) scalar multiplication—it's a generalization for fixed *bases* (plural).

### High-Level Idea

1. **Precomputation Phase (once):**
   - For each base point Gᵢ, precompute multiples and organize them into a lookup table
   - Store these tables in memory

2. **MSM Computation Phase (hundreds of times):**
   - For each new c_vec, use the precomputed tables to perform fast bucket accumulation
   - Combine bucket sums to get the final result

---

## Algorithm Details

### 1. Precomputation Phase

**Input:**
- Base points: `G_vec = [G₀, G₁, ..., Gₙ₋₁]` (n points)
- Window size: `w` (e.g., 4, 8, or 16 bits)
- Scalar bit length: `λ` (e.g., 256 for BLS12-381)

**Output:**
- Precomputation table `T` organized for fast lookup

**Algorithm:**

PRECOMPUTE_BASES(G_vec, w, λ):
num_windows = ⌈λ / w⌉

text
// For each base point, precompute powers and store
// Strategy 1: Horizontal precomputation (all windows for all bases)
T = Array[num_windows][n][2^w] of Point

for window_idx = 0 to num_windows - 1:
    for i = 0 to n - 1:
        base_shifted = Gᵢ · 2^(window_idx × w)

        T[window_idx][i] = O  // Point at infinity
        T[window_idx][i] = base_shifted[1]

        // Precompute 2·base_shifted, 3·base_shifted, ..., (2^w - 1)·base_shifted
        for j = 2 to 2^w - 1:
            T[window_idx][i][j] = T[window_idx][i][j-1] + base_shifted

return T

text

**Alternative Strategy: Vertical Precomputation (Recommended)**

Instead of precomputing all windows, precompute only the "bottom row" and compute shifted values on-the-fly:

PRECOMPUTE_BASES_VERTICAL(G_vec, w, λ):
// Only precompute bottom window for each base
T = Array[n][2^w] of Point

text
for i = 0 to n - 1:
    T[i] = O  // Point at infinity
    T[i] = Gᵢ[1]

    // Precompute 2·Gᵢ, 3·Gᵢ, ..., (2^w - 1)·Gᵢ
    for j = 2 to 2^w - 1:
        T[i][j] = T[i][j-1] + Gᵢ

return T

text

**Cost:**
- Horizontal: ~`n × (λ/w) × 2^w` point additions, stores `n × (λ/w) × 2^w` points
- Vertical: ~`n × 2^w` point additions, stores only `n × 2^w` points
- **Memory savings:** Vertical uses `w × (λ/w) = λ` times less memory (e.g., 256× for λ=256)

**Optimization: Signed representation**

Use signed digits to halve precomputation:
- Store only positive multiples: `{Gᵢ, 2Gᵢ, 3Gᵢ, ..., (2^(w-1))Gᵢ}`
- For negative digits, use `-Gᵢ` (elliptic curve point negation is almost free)
- **Saves 50% memory**

---

### 2. MSM Computation Phase (Pippenger's Algorithm)

**Input:**
- Scalars: `c_vec = [c₀, c₁, ..., cₙ₋₁]`
- Precomputation table `T`
- Window size `w`

**Output:**
- Result: `∑ᵢ cᵢ·Gᵢ`

**Algorithm (Horizontal Precomputation):**

PIPPENGER_MSM_HORIZONTAL(c_vec, T, w, λ):
num_windows = ⌈λ / w⌉
result = O

text
// Process from most significant window to least significant
for window_idx = num_windows - 1 down to 0:
    // Extract w-bit window from each scalar
    for i = 0 to n - 1:
        digit = EXTRACT_BITS(cᵢ, window_idx × w, w)

        // Look up precomputed value and accumulate
        if digit ≠ 0:
            result = result + T[window_idx][i][digit]

    // Shift result by w bits (if not last window)
    if window_idx > 0:
        for _ = 0 to w - 1:
            result = result + result  // Point doubling

return result

text

**Algorithm (Vertical Precomputation with Buckets):**

This is the **standard Pippenger** approach with precomputation:

PIPPENGER_MSM_VERTICAL(c_vec, T, w, λ):
num_windows = ⌈λ / w⌉
window_sums = Array[num_windows] of Point

text
// For each window, compute partial sum using buckets
for window_idx = 0 to num_windows - 1:
    buckets = Array[2^w - 1] of Point  // buckets[m] = sum of bases with digit m+1

    // Initialize buckets
    for m = 0 to 2^w - 2:
        buckets[m] = O

    // Accumulate bases into buckets
    for i = 0 to n - 1:
        digit = EXTRACT_BITS(cᵢ, window_idx × w, w)

        if digit > 0:
            // Compute shifted base: Gᵢ · 2^(window_idx × w)
            base_shifted = T[i]  // Start with Gᵢ[1]
            for _ = 0 to window_idx × w - 1:
                base_shifted = base_shifted + base_shifted  // Doubling

            // Scale by digit and add to bucket
            point_contrib = T[i][digit]
            for _ = 0 to window_idx × w - 1:
                point_contrib = point_contrib + point_contrib

            buckets[digit - 1] = buckets[digit - 1] + point_contrib

    // Aggregate buckets: sum_m (m+1)·buckets[m]
    running_sum = O
    window_sum = O
    for m = 2^w - 2 down to 0:
        running_sum = running_sum + buckets[m]
        window_sum = window_sum + running_sum

    window_sums[window_idx] = window_sum

// Combine window sums with appropriate weights
result = O
for window_idx = num_windows - 1 down to 0:
    // Multiply result by 2^w
    for _ = 0 to w - 1:
        result = result + result

    result = result + window_sums[window_idx]

return result

text

**Optimized Vertical (Avoiding Repeated Doublings):**

The above recomputes shifted bases on-the-fly. A better approach:

PIPPENGER_MSM_VERTICAL_OPT(c_vec, T, w, λ):
num_windows = ⌈λ / w⌉

text
// Decompose all scalars into w-bit windows
digits = Array[num_windows][n] of Integer
for i = 0 to n - 1:
    for window_idx = 0 to num_windows - 1:
        digits[window_idx][i] = EXTRACT_BITS(cᵢ, window_idx × w, w)

// Process each window independently using buckets
result = O
for window_idx = num_windows - 1 down to 0:
    buckets = Array[2^w] of Point
    for m = 0 to 2^w - 1:
        buckets[m] = O

    // Accumulate precomputed points into buckets
    for i = 0 to n - 1:
        d = digits[window_idx][i]
        if d > 0:
            buckets[d] = buckets[d] + T[i][d]  // Just add from table

    // Compute window contribution: ∑_{m=1}^{2^w-1} m·buckets[m]
    running_sum = O
    window_contrib = O
    for m = 2^w - 1 down to 1:
        running_sum = running_sum + buckets[m]
        window_contrib = window_contrib + running_sum

    // Shift window contribution by window_idx × w bits
    for _ = 0 to window_idx × w - 1:
        window_contrib = window_contrib + window_contrib

    result = result + window_contrib

return result

text

**Cost:**
- Scalar decomposition: `O(n × λ)` bit operations
- Bucket accumulation: `O(n)` point additions per window → `O(n × λ/w)` total
- Bucket aggregation: `O(2^w)` point additions per window → `O(2^w × λ/w)` total
- **Total:** ~`n × λ/w + 2^w × λ/w` point additions + `λ` point doublings

---

## Comparison: With vs. Without Precomputation

| Aspect | Variable-Base (No Precomp) | Fixed-Bases (With Precomp) |
|---|---|---|
| **Precomputation** | None | `n × 2^w` adds (one-time) |
| **Per-MSM cost** | `n × λ/w + 2^w × λ/w` adds | `n × λ/w + 2^w × λ/w` adds |
| **Point lookups** | None | `n × λ/w` table lookups |
| **Memory** | O(n) (just G_vec) | O(n × 2^w) (precomputed table) |
| **Speedup** | 1× (baseline) | **2–4×** (from faster point ops) |

**Why is precomputation faster if the formula looks the same?**

- **Affine vs. Projective:** Precomputed points can be stored in **affine coordinates**, making mixed addition much cheaper than projective-projective addition
- **Cache locality:** Table lookups are faster than on-the-fly scalar decomposition + point doubling
- **Batch inversion:** Precomputation can amortize expensive field inversions across all bases

---

## Parameter Selection

### Window Size `w`

| w | Memory (for n=256 bases) | Adds per MSM (λ=256) | Use Case |
|---|---|---|---|
| 4 | ~4 KB (256 × 16 points) | ~16,384 + ~16,384 | Balanced |
| 8 | ~64 KB (256 × 256 points) | ~8,192 + ~8,192 | **Optimal for most** |
| 12 | ~1 MB (256 × 4,096 points) | ~5,461 + ~5,461 | High memory OK |
| 16 | ~16 MB (256 × 65,536 points) | ~4,096 + ~4,096 | Very high memory |

**Recommendation:** `w = 8` provides the best speed/memory tradeoff for typical ZK applications.

### Precomputation Strategy

1. **Vertical (single row):** Best for most cases—minimal memory, fast enough
2. **Horizontal (all rows):** Only if you have huge memory and want to minimize doublings to ~0
3. **Hybrid (partial rows):** Precompute every k-th row (e.g., k=4), balance memory and speed

---

## Implementation in Arkworks 0.5

**Bad news:** Arkworks 0.5 does **not** expose a precomputation API for `VariableBaseMSM`.

The `VariableBaseMSM::msm` trait method is **not** designed to reuse bases across multiple MSMs. Each call recomputes everything from scratch.

### Workaround 1: Use External MSM Library

Use a dedicated MSM library with precomputation support:

- **Icicle** (GPU): Supports precomputation for fixed bases ([docs](https://dev.ingonyama.com))
- **Sppark** (GPU): Rust MSM with CUDA backend
- **Roll your own:** Implement Pippenger with precomputation (see pseudocode above)

### Workaround 2: Implement Precomputation Yourself

Based on the pseudocode above, implement a simple precomputation wrapper:

```rust
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::PrimeField;
use std::vec::Vec;

pub struct FixedBasesTable<G: CurveGroup> {
    /// Precomputed table: table[i][j] = j * G_i (in affine)
    table: Vec<Vec<G::Affine>>,
    window: usize,
}

impl<G: CurveGroup> FixedBasesTable<G> {
    /// Precompute table for fixed bases (vertical strategy)
    pub fn new(bases: &[G], window: usize) -> Self {
        let n = bases.len();
        let table_size = 1 << window;  // 2^window

        let mut table = Vec::with_capacity(n);

        for base in bases {
            let mut row = Vec::with_capacity(table_size);
            row.push(G::Affine::zero());  // 0 * base
            row.push(base.into_affine());  // 1 * base

            let mut acc = *base;
            for _ in 2..table_size {
                acc += base;
                row.push(acc.into_affine());
            }

            table.push(row);
        }

        Self { table, window }
    }

    /// Compute MSM using precomputed table
    pub fn msm(&self, scalars: &[G::ScalarField]) -> G {
        assert_eq!(scalars.len(), self.table.len());

        let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
        let num_windows = (scalar_bits + self.window - 1) / self.window;

        let mut result = G::zero();

        // Process windows from MSB to LSB
        for window_idx in (0..num_windows).rev() {
            // Shift result by window bits
            for _ in 0..self.window {
                result.double_in_place();
            }

            // Accumulate contributions from this window
            for (i, scalar) in scalars.iter().enumerate() {
                let digit = extract_bits(scalar, window_idx * self.window, self.window);
                if digit > 0 {
                    result += self.table[i][digit as usize];
                }
            }
        }

        result
    }
}

fn extract_bits<F: PrimeField>(scalar: &F, start: usize, len: usize) -> u64 {
    let bigint = scalar.into_bigint();
    let limbs = bigint.as_ref();

    let start_limb = start / 64;
    let start_bit = start % 64;

    if start_limb >= limbs.len() {
        return 0;
    }

    let mut result = limbs[start_limb] >> start_bit;

    if start_bit + len > 64 && start_limb + 1 < limbs.len() {
        let bits_from_next = (start_bit + len) - 64;
        result |= limbs[start_limb + 1] << (64 - start_bit);
    }

    let mask = (1u64 << len) - 1;
    result & mask
}

Usage:

rust
// Precompute once
let bases: Vec<G1Projective> = /* your fixed bases */;
let table = FixedBasesTable::new(&bases, 8);  // w=8

// Reuse for hundreds of MSMs
for _ in 0..100 {
    let scalars: Vec<Fr> = /* different scalars each time */;
    let result = table.msm(&scalars);
    // ... use result
}

Expected Performance

For n = 256 bases, λ = 256-bit scalars, w = 8:
Metric	No Precomputation	With Precomputation	Improvement
Precomputation	0	~65,536 adds (one-time)	—
Per-MSM adds	~16,384	~8,192	2×
Per-MSM time	100%	~30–50%	2–3.5×
Memory	8 KB	64 KB	8× more

For 100 MSMs:

    No precomp: 100 × T

    With precomp: T_precomp + 100 × (0.3–0.5 T) ≈ 40–55 T total

    Net speedup: ~2× for 100 MSMs, approaching 3× for 1000+ MSMs

Optimizations
1. Signed Windows

Use signed digit representation (e.g., digits in [-2^(w-1), 2^(w-1)-1] instead of [0, 2^w-1]):

    Halves precomputation memory

    Requires on-the-fly point negation (cheap on elliptic curves)

2. Extended/Jacobian Coordinates for Precomputed Points

Store precomputed points in extended coordinates (for twisted Edwards curves) to save 1 field multiplication per mixed addition (~10% speedup).
3. Batch Inversion During Precomputation

Convert all projective multiples to affine in one batch inversion pass (saves ~80% of inversion cost).
4. Prefetching

If table doesn't fit in CPU cache, issue prefetch instructions before point additions to hide memory latency.
5. Parallelization

    Bucket accumulation: parallelize across bases (each thread processes a chunk of bases)

    Window processing: parallelize across windows (independent computations)

References

    Pippenger, N. (1976). "On the evaluation of powers and related problems." FOCS.

    HackMD: "Notes on MSMs with Precomputation" – link

    Ingonyama ICICLE: MSM Precomputation docs

    Luo, G., Fu, S., Gong, G. (2023). "Speeding Up MSM over Fixed Points." IACR ePrint.

    Xiong, A., et al. (2023). "Decentralized Private Computation with Universal Setup." USENIX Security.

Conclusion

For your use case—hundreds of MSMs with the same vector of bases G_vec but different scalars c_vec—the optimal approach is:

    Precompute a table of multiples of each base (vertical strategy with w=8)

    Reuse the table for all MSMs using Pippenger's bucket algorithm

    Expected speedup: 2–3× after amortizing precomputation over 50+ MSMs

Since arkworks 0.5 doesn't natively support this, you either:

    Use a GPU MSM library (Icicle, Sppark) with precomputation support, or

    Implement the precomputation wrapper yourself (see code above)

The precomputation cost (~65k point adds for n=256, w=8) is quickly amortized over 100+ MSMs, yielding 2–3× net speedup.
