# Reveal Proof Design: Aggregating Packet Verification into a SNARK

## Status: Brainstorming / Design Phase

## Goal

Create a succinct proof that `verify_batch(messages, merkle_root, ...)` returns `true`.
Instead of a verifier re-running the full verification pipeline (which involves many
pairings, MSMs, and hash evaluations), they check a single succinct proof.

---

## What verify_batch Verifies (per hop, N messages × H hops each)

| Proof                    | System           | Curve/Field         | Count per hop | What it checks                              |
|--------------------------|------------------|---------------------|---------------|---------------------------------------------|
| π₁ (sender membership)   | Groth16          | BLS12-381 (pairing) | 1             | Sender's commitment is in the Merkle tree   |
| π₂ (weight subtree)      | Groth16          | BLS12-381 (pairing) | 1             | Weight relation between sender/receiver     |
| π₃ (receiver membership) | Groth16          | BLS12-381 (pairing) | 1             | Receiver's commitment is in the Merkle tree |
| π₄_G1 (Schnorr bridging) | Bulletproof R1CS | BLS12-381 G1        | 1             | Re-randomization of JubJub PKs is correct   |
| π₄_G2 (PK operations)    | Schnorr-like     | JubJub (G3)         | 1             | Diversifier application, hash chain (stub)  |

**Totals for batch of N×H hops:**
- 3·N·H Groth16 proofs (all BLS12-381, two circuits: merkle membership & weight subtree)
- N·H Bulletproof R1CS proofs (BLS12-381 G1 commitments, JubJub arithmetic inside)
- N·H JubJub Schnorr proofs (currently stub)

**Concrete example**: N=30 messages, H=5 hops → 150 hops → 450 Groth16 + 150 Bulletproofs + 150 JubJub Schnorrs.

---

## The Three Groups Problem

The verification touches three distinct algebraic domains:

| Group        | Base field        | Scalar field     | Used for                                                                   |
|--------------|-------------------|------------------|----------------------------------------------------------------------------|
| BLS12-381 G1 | Fp (381 bits)     | Fr (255 bits)    | Groth16 proof elements A, C; Bulletproof commitments; Pedersen commitments |
| BLS12-381 G2 | Fp²               | Fr               | Groth16 proof element B; VK elements γ_G2, δ_G2                            |
| JubJub / G3  | **Fr** (255 bits) | Fr_jj (252 bits) | Public keys; blinded PKs; Schnorr proofs                                   |

**Key relationship**: JubJub's base field = BLS12-381's scalar field Fr. This is by design (embedded curve).

**Implication for circuit field choice**:

| If circuit is over... | G3 (JubJub) ops | Fr arithmetic | G1 ops             | G2 ops                | Pairing               |
|-----------------------|-----------------|---------------|--------------------|-----------------------|-----------------------|
| BLS12-381 Fr          | **Native** ✓    | **Native** ✓  | Non-native (Fp≠Fr) | Very non-native (Fp²) | Impossible in-circuit |
| BLS12-381 Fp          | Non-native      | Non-native    | **Native** ✓       | Somewhat native       | Still very expensive  |
| BN254 Fr (e.g. SP1)   | Non-native      | Non-native    | Non-native         | Non-native            | Impossible            |

**Verdict**: A circuit over BLS12-381 Fr is the natural choice — JubJub and scalar field arithmetic are native, and G1/pairing operations can be deferred to the outer verifier.

---

## Per-Proof-Type Analysis

### A. Groth16 Verification (π₁, π₂, π₃)

**Single proof verification equation:**
```
e(A, B) = e(α, β) · e(inputs, γ) · e(C, δ)
```
where `inputs = γ_abc_g1[0] + Σ com_i + Σ a_j · γ_abc_g1[j]`

**Batch verification** (k same-circuit proofs, random coefficients r₁...rₖ):
```
e(α, β)^(Σ rᵢ) = ∏ e(rᵢ·Aᵢ, Bᵢ) · e(Σ rᵢ·inputsᵢ, γ) · e(Σ rᵢ·Cᵢ, δ)
```
This needs k+2 pairings + MSMs in G1.

**In-circuit cost**: Pairing = completely infeasible (millions of constraints). So we MUST split:

**Strategy: Defer pairings, aggregate inputs in-circuit**

The `inputs_i` computation is:
- For merkle membership: `inputs_i = γ_abc_g1[0] + com_i + merkle_root · γ_abc_g1[1]`
  - `com_i` is a G1 point (passed through directly)
  - `merkle_root` is an Fr scalar
- For weight subtree: `inputs_i = γ_abc_g1[0] + c1_i + c2_i + cv1_i + cv2_i`
  - All G1 points (4 commitments, coms_offset=4, no scalar inputs)

**What the circuit can do** (over Fr):
1. Derive random batch coefficients r₁...rₖ via Fiat-Shamir on the proofs
2. For merkle proofs: compute `combined_scalar = Σ rᵢ · merkle_root_i` (just Fr mults — but merkle_root is the same for all, so `combined_scalar = merkle_root · Σ rᵢ`)
3. Output: the batch coefficients rᵢ and the combined scalar

**What the outer verifier does** (natively):
1. Compute MSMs: `Σ rᵢ · Aᵢ`, `Σ rᵢ · Bᵢ` (wait — Bᵢ are in G2, each proof has different B), `Σ rᵢ · Cᵢ`, `Σ rᵢ · com_i`
2. Assemble the pairing equation and check it

**Problem**: Each Groth16 proof has a distinct B ∈ G2. So we can't avoid k pairings in the batch equation (k+2 total). The circuit doesn't help reduce the number of pairings — it can only help verify that the public inputs are correct and the randomness is binding.

**Alternative: SnarkPack / Groth16 aggregation**

[SnarkPack](https://eprint.iacr.org/2021/529) aggregates k Groth16 proofs into a single aggregate with O(log k) verification. It uses:
- Inner pairing product argument (IPPA)
- Verification: O(log k) pairings + 1 MSM of size k on the public inputs

This could aggregate all 450 Groth16 proofs into one aggregate proof. Verification: ~18 pairings (log₂ 450 ≈ 9, times 2 for IPPA) + 1 MSM of size 450 in G1.

**But**: SnarkPack requires all proofs to share the same SRS (alpha, beta, gamma, delta). We have TWO circuits (merkle_membership and weight_subtree) with different VKs. Options:
1. Run SnarkPack twice (one per circuit) → 2 × O(log k) pairings
2. Use the cross-circuit variant → still groups by (γ, δ) pairs

**Cost summary for Groth16 in the "reveal" proof**:

| Approach | In-circuit work | Outer verifier work |
|----------|----------------|-------------------|
| Naive (no aggregation) | Nothing | 450+2 pairings ≈ 452 pairings |
| SnarkPack (2 circuits) | Nothing (SnarkPack is standalone) | ~20 pairings + 2 MSMs of ~225 |
| Circuit-aided aggregation | Fr arithmetic for randomness derivation | k+2 pairings (unchanged) |

**Recommendation**: SnarkPack for Groth16 aggregation, treated as a separate subprotocol. No need to put Groth16 verification inside an R1CS/PLONK circuit at all.

---

### B. Bulletproof R1CS Verification (π₄_G1, Schnorr Bridging)

**What the verifier does** (per proof):
1. Replay the constraint system (2× re_randomize gadget on JubJub) to get `(wL, wR, wO, wV, wc)`
2. Re-derive Fiat-Shamir challenges from transcript: `y, z, u, x, w, r`
3. Compute verification scalars: `g_scalars[i]`, `h_scalars[i]`, `proof_scalars[j]`
4. Collect into a `VerificationTuple`

**Batch verification** (k proofs):
1. For each proof: compute `VerificationTuple`
2. Sample batch random scalars s₁...sₖ
3. Combine: all scalars multiplied by sᵢ for proof i
4. Single MSM: `Σ (scaled_scalar · point) = 0` over all proof-dependent + proof-independent points

**What's inside the MSM**:
- Per proof: ~6-10 proof-dependent points (A_I1, A_O1, S1, A_I2, A_O2, S2, T₀...T₆, V[])
  - With op_degree=2, t_poly_deg=6: 7 T-points minus 1 skipped = 6 T-points
  - Plus 6 commitment points = ~12 proof-dependent points per proof
- Fixed generators: B, B_blinding, G₁...Gₙ, H₁...Hₙ (shared across all proofs)
  - n = circuit size (num_vars). For our circuit: 2 re_randomize calls ≈ hundreds of variables
  - So 2n + 2 fixed generators

**Total MSM size**: k × ~12 (proof points) + 2n + 2 (fixed generators)
For k=150, n≈500: 150 × 12 + 1002 ≈ 2802 points in G1.

**In-circuit strategy**: Same as sp1-schnorr task — prove the **scalar computation** inside the circuit, defer the MSM to the outer verifier.

The circuit needs to:
1. **Replay the constraint system** to get (wL, wR, wO, wc) — this is pure Fr arithmetic. ✓ Native.
   - But involves JubJub curve arithmetic (re_randomize gadget uses lookup tables, curve additions).
   - JubJub base field = Fr → native in an Fr circuit. ✓
   - The constraint system has ~hundreds of multiplier gates.

2. **Compute Fiat-Shamir challenges** — this is hashing. ⚠️ EXPENSIVE.
   - Current transcript: Merlin (SHA3-256 / Keccak based)
   - Challenges per proof: y, z, u, x, w, r (at least 6 hash evaluations)
   - Plus point/scalar appending to transcript (each append is a hash update)
   - SHA3-256 in a circuit: ~150k constraints per compression ← **this is the bottleneck**
   - For 150 proofs × ~20 hash calls each = 3000 hash calls × 150k = **450M constraints** ← infeasible

3. **Compute verification scalars** from challenges — pure Fr arithmetic. ✓ Native.
   - Involves: exp_iter (powers of y), inner_products, polynomial evaluations
   - O(n) multiplications per proof

**The Hash Problem** (Problem 2):
Keccak/SHA3 in a SNARK circuit is extremely expensive. Options:

| Option | Cost per hash | Implications |
|--------|-------------|-------------|
| SHA3-256 in circuit | ~150k R1CS constraints | 450M constraints for 150 proofs — infeasible |
| Poseidon in circuit | ~250 R1CS constraints | 750k constraints for 150 proofs — feasible! |
| SHA-256 in circuit | ~27k R1CS constraints | 81M constraints — borderline |
| Blake2s in circuit | ~15k R1CS constraints | 45M constraints — might work |

**To use Poseidon**: We'd need to change the Bulletproof transcript from Merlin (SHA3) to a Poseidon-based Fiat-Shamir. This is a significant but clean change — replace the `TranscriptProtocol` implementation. The proofs themselves change (different challenges → different proof bytes) but the security argument is the same.

**Cost summary for Bulletproofs in the "reveal" proof**:

| Component | In-circuit (Fr) | Notes |
|-----------|-----------------|-------|
| Constraint system replay (JubJub ops) | ~500 mults × 150 proofs = 75k mults | Native Fr. JubJub curve additions are cheap (~6 constraints each) |
| Fiat-Shamir (with Poseidon) | ~250 constraints × 20 calls × 150 proofs = 750k constraints | Requires switching transcript hash |
| Verification scalar computation | ~500 mults × 150 proofs = 75k mults | exp_iter, inner products, poly eval |
| **Total in-circuit** | **~900k constraints** | Feasible for a SNARK |
| Outer verifier MSM | ~2800-point MSM in G1 | Done natively, fast |

---

### C. JubJub Schnorr Verification (π₄_G2, PK Operations)

**Currently a stub**, but will eventually verify diversifier application and hash chain integrity.

A Schnorr proof in JubJub (G3) verifies:
```
g^s = R + pk · e       (where e = H(R, pk, m))
```
This involves:
- 1 scalar multiplication on JubJub (g^s)
- 1 scalar multiplication on JubJub (pk · e)
- 1 point addition
- 1 hash evaluation for the challenge e

**In-circuit cost** (circuit over BLS12-381 Fr):
- JubJub is embedded → all operations are native!
- Scalar mult: ~750-1500 constraints (with windowed method)
- Point addition: ~6 constraints (complete addition)
- Hash for challenge: depends on hash function
  - If Poseidon over Fr: ~250 constraints
  - If SHA3: ~150k constraints (don't do this)

**Per Schnorr verification**: ~3500 constraints (2 scalar mults + add + Poseidon hash)
**Batch of 150**: ~525k constraints. Very feasible.

**Batch optimization**: Schnorr proofs batch naturally. Given k proofs, sample random s₁...sₖ and check:
```
g^(Σ sᵢ·sᵢ) = Σ sᵢ·Rᵢ + Σ sᵢ·eᵢ·pkᵢ
```
This reduces to 2 MSMs on JubJub + k hash evaluations.

**In-circuit**: We can either:
1. Verify individually (3500 × 150 = 525k constraints)
2. Compute batch equation scalars in-circuit, defer MSM to outer verifier
   - In-circuit: k hash evaluations + k Fr multiplications ≈ 150 × 300 = 45k constraints
   - Outer: 2 MSMs of size 150 on JubJub (native for BLS12-381 verifier)

Option 2 is more efficient but requires the outer verifier to do JubJub MSM. Since JubJub base field = Fr and the outer verifier operates over BLS12-381, this is efficiently computable.

---

## Architecture Options

### Option 1: Three Separate Aggregation Proofs

```
                    ┌─────────────────────┐
  450 Groth16  ───> │ SnarkPack           │ ──> Aggregate proof (O(log k) pairings to verify)
                    └─────────────────────┘
                    ┌─────────────────────┐
  150 Bulletproofs ─> │ SNARK over Fr       │ ──> Scalar outputs → outer MSM check
                    │ (replay FS + scalars)│
                    └─────────────────────┘
                    ┌─────────────────────┐
  150 JubJub ─────> │ SNARK over Fr       │ ──> Batch equation → outer JubJub MSM check
  Schnorrs          │ (or verify in-circuit)│
                    └─────────────────────┘
```

**Pros**: Clean separation; each uses optimal strategy; SnarkPack is well-studied.
**Cons**: Three separate proofs; verifier does three checks.

### Option 2: Combined SNARK for Bulletproofs + JubJub, SnarkPack for Groth16

```
                    ┌─────────────────────┐
  450 Groth16  ───> │ SnarkPack           │ ──> Aggregate proof
                    └─────────────────────┘
                    ┌─────────────────────────────────┐
  150 BP + 150 JJ ─> │ Single SNARK over BLS12-381 Fr  │ ──> Scalar outputs
                    │ (BP transcript replay +          │     for outer MSM
                    │  JubJub Schnorr verification)    │     (G1 + G3)
                    └─────────────────────────────────┘
```

**Pros**: Two proofs instead of three; Bulletproof and JubJub share the Fr field.
**Cons**: Combined circuit is larger; still two separate verifier checks.

### Option 3: Everything-in-one-SNARK (most ambitious)

Put Groth16 input aggregation, Bulletproof scalar computation, and JubJub Schnorr verification all in one circuit over Fr. The outer verifier does:
1. One SNARK verification (itself a pairing check on BLS12-381 if using Groth16/PLONK for outer)
2. One G1 MSM check for Bulletproof batch equation
3. One G1+G2 pairing check for aggregated Groth16
4. (Optional) One JubJub MSM check

**Challenge**: Proving time for a ~2M constraint circuit is significant (minutes).

---

## Key Open Questions

### Q1: Can we avoid the Fiat-Shamir hashing inside the circuit?

If we use "deferred verification" (circuit outputs scalars, verifier checks MSM), the circuit must prove the scalars are correctly derived. The scalars come from the Fiat-Shamir transcript, which requires hashing. We can't skip this without breaking soundness — the whole point is that the challenges are binding.

**But**: If the outer verifier has access to all the proof points (A_I1, A_O1, S1, T₀...T₆, l_vec, r_vec), they could recompute the transcript themselves! In that case:
- The circuit only needs to verify that the constraint system outputs (wL, wR, wO, wc) are correct
- The outer verifier computes challenges from the raw proof bytes and then evaluates the verification equation

This **eliminates all hashing from the circuit** at the cost of the outer verifier doing the Fiat-Shamir computation (which is fast natively).

**Wait — what does the circuit prove then?**
- It proves that the verification **constraint evaluations** (wL, wR, wO, wc) are correct given the instance data
- The instance data includes JubJub points (pk_star_blinded etc.), commitments, etc.
- The constraint system encodes JubJub curve arithmetic (re_randomize gadget)

Actually, the constraint system replay IS the expensive part that involves JubJub arithmetic. The wL/wR/wO vectors encode whether the R1CS is satisfied. The circuit proves:
"Given these instances, the flattened constraint weights are [wL, wR, wO, wc]"
and the outer verifier uses these weights together with the raw proof to check the MSM.

**This dramatically simplifies the in-circuit work!**

With this approach:
- In-circuit: constraint system evaluation only (JubJub ops, native in Fr) ≈ 75k constraints
- Outer verifier: Fiat-Shamir transcript replay (fast, native SHA3) + MSM check
- No hashing inside the circuit at all!

**Caveat**: The outer verifier must have all raw Bulletproof proof bytes. This increases the public input size but since we're already passing all the messages around, this is acceptable.

### Q2: What SNARK system for the outer circuit?

Options:
- **Groth16 over BLS12-381**: Smallest proof, cheapest verification (3 pairings), trusted setup
- **PLONK/Marlin over BLS12-381**: Universal setup, slightly larger proof
- **Nova/folding scheme**: Could fold all 150 Bulletproof verifications incrementally — interesting for streaming verification
- **STARKs (e.g. SP1)**: No trusted setup, but all BLS12-381 arithmetic is non-native (very expensive)

If the circuit is small (~100k constraints), Groth16 is probably the best choice.

### Q3: How to handle the weight subtree Groth16 proofs?

Weight subtree proofs have 4 G1 commitment inputs and 0 scalar inputs. Their `inputs` computation is:
```
inputs = γ_abc_g1[0] + c1 + c2 + cv1 + cv2
```
This is pure G1 arithmetic (no Fr scalars). For batch aggregation:
```
Σ rᵢ · inputs_i = Σ rᵢ · (γ_abc_g1[0] + c1_i + c2_i + cv1_i + cv2_i)
                = (Σ rᵢ) · γ_abc_g1[0] + Σ rᵢ · c1_i + Σ rᵢ · c2_i + ...
```
This is 4 MSMs of size k in G1 (done by outer verifier). The circuit only needs to provide/verify the rᵢ values.

### Q4: Is there a way to batch across all three proof types?

In principle, if all three produce "MSM = 0" style checks over compatible groups, they could share a single batch randomizer. But:
- Groth16 produces a pairing equation, not an MSM equation
- Bulletproofs produce an MSM in G1
- JubJub Schnorr produces an MSM in G3

Different groups = different MSMs. Can't combine. Three checks minimum (or two if we fold JubJub MSM into the circuit).

---

## Recommended Approach (Sketch)

**Phase 1: SnarkPack for Groth16** (standalone, no circuit needed)
- Aggregate 300 merkle-membership proofs with SnarkPack → aggregate proof₁
- Aggregate 150 weight-subtree proofs with SnarkPack → aggregate proof₂
- Verifier checks: 2 × O(log k) ≈ 20 pairings + 2 MSMs

**Phase 2: SNARK over BLS12-381 Fr for Bulletproofs + JubJub**
- Circuit proves:
  - For each of 150 Bulletproof proofs: constraint system evaluation (wL, wR, wO, wc) is correct
  - For each of 150 JubJub Schnorr proofs: either full in-circuit verification OR batch scalar computation
- Circuit size: ~600k–1M constraints
- Outer verifier:
  - Verifies the SNARK (1 pairing check)
  - Recomputes Bulletproof Fiat-Shamir challenges from raw proof bytes (native SHA3, fast)
  - Checks Bulletproof batch MSM equation using circuit-provided wL/wR/wO + self-computed challenges
  - (If JubJub not fully verified in-circuit) Checks JubJub batch MSM

**Total outer verifier work**:
- ~22 pairings (SnarkPack × 2 + SNARK verification)
- ~2 MSMs of size ~225 in G1 (SnarkPack public inputs)
- ~1 MSM of size ~2800 in G1 (Bulletproof batch check)
- ~1 MSM of size ~300 in G3 (JubJub batch, if deferred)
- Native SHA3 transcript replay (~fast)

Compared to original verify_batch:
- ~452 pairings → ~22 pairings (20× reduction)
- ~2800-point G1 MSM → same (Bulletproof MSM doesn't reduce, it was already batched)
- ~150 individual Schnorr verifications → 1 batch MSM

**Main benefit**: Massive pairing reduction from SnarkPack. The SNARK adds a constant verification cost but enables verifiable delegation.

---

## Rough Constraint Estimates

| Component | Constraints | Notes |
|-----------|------------|-------|
| BP constraint replay (150 proofs × ~500 mults) | ~75k | JubJub re_randomize is native in Fr |
| JubJub Schnorr (150 × ~3500 per verification) | ~525k | If done fully in-circuit |
| JubJub Schnorr (150 × ~300 batch scalars) | ~45k | If deferred to outer MSM |
| Fiat-Shamir (if Poseidon, 150 × 20 × 250) | ~750k | Only needed if outer verifier can't replay transcript |
| Fiat-Shamir (if outsourced to verifier) | 0 | Preferred approach |
| **Total (preferred: outsource FS + full JubJub)** | **~600k** | Feasible for Groth16 prover |
| **Total (if FS must be in-circuit, Poseidon)** | **~1.35M** | Still feasible but slower |
| **Total (if FS uses SHA3 in-circuit)** | **~450M** | Infeasible |

---

## Dependency Analysis

1. **SnarkPack**: Exists as a library (bellperson/SnarkPack). Needs adaptation to arkworks + our Groth16 fork.
2. **Poseidon transcript** (if needed): Replace Merlin-based TranscriptProtocol. Moderate effort.
3. **Outer SNARK circuit**: New circuit over BLS12-381 Fr proving constraint system evaluation. The sp1-schnorr work (verifier CS replay, constraint flattening) is directly reusable.
4. **JubJub Schnorr proofs**: Currently stub — need to implement the actual protocol before we can prove its verification.

---

## Summary of the Three Problems

**Problem 1 (Three groups)**: Addressed by choosing BLS12-381 Fr as circuit field (JubJub native, Fr native) and deferring G1/G2 operations to outer verifier. Three separate batch checks at the outer level (pairing + G1 MSM + G3 MSM), but the circuit is unified.

**Problem 2 (Hashes)**: Addressed by outsourcing Fiat-Shamir to the outer verifier (who has access to raw proof bytes and can compute SHA3 natively). If this is not possible, switch to Poseidon for the Bulletproof transcript (~250 constraints/hash vs ~150k for SHA3).

**Problem 3 (Groth16 verification)**: Addressed by using SnarkPack for proof aggregation. No pairing computation happens inside any circuit. SnarkPack reduces 450 proofs to ~20 pairing checks. The reveal SNARK circuit doesn't touch Groth16 at all.
