# ZK Brownian Forward Protocol - Implementation Specification

## Overview

A zero-knowledge message forwarding protocol where nodes forward packets through a network and prove correct forwarding behavior without revealing routing information.

## Protocol Functions (High-Level)

### Setup and Key Management
- **Setup(λ, N, M)**: Initialize system with N nodes, max out-degree M
- **KeyGen()**: Generate key pair (sk, pk) for each node
- **Diversify(pk, d)**: Create unlinkable diversified public key ppk_d

### Message Lifecycle
- **Spawn(sk, pid, sid)**: Create initial message
- **Forward(...)**: Core forwarding function (primary implementation focus)
- **Verify(m, h, C, P)**: Verify message validity

### Weight Commitment
- **Commit(i, w_{i,1}...w_{i,M}; r)**: Commit to outgoing edge weights
- **Merge(C_1...C_N)**: Merge into full weight matrix

## Forward Function - Implementation Focus

### Function Signature
```
Forward(pk_ν, sk_ν, m) -> (m', k_R, d)
```

### Inputs
- **pk_ν**: Public key of current forwarder
- **sk_ν**: Secret key of current forwarder
- **m**: Message structure containing:
  - `pid`: Packet ID (0 to #users)
  - `sid`: Session/epoch ID
  - `{(ppk_i, φ_i, π_i)}_{i=1}^ν`: History of diversified pks, PRF outputs, proofs
  - `ppk_0, π_0`: Initial diversified pk and proof from Spawn

### Outputs
- **m'**: Updated message with new hop added
- **k_R**: Index of receiver in node list
- **d**: Diversifier for creating ppk_{ν+1}

### Algorithm Steps

1. **Hop Count Check**
   - Verify ν ≤ ν_max (abort if exceeded)

2. **Derive PRF Input (θ)**
   - θ ← Hash(φ_ν, sid, pid, ν)
   - Note: φ_0 = 0 (or dummy value)

3. **Compute PRF Output (φ_{ν+1})**
   - φ_{ν+1} ← G^{1/(θ+sk)}
   - **Q: What is G? Generator of which group/curve?**

4. **Select Next Hop**
   - Extract ρ_{ν+1} ← First32Bits(φ_{ν+1})
   - Use ρ_{ν+1} and weight matrix C to select pk_{ν+1} at index k_R
   - **Q: What's the exact selection algorithm? How do weights map to selection?**
   - **Q: Is this weighted random sampling? Cumulative distribution?**

5. **Create Diversified Public Key**
   - Sample random d
   - ppk_{ν+1} ← (pk_{ν+1}^d, G^d)
   - **Q: Is this ElGamal-style? What group operations?**

6. **Generate Proof (π_{ν+1})**
   - Prove:
     1. Ownership of m w.r.t. ppk_ν and sk (hidden)
     2. Selection of pk_{ν+1} (hidden) according to ρ_{ν+1}
     3. Correct derivation of ppk_{ν+1} relative to pk_{ν+1}
     4. Correct derivation of PRF φ_{ν+1} from θ and sk corresponding to ppk_ν

7. **Post to Bulletin Board**
   - m' = (pid, sid, {ppk_i, φ_i, π_i}_{i=1}^{ν+1}, ppk_0, π_0)
   - Post (m', k_R, d) anonymously addressed to ppk_{ν+1}

## Cryptographic Primitives

### Proof System (from spec lines 63-95)
The protocol uses multiple proof components:

1. **π_1**: Groth16 in G_1
   - Merkle tree membership for (pk, md_{2,k_s}) ∈ MT(md_1)
   - Verifies w.r.t. commitment C_1 = G_1^{pk_x} G_2^{pk_y} G_3^{md_{2,k_s}} H^r

2. **π_2**: Groth16/Catalano-Fiore in G_1 (weights sub-tree)
   - Opens weight commitments
   - Merkle proofs for receiver and pre-receiver positions

3. **π_3**: Groth16 in G_1
   - Merkle membership for (pk_r, md_{2,k_r}) ∈ MT(md_{2,k_s})

4. **π_{4,G_1}**: Lightweight Schnorr for bridging groups
   - Proves blinded public key relations
   - Opens commitments C_1, C_3
   - Range proof: v_1 < ρ ≤ v_2

5. **π_{4,G_2}**: Public key operations (pks in G_2)
   - Ownership: pk* = G^sk · H^r
   - Valid diversified pk: (ppk_{s,2})^sk = ppk_{s,1}
   - Diversify correctness: ppk_r = (pk_r^d, G^d)
   - PRF correctness: φ^{(sk+θ)} = H

## Questions for Implementation

### Curve/Group Selection
- **Q: Which pairing-friendly curve? BLS12-381, BN254, BLS12-377?**
BLS
- **Q: Are we using G_1 and G_2 from the pairing?**
Both!
- **Q: What are the generators G, H, G_i, H_i?**
You have to pre-generate random generators for each

### Hash Functions
- **Q: Which hash for deriving θ? Poseidon, SHA256, Blake2?**
Use poseidon for everything.
- **Q: Hash to curve method for public key hashing?**
Public keys are G2 points, so pairs of G1's scalar field elements. You can use poseidon in scalar field of G1.

### Weight Matrix
- **Q: What's the format/structure of matrix C?**
- **Q: How are weights represented? Fixed point? Floating point? Field elements?**
Let's say weights are up to 32 bits, and all weight should sum to 2^32.
- **Q: How does First32Bits(φ_{ν+1}) map to weight-based selection?**
So your poseidon hash is
- **Q: Are weights normalized to sum to 1?**
To sum to 2^32

### Message Structure
- **Q: Exact serialization format for messages?**
don't care
- **Q: Maximum message size?**
don't care
- **Q: How is ν (hop count) stored/tracked?**
It's part of the message structure

### Constants
- **Q: What is ν_max (maximum hops)?**
10
- **Q: What is N (number of nodes)?**
hundreds
- **Q: What is M (max out-degree)?**
tens

### Bulletin Board
- **Q: What's the interface for posting messages?**
Don't care now, stub easily.
- **Q: How is anonymity achieved in posting?**
- **Q: Storage/retrieval mechanism?**

### Proving System Details
- **Q: Which Groth16 implementation/library?**
You'll have to implement Groth16 from scratch. I was thinking of the SAVER paper. Feel free to copy some existing implementations.
- **Q: Pre-generated setup parameters (trusted setup)?**
Just pre-generate them.
- **Q: Circuit size estimates?**
- **Q: Proof randomization strategy (mentioned in line 51)?**

### PRF Computation
- **Q: For φ_{ν+1} = G^{1/(θ+sk)}, how do we compute 1/(θ+sk)?**
It's an inversion in the field.
- **Q: Is this modular inverse in the scalar field?**
- **Q: What if θ + sk = 0? (collision handling)**
Can't happen, sk is randomly chosen.

### Diversification
- **Q: How is random d sampled? From which distribution/field?**
- **Q: ppk format - is it always a tuple (pk^d, G^d)?**
- **Q: Decryption: how does sk holder recognize their ppk_d?**

### Public Key Hashing Options (lines 51-58)
The spec mentions three options:
1. Two curves / two Schnorrs approach (Curve Trees paper)
2. pk' = Poseidon(sk)
3. Kiwi commitments

- **Q: Which approach should we use?**

## Implementation Scope

### Priority 1: Core Forward Function
- [ ] Data structures for message m
- [ ] PRF computation (θ derivation)
- [ ] PRF computation (φ_{ν+1} derivation)
- [ ] Next hop selection algorithm
- [ ] Diversified public key generation
- [ ] Message update logic

### Priority 2: Proof Generation
- [ ] Circuit design for π_{ν+1}
- [ ] Constraint system for all 4 proof components
- [ ] Witness generation
- [ ] Proof assembly

### Priority 3: Supporting Functions
- [ ] Spawn implementation
- [ ] Verify implementation
- [ ] KeyGen/Diversify
- [ ] Weight matrix handling

### Priority 4: Integration
- [ ] Bulletin board interface
- [ ] Serialization/deserialization
- [ ] Testing infrastructure
- [ ] Performance optimization

## Notes

- The spec document notes it is "incomplete and inconsistent" (line 1)
- Groth16 proofs are randomizable (line 51)
- Commit-and-proof pattern with rerandomization possible (SAVER reference)
- Notation: md = Merkle digest, generators in G_1 are G_i, in G_2 are H_i

## References from Spec
- Curve Trees paper (for bridging Schnorrs)
- SAVER (for commit-and-proof rerandomization)
- Catalano-Fiore (for zk set membership, eprint 2019/1255)
