# zkbrownian-rs

A Rust implementation of the ZK Brownian Forward Protocol - a zero-knowledge message forwarding protocol where nodes forward packets through a network and prove correct forwarding behavior without revealing routing information.

## Overview

This protocol enables privacy-preserving message routing where:
- Messages are forwarded through a network of nodes
- Each forwarder proves correct behavior without revealing their identity
- Routing decisions are based on committed weight matrices
- Diversified public keys provide unlinkability

## Project Structure

```
zkbrownian-rs/
├── src/
│   ├── lib.rs              # Main library entry point
│   ├── main.rs             # CLI binary
│   ├── types.rs            # Core data structures
│   ├── crypto/             # Cryptographic primitives
│   │   ├── mod.rs
│   │   ├── poseidon.rs     # Poseidon hash for BLS12-381
│   │   ├── curve_ops.rs    # Curve operations (G1, G2)
│   │   ├── prf.rs          # PRF computation
│   │   └── generators.rs   # Generator pre-generation
│   ├── proving/            # Zero-knowledge proving system
│   │   ├── mod.rs
│   │   ├── groth16.rs      # Groth16 implementation (stub)
│   │   ├── circuits.rs     # Circuit definitions
│   │   └── constraints.rs  # R1CS constraints
│   └── protocol/           # Protocol functions
│       ├── mod.rs
│       ├── forward.rs      # Forward function (main focus)
│       ├── spawn.rs        # Message spawning
│       ├── verify.rs       # Message verification
│       ├── routing.rs      # Weight-based routing
│       └── bulletin_board.rs # Message posting interface
├── examples/
│   └── basic_forward.rs    # Basic usage example
├── benches/
│   └── forward_bench.rs    # Performance benchmarks
├── spec.md                 # Implementation specification
└── spec.tex                # Original LaTeX specification
```

## Core Components

### Forward Function

The main forwarding operation: `Forward(pk_ν, sk_ν, m) -> (m', k_R, d)`

**Algorithm:**
1. Check hop count ν ≤ ν_max (max 10 hops)
2. Derive θ ← Hash(φ_ν, sid, pid, ν) using Poseidon
3. Compute φ_{ν+1} ← G^{1/(θ+sk)} (PRF output)
4. Extract ρ_{ν+1} ← First32Bits(φ_{ν+1})
5. Select next hop based on ρ and weight matrix
6. Create diversified public key ppk_{ν+1} = (pk^d, G^d)
7. Generate ZK proof π_{ν+1}
8. Return updated message m'

### Cryptographic Primitives

- **Curve**: BLS12-381 pairing-friendly curve
- **Groups**: Both G1 and G2 from the pairing
- **Hash**: Poseidon for all hashing operations
- **Keys**: Public keys in G2, secret keys as scalars
- **Diversification**: ElGamal-style diversified keys for unlinkability

### Proving System

Five proof components (currently stubbed):
1. **π_1**: Groth16 in G1 - Sender public key membership
2. **π_2**: Groth16/Catalano-Fiore in G1 - Weight sub-tree proofs
3. **π_3**: Groth16 in G1 - Receiver public key membership
4. **π_{4,G1}**: Schnorr in G1 - Bridging proof
5. **π_{4,G2}**: Schnorr in G2 - Public key operations

## Building

### Using Nix (Recommended)

```bash
# Enter development environment
nix develop

# Build the project
cargo build

# Run tests
cargo test

# Run example
cargo run --example basic_forward

# Run benchmarks
cargo bench
```

### Using Cargo Directly

Requires Rust 1.70+ with Cargo installed.

```bash
cargo build
cargo test
cargo run --example basic_forward
```

## Usage Example

```rust
use zkbrownian::crypto::curve_ops::keygen;
use zkbrownian::protocol::{spawn, forward, WeightMatrix};
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();

    // Generate keys
    let (sk, pk) = keygen(&mut rng);

    // Spawn message
    let message = spawn(&sk, &pk, 42, 1000, &mut rng).unwrap();

    // Setup network
    let all_pks = vec![pk.clone()];
    let weight_matrix = WeightMatrix::uniform(1, 1u64 << 32);

    // Forward message
    let (new_message, next_hop, _diversifier) = forward(
        &pk,
        &sk,
        &message,
        &weight_matrix,
        &all_pks,
        &mut rng,
    ).unwrap();

    println!("Forwarded to node: {}", next_hop);
}
```

## Implementation Status

### ✅ Completed
- [x] Project structure and build system
- [x] Core data structures (Message, keys, proofs)
- [x] BLS12-381 curve operations
- [x] Key generation and diversification
- [x] PRF computation (φ = G^{1/(θ+sk)})
- [x] Poseidon hash (stub, needs full implementation)
- [x] Weight-based routing
- [x] Forward function (with stub proofs)
- [x] Spawn function
- [x] Verify function (stub)
- [x] Bulletin board interface
- [x] Basic example and benchmarks

### 🚧 In Progress / TODO
- [ ] Full Poseidon hash implementation for BLS12-381
- [ ] Groth16 proving system (from scratch)
- [ ] Circuit implementations for all 5 proof components
- [ ] R1CS constraint generation
- [ ] Merkle tree for weight commitments
- [ ] Full proof generation in Forward
- [ ] Full verification in Verify
- [ ] Proof rerandomization (SAVER technique)
- [ ] Better PRF output to routing value conversion
- [ ] Comprehensive test suite
- [ ] Performance optimizations

## Configuration

Constants in `src/lib.rs`:
- `MAX_HOPS`: 10 (maximum message hops)
- `NUM_NODES`: 256 (default number of nodes)
- `MAX_OUT_DEGREE`: 32 (max neighbors per node)
- `WEIGHT_SUM`: 2^32 (sum of all weights)

## Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test crypto::
cargo test protocol::

# Run with output
cargo test -- --nocapture
```

## Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench keygen
```

## References

- Original specification: `spec.tex`
- Implementation spec: `spec.md`
- Groth16 paper: [Groth16](https://eprint.iacr.org/2016/260)
- SAVER paper: [SAVER](https://eprint.iacr.org/2019/1270)
- Curve Trees: [Curve Trees](https://eprint.iacr.org/2022/756)

## License

[Specify license here]

## Contributing

This is a research implementation. Contributions welcome!

## Security Warning

⚠️ **This is experimental research code. Do not use in production.**

- The Poseidon hash is currently a stub
- The proving system needs full implementation
- No security audit has been performed
- Cryptographic parameters need careful review
