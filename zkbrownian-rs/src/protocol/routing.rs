//! Routing logic for weight-based next-hop selection
//!
//! Uses PRF output ρ and weight matrix to select next hop

use crate::types::{ProtocolError, ProtocolResult, PublicKey};

/// Weight matrix for routing decisions
#[derive(Clone, Debug)]
pub struct WeightMatrix {
    /// For each node, list of (neighbor_index, weight) pairs
    /// All weights for a node sum to 2^32
    pub adjacency: Vec<Vec<(usize, u32)>>,
}

impl WeightMatrix {
    /// Create a new weight matrix
    pub fn new(num_nodes: usize) -> Self {
        Self {
            adjacency: vec![Vec::new(); num_nodes],
        }
    }

    /// Create a uniform weight matrix where each node has equal weight to all others
    pub fn uniform(num_nodes: usize, total_weight: u64) -> Self {
        let mut matrix = Self::new(num_nodes);

        if num_nodes <= 1 {
            return matrix;
        }

        let weight_per_neighbor = (total_weight / (num_nodes - 1) as u64) as u32;
        let mut remainder = (total_weight % (num_nodes - 1) as u64) as u32;

        for i in 0..num_nodes {
            for j in 0..num_nodes {
                if i != j {
                    let mut weight = weight_per_neighbor;
                    // Distribute remainder to first few neighbors
                    if remainder > 0 {
                        weight += 1;
                        remainder -= 1;
                    }
                    matrix.adjacency[i].push((j, weight));
                }
            }
        }

        matrix
    }

    /// Add an edge with a specific weight
    pub fn add_edge(&mut self, from: usize, to: usize, weight: u32) {
        if from < self.adjacency.len() {
            self.adjacency[from].push((to, weight));
        }
    }

    /// Get weights for a specific node
    pub fn get_weights(&self, node_index: usize) -> &[(usize, u32)] {
        if node_index < self.adjacency.len() {
            &self.adjacency[node_index]
        } else {
            &[]
        }
    }
}

/// Select next hop based on routing value ρ and weight matrix
///
/// Algorithm:
/// 1. Get weights for current node from weight matrix
/// 2. Treat weights as cumulative distribution
/// 3. ρ (32-bit value from PRF) maps to range [0, 2^32)
/// 4. Find which weight bucket ρ falls into
///
/// Example:
/// Weights: [(node0, 1B), (node1, 2B), (node2, 1B)]  (sum = 2^32)
/// Ranges:  [0, 1B) -> node0, [1B, 3B) -> node1, [3B, 2^32) -> node2
/// If ρ = 2.5B, select node1
///
/// # Arguments
/// * `rho` - 32-bit routing value from PRF
/// * `weight_matrix` - Weight matrix
/// * `all_public_keys` - List of all node public keys
///
/// # Returns
/// (index, public_key) of selected next hop
pub fn select_next_hop(
    rho: u32,
    weight_matrix: &WeightMatrix,
    all_public_keys: &[PublicKey],
) -> ProtocolResult<(usize, PublicKey)> {
    // For now, simple implementation:
    // Get weights for "current node" (assume node 0 for simplicity)
    // TODO: Track actual current node in message

    if all_public_keys.is_empty() {
        return Err(ProtocolError::InvalidWeightSelection);
    }

    // Get weights for first node (placeholder)
    let weights = weight_matrix.get_weights(0);

    if weights.is_empty() {
        return Err(ProtocolError::InvalidWeightSelection);
    }

    // Convert ρ (u32) to position in cumulative distribution
    // ρ is in range [0, 2^32), weights sum to 2^32

    let mut cumulative: u64 = 0;
    for &(node_idx, weight) in weights {
        cumulative += weight as u64;
        if (rho as u64) < cumulative {
            // Found the bucket
            if node_idx >= all_public_keys.len() {
                return Err(ProtocolError::InvalidWeightSelection);
            }
            return Ok((node_idx, all_public_keys[node_idx].clone()));
        }
    }

    // If we get here, ρ didn't fall into any bucket (shouldn't happen if weights sum correctly)
    // Default to last neighbor
    let (last_idx, _) = weights.last().unwrap();
    if *last_idx >= all_public_keys.len() {
        return Err(ProtocolError::InvalidWeightSelection);
    }
    Ok((*last_idx, all_public_keys[*last_idx].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use crate::WEIGHT_SUM;
    use rand::thread_rng;

    #[test]
    fn test_weight_matrix_uniform() {
        let matrix = WeightMatrix::uniform(3, WEIGHT_SUM);

        // Each node should have 2 neighbors (all others)
        for i in 0..3 {
            assert_eq!(matrix.get_weights(i).len(), 2);
        }

        // Check weights sum to WEIGHT_SUM
        let weights = matrix.get_weights(0);
        let sum: u64 = weights.iter().map(|(_, w)| *w as u64).sum();
        assert_eq!(sum, WEIGHT_SUM);
    }

    #[test]
    fn test_select_next_hop() {
        let mut rng = thread_rng();

        // Create 3 nodes
        let (_, pk0) = keygen(&mut rng);
        let (_, pk1) = keygen(&mut rng);
        let (_, pk2) = keygen(&mut rng);
        let all_pks = vec![pk0, pk1, pk2];

        // Create uniform weight matrix
        let matrix = WeightMatrix::uniform(3, WEIGHT_SUM);

        // Test selection with different ρ values
        let (idx1, _) = select_next_hop(0, &matrix, &all_pks).unwrap();
        let (idx2, _) = select_next_hop(u32::MAX / 2, &matrix, &all_pks).unwrap();
        let (idx3, _) = select_next_hop(u32::MAX, &matrix, &all_pks).unwrap();

        // All selections should be valid
        assert!(idx1 < 3);
        assert!(idx2 < 3);
        assert!(idx3 < 3);

        println!("Selected nodes: {}, {}, {}", idx1, idx2, idx3);
    }

    #[test]
    fn test_weight_matrix_custom() {
        let mut matrix = WeightMatrix::new(3);

        // Node 0 -> Node 1 with weight 3B, Node 2 with weight 1B
        matrix.add_edge(0, 1, 3_000_000_000);
        matrix.add_edge(0, 2, 1_000_000_000);

        let weights = matrix.get_weights(0);
        assert_eq!(weights.len(), 2);
        assert_eq!(weights[0], (1, 3_000_000_000));
        assert_eq!(weights[1], (2, 1_000_000_000));
    }
}
