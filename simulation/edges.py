
#!/usr/bin/env python3
"""
Social Network Packet Forwarding Simulation

- Builds a directed social graph with community structure (SBM) and partial reciprocity.
- Assigns edge weights so that each node's outgoing weights sum to 1.
- Simulates packet forwarding where each node originates N packets per epoch,
  packets are forwarded for a fixed number of steps following the edge weight distribution.
- Repeats for E epochs and reports aggregate stats.

Author: (you)
"""

from __future__ import annotations
import argparse
import math
import random
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

import numpy as np
import networkx as nx


# -----------------------------
# Graph generation
# -----------------------------
def _random_partition_sizes(num_nodes: int, k_communities: int, dispersion: float = 1.0, rng: np.random.Generator | None = None) -> List[int]:
    """
    Create community sizes that sum to num_nodes. Uses a Dirichlet to add variation.

    dispersion ~ 1.0 is near-uniform; lower values add more skew.
    """
    rng = rng or np.random.default_rng()
    alpha = np.array([dispersion] * k_communities, dtype=float)
    proportions = rng.dirichlet(alpha)
    sizes = np.maximum(1, np.round(proportions * num_nodes).astype(int))
    # Adjust to match exact total
    diff = num_nodes - int(sizes.sum())
    # Fix total with small adjustments
    i = 0
    while diff != 0:
        j = i % k_communities
        if diff > 0:
            sizes[j] += 1
            diff -= 1
        else:
            # avoid shrinking a community to zero
            if sizes[j] > 1:
                sizes[j] -= 1
                diff += 1
        i += 1
    return sizes.tolist()


def generate_social_network(
    num_nodes: int = 500,
    num_communities: int = 6,
    intra_p: float = 0.08,
    inter_p: float = 0.005,
    reciprocity: float = 0.35,
    extra_edge_factor: float = 0.05,
    community_dispersion: float = 1.0,
    seed: int | None = 42,
) -> nx.DiGraph:
    """
    Generate a directed social network with community structure and partial reciprocity.

    Steps:
      1) Construct an undirected Stochastic Block Model (SBM) with num_communities.
      2) Convert to a directed graph by orienting each edge:
         - With probability `reciprocity`, add both directions.
         - Otherwise, add a single direction at random.
      3) Add a small number of extra directed edges using a simple preferential attachment heuristic.
      4) Ensure every node has at least one outgoing edge (connect to random node if needed).
      5) Assign and normalize outgoing edge weights per node (summing to 1).

    Parameters
    ----------
    num_nodes : int
        Number of nodes.
    num_communities : int
        Number of communities.
    intra_p : float
        Edge probability within a community (undirected SBM).
    inter_p : float
        Edge probability between communities (undirected SBM).
    reciprocity : float
        Probability that an undirected tie becomes reciprocal (both directions).
    extra_edge_factor : float
        Fraction of |E| to add as extra directed edges (light preferential attachment).
    community_dispersion : float
        Dirichlet dispersion for community size variability (1.0 ~ near-uniform).
    seed : int | None
        Random seed for reproducibility.

    Returns
    -------
    G : nx.DiGraph
        Directed graph with edge attribute 'weight' normalized per node.
    """
    rng = np.random.default_rng(seed)
    py_random = random.Random(seed)

    # 1) Community sizes
    sizes = _random_partition_sizes(num_nodes, num_communities, dispersion=community_dispersion, rng=rng)

    # 2) Probability matrix
    p = np.full((num_communities, num_communities), inter_p, dtype=float)
    np.fill_diagonal(p, intra_p)

    # 3) Undirected SBM
    G_undirected = nx.stochastic_block_model(sizes, p, seed=seed, directed=False, selfloops=False)

    # 4) Convert to directed with partial reciprocity
    G = nx.DiGraph()
    G.add_nodes_from(G_undirected.nodes())

    for u, v in G_undirected.edges():
        if rng.random() < reciprocity:
            G.add_edge(u, v)
            G.add_edge(v, u)
        else:
            if rng.random() < 0.5:
                G.add_edge(u, v)
            else:
                G.add_edge(v, u)

    # 5) Add extra directed edges (light preferential attachment flavor)
    base_m = max(1, int(extra_edge_factor * max(1, G.number_of_edges())))
    # create preference lists (degree+1 to avoid zero-prob)
    out_pref = np.array([G.out_degree(n) + 1 for n in G.nodes()], dtype=float)
    in_pref = np.array([G.in_degree(n) + 1 for n in G.nodes()], dtype=float)
    out_pref /= out_pref.sum()
    in_pref /= in_pref.sum()

    node_list = list(G.nodes())
    node_index = {n: i for i, n in enumerate(node_list)}

    trials = 0
    added = 0
    max_trials = base_m * 20  # avoid long loops
    while added < base_m and trials < max_trials:
        src = node_list[rng.choice(len(node_list), p=out_pref)]
        dst = node_list[rng.choice(len(node_list), p=in_pref)]
        if src != dst and not G.has_edge(src, dst):
            G.add_edge(src, dst)
            added += 1
        trials += 1

    # 6) Ensure every node has at least one outgoing edge
    for n in G.nodes():
        if G.out_degree(n) == 0:
            # connect to a random other node
            candidates = node_list.copy()
            candidates.remove(n)
            target = py_random.choice(candidates)
            G.add_edge(n, target)

    # 7) Assign and normalize outgoing edge weights via Dirichlet
    for n in G.nodes():
        succs = list(G.successors(n))
        k = len(succs)
        # draw random positive weights then normalize (Dirichlet)
        w = rng.dirichlet(np.ones(k))
        for s, w_i in zip(succs, w):
            G[n][s]["weight"] = float(w_i)

        # numerical guard to ensure sum==1 exactly
        # (due to float rounding, adjust the largest)
        total = sum(G[n][s]["weight"] for s in succs)
        if not math.isclose(total, 1.0):
            # adjust the max edge to make sum exactly 1
            max_s = max(succs, key=lambda x: G[n][x]["weight"])
            G[n][max_s]["weight"] += 1.0 - total

    return G


# -----------------------------
# Simulation
# -----------------------------
def _build_sampling_structures(G: nx.DiGraph):
    """
    Precompute neighbor arrays and cumulative weights for fast sampling.
    Returns:
        neigh: dict[node] -> np.array of neighbors
        cdf: dict[node] -> np.array cumulative sum of weights (monotonic increasing ending at 1.0)
    """
    neigh = {}
    cdf = {}
    for n in G.nodes():
        succs = list(G.successors(n))
        weights = np.array([G[n][s]["weight"] for s in succs], dtype=float)
        # numerical guard
        s = weights.sum()
        if s <= 0:
            # fallback: uniform
            weights = np.ones_like(weights) / len(weights)
        else:
            weights /= s
        neigh[n] = np.array(succs, dtype=int)
        cdf[n] = np.cumsum(weights)
        cdf[n][-1] = 1.0  # ensure exact 1.0
    return neigh, cdf


def _sample_next(r: float, neighbors: np.ndarray, cdf: np.ndarray) -> int:
    """Binary search to sample from CDF"""
    idx = int(np.searchsorted(cdf, r, side="left"))
    idx = min(idx, len(neighbors) - 1)
    return int(neighbors[idx])


def simulate_forwarding(
    G: nx.DiGraph,
    n_packets_per_node: int = 5,
    steps_per_packet: int = 10,
    epochs: int = 10,
    teleport: float = 0.0,
    seed: int | None = 123,
) -> Dict[str, any]:
    """
    Simulate packet forwarding.

    For each epoch:
      - Each node originates n_packets_per_node packets.
      - Each packet is forwarded for steps_per_packet hops.
      - At each hop, choose next node according to outgoing weights. If teleport>0,
        with probability `teleport` jump to a random node (helps avoid sinks, optional).

    Returns a dictionary with:
      - node_visits: Counter of how many times each node was visited (across all epochs).
      - edge_flows: Counter of how many times each directed edge was traversed.
      - epochs: number of epochs
      - total_packets: total number of packets originated
      - steps_per_packet

    Notes:
      - Nodes are "visited" at each hop; origins also count as visited at step 0.
    """
    rng = np.random.default_rng(seed)
    node_visits = Counter()
    edge_flows = Counter()

    nodes = list(G.nodes())
    neigh, cdf = _build_sampling_structures(G)

    total_packets = epochs * len(nodes) * n_packets_per_node

    for _e in range(epochs):
        for s in nodes:
            for _p in range(n_packets_per_node):
                curr = s
                # count origin as visited
                node_visits[curr] += 1
                for _step in range(steps_per_packet):
                    # Optionally teleport
                    if teleport > 0.0 and rng.random() < teleport:
                        nxt = int(rng.choice(nodes))
                    else:
                        # sample neighbor according to weights
                        # all nodes guaranteed to have >=1 outgoing edge
                        r = rng.random()
                        nxt = _sample_next(r, neigh[curr], cdf[curr])

                    edge_flows[(curr, nxt)] += 1
                    curr = nxt
                    node_visits[curr] += 1

    return {
        "node_visits": node_visits,
        "edge_flows": edge_flows,
        "epochs": epochs,
        "total_packets": total_packets,
        "steps_per_packet": steps_per_packet,
    }


# -----------------------------
# Utilities and CLI
# -----------------------------
def check_weight_normalization(G: nx.DiGraph, atol: float = 1e-9) -> Tuple[int, int]:
    """
    Check that outgoing weights per node sum to ~1.
    Returns: (ok_count, bad_count)
    """
    ok = 0
    bad = 0
    for n in G.nodes():
        succs = list(G.successors(n))
        s = sum(G[n][s]["weight"] for s in succs)
        if math.isclose(s, 1.0, rel_tol=0, abs_tol=atol):
            ok += 1
        else:
            bad += 1
    return ok, bad


def print_top_k(counter: Counter, k: int = 10, label: str = "items"):
    print(f"\nTop {k} {label}:")
    for i, (item, cnt) in enumerate(counter.most_common(k), 1):
        print(f"{i:>2}. {item} -> {cnt}")



import numpy as np

def compute_stationary_distribution(G):
    """
    Compute the stationary distribution π for a row-stochastic weighted DiGraph G.
    Returns a dict: node -> π[node]
    """
    # Ensure consistent node ordering
    nodes = list(G.nodes())
    n = len(nodes)

    # Build transition matrix P (row-stochastic)
    P = np.zeros((n, n))
    node_index = {node: i for i, node in enumerate(nodes)}

    for i, u in enumerate(nodes):
        succs = list(G.successors(u))
        for v in succs:
            j = node_index[v]
            P[i, j] = G[u][v]["weight"]

    # Transpose because right eigenvector of P^T is left eigenvector of P
    evals, evecs = np.linalg.eig(P.T)

    # eigenvalue 1
    idx = np.argmin(np.abs(evals - 1.0))
    stationary = np.real(evecs[:, idx])

    # normalize
    stationary /= stationary.sum()

    # enforce positivity
    stationary = np.abs(stationary)

    stationary /= stationary.sum()

    # return mapping
    return {nodes[i]: float(stationary[i]) for i in range(n)}


def main():
    parser = argparse.ArgumentParser(description="Simulate packet forwarding on a weighted directed social network.")
    parser.add_argument("--nodes", type=int, default=500, help="Number of nodes")
    parser.add_argument("--communities", type=int, default=6, help="Number of communities")
    parser.add_argument("--intra_p", type=float, default=0.08, help="Intra-community edge probability")
    parser.add_argument("--inter_p", type=float, default=0.005, help="Inter-community edge probability")
    parser.add_argument("--reciprocity", type=float, default=0.35, help="Probability of reciprocal directed ties")
    parser.add_argument("--extra_edge_factor", type=float, default=0.05, help="Fraction of edges to add as extra directed edges")
    parser.add_argument("--community_dispersion", type=float, default=1.0, help="Dirichlet dispersion for community sizes (1.0 ~ near-uniform)")
    parser.add_argument("--seed", type=int, default=42, help="Seed for graph generation")

    parser.add_argument("--packets_per_node", type=int, default=5, help="Packets originated by each node per epoch")
    parser.add_argument("--steps_per_packet", type=int, default=10, help="Forwarding steps per packet")
    parser.add_argument("--epochs", type=int, default=10, help="Number of epochs")
    parser.add_argument("--teleport", type=float, default=0.0, help="Teleport probability per hop (optional)")
    parser.add_argument("--sim_seed", type=int, default=123, help="Seed for simulation")

    parser.add_argument("--topk", type=int, default=10, help="How many top nodes/edges to print")
    args = parser.parse_args()

    # Build graph
    G = generate_social_network(
        num_nodes=args.nodes,
        num_communities=args.communities,
        intra_p=args.intra_p,
        inter_p=args.inter_p,
        reciprocity=args.reciprocity,
        extra_edge_factor=args.extra_edge_factor,
        community_dispersion=args.community_dispersion,
        seed=args.seed,
    )

    # Sanity check normalization
    ok, bad = check_weight_normalization(G)
    print(f"Graph built: |V|={G.number_of_nodes()} |E|={G.number_of_edges()}")
    print(f"Outgoing weight normalization: OK={ok}, BAD={bad}")

    # Simulate
    results = simulate_forwarding(
        G,
        n_packets_per_node=args.packets_per_node,
        steps_per_packet=args.steps_per_packet,
        epochs=args.epochs,
        teleport=args.teleport,
        seed=args.sim_seed,
    )

    # Report
    node_visits = results["node_visits"]
    edge_flows = results["edge_flows"]

    print(f"\nSimulation complete: epochs={results['epochs']}, total_packets={results['total_packets']}, steps_per_packet={results['steps_per_packet']}")

    # Top nodes by visits
    print_top_k(node_visits, k=args.topk, label="nodes by visits")

    # Top edges by flow
    print_top_k(edge_flows, k=args.topk, label="edges by traversals")



    # After simulation
    stationary = compute_stationary_distribution(G)

    # Convert to comparable numpy vectors
    nodes = list(G.nodes())
    sim_vector = np.array([node_visits[n] for n in nodes], dtype=float)
    sim_vector /= sim_vector.sum()

    theory_vector = np.array([stationary[n] for n in nodes])

    # Compute L1 error between empirical and theoretical distributions
    err = np.sum(np.abs(sim_vector - theory_vector))

    print("\n--- Steady State Validation ---")
    print("L1 difference between simulation and theoretical stationary distribution:", err)
    print("(closer to 0 means better convergence)")




if __name__ == "__main__":
    main()
