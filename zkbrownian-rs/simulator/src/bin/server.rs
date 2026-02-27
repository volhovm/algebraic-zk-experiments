//! Server binary for the ZK Brownian Android benchmark simulator
//!
//! Runs on the PC, emulates all non-phone nodes, orchestrates routing,
//! collects benchmark timings from the phone.
//!
//! Uses a single WebSocket endpoint (/ws) for all phone communication.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::extract::State;
use axum::extract::WebSocketUpgrade;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rand::thread_rng;
use tokio::sync::{Mutex, Notify};

use zkbrownian::protocol::{
    forward_batch, generate_random_state, spawn, verify_batch, GeneratedState, UserView,
};
use zkbrownian::types::{Message, PublicKey, PublicParams, ScalarField, WeightCommitment};
use zkbrownian_simulator::serialization::{
    serialize_public_params, serialize_user_view, serialize_verification_data,
};
use zkbrownian_simulator::{BenchmarkReport, PhoneMsg, ServerMsg};

#[derive(Parser)]
#[command(name = "zkbrownian-server")]
#[command(about = "Server for ZK Brownian Android benchmark")]
struct Cli {
    /// Number of nodes in the network
    #[arg(long, default_value = "5")]
    num_nodes: usize,

    /// Which node index the phone will play
    #[arg(long, default_value = "0")]
    phone_node: usize,

    /// Number of packets each node spawns
    #[arg(long, default_value = "16")]
    packets_per_node: usize,

    /// Time-to-live: messages at this hop count are finalized
    #[arg(long, default_value = "5")]
    ttl: usize,

    /// Server port
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Directory to write setup data files
    #[arg(long, default_value = "./setup-data")]
    setup_dir: String,

    /// Maximum batch size for processing / sending
    #[arg(long, default_value = "64")]
    max_batch_size: usize,

    /// Server-side verification mode: clients skip verify, server verifies forwarded outputs
    #[arg(long, default_value = "false")]
    server_verification: bool,
}

/// Server state shared across handlers and the background processing loop
struct ServerState {
    pp: Arc<PublicParams>,
    generated_state: GeneratedState,
    phone_node: usize,
    ttl: usize,
    packets_per_node: usize,

    /// Per-node message queues: queues[i] contains messages addressed to node i
    queues: Vec<Vec<Message>>,

    /// Total messages expected = num_nodes * packets_per_node
    total_expected: usize,
    /// Messages that have completed (reached TTL, finalized)
    total_completed: usize,
    /// Per-node count of finalized packets
    finalized_per_node: Vec<usize>,
    /// Whether the protocol is done
    done: bool,
    /// Whether /start has been called
    started: bool,

    /// Verification data
    merkle_root: ScalarField,
    all_public_keys: Vec<PublicKey>,
    weight_commitment: WeightCommitment,

    /// Maximum batch size for processing / sending
    max_batch_size: usize,

    /// Server-side verification mode
    server_verification: bool,

    /// Config bytes to send to phone on first notification (set when Start is received)
    pending_config: Option<Vec<u8>>,

    /// Notified when phone's queue gets new messages
    phone_notify: Arc<Notify>,
    /// Shutdown signal — notified after benchmark report is received
    shutdown: Arc<tokio::sync::Notify>,
}

type SharedState = Arc<Mutex<ServerState>>;

/// GET /ws — upgrade to WebSocket
async fn handle_ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    ws.max_frame_size(256 * 1024 * 1024)
        .max_message_size(256 * 1024 * 1024)
        .on_upgrade(move |socket| handle_ws_connection(socket, state))
}

/// Handle the WebSocket connection with the phone
async fn handle_ws_connection(socket: WebSocket, state: SharedState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let phone_notify = state.lock().await.phone_notify.clone();
    let shutdown = state.lock().await.shutdown.clone();

    // Writer task: pushes work to phone when phone_notify fires
    let state_writer = state.clone();
    let writer_handle = tokio::spawn(async move {
        loop {
            phone_notify.notified().await;

            // Send pending config first if any
            {
                let mut s = state_writer.lock().await;
                if let Some(config_bytes) = s.pending_config.take() {
                    drop(s);
                    if ws_sender
                        .send(WsMessage::Binary(config_bytes.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
            }

            let msg = {
                let mut s = state_writer.lock().await;
                let phone_node = s.phone_node;
                let max_batch = s.max_batch_size;
                let queue_len = s.queues[phone_node].len();

                if queue_len > 0 {
                    let drain_count = queue_len.min(max_batch);
                    let messages: Vec<Message> =
                        s.queues[phone_node].drain(..drain_count).collect();
                    let remaining = s.queues[phone_node].len();
                    let is_done = s.done;

                    if remaining > 0 || (is_done && remaining == 0) {
                        // Self-notify: more messages to send, or need to send Done next
                        s.phone_notify.notify_one();
                    }

                    println!(
                        "  [ws] Sending {} messages to phone ({} remaining, {} / {} completed)",
                        messages.len(),
                        remaining,
                        s.total_completed,
                        s.total_expected
                    );
                    Some(ServerMsg::Work(messages))
                } else if s.done {
                    Some(ServerMsg::Done)
                } else {
                    None
                }
            };

            if let Some(server_msg) = msg {
                let is_done = matches!(server_msg, ServerMsg::Done);
                let bytes = bincode::serialize(&server_msg).expect("Failed to serialize ServerMsg");
                if ws_sender
                    .send(WsMessage::Binary(bytes.into()))
                    .await
                    .is_err()
                {
                    break;
                }
                if is_done {
                    break;
                }
            }
        }
    });

    // Reader loop: receives PhoneMsg from phone
    while let Some(Ok(ws_msg)) = ws_receiver.next().await {
        let data = match ws_msg {
            WsMessage::Binary(b) => b,
            WsMessage::Close(_) => break,
            _ => continue,
        };

        let phone_msg: PhoneMsg = match bincode::deserialize(&data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("  [ws] Failed to deserialize PhoneMsg: {}", e);
                continue;
            }
        };

        match phone_msg {
            PhoneMsg::Start => {
                let mut s = state.lock().await;
                if !s.started {
                    s.started = true;
                    println!("\n=== Phone connected via WebSocket, starting protocol ===");

                    // Send config to phone so it knows how many packets to spawn
                    let config_msg = ServerMsg::Config {
                        packets_per_node: s.packets_per_node,
                        phone_node: s.phone_node,
                        ttl: s.ttl,
                    };
                    let config_bytes =
                        bincode::serialize(&config_msg).expect("Failed to serialize Config");
                    // Send directly on the reader's half isn't possible, so
                    // push a synthetic notification — but we need the writer to
                    // send it.  Easiest: store a pending config and have the
                    // writer pick it up.  Actually let's just use the ws_sender
                    // from here — but we don't have it.
                    //
                    // Store pending config in state for the writer to pick up.
                    s.pending_config = Some(config_bytes);
                    s.phone_notify.notify_one();
                }
            }
            PhoneMsg::Result(result) => {
                // Extract verification data from state before potentially verifying
                let (server_verification, merkle_root, weight_commitment, all_public_keys, pp) = {
                    let s = state.lock().await;
                    (
                        s.server_verification,
                        s.merkle_root,
                        s.weight_commitment.clone(),
                        s.all_public_keys.clone(),
                        s.pp.clone(),
                    )
                };

                // In server-verification mode, verify forwarded messages from phone
                // before distributing to queues
                // TODO: future optimization — only verify the newest hop (incremental verification)
                if server_verification && !result.results.is_empty() {
                    let (forwarded_msgs, _destinations): (Vec<Message>, Vec<usize>) =
                        result.results.iter().cloned().unzip();
                    let all_valid = verify_batch(
                        &forwarded_msgs,
                        merkle_root,
                        &weight_commitment,
                        &all_public_keys,
                        &pp,
                    )
                    .expect("Server verification of phone forwarded output failed");
                    assert!(
                        all_valid,
                        "Server verification failed for phone forwarded output"
                    );
                }

                let mut s = state.lock().await;

                // Count finalized messages
                let phone_node = s.phone_node;
                s.total_completed += result.messages_finalized;
                s.finalized_per_node[phone_node] += result.messages_finalized;

                // Distribute forwarded messages
                let mut forwarded = 0;
                let mut phone_got_messages = false;
                for (message, next_node) in result.results {
                    if next_node == phone_node {
                        phone_got_messages = true;
                    }
                    s.queues[next_node].push(message);
                    forwarded += 1;
                }

                println!(
                    "  [ws-result] Phone batch: {} forwarded, {} finalized (verify={:.1}ms, fwd={:.1}ms) [{} / {} completed]",
                    forwarded,
                    result.messages_finalized,
                    result.verify_time_ms,
                    result.forward_time_ms,
                    s.total_completed,
                    s.total_expected,
                );

                if s.total_completed >= s.total_expected {
                    s.done = true;
                    print_finalized_summary(&s);
                    s.phone_notify.notify_one();
                } else if phone_got_messages {
                    s.phone_notify.notify_one();
                }
            }
            PhoneMsg::Benchmark(report) => {
                print_benchmark_report(&report);
                // Trigger shutdown
                shutdown.notify_one();
                break;
            }
        }
    }

    // Clean up writer task
    writer_handle.abort();
}

fn print_benchmark_report(report: &BenchmarkReport) {
    let safe_div = |n: f64, d: usize| -> f64 {
        if d > 0 {
            n / d as f64
        } else {
            0.0
        }
    };

    println!("\n=== Benchmark Report from Phone ===");
    println!("  Batches: {}", report.num_batches);
    println!("  Messages verified: {}", report.total_messages_verified);
    println!("  Messages forwarded: {}", report.total_messages_forwarded);
    println!(
        "  Messages finalized (reached TTL): {}",
        report.total_messages_finalized
    );

    println!("\n  --- Crypto ---");
    println!(
        "  Verify:  {:.1} ms total, {:.2} ms/msg",
        report.total_verify_time_ms,
        safe_div(report.total_verify_time_ms, report.total_messages_verified),
    );
    println!(
        "  Forward: {:.1} ms total, {:.2} ms/msg",
        report.total_forward_time_ms,
        safe_div(
            report.total_forward_time_ms,
            report.total_messages_forwarded
        ),
    );

    println!("\n  --- WS/network ---");
    println!("  WS recv:   {:.1} ms total", report.total_ws_recv_ms);
    println!(
        "  WS send:   {:.1} ms total, {:.1} ms/batch",
        report.total_ws_send_ms,
        safe_div(report.total_ws_send_ms, report.num_batches),
    );

    println!("\n  --- Serialization ---");
    println!("  Recv deser:   {:.1} ms total", report.total_recv_deser_ms);
    println!(
        "  Result ser:   {:.1} ms total, {:.1} ms/batch",
        report.total_result_ser_ms,
        safe_div(report.total_result_ser_ms, report.num_batches),
    );

    if !report.per_batch.is_empty() {
        println!("\n  --- Per-batch breakdown ---");
        for (i, bt) in report.per_batch.iter().enumerate() {
            println!(
                "    [{:>3}] verified={:>4}  verify={:.1}ms ({:.2}ms/msg)  fwd={:.1}ms ({:.2}ms/msg)  ser={:.1}ms  ws={:.1}ms  finalized={}",
                i + 1,
                bt.batch_size,
                bt.verify_time_ms,
                safe_div(bt.verify_time_ms, bt.batch_size),
                bt.forward_time_ms,
                safe_div(bt.forward_time_ms, bt.messages_forwarded),
                bt.result_ser_ms,
                bt.result_ws_ms,
                bt.messages_finalized,
            );
        }
    }
}

/// GET /status — progress info
async fn handle_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let s = state.lock().await;
    let queue_sizes: Vec<usize> = s.queues.iter().map(|q| q.len()).collect();
    Json(serde_json::json!({
        "total_expected": s.total_expected,
        "total_completed": s.total_completed,
        "queue_sizes": queue_sizes,
        "done": s.done,
        "started": s.started,
    }))
}

fn print_finalized_summary(s: &ServerState) {
    println!("\n=== All messages completed! ===");
    println!("\n  Finalized packets per node:");
    let total: usize = s.finalized_per_node.iter().sum();
    for (node_idx, &count) in s.finalized_per_node.iter().enumerate() {
        let is_phone = if node_idx == s.phone_node {
            " (phone)"
        } else {
            ""
        };
        println!("    Node {}: {}{}", node_idx, count, is_phone);
    }
    println!("    Total: {} (expected {})", total, s.total_expected);
}

/// Background processing loop: process non-phone nodes sequentially
async fn processing_loop(state: SharedState) {
    // Wait for start
    loop {
        {
            let s = state.lock().await;
            if s.started {
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let phone_notify = state.lock().await.phone_notify.clone();

    // Spawn initial packets into queues
    {
        let mut s = state.lock().await;
        let mut rng = thread_rng();

        println!("\nSpawning packets...");
        let num_nodes = s.generated_state.users_view.len();
        let packets_per_node = s.total_expected / num_nodes;

        let phone_node = s.phone_node;
        for user_idx in 0..num_nodes {
            if user_idx == phone_node {
                println!(
                    "  Node {} (phone) — will spawn {} packets locally",
                    user_idx, packets_per_node
                );
                continue;
            }
            let sk = s.generated_state.users_view[user_idx].secret_key.clone();
            let pk = s.generated_state.users_view[user_idx].public_key.clone();
            let session_id = 1000 + user_idx;

            for packet_id in 0..packets_per_node {
                let message = spawn(&sk, &pk, packet_id as u32, session_id as u64, &mut rng)
                    .expect("Failed to spawn message");

                s.queues[user_idx].push(message);
            }
            println!(
                "  Node {} spawned {} packets (session {})",
                user_idx, packets_per_node, session_id
            );
        }
        println!(
            "  Total: {} packets spawned on server, {} will be spawned on phone",
            (num_nodes - 1) * packets_per_node,
            packets_per_node
        );
    }

    // Main processing loop
    let mut round = 0;
    loop {
        let done = {
            let s = state.lock().await;
            s.done
        };
        if done {
            break;
        }

        round += 1;

        // Get config from state
        let (num_nodes, phone_node, ttl, max_batch, server_verification) = {
            let s = state.lock().await;
            (
                s.queues.len(),
                s.phone_node,
                s.ttl,
                s.max_batch_size,
                s.server_verification,
            )
        };

        let round_start = Instant::now();
        let mut round_forwards = 0;
        let mut round_finalized = 0;

        // Process each non-phone node sequentially
        for node_idx in 0..num_nodes {
            if node_idx == phone_node {
                continue;
            }

            // Drain at most max_batch_size from this node's queue
            let messages: Vec<Message> = {
                let mut s = state.lock().await;
                let drain_count = s.queues[node_idx].len().min(max_batch);
                s.queues[node_idx].drain(..drain_count).collect()
            };

            if messages.is_empty() {
                continue;
            }

            // Batch verify input messages (skipped in server-verification mode)
            let (merkle_root, weight_commitment, all_public_keys, pp) = {
                let s = state.lock().await;
                (
                    s.merkle_root,
                    s.weight_commitment.clone(),
                    s.all_public_keys.clone(),
                    s.pp.clone(),
                )
            };

            if !server_verification {
                let all_valid = verify_batch(
                    &messages,
                    merkle_root,
                    &weight_commitment,
                    &all_public_keys,
                    &pp,
                )
                .expect("Batch verification failed");
                assert!(all_valid, "Node {} received invalid messages", node_idx);
            }

            // Separate: messages at TTL → finalized, rest → forward
            let mut to_forward = Vec::new();
            let mut finalized = 0;

            for msg in messages {
                if msg.hop_count() >= ttl {
                    finalized += 1;
                } else {
                    to_forward.push(msg);
                }
            }

            round_finalized += finalized;

            // Batch forward remaining
            if !to_forward.is_empty() {
                let user_view = {
                    let s = state.lock().await;
                    s.generated_state.users_view[node_idx].clone()
                };

                let batch_inputs: Vec<(&UserView, &Message)> =
                    to_forward.iter().map(|msg| (&user_view, msg)).collect();

                // Scope rng so it doesn't live across await
                let batch_results = {
                    let mut rng = thread_rng();
                    forward_batch(&pp, &batch_inputs, &mut rng).expect("Batch forward failed")
                };

                // In server-verification mode, verify forwarded output before distributing
                // TODO: future optimization — only verify the newest hop (incremental verification)
                if server_verification {
                    let (forwarded_msgs, _destinations): (Vec<Message>, Vec<usize>) =
                        batch_results.iter().cloned().unzip();
                    let all_valid = verify_batch(
                        &forwarded_msgs,
                        merkle_root,
                        &weight_commitment,
                        &all_public_keys,
                        &pp,
                    )
                    .expect("Server verification of forwarded output failed");
                    assert!(
                        all_valid,
                        "Server verification failed for node {} forwarded output",
                        node_idx
                    );
                }

                // Distribute results to destination node queues
                let mut phone_got_messages = false;
                {
                    let mut s = state.lock().await;
                    for (new_message, next_node) in batch_results {
                        if next_node == phone_node {
                            phone_got_messages = true;
                        }
                        s.queues[next_node].push(new_message);
                        round_forwards += 1;
                    }
                }
                if phone_got_messages {
                    phone_notify.notify_one();
                }
            }

            // Update completed count
            {
                let mut s = state.lock().await;
                s.total_completed += finalized;
                s.finalized_per_node[node_idx] += finalized;
                if s.total_completed >= s.total_expected {
                    s.done = true;
                    print_finalized_summary(&s);
                    drop(s);
                    phone_notify.notify_one();
                    return;
                }
            }
        }

        let round_elapsed = round_start.elapsed();
        let (total_completed, total_expected, phone_queue_size) = {
            let s = state.lock().await;
            (
                s.total_completed,
                s.total_expected,
                s.queues[s.phone_node].len(),
            )
        };

        if round_forwards > 0 || round_finalized > 0 {
            println!(
                "  [round {:>3}] {} forwards, {} finalized in {:.1}ms (phone_queue={}, {}/{} completed)",
                round,
                round_forwards,
                round_finalized,
                round_elapsed.as_secs_f64() * 1000.0,
                phone_queue_size,
                total_completed,
                total_expected,
            );
        }

        // Yield to other tasks
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("=== ZK Brownian Simulator Server ===");
    println!("  Nodes: {}", cli.num_nodes);
    println!("  Phone node: {}", cli.phone_node);
    println!("  Packets per node: {}", cli.packets_per_node);
    println!("  TTL: {}", cli.ttl);
    println!("  Port: {}", cli.port);
    println!("  Setup dir: {}", cli.setup_dir);
    println!("  Server verification: {}", cli.server_verification);

    assert!(
        cli.phone_node < cli.num_nodes,
        "phone_node must be < num_nodes"
    );

    // Step 1: Generate parameters and state
    println!("\nGenerating public parameters...");
    let start = Instant::now();
    let mut rng = thread_rng();
    let pp = PublicParams::generate(cli.num_nodes, 10, &mut rng).expect("Failed to generate PP");
    println!("  PP generated in {:.2}s", start.elapsed().as_secs_f64());

    println!("Generating random state...");
    let start = Instant::now();
    let generated_state = generate_random_state(&pp, cli.num_nodes, &mut rng);
    println!("  State generated in {:.2}s", start.elapsed().as_secs_f64());

    // Extract verification data
    let merkle_root = generated_state.protocol_state.merkle_tree.root;
    let all_public_keys: Vec<PublicKey> = generated_state
        .users_view
        .iter()
        .map(|uv| uv.public_key.clone())
        .collect();
    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    // Step 2: Serialize setup data for phone
    println!("\nSerializing setup data...");
    std::fs::create_dir_all(&cli.setup_dir).expect("Failed to create setup dir");

    let start = Instant::now();
    let pp_bytes = serialize_public_params(&pp);
    let pp_path = format!("{}/public_params.bin", cli.setup_dir);
    std::fs::write(&pp_path, &pp_bytes).expect("Failed to write PP");
    println!("  PublicParams: {} bytes -> {}", pp_bytes.len(), pp_path);

    let uv_bytes = serialize_user_view(&generated_state.users_view[cli.phone_node]);
    let uv_path = format!("{}/user_view.bin", cli.setup_dir);
    std::fs::write(&uv_path, &uv_bytes).expect("Failed to write UserView");
    println!(
        "  UserView[{}]: {} bytes -> {}",
        cli.phone_node,
        uv_bytes.len(),
        uv_path
    );

    let vd_bytes = serialize_verification_data(&merkle_root, &all_public_keys);
    let vd_path = format!("{}/verification_data.bin", cli.setup_dir);
    std::fs::write(&vd_path, &vd_bytes).expect("Failed to write verification data");
    println!(
        "  VerificationData: {} bytes -> {}",
        vd_bytes.len(),
        vd_path
    );

    println!("  Serialization took {:.2}s", start.elapsed().as_secs_f64());

    println!("\n  Setup files written.");
    println!("  To deploy to phone:");
    println!("    adb push {} /data/local/tmp/zkbrownian/", cli.setup_dir);

    // Step 3: Create server state
    let total_expected = cli.num_nodes * cli.packets_per_node;
    let pp = Arc::new(pp);
    let queues: Vec<Vec<Message>> = (0..cli.num_nodes).map(|_| Vec::new()).collect();

    let phone_notify = Arc::new(Notify::new());
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let server_state = ServerState {
        pp: pp.clone(),
        generated_state,
        phone_node: cli.phone_node,
        ttl: cli.ttl,
        packets_per_node: cli.packets_per_node,
        queues,
        total_expected,
        total_completed: 0,
        finalized_per_node: vec![0; cli.num_nodes],
        done: false,
        started: false,
        max_batch_size: cli.max_batch_size,
        server_verification: cli.server_verification,
        pending_config: None,
        phone_notify,
        merkle_root,
        all_public_keys,
        weight_commitment,
        shutdown: shutdown.clone(),
    };

    let shared_state: SharedState = Arc::new(Mutex::new(server_state));

    // Step 4: Start background processing loop
    let state_clone = shared_state.clone();
    tokio::spawn(async move {
        processing_loop(state_clone).await;
    });

    // Step 5: Start server with /ws and /status
    let app = Router::new()
        .route("/ws", get(handle_ws_upgrade))
        .route("/status", get(handle_status))
        .with_state(shared_state);

    let addr = format!("0.0.0.0:{}", cli.port);
    println!("\nServer listening on {}", addr);
    println!("Waiting for phone to connect via WebSocket at /ws ...");
    println!(
        "Total: {} messages ({} nodes x {} packets, TTL={})",
        total_expected, cli.num_nodes, cli.packets_per_node, cli.ttl
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.notified().await;
            println!("\n=== Server shutting down ===");
        })
        .await
        .expect("Server error");
}
