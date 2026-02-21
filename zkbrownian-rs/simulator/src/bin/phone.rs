//! Phone binary for the ZK Brownian Android benchmark simulator
//!
//! Cross-compiled for Android (aarch64-linux-android).
//! Connects to server via WebSocket. Crypto processing runs on a dedicated
//! thread, decoupled from network I/O via channels.

use std::time::{Duration, Instant};

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rand::thread_rng;

use zkbrownian::protocol::{forward_batch, spawn, verify_batch, UserView};
use zkbrownian::types::{Message, WeightCommitment};
use zkbrownian_simulator::serialization::{
    deserialize_public_params, deserialize_user_view, deserialize_verification_data,
};
use zkbrownian_simulator::{BatchForwardResult, BatchTiming, BenchmarkReport, PhoneMsg, ServerMsg};

#[derive(Parser)]
#[command(name = "zkbrownian-phone")]
#[command(about = "Phone client for ZK Brownian Android benchmark")]
struct Cli {
    /// Server URL (e.g. http://192.168.1.100:8080)
    #[arg(long)]
    server_url: String,

    /// Directory containing setup data files
    #[arg(long, default_value = "/data/local/tmp/zkbrownian")]
    setup_dir: String,

    /// Maximum batch size before processing
    #[arg(long, default_value = "64")]
    max_batch_size: usize,

    /// Batch timeout in seconds (process accumulated messages after this)
    #[arg(long, default_value = "5")]
    batch_timeout_secs: u64,

    /// TTL: messages at this hop count are finalized (walk complete)
    #[arg(long, default_value = "5")]
    ttl: usize,

    /// Number of packets to spawn locally on this phone node
    #[arg(long, default_value = "16")]
    packets_per_node: usize,

    /// This phone's node index (used for session ID when spawning)
    #[arg(long, default_value = "0")]
    phone_node: usize,
}

/// Messages sent from WS reader to crypto thread
enum InboundMsg {
    Messages(Vec<Message>),
    Done,
}

fn safe_div(num: f64, den: usize) -> f64 {
    if den > 0 {
        num / den as f64
    } else {
        0.0
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    println!("=== ZK Brownian Phone Client (WebSocket) ===");
    println!("  Server: {}", cli.server_url);
    println!("  Setup dir: {}", cli.setup_dir);
    println!("  Max batch size: {}", cli.max_batch_size);
    println!("  Batch timeout: {}s", cli.batch_timeout_secs);
    println!("  TTL: {}", cli.ttl);

    // Step 1: Load setup data
    println!("\nLoading PublicParams...");
    let start = Instant::now();
    let pp_bytes =
        std::fs::read(format!("{}/public_params.bin", cli.setup_dir)).expect("Failed to read PP");
    println!(
        "  Read {} bytes in {:.2}s",
        pp_bytes.len(),
        start.elapsed().as_secs_f64()
    );

    let start = Instant::now();
    let pp = deserialize_public_params(&pp_bytes).expect("Failed to deserialize PP");
    println!(
        "  Deserialized PP in {:.2}s (nodes={}, max_degree={})",
        start.elapsed().as_secs_f64(),
        pp.num_nodes,
        pp.max_out_degree
    );

    println!("\nLoading UserView...");
    let start = Instant::now();
    let uv_bytes =
        std::fs::read(format!("{}/user_view.bin", cli.setup_dir)).expect("Failed to read UV");
    println!(
        "  Read {} bytes in {:.2}s",
        uv_bytes.len(),
        start.elapsed().as_secs_f64()
    );

    let start = Instant::now();
    let user_view = deserialize_user_view(&uv_bytes).expect("Failed to deserialize UV");
    println!(
        "  Deserialized UV in {:.2}s (neighbors={})",
        start.elapsed().as_secs_f64(),
        user_view.neighbours_view.neighbors.len()
    );

    println!("\nLoading verification data...");
    let start = Instant::now();
    let vd_bytes = std::fs::read(format!("{}/verification_data.bin", cli.setup_dir))
        .expect("Failed to read verification data");
    let (merkle_root, all_public_keys) =
        deserialize_verification_data(&vd_bytes).expect("Failed to deserialize verification data");
    println!(
        "  Loaded merkle_root + {} public keys in {:.2}s",
        all_public_keys.len(),
        start.elapsed().as_secs_f64()
    );

    let weight_commitment = WeightCommitment {
        commitment: vec![],
        metadata: vec![],
    };

    // Step 2: Connect via WebSocket
    let ws_url = http_to_ws_url(&cli.server_url);
    println!("\nConnecting to WebSocket at {}...", ws_url);

    let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    config.max_frame_size = Some(256 * 1024 * 1024);
    config.max_message_size = Some(256 * 1024 * 1024);

    let (ws_stream, _) = tokio_tungstenite::connect_async_with_config(ws_url, Some(config), false)
        .await
        .expect("Failed to connect WebSocket");
    println!("  WebSocket connected.");

    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    // Step 3: Send Start message
    let start_bytes =
        bincode::serialize(&PhoneMsg::Start).expect("Failed to serialize PhoneMsg::Start");
    ws_sink
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            start_bytes.into(),
        ))
        .await
        .expect("Failed to send Start");
    println!("  Sent Start to server.");

    // Step 4: Create channels
    // Inbound: WS reader -> crypto thread (std::sync::mpsc for recv_timeout)
    let (inbound_tx, inbound_rx) = std::sync::mpsc::channel::<InboundMsg>();
    // Outbound: crypto thread -> WS writer (tokio mpsc for async sending)
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // Step 5: Spawn crypto thread
    // Use a oneshot channel so we can await completion without blocking the
    // tokio event loop (which would starve the reader/writer tasks on
    // current_thread runtime).
    let (crypto_done_tx, crypto_done_rx) = tokio::sync::oneshot::channel::<()>();
    let batch_size = cli.max_batch_size;
    let batch_timeout_secs = cli.batch_timeout_secs;
    let ttl = cli.ttl;
    let packets_per_node = cli.packets_per_node;
    let phone_node = cli.phone_node;
    std::thread::spawn(move || {
        crypto_thread(
            inbound_rx,
            outbound_tx,
            user_view,
            pp,
            merkle_root,
            weight_commitment,
            all_public_keys,
            batch_size,
            batch_timeout_secs,
            ttl,
            packets_per_node,
            phone_node,
        );
        let _ = crypto_done_tx.send(());
    });

    // Step 6: Spawn WS reader task (async)
    let reader_handle = tokio::spawn(async move {
        while let Some(msg) = ws_stream.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("  [ws-reader] Error: {}", e);
                    break;
                }
            };

            let data = match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => b,
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => continue,
            };

            let server_msg: ServerMsg = match bincode::deserialize(&data) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("  [ws-reader] Failed to deserialize ServerMsg: {}", e);
                    continue;
                }
            };

            match server_msg {
                ServerMsg::Work(messages) => {
                    println!("  [ws-reader] Received {} messages", messages.len());
                    if inbound_tx.send(InboundMsg::Messages(messages)).is_err() {
                        break;
                    }
                }
                ServerMsg::Done => {
                    println!("  [ws-reader] Received Done");
                    let _ = inbound_tx.send(InboundMsg::Done);
                    break;
                }
            }
        }
    });

    // Step 7: WS writer task — forward outbound bytes to ws_sink
    let writer_handle = tokio::spawn(async move {
        while let Some(bytes) = outbound_rx.recv().await {
            if ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    bytes.into(),
                ))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Wait for crypto thread to finish (it drives the lifecycle).
    // Awaiting (not blocking) keeps the event loop free for reader/writer tasks.
    let _ = crypto_done_rx.await;

    // Clean up async tasks
    reader_handle.abort();
    writer_handle.abort();
}

/// Crypto thread: accumulates messages, runs verify+forward, sends results
#[allow(clippy::too_many_arguments)]
fn crypto_thread(
    inbound_rx: std::sync::mpsc::Receiver<InboundMsg>,
    outbound_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    user_view: UserView,
    pp: zkbrownian::types::PublicParams,
    merkle_root: zkbrownian::types::ScalarField,
    weight_commitment: WeightCommitment,
    all_public_keys: Vec<zkbrownian::types::PublicKey>,
    max_batch_size: usize,
    batch_timeout_secs: u64,
    ttl: usize,
    packets_per_node: usize,
    phone_node: usize,
) {
    let mut rng = thread_rng();
    let batch_timeout = Duration::from_secs(batch_timeout_secs);
    let mut buffer: Vec<Message> = Vec::new();
    let mut last_process_time = Instant::now();

    // Spawn local packets immediately — no WS round-trip needed
    println!(
        "\n[crypto] Spawning {} local packets (node {})...",
        packets_per_node, phone_node
    );
    let spawn_start = Instant::now();
    let session_id = 1000 + phone_node;
    for packet_id in 0..packets_per_node {
        let message = spawn(
            &user_view.secret_key,
            &user_view.public_key,
            packet_id as u32,
            session_id as u64,
            &mut rng,
        )
        .expect("Failed to spawn message");
        buffer.push(message);
    }
    println!(
        "[crypto] Spawned {} packets locally in {:.1}ms",
        packets_per_node,
        spawn_start.elapsed().as_secs_f64() * 1000.0
    );

    // Cumulative counters
    let mut batch_timings: Vec<BatchTiming> = Vec::new();
    let mut total_verified = 0usize;
    let mut total_forwarded = 0usize;
    let mut total_finalized = 0usize;
    let mut total_verify_ms = 0.0f64;
    let mut total_forward_ms = 0.0f64;
    let mut total_result_ser_ms = 0.0f64;
    let mut total_result_ws_ms = 0.0f64;

    println!("[crypto] Starting processing loop...");
    let overall_start = Instant::now();

    let mut done = false;

    loop {
        // Skip recv when buffer already has enough to process
        let should_recv = buffer.len() < max_batch_size && !done;

        if should_recv {
            // Wait for first message or timeout
            let msg = if buffer.is_empty() {
                // Block until we get something
                match inbound_rx.recv() {
                    Ok(m) => Some(m),
                    Err(_) => break, // channel closed
                }
            } else {
                // We have buffered messages, use timeout
                let remaining = batch_timeout.saturating_sub(last_process_time.elapsed());
                match inbound_rx.recv_timeout(remaining) {
                    Ok(m) => Some(m),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        done = true;
                        None
                    }
                }
            };

            // Process received message
            if let Some(m) = msg {
                match m {
                    InboundMsg::Messages(messages) => {
                        buffer.extend(messages);
                    }
                    InboundMsg::Done => {
                        done = true;
                    }
                }
            }

            // Drain any additional messages available without blocking
            loop {
                match inbound_rx.try_recv() {
                    Ok(InboundMsg::Messages(messages)) => {
                        buffer.extend(messages);
                    }
                    Ok(InboundMsg::Done) => {
                        done = true;
                    }
                    Err(_) => break,
                }
            }
        }

        // Check if we should process
        let should_process = buffer.len() >= max_batch_size
            || (done && !buffer.is_empty())
            || (!buffer.is_empty() && last_process_time.elapsed() >= batch_timeout);

        if should_process {
            process_batch(
                &mut buffer,
                max_batch_size,
                &user_view,
                &pp,
                &merkle_root,
                &weight_commitment,
                &all_public_keys,
                ttl,
                &outbound_tx,
                &mut rng,
                &mut batch_timings,
                &mut total_verified,
                &mut total_forwarded,
                &mut total_finalized,
                &mut total_verify_ms,
                &mut total_forward_ms,
                &mut total_result_ser_ms,
                &mut total_result_ws_ms,
            );
            last_process_time = Instant::now();
        }

        if done && buffer.is_empty() {
            println!("\n[crypto] === Server signaled done ===");
            break;
        }
    }

    let overall_elapsed = overall_start.elapsed();

    // Print and send benchmark report
    println!("\n=== Benchmark Results ===");
    println!(
        "  Total wall-clock time: {:.2}s",
        overall_elapsed.as_secs_f64()
    );
    println!("  Batches: {}", batch_timings.len());
    println!("  Messages verified: {}", total_verified);
    println!("  Messages forwarded: {}", total_forwarded);
    println!("  Messages finalized (reached TTL): {}", total_finalized);

    println!("\n  --- Crypto ---");
    println!(
        "  Verify:  {:.1} ms total, {:.2} ms/msg",
        total_verify_ms,
        safe_div(total_verify_ms, total_verified),
    );
    println!(
        "  Forward: {:.1} ms total, {:.2} ms/msg",
        total_forward_ms,
        safe_div(total_forward_ms, total_forwarded),
    );

    println!("\n  --- WS/network ---");
    println!(
        "  WS send: {:.1} ms total, {:.1} ms/batch",
        total_result_ws_ms,
        safe_div(total_result_ws_ms, batch_timings.len()),
    );

    println!("\n  --- Serialization ---");
    println!(
        "  Result ser:   {:.1} ms total, {:.1} ms/batch",
        total_result_ser_ms,
        safe_div(total_result_ser_ms, batch_timings.len()),
    );

    if !batch_timings.is_empty() {
        println!("\n  --- Per-batch breakdown ---");
        for (i, bt) in batch_timings.iter().enumerate() {
            let n_fwd = bt.messages_forwarded;
            println!(
                "    [{:>3}] verified={:>4}  verify={:.1}ms ({:.2}ms/msg)  fwd={:.1}ms ({:.2}ms/msg)  ser={:.1}ms  ws={:.1}ms  finalized={}",
                i + 1,
                bt.batch_size,
                bt.verify_time_ms,
                safe_div(bt.verify_time_ms, bt.batch_size),
                bt.forward_time_ms,
                safe_div(bt.forward_time_ms, n_fwd),
                bt.result_ser_ms,
                bt.result_ws_ms,
                bt.messages_finalized,
            );
        }
    }

    let report = BenchmarkReport {
        num_batches: batch_timings.len(),
        total_messages_verified: total_verified,
        total_messages_forwarded: total_forwarded,
        total_messages_finalized: total_finalized,
        total_verify_time_ms: total_verify_ms,
        total_forward_time_ms: total_forward_ms,
        total_ws_recv_ms: 0.0, // WS recv is async, not measured in crypto thread
        total_ws_send_ms: total_result_ws_ms,
        total_recv_deser_ms: 0.0, // Deserialization is async, not measured in crypto thread
        total_result_ser_ms,
        per_batch: batch_timings,
    };

    let report_bytes =
        bincode::serialize(&PhoneMsg::Benchmark(report)).expect("Failed to serialize benchmark");
    let _ = outbound_tx.send(report_bytes);

    // Give the writer task a moment to flush the benchmark message
    std::thread::sleep(Duration::from_millis(500));

    println!("\nBenchmark report sent to server.");
}

#[allow(clippy::too_many_arguments)]
fn process_batch(
    buffer: &mut Vec<Message>,
    max_batch_size: usize,
    user_view: &UserView,
    pp: &zkbrownian::types::PublicParams,
    merkle_root: &zkbrownian::types::ScalarField,
    weight_commitment: &WeightCommitment,
    all_public_keys: &[zkbrownian::types::PublicKey],
    ttl: usize,
    outbound_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    rng: &mut impl rand::Rng,
    batch_timings: &mut Vec<BatchTiming>,
    total_verified: &mut usize,
    total_forwarded: &mut usize,
    total_finalized: &mut usize,
    total_verify_ms: &mut f64,
    total_forward_ms: &mut f64,
    total_result_ser_ms: &mut f64,
    total_result_ws_ms: &mut f64,
) {
    let drain_count = buffer.len().min(max_batch_size);
    let messages: Vec<Message> = buffer.drain(..drain_count).collect();
    let batch_size = messages.len();
    let batch_num = batch_timings.len() + 1;

    println!(
        "  [batch {:>3}] Processing {} messages...",
        batch_num, batch_size
    );

    // Batch verify
    let verify_start = Instant::now();
    let all_valid = verify_batch(
        &messages,
        *merkle_root,
        weight_commitment,
        all_public_keys,
        pp,
    )
    .expect("Batch verification error");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    assert!(all_valid, "Phone received invalid messages");

    *total_verified += batch_size;
    *total_verify_ms += verify_ms;

    // Separate: messages at TTL -> finalized, rest -> forward
    let mut to_forward = Vec::new();
    let mut finalized = 0;

    for msg in messages {
        if msg.hop_count() >= ttl {
            finalized += 1;
        } else {
            to_forward.push(msg);
        }
    }

    *total_finalized += finalized;

    // Batch forward remaining
    let mut forward_ms = 0.0;
    let mut results = Vec::new();
    let num_to_forward = to_forward.len();

    if !to_forward.is_empty() {
        let batch_inputs: Vec<(UserView, Message)> = to_forward
            .into_iter()
            .map(|msg| (user_view.clone(), msg))
            .collect();

        let forward_start = Instant::now();
        let batch_results =
            forward_batch(pp, &batch_inputs, rng).expect("Failed to batch forward messages");
        forward_ms = forward_start.elapsed().as_secs_f64() * 1000.0;

        *total_forwarded += batch_results.len();
        results = batch_results;
    }

    *total_forward_ms += forward_ms;

    // Serialize the result as PhoneMsg::Result
    let result = BatchForwardResult {
        results,
        messages_finalized: finalized,
        verify_time_ms: verify_ms,
        forward_time_ms: forward_ms,
    };

    let ser_start = Instant::now();
    let body = bincode::serialize(&PhoneMsg::Result(result)).expect("Failed to serialize result");
    let ser_ms = ser_start.elapsed().as_secs_f64() * 1000.0;
    *total_result_ser_ms += ser_ms;

    let body_bytes = body.len();

    // Send via outbound channel (measured as ws time from crypto thread's perspective)
    let ws_start = Instant::now();
    if let Err(e) = outbound_tx.send(body) {
        eprintln!("  Warning: failed to send result to WS writer: {}", e);
    }
    let ws_ms = ws_start.elapsed().as_secs_f64() * 1000.0;
    *total_result_ws_ms += ws_ms;

    println!(
        "           verify={:.1}ms ({:.2}ms/msg)  fwd={:.1}ms ({:.2}ms/msg)  ser={:.1}ms ({:.1}KB)  ws={:.1}ms  forwarded={}  finalized={}",
        verify_ms,
        safe_div(verify_ms, batch_size),
        forward_ms,
        safe_div(forward_ms, num_to_forward),
        ser_ms,
        body_bytes as f64 / 1024.0,
        ws_ms,
        num_to_forward,
        finalized,
    );

    // Record timing
    batch_timings.push(BatchTiming {
        batch_size,
        messages_forwarded: num_to_forward,
        messages_finalized: finalized,
        verify_time_ms: verify_ms,
        forward_time_ms: forward_ms,
        result_ser_ms: ser_ms,
        result_ws_ms: ws_ms,
    });
}

/// Convert http://host:port to ws://host:port/ws
fn http_to_ws_url(url: &str) -> String {
    let base = url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let base = base.trim_end_matches('/');
    format!("{}/ws", base)
}
