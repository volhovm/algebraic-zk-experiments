//! Phone binary for the ZK Brownian Android benchmark simulator
//!
//! Cross-compiled for Android (aarch64-linux-android).
//! Polls the server for batches of messages, runs batch verify + batch forward,
//! reports timings.

use std::time::{Duration, Instant};

use clap::Parser;
use rand::thread_rng;

use zkbrownian::protocol::{forward_batch, verify_batch, UserView};
use zkbrownian::types::{Message, WeightCommitment};
use zkbrownian_simulator::serialization::{
    deserialize_public_params, deserialize_user_view, deserialize_verification_data,
};
use zkbrownian_simulator::{BatchForwardResult, BatchTiming, BenchmarkReport, PollResponse};

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

    /// Poll interval in milliseconds when no work is available
    #[arg(long, default_value = "100")]
    poll_interval_ms: u64,

    /// Maximum batch size before processing
    #[arg(long, default_value = "64")]
    max_batch_size: usize,

    /// Batch timeout in seconds (process accumulated messages after this)
    #[arg(long, default_value = "5")]
    batch_timeout_secs: u64,

    /// TTL: messages at this hop count are dropped, not forwarded
    #[arg(long, default_value = "5")]
    ttl: usize,
}

fn main() {
    let cli = Cli::parse();

    println!("=== ZK Brownian Phone Client ===");
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

    // Step 2: Create HTTP client
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to create HTTP client");

    // Step 3: POST /start to trigger server
    println!("\nSending /start to server...");
    let start_url = format!("{}/start", cli.server_url);
    client
        .post(&start_url)
        .send()
        .expect("Failed to start server");
    println!("  Server started.");

    // Step 4: Accumulation and processing loop
    let mut rng = thread_rng();
    let mut buffer: Vec<Message> = Vec::new();
    let mut last_process_time = Instant::now();
    let batch_timeout = Duration::from_secs(cli.batch_timeout_secs);

    let mut batch_timings: Vec<BatchTiming> = Vec::new();
    let mut total_verified = 0usize;
    let mut total_forwarded = 0usize;
    let mut total_dropped = 0usize;
    let mut total_verify_time_ms = 0.0f64;
    let mut total_forward_time_ms = 0.0f64;

    println!("\nStarting poll loop...");
    let overall_start = Instant::now();

    loop {
        // Poll server
        let poll_url = format!("{}/poll", cli.server_url);
        let resp = client.get(&poll_url).send().expect("Failed to poll server");
        let poll_response: PollResponse = resp.json().expect("Failed to parse poll response");

        match poll_response {
            PollResponse::Work(messages) => {
                println!(
                    "  Received {} messages (buffer: {})",
                    messages.len(),
                    buffer.len()
                );
                buffer.extend(messages);
            }
            PollResponse::NoWork => {
                // Process whatever we have if buffer is non-empty and timeout elapsed
                if !buffer.is_empty() && last_process_time.elapsed() >= batch_timeout {
                    // Fall through to processing below
                } else {
                    std::thread::sleep(Duration::from_millis(cli.poll_interval_ms));
                    continue;
                }
            }
            PollResponse::Done => {
                // Process remaining buffer if any
                if !buffer.is_empty() {
                    process_batch(
                        &mut buffer,
                        &user_view,
                        &pp,
                        &merkle_root,
                        &weight_commitment,
                        &all_public_keys,
                        cli.ttl,
                        &client,
                        &cli.server_url,
                        &mut rng,
                        &mut batch_timings,
                        &mut total_verified,
                        &mut total_forwarded,
                        &mut total_dropped,
                        &mut total_verify_time_ms,
                        &mut total_forward_time_ms,
                    );
                }
                println!("\n=== Server signaled done ===");
                break;
            }
        }

        // Check if we should process the buffer
        let should_process = buffer.len() >= cli.max_batch_size
            || (!buffer.is_empty() && last_process_time.elapsed() >= batch_timeout);

        if should_process {
            process_batch(
                &mut buffer,
                &user_view,
                &pp,
                &merkle_root,
                &weight_commitment,
                &all_public_keys,
                cli.ttl,
                &client,
                &cli.server_url,
                &mut rng,
                &mut batch_timings,
                &mut total_verified,
                &mut total_forwarded,
                &mut total_dropped,
                &mut total_verify_time_ms,
                &mut total_forward_time_ms,
            );
            last_process_time = Instant::now();
        }
    }

    let overall_elapsed = overall_start.elapsed();

    // Step 5: Print and send benchmark report
    println!("\n=== Benchmark Results ===");
    println!(
        "  Total wall-clock time: {:.2}s",
        overall_elapsed.as_secs_f64()
    );
    println!("  Batches: {}", batch_timings.len());
    println!("  Messages verified: {}", total_verified);
    println!("  Messages forwarded: {}", total_forwarded);
    println!("  Messages dropped (TTL): {}", total_dropped);
    println!(
        "  Total verify time: {:.2} ms ({:.2} ms/msg)",
        total_verify_time_ms,
        if total_verified > 0 {
            total_verify_time_ms / total_verified as f64
        } else {
            0.0
        }
    );
    println!(
        "  Total forward time: {:.2} ms ({:.2} ms/msg)",
        total_forward_time_ms,
        if total_forwarded > 0 {
            total_forward_time_ms / total_forwarded as f64
        } else {
            0.0
        }
    );

    if !batch_timings.is_empty() {
        println!("\n  Per-batch timings:");
        for (i, bt) in batch_timings.iter().enumerate() {
            println!(
                "    [{:>3}] size={:>4}, verify={:.1}ms, fwd={:.1}ms, dropped={}",
                i + 1,
                bt.batch_size,
                bt.verify_time_ms,
                bt.forward_time_ms,
                bt.messages_dropped,
            );
        }
    }

    let report = BenchmarkReport {
        num_batches: batch_timings.len(),
        total_messages_verified: total_verified,
        total_messages_forwarded: total_forwarded,
        total_messages_dropped: total_dropped,
        total_verify_time_ms,
        total_forward_time_ms,
        per_batch: batch_timings,
    };

    let benchmark_url = format!("{}/benchmark", cli.server_url);
    let _ = client.post(&benchmark_url).json(&report).send();
    println!("\nBenchmark report sent to server.");
}

#[allow(clippy::too_many_arguments)]
fn process_batch(
    buffer: &mut Vec<Message>,
    user_view: &UserView,
    pp: &zkbrownian::types::PublicParams,
    merkle_root: &zkbrownian::types::ScalarField,
    weight_commitment: &WeightCommitment,
    all_public_keys: &[zkbrownian::types::PublicKey],
    ttl: usize,
    client: &reqwest::blocking::Client,
    server_url: &str,
    rng: &mut impl rand::Rng,
    batch_timings: &mut Vec<BatchTiming>,
    total_verified: &mut usize,
    total_forwarded: &mut usize,
    total_dropped: &mut usize,
    total_verify_time_ms: &mut f64,
    total_forward_time_ms: &mut f64,
) {
    let messages: Vec<Message> = std::mem::take(buffer);
    let batch_size = messages.len();

    println!(
        "  [batch {:>3}] Processing {} messages...",
        batch_timings.len() + 1,
        batch_size,
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
    let verify_elapsed_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    assert!(all_valid, "Phone received invalid messages");

    *total_verified += batch_size;
    *total_verify_time_ms += verify_elapsed_ms;

    // Separate: messages at TTL → drop, rest → forward
    let mut to_forward = Vec::new();
    let mut dropped = 0;

    for msg in messages {
        if msg.hop_count() >= ttl {
            dropped += 1;
        } else {
            to_forward.push(msg);
        }
    }

    *total_dropped += dropped;

    // Batch forward remaining
    let mut forward_elapsed_ms = 0.0;
    let mut results = Vec::new();

    if !to_forward.is_empty() {
        let batch_inputs: Vec<(UserView, Message)> = to_forward
            .into_iter()
            .map(|msg| (user_view.clone(), msg))
            .collect();

        let forward_start = Instant::now();
        let batch_results =
            forward_batch(pp, &batch_inputs, rng).expect("Failed to batch forward messages");
        forward_elapsed_ms = forward_start.elapsed().as_secs_f64() * 1000.0;

        *total_forwarded += batch_results.len();
        results = batch_results;
    }

    *total_forward_time_ms += forward_elapsed_ms;

    println!(
        "           verify={:.1}ms, fwd={:.1}ms, forwarded={}, dropped={}",
        verify_elapsed_ms,
        forward_elapsed_ms,
        results.len(),
        dropped,
    );

    // Record timing
    batch_timings.push(BatchTiming {
        batch_size,
        verify_time_ms: verify_elapsed_ms,
        forward_time_ms: forward_elapsed_ms,
        messages_dropped: dropped,
    });

    // POST result back to server
    let result = BatchForwardResult {
        results,
        messages_dropped: dropped,
        verify_time_ms: verify_elapsed_ms,
        forward_time_ms: forward_elapsed_ms,
    };

    let result_url = format!("{}/result", server_url);
    if let Err(e) = client.post(&result_url).json(&result).send() {
        eprintln!("  Warning: failed to post result: {}", e);
    }
}
