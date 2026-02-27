pub mod serialization;

use serde::{Deserialize, Serialize};
use zkbrownian::types::Message;

/// Phone submits a batch of forwarded messages back to server
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchForwardResult {
    /// (new_message, next_hop_index) pairs
    pub results: Vec<(Message, usize)>,
    /// Number of messages that reached TTL (completed their random walk)
    pub messages_finalized: usize,
    /// Timing: how long batch_verify took (ms)
    pub verify_time_ms: f64,
    /// Timing: how long batch_forward took (ms)
    pub forward_time_ms: f64,
}

/// Server -> Phone messages over WebSocket
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMsg {
    /// Configuration sent once after the phone connects
    Config {
        packets_per_node: usize,
        phone_node: usize,
        ttl: usize,
    },
    /// Here are messages for you to process
    Work(Vec<Message>),
    /// All messages have reached TTL, we're done
    Done,
}

/// Phone -> Server messages over WebSocket
#[derive(Serialize, Deserialize, Debug)]
pub enum PhoneMsg {
    /// Phone is ready, trigger processing
    Start,
    /// Batch of forwarded results
    Result(BatchForwardResult),
    /// Final benchmark report
    Benchmark(BenchmarkReport),
}

/// Final benchmark report from the phone
#[derive(Serialize, Deserialize, Debug)]
pub struct BenchmarkReport {
    pub num_batches: usize,
    pub total_messages_verified: usize,
    pub total_messages_forwarded: usize,
    pub total_messages_finalized: usize,
    /// Crypto timings
    pub total_verify_time_ms: f64,
    pub total_forward_time_ms: f64,
    /// WS/network timings
    pub total_ws_recv_ms: f64,
    pub total_ws_send_ms: f64,
    /// Serialization timings
    pub total_recv_deser_ms: f64,
    pub total_result_ser_ms: f64,
    /// Per-batch breakdown
    pub per_batch: Vec<BatchTiming>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchTiming {
    /// Total messages received and verified in this batch
    pub batch_size: usize,
    /// Messages that were forwarded (hop_count < TTL)
    pub messages_forwarded: usize,
    /// Messages that reached TTL (completed their random walk)
    pub messages_finalized: usize,
    /// Crypto
    pub verify_time_ms: f64,
    pub forward_time_ms: f64,
    /// Serialization: bincode-encode PhoneMsg::Result
    pub result_ser_ms: f64,
    /// WS: send result over websocket
    pub result_ws_ms: f64,
}
