pub mod serialization;

use serde::{Deserialize, Serialize};
use zkbrownian::types::Message;

/// Phone submits a batch of forwarded messages back to server
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchForwardResult {
    /// (new_message, next_hop_index) pairs
    pub results: Vec<(Message, usize)>,
    /// Number of messages that reached TTL and were dropped
    pub messages_dropped: usize,
    /// Timing: how long batch_verify took (ms)
    pub verify_time_ms: f64,
    /// Timing: how long batch_forward took (ms)
    pub forward_time_ms: f64,
}

/// Phone polls server: get all queued messages at once
#[derive(Serialize, Deserialize, Debug)]
pub enum PollResponse {
    /// Here are messages for you to process
    Work(Vec<Message>),
    /// Nothing in your queue right now
    NoWork,
    /// All messages have reached TTL, we're done
    Done,
}

/// Final benchmark report from the phone
#[derive(Serialize, Deserialize, Debug)]
pub struct BenchmarkReport {
    pub num_batches: usize,
    pub total_messages_verified: usize,
    pub total_messages_forwarded: usize,
    pub total_messages_dropped: usize,
    pub total_verify_time_ms: f64,
    pub total_forward_time_ms: f64,
    pub per_batch: Vec<BatchTiming>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchTiming {
    pub batch_size: usize,
    pub verify_time_ms: f64,
    pub forward_time_ms: f64,
    pub messages_dropped: usize,
}
