//! Bulletin board interface (stub)
//!
//! Interface for posting and retrieving messages anonymously

use crate::types::{DiversifiedPublicKey, Message, ProtocolResult};

/// Bulletin board entry
#[derive(Clone, Debug)]
pub struct BulletinBoardEntry {
    /// The message
    pub message: Message,
    /// Index of receiver
    pub receiver_index: usize,
    /// Addressed to this diversified public key
    pub addressed_to: DiversifiedPublicKey,
}

/// Bulletin board trait (stub)
pub trait BulletinBoard {
    /// Post a message anonymously
    fn post(&mut self, entry: BulletinBoardEntry) -> ProtocolResult<()>;

    /// Get all messages (for scanning)
    fn get_all_messages(&self) -> Vec<BulletinBoardEntry>;

    /// Get messages addressed to a specific diversified public key
    fn get_messages_for(&self, ppk: &DiversifiedPublicKey) -> Vec<BulletinBoardEntry>;
}

/// Simple in-memory bulletin board implementation
#[derive(Default)]
pub struct InMemoryBulletinBoard {
    entries: Vec<BulletinBoardEntry>,
}

impl InMemoryBulletinBoard {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl BulletinBoard for InMemoryBulletinBoard {
    fn post(&mut self, entry: BulletinBoardEntry) -> ProtocolResult<()> {
        self.entries.push(entry);
        Ok(())
    }

    fn get_all_messages(&self) -> Vec<BulletinBoardEntry> {
        self.entries.clone()
    }

    fn get_messages_for(&self, ppk: &DiversifiedPublicKey) -> Vec<BulletinBoardEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.addressed_to.ppk_1 == ppk.ppk_1 && entry.addressed_to.ppk_2 == ppk.ppk_2
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve_ops::keygen;
    use crate::protocol::spawn::spawn;
    use rand::thread_rng;

    #[test]
    fn test_bulletin_board() {
        let mut rng = thread_rng();
        let (sk, pk) = keygen(&mut rng);

        let message = spawn(&sk, &pk, 1, 100, &mut rng).unwrap();

        let mut bb = InMemoryBulletinBoard::new();

        let entry = BulletinBoardEntry {
            message: message.clone(),
            receiver_index: 0,
            addressed_to: message.ppk_0.clone(),
        };

        bb.post(entry).unwrap();

        assert_eq!(bb.get_all_messages().len(), 1);

        let messages = bb.get_messages_for(&message.ppk_0);
        assert_eq!(messages.len(), 1);
    }
}
