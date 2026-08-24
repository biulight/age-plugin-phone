//! Conversion helpers for the standard age plugin recipient payload.

use crate::{Error, PAYLOAD_VERSION, RECIPIENT_PAYLOAD_BYTES, Recipient};

impl Recipient {
    /// Parses the decoded payload passed to `recipient-v1` by an age client.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong length, unknown version, or invalid P-256 public key.
    pub fn from_plugin_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECIPIENT_PAYLOAD_BYTES {
            return Err(Error::InvalidRecipientLength);
        }
        if bytes[0] != PAYLOAD_VERSION {
            return Err(Error::UnsupportedRecipientVersion);
        }
        Self::from_public_key_bytes(&bytes[1..])
    }

    /// Returns the decoded payload used by the `age1phone` plugin recipient.
    #[must_use]
    pub fn plugin_bytes(&self) -> [u8; RECIPIENT_PAYLOAD_BYTES] {
        let mut bytes = [0; RECIPIENT_PAYLOAD_BYTES];
        bytes[0] = PAYLOAD_VERSION;
        bytes[1..].copy_from_slice(&self.public_key_bytes());
        bytes
    }
}
