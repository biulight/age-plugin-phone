//! Transport-independent data model for phone pairing and age file-key unwrap requests.
//!
//! This crate does not implement serialization, cryptography, QR framing, or BLE framing yet. The
//! types are an reviewable boundary, not a frozen wire-format specification.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The only protocol version understood by this scaffold.
pub const PROTOCOL_VERSION: u16 = 1;

/// Pairing data displayed by the desktop and scanned by the phone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingOffer {
    /// Protocol version.
    pub version: u16,
    /// Random stable identifier for this desktop installation.
    pub desktop_id: String,
    /// Untrusted human-readable desktop label.
    pub desktop_label: String,
    /// Encoded desktop static public key.
    pub desktop_public_key: String,
    /// Fresh pairing nonce.
    pub nonce: String,
}

/// Pairing response displayed by the phone and scanned by the desktop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingResponse {
    /// Protocol version.
    pub version: u16,
    /// Stable identifier for the phone-held identity.
    pub identity_id: String,
    /// Public age recipient corresponding to the phone-held key.
    pub recipient: String,
    /// Encoded phone static public key.
    pub phone_public_key: String,
    /// Digest of the accepted pairing offer.
    pub offer_digest: String,
    /// Phone signature over all preceding fields.
    pub signature: String,
}

/// A request to unwrap one matching age recipient stanza.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrapRequest {
    /// Protocol version.
    pub version: u16,
    /// Unique random request identifier.
    pub request_id: String,
    /// Target phone-held identity.
    pub identity_id: String,
    /// Paired desktop identifier.
    pub desktop_id: String,
    /// Encoded one-time desktop session public key.
    pub session_public_key: String,
    /// Encoded age recipient stanza, including its type and arguments.
    pub recipient_stanza: String,
    /// Fresh request nonce.
    pub nonce: String,
    /// Short absolute expiry represented as Unix time.
    pub expires_at_unix: u64,
    /// Optional, untrusted label to display to the user.
    pub caller_hint: Option<String>,
    /// Desktop signature over all preceding fields.
    pub signature: String,
}

/// A phone response containing only a request-bound encrypted age file key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrapResponse {
    /// Protocol version.
    pub version: u16,
    /// Identifier copied from the accepted request.
    pub request_id: String,
    /// Digest of the complete accepted request.
    pub request_digest: String,
    /// File key encrypted to the request's one-time session public key.
    pub encrypted_file_key: String,
    /// Response nonce.
    pub nonce: String,
    /// Phone signature over all preceding fields.
    pub signature: String,
}

/// Structural validation failures detected before cryptographic verification.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// The peer selected an unsupported protocol version.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    /// A required textual field is empty.
    #[error("required field {0} is empty")]
    EmptyField(&'static str),
}

impl PairingOffer {
    /// Checks version and required fields without treating labels as trusted data.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or an empty required field.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_version(self.version)?;
        require("desktop_id", &self.desktop_id)?;
        require("desktop_public_key", &self.desktop_public_key)?;
        require("nonce", &self.nonce)
    }
}

impl UnwrapRequest {
    /// Checks version and required fields before signature and expiry verification.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or an empty required field.
    pub fn validate_structure(&self) -> Result<(), ValidationError> {
        validate_version(self.version)?;
        require("request_id", &self.request_id)?;
        require("identity_id", &self.identity_id)?;
        require("desktop_id", &self.desktop_id)?;
        require("session_public_key", &self.session_public_key)?;
        require("recipient_stanza", &self.recipient_stanza)?;
        require("nonce", &self.nonce)?;
        require("signature", &self.signature)
    }
}

fn validate_version(version: u16) -> Result<(), ValidationError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ValidationError::UnsupportedVersion(version))
    }
}

fn require(name: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Err(ValidationError::EmptyField(name))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_offer_rejects_unknown_version() {
        let offer = PairingOffer {
            version: PROTOCOL_VERSION + 1,
            desktop_id: "desktop-1".into(),
            desktop_label: "untrusted label".into(),
            desktop_public_key: "public-key".into(),
            nonce: "nonce".into(),
        };

        assert_eq!(
            offer.validate(),
            Err(ValidationError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn unwrap_request_requires_a_recipient_stanza() {
        let request = UnwrapRequest {
            version: PROTOCOL_VERSION,
            request_id: "request-1".into(),
            identity_id: "identity-1".into(),
            desktop_id: "desktop-1".into(),
            session_public_key: "session-key".into(),
            recipient_stanza: String::new(),
            nonce: "nonce".into(),
            expires_at_unix: 1,
            caller_hint: None,
            signature: "signature".into(),
        };

        assert_eq!(
            request.validate_structure(),
            Err(ValidationError::EmptyField("recipient_stanza"))
        );
    }
}
