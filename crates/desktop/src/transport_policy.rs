//! Deterministic selection policy above the protocol-independent transport sessions.
//!
//! Selection happens before a protocol session is created. A resolved route names exactly one
//! transport and never represents a fallback order.

use std::{fmt, net::SocketAddr, str::FromStr};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportChoice {
    #[default]
    Auto,
    Adb,
    Ble,
    Wifi,
    Qr,
}

impl fmt::Display for TransportChoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Adb => "adb",
            Self::Ble => "ble",
            Self::Wifi => "wifi",
            Self::Qr => "qr",
        })
    }
}

impl FromStr for TransportChoice {
    type Err = ParseTransportChoiceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "adb" => Ok(Self::Adb),
            "ble" => Ok(Self::Ble),
            "wifi" => Ok(Self::Wifi),
            "qr" => Ok(Self::Qr),
            _ => Err(ParseTransportChoiceError),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("expected one of: auto, adb, ble, wifi, qr")]
pub struct ParseTransportChoiceError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    Adb,
    Ble,
    Wifi,
    Qr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportOperation {
    Pairing,
    Unwrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCapability {
    pub kind: TransportKind,
    pub pairing: bool,
    pub unwrap: bool,
    pub implemented: bool,
}

pub const TRANSPORT_CAPABILITIES: [TransportCapability; 4] = [
    TransportCapability {
        kind: TransportKind::Adb,
        pairing: true,
        unwrap: true,
        implemented: true,
    },
    TransportCapability {
        kind: TransportKind::Ble,
        pairing: false,
        unwrap: false,
        implemented: false,
    },
    TransportCapability {
        kind: TransportKind::Wifi,
        pairing: true,
        unwrap: true,
        implemented: true,
    },
    TransportCapability {
        kind: TransportKind::Qr,
        pairing: true,
        unwrap: true,
        implemented: true,
    },
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportHints {
    pub adb_serial: Option<String>,
    pub wifi_address: Option<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRoute {
    kind: TransportKind,
    adb_serial: Option<String>,
    wifi_address: Option<SocketAddr>,
}

impl TransportRoute {
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        self.kind
    }

    #[must_use]
    pub fn adb_serial(&self) -> Option<&str> {
        self.adb_serial.as_deref()
    }

    #[must_use]
    pub fn wifi_address(&self) -> Option<SocketAddr> {
        self.wifi_address
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransportPolicyError {
    #[error("ADB and Wi-Fi route hints cannot be combined")]
    ConflictingHints,
    #[error("the selected transport does not accept these route hints")]
    InconsistentHints,
    #[error("the selected transport route hint is malformed or unsupported")]
    InvalidRouteHint,
    #[error("foreground Wi-Fi requires an explicit endpoint")]
    MissingWifiEndpoint,
    #[error("the selected transport does not support this operation")]
    UnsupportedOperation,
    #[error("the selected transport is not implemented")]
    Unavailable,
}

/// Resolves one user choice and its untrusted route hints into one concrete transport.
///
/// # Errors
///
/// Returns an error for conflicting, inconsistent, missing, or malformed route hints, and when
/// the selected transport is unavailable or does not support the requested operation.
pub fn resolve_transport(
    choice: TransportChoice,
    operation: TransportOperation,
    hints: TransportHints,
) -> Result<TransportRoute, TransportPolicyError> {
    resolve_transport_for_platform(choice, operation, hints, cfg!(windows))
}

fn resolve_transport_for_platform(
    choice: TransportChoice,
    operation: TransportOperation,
    hints: TransportHints,
    windows: bool,
) -> Result<TransportRoute, TransportPolicyError> {
    if hints.adb_serial.is_some() && hints.wifi_address.is_some() {
        return Err(TransportPolicyError::ConflictingHints);
    }

    let kind = match choice {
        TransportChoice::Auto => {
            if hints.adb_serial.is_some() {
                TransportKind::Adb
            } else if hints.wifi_address.is_some() {
                TransportKind::Wifi
            } else if windows {
                TransportKind::Adb
            } else {
                TransportKind::Qr
            }
        }
        TransportChoice::Adb => TransportKind::Adb,
        TransportChoice::Ble => TransportKind::Ble,
        TransportChoice::Wifi => TransportKind::Wifi,
        TransportChoice::Qr => TransportKind::Qr,
    };

    let Some(capability) = TRANSPORT_CAPABILITIES
        .iter()
        .find(|capability| capability.kind == kind)
    else {
        return Err(TransportPolicyError::Unavailable);
    };
    if !capability.implemented {
        return Err(TransportPolicyError::Unavailable);
    }
    let supported = match operation {
        TransportOperation::Pairing => capability.pairing,
        TransportOperation::Unwrap => capability.unwrap,
    };
    if !supported {
        return Err(TransportPolicyError::UnsupportedOperation);
    }

    match kind {
        TransportKind::Adb if hints.wifi_address.is_some() => {
            return Err(TransportPolicyError::InconsistentHints);
        }
        TransportKind::Wifi if hints.adb_serial.is_some() => {
            return Err(TransportPolicyError::InconsistentHints);
        }
        TransportKind::Wifi if hints.wifi_address.is_none() => {
            return Err(TransportPolicyError::MissingWifiEndpoint);
        }
        TransportKind::Ble | TransportKind::Qr
            if hints.adb_serial.is_some() || hints.wifi_address.is_some() =>
        {
            return Err(TransportPolicyError::InconsistentHints);
        }
        TransportKind::Adb | TransportKind::Ble | TransportKind::Wifi | TransportKind::Qr => {}
    }

    if let Some(serial) = hints.adb_serial.as_deref()
        && !crate::adb::valid_serial(serial)
    {
        return Err(TransportPolicyError::InvalidRouteHint);
    }
    if let Some(endpoint) = hints.wifi_address
        && crate::wifi::validate_endpoint(endpoint).is_err()
    {
        return Err(TransportPolicyError::InvalidRouteHint);
    }

    Ok(TransportRoute {
        kind,
        adb_serial: hints.adb_serial,
        wifi_address: hints.wifi_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi_address() -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 20], crate::wifi::WIFI_UNWRAP_PORT))
    }

    #[test]
    fn parses_only_the_five_canonical_choices() {
        for (text, choice) in [
            ("auto", TransportChoice::Auto),
            ("adb", TransportChoice::Adb),
            ("ble", TransportChoice::Ble),
            ("wifi", TransportChoice::Wifi),
            ("qr", TransportChoice::Qr),
        ] {
            assert_eq!(text.parse(), Ok(choice));
            assert_eq!(choice.to_string(), text);
        }
        for invalid in ["", "AUTO", "usb", "wifi,qr"] {
            assert_eq!(
                invalid.parse::<TransportChoice>(),
                Err(ParseTransportChoiceError)
            );
        }
    }

    #[test]
    fn auto_preserves_platform_defaults_without_creating_a_fallback_order() {
        let windows = resolve_transport_for_platform(
            TransportChoice::Auto,
            TransportOperation::Unwrap,
            TransportHints::default(),
            true,
        )
        .unwrap();
        assert_eq!(windows.kind(), TransportKind::Adb);

        let other = resolve_transport_for_platform(
            TransportChoice::Auto,
            TransportOperation::Unwrap,
            TransportHints::default(),
            false,
        )
        .unwrap();
        assert_eq!(other.kind(), TransportKind::Qr);
    }

    #[test]
    fn auto_route_hints_pin_exactly_one_transport() {
        let adb = resolve_transport_for_platform(
            TransportChoice::Auto,
            TransportOperation::Pairing,
            TransportHints {
                adb_serial: Some("phone".to_owned()),
                wifi_address: None,
            },
            false,
        )
        .unwrap();
        assert_eq!(adb.kind(), TransportKind::Adb);
        assert_eq!(adb.adb_serial(), Some("phone"));

        let wifi = resolve_transport_for_platform(
            TransportChoice::Auto,
            TransportOperation::Unwrap,
            TransportHints {
                adb_serial: None,
                wifi_address: Some(wifi_address()),
            },
            true,
        )
        .unwrap();
        assert_eq!(wifi.kind(), TransportKind::Wifi);
        assert_eq!(wifi.wifi_address(), Some(wifi_address()));
    }

    #[test]
    fn rejects_conflicting_missing_and_cross_transport_hints() {
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Auto,
                TransportOperation::Unwrap,
                TransportHints {
                    adb_serial: Some("phone".to_owned()),
                    wifi_address: Some(wifi_address()),
                },
                true,
            ),
            Err(TransportPolicyError::ConflictingHints)
        );
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Wifi,
                TransportOperation::Unwrap,
                TransportHints::default(),
                true,
            ),
            Err(TransportPolicyError::MissingWifiEndpoint)
        );
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Qr,
                TransportOperation::Unwrap,
                TransportHints {
                    adb_serial: Some("phone".to_owned()),
                    wifi_address: None,
                },
                true,
            ),
            Err(TransportPolicyError::InconsistentHints)
        );
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Adb,
                TransportOperation::Unwrap,
                TransportHints {
                    adb_serial: Some("bad serial".to_owned()),
                    wifi_address: None,
                },
                true,
            ),
            Err(TransportPolicyError::InvalidRouteHint)
        );
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Wifi,
                TransportOperation::Unwrap,
                TransportHints {
                    adb_serial: None,
                    wifi_address: Some(SocketAddr::from(([8, 8, 8, 8], 47_140))),
                },
                true,
            ),
            Err(TransportPolicyError::InvalidRouteHint)
        );
    }

    #[test]
    fn accepts_wifi_pairing_and_rejects_unimplemented_ble() {
        assert_eq!(
            resolve_transport_for_platform(
                TransportChoice::Wifi,
                TransportOperation::Pairing,
                TransportHints {
                    adb_serial: None,
                    wifi_address: Some(wifi_address()),
                },
                true,
            )
            .unwrap()
            .kind(),
            TransportKind::Wifi
        );
        for operation in [TransportOperation::Pairing, TransportOperation::Unwrap] {
            assert_eq!(
                resolve_transport_for_platform(
                    TransportChoice::Ble,
                    operation,
                    TransportHints::default(),
                    true,
                ),
                Err(TransportPolicyError::Unavailable)
            );
        }
    }

    #[test]
    fn capability_table_is_complete_and_has_no_duplicate_kinds() {
        assert_eq!(TRANSPORT_CAPABILITIES.len(), 4);
        for (index, capability) in TRANSPORT_CAPABILITIES.iter().enumerate() {
            assert!(
                TRANSPORT_CAPABILITIES[index + 1..]
                    .iter()
                    .all(|other| other.kind != capability.kind)
            );
        }
    }
}
