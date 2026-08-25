//! Standard age `recipient-v1` adapter for the experimental P-256 recipient.

use std::{collections::HashSet, io};

use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret as _,
};
use age_plugin::{
    Callbacks,
    recipient::{self, RecipientPluginV1},
};
use age_plugin_phone_recipient_p256::{
    PLUGIN_NAME, PairedRecipient, Recipient, TaggedStanza, wrap_file_key, wrap_file_key_v2,
};
use rand_core::OsRng;

use crate::pairing::PublicIdentityStub;

#[derive(Default)]
pub struct PhoneRecipientPlugin {
    recipients: Vec<(usize, WrappingRecipient)>,
}

enum WrappingRecipient {
    Legacy(Recipient),
    Paired(PairedRecipient),
}

impl RecipientPluginV1 for PhoneRecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Recipient {
                index,
                message: "recipient was routed to the wrong plugin".into(),
            });
        }
        let recipient = match bytes.first() {
            Some(1) => Recipient::from_plugin_bytes(bytes).map(WrappingRecipient::Legacy),
            Some(2) => PairedRecipient::from_plugin_bytes(bytes).map(WrappingRecipient::Paired),
            _ => Err(age_plugin_phone_recipient_p256::Error::UnsupportedRecipientVersion),
        }
        .map_err(|_| recipient::Error::Recipient {
            index,
            message: "malformed or unsupported phone recipient".into(),
        })?;
        self.recipients.push((index, recipient));
        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Identity {
                index,
                message: "identity was routed to the wrong plugin".into(),
            });
        }
        let stub = PublicIdentityStub::decode(bytes).map_err(|_| recipient::Error::Identity {
            index,
            message: "malformed or unsupported public phone identity stub".into(),
        })?;
        let recipient = stub
            .paired_recipient()
            .map(WrappingRecipient::Paired)
            .map_err(|_| recipient::Error::Identity {
                index,
                message: "public phone identity contains an invalid recipient".into(),
            })?;
        self.recipients.push((index, recipient));
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let mut files = Vec::with_capacity(file_keys.len());
        for file_key in file_keys {
            let mut stanzas = Vec::with_capacity(self.recipients.len());
            for (index, recipient) in &self.recipients {
                let stanza = match recipient {
                    WrappingRecipient::Legacy(recipient) => {
                        wrap_file_key(recipient, file_key.expose_secret(), &mut OsRng)
                    }
                    WrappingRecipient::Paired(recipient) => {
                        wrap_file_key_v2(recipient, file_key.expose_secret(), &mut OsRng)
                    }
                };
                let Ok(stanza) = stanza else {
                    return Ok(Err(vec![recipient::Error::Recipient {
                        index: *index,
                        message: "failed to wrap file key for phone recipient".into(),
                    }]));
                };
                stanzas.push(to_age_stanza(stanza));
            }
            files.push(stanzas);
        }
        Ok(Ok(files))
    }
}

fn to_age_stanza(stanza: TaggedStanza) -> Stanza {
    Stanza {
        tag: stanza.tag,
        args: stanza.args,
        body: stanza.body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_plugin_phone_recipient_p256::unwrap_file_key;
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};

    struct NoCallbacks;

    impl<E> Callbacks<E> for NoCallbacks {
        fn message(&mut self, _: &str) -> age_core::plugin::Result<()> {
            Ok(Ok(()))
        }

        fn confirm(&mut self, _: &str, _: &str, _: Option<&str>) -> age_core::plugin::Result<bool> {
            Ok(Ok(false))
        }

        fn request_public(&mut self, _: &str) -> age_core::plugin::Result<String> {
            Ok(Err(age_core::plugin::Error::Unsupported))
        }

        fn request_secret(
            &mut self,
            _: &str,
        ) -> age_core::plugin::Result<age_core::secrecy::SecretString> {
            Ok(Err(age_core::plugin::Error::Unsupported))
        }

        fn error(&mut self, _: E) -> age_core::plugin::Result<()> {
            Ok(Ok(()))
        }
    }

    #[test]
    fn wraps_every_file_key_for_every_plugin_recipient() {
        let identity_a = SecretKey::random(&mut OsRng);
        let identity_b = SecretKey::random(&mut OsRng);
        let recipient_a = Recipient::from_public_key_bytes(
            identity_a.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let recipient_b = Recipient::from_public_key_bytes(
            identity_b.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let mut plugin = PhoneRecipientPlugin::default();
        assert!(
            plugin
                .add_recipient(0, PLUGIN_NAME, &recipient_a.plugin_bytes())
                .is_ok()
        );
        assert!(
            plugin
                .add_recipient(1, PLUGIN_NAME, &recipient_b.plugin_bytes())
                .is_ok()
        );
        let first = FileKey::new(Box::new([1; 16]));
        let second = FileKey::new(Box::new([2; 16]));
        let Ok(files) = plugin
            .wrap_file_keys(vec![first, second], NoCallbacks)
            .unwrap()
        else {
            panic!("validated recipients must wrap");
        };
        assert_eq!(files.iter().map(Vec::len).collect::<Vec<_>>(), [2, 2]);
        for (file_index, expected) in [[1; 16], [2; 16]].into_iter().enumerate() {
            for (stanza_index, identity) in [&identity_a, &identity_b].into_iter().enumerate() {
                let stanza = &files[file_index][stanza_index];
                let value = unwrap_file_key(
                    identity,
                    &TaggedStanza {
                        tag: stanza.tag.clone(),
                        args: stanza.args.clone(),
                        body: stanza.body.clone(),
                    },
                )
                .unwrap();
                assert_eq!(&value[..], &expected);
            }
        }
    }
}
