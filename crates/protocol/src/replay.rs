#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::HashSet;

use minicbor::{Decoder, Encoder};

use crate::{Error, Id, MAX_REQUEST_LIFETIME_SECS, PairingRecord, ProtocolDigest, ProtocolNonce};

const STATE_VERSION: u16 = 2;
const REQUEST_ENTRY: u16 = 1;
const RESPONSE_ENTRY: u16 = 2;
// A worst-case request entry is 62 bytes, keeping the largest accepted state below 1 MiB.
const MAX_CONFIGURED_ENTRIES: usize = 16_384;
pub const DEFAULT_REPLAY_CAPACITY: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ReplayRole {
    PhoneRequests = 1,
    DesktopResponses = 2,
}

impl TryFrom<u16> for ReplayRole {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PhoneRequests),
            2 => Ok(Self::DesktopResponses),
            _ => Err(Error::ReplayState),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayScope {
    pub role: ReplayRole,
    pub desktop_id: Id,
    pub identity_id: Id,
}

impl ReplayScope {
    #[must_use]
    pub const fn new(role: ReplayRole, desktop_id: Id, identity_id: Id) -> Self {
        Self {
            role,
            desktop_id,
            identity_id,
        }
    }

    #[must_use]
    pub const fn for_pairing(role: ReplayRole, pairing: &PairingRecord) -> Self {
        Self::new(role, pairing.desktop_id, pairing.identity_id)
    }
}

/// A replay-consumption backend.
///
/// Implementations used outside tests must durably commit a token before returning success. A
/// storage error must fail closed and must not be converted into an in-memory fallback.
pub trait ReplayStore {
    fn consume_request(
        &mut self,
        desktop_id: Id,
        identity_id: Id,
        request_id: Id,
        nonce: ProtocolNonce,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<(), Error>;

    fn consume_response(
        &mut self,
        desktop_id: Id,
        identity_id: Id,
        response_digest: ProtocolDigest,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<(), Error>;
}

/// Non-durable replay detection for deterministic tests only.
///
/// Production callers must use a backend satisfying [`ReplayStore`]'s durability contract.
#[derive(Default)]
pub struct ReplayGuard {
    requests: HashSet<Id>,
    nonces: HashSet<ProtocolNonce>,
    responses: HashSet<ProtocolDigest>,
}

impl ReplayStore for ReplayGuard {
    fn consume_request(
        &mut self,
        _desktop_id: Id,
        _identity_id: Id,
        request_id: Id,
        nonce: ProtocolNonce,
        _expires_at_unix: u64,
        _now_unix: u64,
    ) -> Result<(), Error> {
        if self.requests.contains(&request_id) || self.nonces.contains(&nonce) {
            return Err(Error::Replay);
        }
        self.requests.insert(request_id);
        self.nonces.insert(nonce);
        Ok(())
    }

    fn consume_response(
        &mut self,
        _desktop_id: Id,
        _identity_id: Id,
        response_digest: ProtocolDigest,
        _expires_at_unix: u64,
        _now_unix: u64,
    ) -> Result<(), Error> {
        if !self.responses.insert(response_digest) {
            return Err(Error::Replay);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReplayEntry {
    Request {
        request_id: Id,
        nonce: ProtocolNonce,
        expires_at_unix: u64,
    },
    Response {
        digest: ProtocolDigest,
        expires_at_unix: u64,
    },
}

impl ReplayEntry {
    const fn expires_at_unix(&self) -> u64 {
        match self {
            Self::Request {
                expires_at_unix, ..
            }
            | Self::Response {
                expires_at_unix, ..
            } => *expires_at_unix,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayState {
    scope: ReplayScope,
    last_seen_unix: u64,
    entries: Vec<ReplayEntry>,
}

impl ReplayState {
    fn new(scope: ReplayScope, now_unix: u64) -> Self {
        Self {
            scope,
            last_seen_unix: now_unix,
            entries: Vec::new(),
        }
    }

    fn consume_request(
        &mut self,
        scope: ReplayScope,
        request_id: Id,
        nonce: ProtocolNonce,
        expires_at_unix: u64,
        now_unix: u64,
        capacity: usize,
    ) -> Result<(), Error> {
        validate_expiry(expires_at_unix, now_unix)?;
        self.prepare(scope, ReplayRole::PhoneRequests, now_unix)?;
        if self.entries.iter().any(|entry| {
            matches!(
                entry,
                ReplayEntry::Request {
                    request_id: existing_id,
                    nonce: existing_nonce,
                    ..
                } if *existing_id == request_id || *existing_nonce == nonce
            )
        }) {
            return Err(Error::Replay);
        }
        self.reserve(capacity)?;
        self.entries.push(ReplayEntry::Request {
            request_id,
            nonce,
            expires_at_unix,
        });
        self.finish(now_unix);
        Ok(())
    }

    fn consume_response(
        &mut self,
        scope: ReplayScope,
        digest: ProtocolDigest,
        expires_at_unix: u64,
        now_unix: u64,
        capacity: usize,
    ) -> Result<(), Error> {
        validate_expiry(expires_at_unix, now_unix)?;
        self.prepare(scope, ReplayRole::DesktopResponses, now_unix)?;
        if self.entries.iter().any(
            |entry| matches!(entry, ReplayEntry::Response { digest: existing, .. } if *existing == digest),
        ) {
            return Err(Error::Replay);
        }
        self.reserve(capacity)?;
        self.entries.push(ReplayEntry::Response {
            digest,
            expires_at_unix,
        });
        self.finish(now_unix);
        Ok(())
    }

    fn prepare(
        &mut self,
        scope: ReplayScope,
        role: ReplayRole,
        now_unix: u64,
    ) -> Result<(), Error> {
        if self.scope != scope || self.scope.role != role {
            return Err(Error::ReplayState);
        }
        if now_unix < self.last_seen_unix {
            return Err(Error::ClockRollback);
        }
        self.entries
            .retain(|entry| entry.expires_at_unix() >= now_unix);
        Ok(())
    }

    fn reserve(&self, capacity: usize) -> Result<(), Error> {
        if self.entries.len() >= capacity {
            Err(Error::ReplayCapacity)
        } else {
            Ok(())
        }
    }

    fn finish(&mut self, now_unix: u64) {
        self.last_seen_unix = now_unix;
        self.entries.sort_unstable();
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(6)
            .unwrap()
            .u16(STATE_VERSION)
            .unwrap()
            .u16(self.scope.role as u16)
            .unwrap()
            .bytes(&self.scope.desktop_id)
            .unwrap()
            .bytes(&self.scope.identity_id)
            .unwrap()
            .u64(self.last_seen_unix)
            .unwrap()
            .array(u64::try_from(self.entries.len()).unwrap())
            .unwrap();
        for entry in &self.entries {
            match entry {
                ReplayEntry::Request {
                    request_id,
                    nonce,
                    expires_at_unix,
                } => {
                    encoder
                        .array(4)
                        .unwrap()
                        .u16(REQUEST_ENTRY)
                        .unwrap()
                        .bytes(request_id)
                        .unwrap()
                        .bytes(nonce)
                        .unwrap()
                        .u64(*expires_at_unix)
                        .unwrap();
                }
                ReplayEntry::Response {
                    digest,
                    expires_at_unix,
                } => {
                    encoder
                        .array(3)
                        .unwrap()
                        .u16(RESPONSE_ENTRY)
                        .unwrap()
                        .bytes(digest)
                        .unwrap()
                        .u64(*expires_at_unix)
                        .unwrap();
                }
            }
        }
        encoder.into_writer()
    }

    fn decode(encoded: &[u8], capacity: usize) -> Result<Self, Error> {
        let mut decoder = Decoder::new(encoded);
        exact_array(&mut decoder, 6)?;
        if decoder.u16().map_err(|_| Error::ReplayState)? != STATE_VERSION {
            return Err(Error::ReplayState);
        }
        let role = ReplayRole::try_from(decoder.u16().map_err(|_| Error::ReplayState)?)?;
        let desktop_id = fixed(decoder.bytes().map_err(|_| Error::ReplayState)?)?;
        let identity_id = fixed(decoder.bytes().map_err(|_| Error::ReplayState)?)?;
        let last_seen_unix = decoder.u64().map_err(|_| Error::ReplayState)?;
        let count = decoder
            .array()
            .map_err(|_| Error::ReplayState)?
            .ok_or(Error::ReplayState)?;
        let count = usize::try_from(count).map_err(|_| Error::ReplayState)?;
        if count > capacity {
            return Err(Error::ReplayCapacity);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(match role {
                ReplayRole::PhoneRequests => {
                    exact_array(&mut decoder, 4)?;
                    if decoder.u16().map_err(|_| Error::ReplayState)? != REQUEST_ENTRY {
                        return Err(Error::ReplayState);
                    }
                    ReplayEntry::Request {
                        request_id: fixed(decoder.bytes().map_err(|_| Error::ReplayState)?)?,
                        nonce: fixed(decoder.bytes().map_err(|_| Error::ReplayState)?)?,
                        expires_at_unix: decoder.u64().map_err(|_| Error::ReplayState)?,
                    }
                }
                ReplayRole::DesktopResponses => {
                    exact_array(&mut decoder, 3)?;
                    if decoder.u16().map_err(|_| Error::ReplayState)? != RESPONSE_ENTRY {
                        return Err(Error::ReplayState);
                    }
                    ReplayEntry::Response {
                        digest: fixed(decoder.bytes().map_err(|_| Error::ReplayState)?)?,
                        expires_at_unix: decoder.u64().map_err(|_| Error::ReplayState)?,
                    }
                }
            });
        }
        if decoder.position() != encoded.len() {
            return Err(Error::ReplayState);
        }
        let state = Self {
            scope: ReplayScope::new(role, desktop_id, identity_id),
            last_seen_unix,
            entries,
        };
        state.validate(capacity)?;
        if state.encode() != encoded {
            return Err(Error::ReplayState);
        }
        Ok(state)
    }

    fn validate(&self, capacity: usize) -> Result<(), Error> {
        validate_capacity(capacity)?;
        if self.entries.len() > capacity
            || self
                .entries
                .iter()
                .any(|entry| entry.expires_at_unix() < self.last_seen_unix)
            || self.entries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::ReplayState);
        }
        let mut request_ids = HashSet::new();
        let mut nonces = HashSet::new();
        let mut responses = HashSet::new();
        for entry in &self.entries {
            match entry {
                ReplayEntry::Request {
                    request_id, nonce, ..
                } if self.scope.role == ReplayRole::PhoneRequests => {
                    if !request_ids.insert(*request_id) || !nonces.insert(*nonce) {
                        return Err(Error::ReplayState);
                    }
                }
                ReplayEntry::Response { digest, .. }
                    if self.scope.role == ReplayRole::DesktopResponses =>
                {
                    if !responses.insert(*digest) {
                        return Err(Error::ReplayState);
                    }
                }
                _ => return Err(Error::ReplayState),
            }
        }
        Ok(())
    }
}

fn exact_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), Error> {
    if decoder.array().map_err(|_| Error::ReplayState)? == Some(expected) {
        Ok(())
    } else {
        Err(Error::ReplayState)
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::ReplayState)
}

fn validate_capacity(capacity: usize) -> Result<(), Error> {
    if (1..=MAX_CONFIGURED_ENTRIES).contains(&capacity) {
        Ok(())
    } else {
        Err(Error::ReplayCapacity)
    }
}

fn validate_expiry(expires_at_unix: u64, now_unix: u64) -> Result<(), Error> {
    if expires_at_unix < now_unix {
        Err(Error::Expired)
    } else if expires_at_unix > now_unix.saturating_add(MAX_REQUEST_LIFETIME_SECS) {
        Err(Error::LifetimeTooLong)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
mod file {
    use std::{
        ffi::OsString,
        fs::{self, File, OpenOptions},
        io::{Read as _, Write as _},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rustix::fs::{FlockOperation, flock};

    use super::{ReplayRole, ReplayScope, ReplayState, ReplayStore, validate_capacity};
    use crate::{Error, Id, ProtocolDigest, ProtocolNonce};

    const MAX_STATE_BYTES: u64 = 1_048_576;
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct FileReplayGuard {
        path: PathBuf,
        state: ReplayState,
        capacity: usize,
        poisoned: bool,
        _lock: File,
    }

    impl FileReplayGuard {
        pub fn create(
            path: impl AsRef<Path>,
            scope: ReplayScope,
            capacity: usize,
            now_unix: u64,
        ) -> Result<Self, Error> {
            validate_capacity(capacity)?;
            let path = checked_path(path.as_ref())?;
            let lock = acquire_lock(&path)?;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) | Err(_) => return Err(Error::ReplayState),
            }
            let state = ReplayState::new(scope, now_unix);
            persist_create(&path, &state.encode())?;
            Ok(Self {
                path,
                state,
                capacity,
                poisoned: false,
                _lock: lock,
            })
        }

        pub fn open(
            path: impl AsRef<Path>,
            expected_scope: ReplayScope,
            capacity: usize,
        ) -> Result<Self, Error> {
            validate_capacity(capacity)?;
            let path = checked_path(path.as_ref())?;
            let lock = acquire_lock(&path)?;
            let encoded = read_private_file(&path)?;
            let state = ReplayState::decode(&encoded, capacity)?;
            if state.scope != expected_scope {
                return Err(Error::ReplayState);
            }
            Ok(Self {
                path,
                state,
                capacity,
                poisoned: false,
                _lock: lock,
            })
        }

        #[must_use]
        pub const fn scope(&self) -> ReplayScope {
            self.state.scope
        }

        fn commit(&mut self, next: ReplayState) -> Result<(), Error> {
            if self.poisoned {
                return Err(Error::ReplayState);
            }
            if atomic_replace(&self.path, &next.encode()).is_err() {
                self.poisoned = true;
                return Err(Error::ReplayState);
            }
            self.state = next;
            Ok(())
        }
    }

    impl ReplayStore for FileReplayGuard {
        fn consume_request(
            &mut self,
            desktop_id: Id,
            identity_id: Id,
            request_id: Id,
            nonce: ProtocolNonce,
            expires_at_unix: u64,
            now_unix: u64,
        ) -> Result<(), Error> {
            if self.poisoned {
                return Err(Error::ReplayState);
            }
            let mut next = self.state.clone();
            next.consume_request(
                ReplayScope::new(ReplayRole::PhoneRequests, desktop_id, identity_id),
                request_id,
                nonce,
                expires_at_unix,
                now_unix,
                self.capacity,
            )?;
            self.commit(next)
        }

        fn consume_response(
            &mut self,
            desktop_id: Id,
            identity_id: Id,
            response_digest: ProtocolDigest,
            expires_at_unix: u64,
            now_unix: u64,
        ) -> Result<(), Error> {
            if self.poisoned {
                return Err(Error::ReplayState);
            }
            let mut next = self.state.clone();
            next.consume_response(
                ReplayScope::new(ReplayRole::DesktopResponses, desktop_id, identity_id),
                response_digest,
                expires_at_unix,
                now_unix,
                self.capacity,
            )?;
            self.commit(next)
        }
    }

    fn checked_path(path: &Path) -> Result<PathBuf, Error> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(Error::ReplayState);
        }
        let parent = path.parent().ok_or(Error::ReplayState)?;
        let metadata = fs::metadata(parent).map_err(|_| Error::ReplayState)?;
        if !metadata.is_dir() {
            return Err(Error::ReplayState);
        }
        Ok(path.to_path_buf())
    }

    fn acquire_lock(path: &Path) -> Result<File, Error> {
        let lock_path = sibling_path(path, ".lock")?;
        reject_symlink_if_present(&lock_path)?;
        let lock = private_options()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(|_| Error::ReplayState)?;
        ensure_private_regular(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::ReplayState)?;
        Ok(lock)
    }

    fn read_private_file(path: &Path) -> Result<Vec<u8>, Error> {
        reject_symlink_if_present(path)?;
        let file = File::open(path).map_err(|_| Error::ReplayState)?;
        ensure_private_regular(&file)?;
        if file.metadata().map_err(|_| Error::ReplayState)?.len() > MAX_STATE_BYTES {
            return Err(Error::ReplayState);
        }
        let mut encoded = Vec::new();
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| Error::ReplayState)?;
        if encoded.is_empty() || u64::try_from(encoded.len()).unwrap() > MAX_STATE_BYTES {
            return Err(Error::ReplayState);
        }
        Ok(encoded)
    }

    fn persist_create(path: &Path, encoded: &[u8]) -> Result<(), Error> {
        let temporary = write_temporary(path, encoded)?;
        if fs::hard_link(&temporary, path).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::ReplayState);
        }
        let remove_result = fs::remove_file(&temporary);
        let sync_result = sync_parent(path);
        if remove_result.is_err() || sync_result.is_err() {
            return Err(Error::ReplayState);
        }
        Ok(())
    }

    fn atomic_replace(path: &Path, encoded: &[u8]) -> Result<(), Error> {
        let temporary = write_temporary(path, encoded)?;
        if fs::rename(&temporary, path).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::ReplayState);
        }
        sync_parent(path)
    }

    fn write_temporary(path: &Path, encoded: &[u8]) -> Result<PathBuf, Error> {
        for _ in 0..32 {
            let suffix = format!(
                ".{}.{}.tmp",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let temporary = sibling_path(path, &suffix)?;
            let mut file = match private_options()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(Error::ReplayState),
            };
            if file.write_all(encoded).is_err() || file.sync_all().is_err() {
                let _ = fs::remove_file(&temporary);
                return Err(Error::ReplayState);
            }
            return Ok(temporary);
        }
        Err(Error::ReplayState)
    }

    fn sync_parent(path: &Path) -> Result<(), Error> {
        File::open(path.parent().ok_or(Error::ReplayState)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::ReplayState)
    }

    fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf, Error> {
        let mut name = OsString::from(path.file_name().ok_or(Error::ReplayState)?);
        name.push(suffix);
        Ok(path.parent().ok_or(Error::ReplayState)?.join(name))
    }

    fn reject_symlink_if_present(path: &Path) -> Result<(), Error> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::ReplayState),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::ReplayState),
        }
    }

    fn ensure_private_regular(file: &File) -> Result<(), Error> {
        let metadata = file.metadata().map_err(|_| Error::ReplayState)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            Err(Error::ReplayState)
        } else {
            Ok(())
        }
    }

    fn private_options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.mode(0o600);
        options
    }
}

#[cfg(unix)]
pub use file::FileReplayGuard;

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP: Id = [0x11; 16];
    const IDENTITY: Id = [0x22; 16];

    #[test]
    fn state_is_canonical_bounded_and_clock_monotonic() {
        let scope = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
        let mut state = ReplayState::new(scope, 100);
        state
            .consume_request(scope, [1; 16], [2; 32], 110, 100, 1)
            .unwrap();
        let encoded = state.encode();
        assert_eq!(ReplayState::decode(&encoded, 1).unwrap(), state);

        assert_eq!(
            state
                .clone()
                .consume_request(scope, [1; 16], [3; 32], 110, 100, 1)
                .unwrap_err(),
            Error::Replay
        );
        assert_eq!(
            state
                .clone()
                .consume_request(scope, [3; 16], [4; 32], 110, 100, 1)
                .unwrap_err(),
            Error::ReplayCapacity
        );
        assert_eq!(
            state
                .clone()
                .consume_request(scope, [3; 16], [4; 32], 110, 99, 1)
                .unwrap_err(),
            Error::ClockRollback
        );

        state
            .consume_request(scope, [3; 16], [4; 32], 120, 111, 1)
            .unwrap();
        assert_eq!(state.entries.len(), 1);

        let mut trailing = state.encode();
        trailing.push(0);
        assert_eq!(
            ReplayState::decode(&trailing, 1).unwrap_err(),
            Error::ReplayState
        );
    }

    #[test]
    fn state_rejects_wrong_role_scope_and_invalid_capacity() {
        let phone = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
        let desktop = ReplayScope::new(ReplayRole::DesktopResponses, DESKTOP, IDENTITY);
        let mut state = ReplayState::new(phone, 100);
        assert_eq!(
            state
                .consume_response(desktop, [1; 32], 110, 100, 1)
                .unwrap_err(),
            Error::ReplayState
        );
        assert_eq!(validate_capacity(0).unwrap_err(), Error::ReplayCapacity);
        assert_eq!(
            validate_capacity(MAX_CONFIGURED_ENTRIES + 1).unwrap_err(),
            Error::ReplayCapacity
        );
    }

    #[test]
    fn state_rejects_unknown_noncanonical_unsorted_and_duplicate_entries() {
        let scope = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
        let empty = ReplayState::new(scope, 100).encode();

        let mut unknown_version = empty.clone();
        unknown_version[1] = 3;
        assert_eq!(
            ReplayState::decode(&unknown_version, 2).unwrap_err(),
            Error::ReplayState
        );

        let mut old_version = empty.clone();
        old_version[1] = 1;
        assert_eq!(
            ReplayState::decode(&old_version, 2).unwrap_err(),
            Error::ReplayState
        );

        let mut extra_field = empty.clone();
        extra_field[0] = 0x87;
        assert_eq!(
            ReplayState::decode(&extra_field, 2).unwrap_err(),
            Error::ReplayState
        );

        let mut noncanonical = empty;
        noncanonical.splice(1..2, [0x19, 0x00, 0x01]);
        assert_eq!(
            ReplayState::decode(&noncanonical, 2).unwrap_err(),
            Error::ReplayState
        );

        let unsorted = ReplayState {
            scope,
            last_seen_unix: 100,
            entries: vec![
                ReplayEntry::Request {
                    request_id: [2; 16],
                    nonce: [2; 32],
                    expires_at_unix: 110,
                },
                ReplayEntry::Request {
                    request_id: [1; 16],
                    nonce: [1; 32],
                    expires_at_unix: 110,
                },
            ],
        };
        assert_eq!(
            ReplayState::decode(&unsorted.encode(), 2).unwrap_err(),
            Error::ReplayState
        );

        let duplicate_id = ReplayState {
            scope,
            last_seen_unix: 100,
            entries: vec![
                ReplayEntry::Request {
                    request_id: [1; 16],
                    nonce: [1; 32],
                    expires_at_unix: 110,
                },
                ReplayEntry::Request {
                    request_id: [1; 16],
                    nonce: [2; 32],
                    expires_at_unix: 110,
                },
            ],
        };
        assert_eq!(
            ReplayState::decode(&duplicate_id.encode(), 2).unwrap_err(),
            Error::ReplayState
        );

        let duplicate_nonce = ReplayState {
            scope,
            last_seen_unix: 100,
            entries: vec![
                ReplayEntry::Request {
                    request_id: [1; 16],
                    nonce: [1; 32],
                    expires_at_unix: 110,
                },
                ReplayEntry::Request {
                    request_id: [2; 16],
                    nonce: [1; 32],
                    expires_at_unix: 110,
                },
            ],
        };
        assert_eq!(
            ReplayState::decode(&duplicate_nonce.encode(), 2).unwrap_err(),
            Error::ReplayState
        );
    }

    #[cfg(unix)]
    mod unix {
        use std::{
            fs,
            os::unix::fs::PermissionsExt as _,
            path::{Path, PathBuf},
            sync::atomic::{AtomicU64, Ordering},
        };

        use super::*;
        use crate::FileReplayGuard;

        static DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "age-plugin-phone-replay-{label}-{}-{}",
                    std::process::id(),
                    DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                Self(path)
            }

            fn state_path(&self) -> PathBuf {
                self.0.join("replay.cbor")
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn file_state_survives_restart_and_rejects_concurrent_open() {
            let directory = TestDirectory::new("restart");
            let path = directory.state_path();
            let scope = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
            let mut first = FileReplayGuard::create(&path, scope, 2, 100).unwrap();
            assert_eq!(
                FileReplayGuard::open(&path, scope, 2).err().unwrap(),
                Error::ReplayState
            );
            first
                .consume_request(DESKTOP, IDENTITY, [1; 16], [2; 32], 110, 100)
                .unwrap();
            drop(first);

            let mut reopened = FileReplayGuard::open(&path, scope, 2).unwrap();
            assert_eq!(reopened.scope(), scope);
            assert_eq!(
                reopened
                    .consume_request(DESKTOP, IDENTITY, [1; 16], [2; 32], 110, 100)
                    .unwrap_err(),
                Error::Replay
            );
            assert_eq!(
                reopened
                    .consume_request(DESKTOP, IDENTITY, [3; 16], [4; 32], 110, 99)
                    .unwrap_err(),
                Error::ClockRollback
            );
            drop(reopened);

            let wrong_scope = ReplayScope::new(ReplayRole::PhoneRequests, [9; 16], IDENTITY);
            assert_eq!(
                FileReplayGuard::open(&path, wrong_scope, 2).err().unwrap(),
                Error::ReplayState
            );
        }

        #[test]
        fn file_state_persists_response_consumption() {
            let directory = TestDirectory::new("response");
            let path = directory.state_path();
            let scope = ReplayScope::new(ReplayRole::DesktopResponses, DESKTOP, IDENTITY);
            let mut guard = FileReplayGuard::create(&path, scope, 1, 100).unwrap();
            guard
                .consume_response(DESKTOP, IDENTITY, [5; 32], 110, 100)
                .unwrap();
            drop(guard);

            let mut reopened = FileReplayGuard::open(&path, scope, 1).unwrap();
            assert_eq!(
                reopened
                    .consume_response(DESKTOP, IDENTITY, [5; 32], 110, 100)
                    .unwrap_err(),
                Error::Replay
            );
        }

        #[test]
        fn missing_corrupt_and_non_private_state_fail_closed() {
            let directory = TestDirectory::new("corrupt");
            let path = directory.state_path();
            let scope = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
            assert_eq!(
                FileReplayGuard::open(&path, scope, 1).err().unwrap(),
                Error::ReplayState
            );

            drop(FileReplayGuard::create(&path, scope, 1, 100).unwrap());
            fs::write(&path, [0xff]).unwrap();
            assert_eq!(
                FileReplayGuard::open(&path, scope, 1).err().unwrap(),
                Error::ReplayState
            );

            fs::remove_file(&path).unwrap();
            drop(FileReplayGuard::create(&path, scope, 1, 100).unwrap());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                FileReplayGuard::open(&path, scope, 1).err().unwrap(),
                Error::ReplayState
            );
        }

        #[test]
        fn write_failure_poisons_guard_without_consuming_token() {
            let directory = TestDirectory::new("failure");
            let path = directory.state_path();
            let moved = directory.path().with_extension("moved");
            let scope = ReplayScope::new(ReplayRole::PhoneRequests, DESKTOP, IDENTITY);
            let mut guard = FileReplayGuard::create(&path, scope, 1, 100).unwrap();

            fs::rename(directory.path(), &moved).unwrap();
            assert_eq!(
                guard
                    .consume_request(DESKTOP, IDENTITY, [1; 16], [2; 32], 110, 100)
                    .unwrap_err(),
                Error::ReplayState
            );
            fs::rename(&moved, directory.path()).unwrap();
            assert_eq!(
                guard
                    .consume_request(DESKTOP, IDENTITY, [1; 16], [2; 32], 110, 100)
                    .unwrap_err(),
                Error::ReplayState
            );
            drop(guard);

            let mut reopened = FileReplayGuard::open(&path, scope, 1).unwrap();
            reopened
                .consume_request(DESKTOP, IDENTITY, [1; 16], [2; 32], 110, 100)
                .unwrap();
        }
    }
}
