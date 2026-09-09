//! macOS replay storage; uncertain commits leave a durable pending marker.

use age_plugin_phone_platform_storage::macos::{Directory, Error as StorageError, PrivateLock};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use super::{ReplayRole, ReplayScope, ReplayState, ReplayStore, validate_capacity};
use crate::protocol::{Error, Id, ProtocolDigest, ProtocolNonce};

const MAX_STATE_BYTES: u64 = 1_048_576;

pub struct FileReplayGuard {
    state: ReplayState,
    capacity: usize,
    poisoned: bool,
    #[cfg(test)]
    failure_stage: u8,
    directory: Directory,
    child: PathBuf,
    pending: PathBuf,
    lock: PrivateLock,
}

impl FileReplayGuard {
    pub fn create(
        path: impl AsRef<Path>,
        scope: ReplayScope,
        capacity: usize,
        now_unix: u64,
    ) -> Result<Self, Error> {
        validate_capacity(capacity)?;
        let (directory, child, pending, lock) = open_storage(path.as_ref())?;
        let state = ReplayState::new(scope, now_unix);
        directory
            .create(&child, &state.encode())
            .map_err(|_| Error::ReplayState)?;
        Ok(Self {
            state,
            capacity,
            poisoned: false,
            #[cfg(test)]
            failure_stage: 0,
            directory,
            child,
            pending,
            lock,
        })
    }

    pub fn open(
        path: impl AsRef<Path>,
        expected_scope: ReplayScope,
        capacity: usize,
    ) -> Result<Self, Error> {
        validate_capacity(capacity)?;
        let (directory, child, pending, lock) = open_storage(path.as_ref())?;
        let encoded = directory
            .read(&child, MAX_STATE_BYTES)
            .map_err(|_| Error::ReplayState)?;
        let state = ReplayState::decode(&encoded, capacity)?;
        if state.scope != expected_scope {
            return Err(Error::ReplayState);
        }
        Ok(Self {
            state,
            capacity,
            poisoned: false,
            #[cfg(test)]
            failure_stage: 0,
            directory,
            child,
            pending,
            lock,
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
        let result: Result<(), StorageError> = (|| {
            self.lock.validate(&self.directory)?;
            self.directory.create(&self.pending, b"pending")?;
            #[cfg(test)]
            if self.failure_stage == 1 {
                return Err(StorageError::Storage);
            }
            self.directory.replace(&self.child, &next.encode())?;
            #[cfg(test)]
            if self.failure_stage == 2 {
                return Err(StorageError::Storage);
            }
            self.lock.validate(&self.directory)?;
            self.directory.remove(&self.pending)?;
            #[cfg(test)]
            if self.failure_stage == 3 {
                return Err(StorageError::Storage);
            }
            Ok(())
        })();
        if result.is_err() {
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

fn open_storage(path: &Path) -> Result<(Directory, PathBuf, PathBuf, PrivateLock), Error> {
    let directory = Directory::open(path.parent().ok_or(Error::ReplayState)?)
        .map_err(|_| Error::ReplayState)?;
    let child = PathBuf::from(path.file_name().ok_or(Error::ReplayState)?);
    let mut pending = OsString::from(child.as_os_str());
    pending.push(".pending");
    let pending = PathBuf::from(pending);
    let mut lock = OsString::from(child.as_os_str());
    lock.push(".lock");
    let lock = directory
        .lock(Path::new(&lock))
        .map_err(|_| Error::ReplayState)?;
    match directory.read(&pending, 64) {
        Err(StorageError::Missing) => {}
        _ => return Err(Error::ReplayState),
    }
    Ok((directory, child, pending, lock))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    fn fixture() -> (PathBuf, ReplayScope) {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "phone-m2-replay-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        Directory::prepare(&root).unwrap();
        (
            root,
            ReplayScope::new(ReplayRole::DesktopResponses, [1; 16], [2; 16]),
        )
    }
    #[test]
    fn uncertain_commit_blocks_restart_and_other_pairings_survive() {
        let (root, scope) = fixture();
        let path = root.join("responses");
        let mut first = FileReplayGuard::create(&path, scope, 2, 100).unwrap();
        let mut other = FileReplayGuard::create(root.join("other"), scope, 2, 100).unwrap();
        first.failure_stage = 1;
        assert_eq!(
            first.consume_response([1; 16], [2; 16], [3; 32], 110, 100),
            Err(Error::ReplayState)
        );
        assert!(root.join("responses.pending").exists());
        first.failure_stage = 0;
        assert!(
            first
                .consume_response([1; 16], [2; 16], [3; 32], 110, 100)
                .is_err()
        );
        drop(first);
        assert!(FileReplayGuard::open(&path, scope, 2).is_err());
        assert!(FileReplayGuard::create(&path, scope, 2, 100).is_err());
        other
            .consume_response([1; 16], [2; 16], [4; 32], 110, 100)
            .unwrap();
        drop(other);
        let mut reopened = FileReplayGuard::open(root.join("other"), scope, 2).unwrap();
        assert_eq!(
            reopened.consume_response([1; 16], [2; 16], [4; 32], 110, 100),
            Err(Error::Replay)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn post_replacement_failures_never_restore_consumption() {
        for stage in [2, 3] {
            let (root, scope) = fixture();
            let path = root.join("responses");
            let mut guard = FileReplayGuard::create(&path, scope, 2, 100).unwrap();
            guard.failure_stage = stage;
            assert!(
                guard
                    .consume_response([1; 16], [2; 16], [3; 32], 110, 100)
                    .is_err()
            );
            drop(guard);
            match FileReplayGuard::open(&path, scope, 2) {
                Ok(mut reopened) => assert_eq!(
                    reopened.consume_response([1; 16], [2; 16], [3; 32], 110, 100),
                    Err(Error::Replay)
                ),
                Err(error) => assert_eq!(error, Error::ReplayState),
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn replaced_lock_and_missing_state_cannot_commit() {
        let (root, scope) = fixture();
        let path = root.join("responses");
        let mut guard = FileReplayGuard::create(&path, scope, 2, 100).unwrap();
        std::fs::rename(root.join("responses.lock"), root.join("old.lock")).unwrap();
        let other = FileReplayGuard::open(&path, scope, 2).unwrap();
        assert!(
            guard
                .consume_response([1; 16], [2; 16], [3; 32], 110, 100)
                .is_err()
        );
        drop(other);
        drop(guard);
        let mut guard = FileReplayGuard::open(&path, scope, 2).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(
            guard
                .consume_response([1; 16], [2; 16], [3; 32], 110, 100)
                .is_err()
        );
        drop(guard);
        assert!(FileReplayGuard::create(&path, scope, 2, 100).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn independent_process_lock_and_replay() {
        const CHILD: &str = "AGE_PHONE_M2_REPLAY_TEST";
        if let Some(root) = std::env::var_os(CHILD) {
            let scope = ReplayScope::new(ReplayRole::DesktopResponses, [1; 16], [2; 16]);
            let result = FileReplayGuard::open(Path::new(&root).join("responses"), scope, 2);
            if std::env::var_os("AGE_PHONE_M2_LOCKED").is_some() {
                assert!(result.is_err());
            } else {
                let mut guard = result.unwrap();
                assert_eq!(
                    guard.consume_response([1; 16], [2; 16], [3; 32], 110, 100),
                    Err(Error::Replay)
                );
            }
            return;
        }
        let (root, scope) = fixture();
        let mut guard = FileReplayGuard::create(root.join("responses"), scope, 2, 100).unwrap();
        let run = |locked| {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "protocol::replay::macos_file::tests::independent_process_lock_and_replay",
                "--exact",
            ])
            .env(CHILD, &root);
            if locked {
                cmd.env("AGE_PHONE_M2_LOCKED", "1");
            } else {
                cmd.env_remove("AGE_PHONE_M2_LOCKED");
            }
            assert!(cmd.status().unwrap().success());
        };
        run(true);
        guard
            .consume_response([1; 16], [2; 16], [3; 32], 110, 100)
            .unwrap();
        drop(guard);
        run(false);
        std::fs::remove_dir_all(root).unwrap();
    }
}
