//! Developer-oriented ADB reverse transport for the Windows Alpha.
//!
//! ADB device properties are used only to select the requested transport endpoint. The protocol
//! layer still authenticates every message and binds it to a paired desktop.

#![allow(clippy::missing_errors_doc)]

use std::{
    io::{self, Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use age_plugin_phone_transport::{
    DesktopStreamSession, DesktopTransport, SessionPurpose, TransportError, TransportLimits,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

pub const ANDROID_LOOPBACK_PORT: u16 = 47_139;
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MESSAGE_TIMEOUT: Duration = Duration::from_secs(90);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const DEFAULT_ADB_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_GUARD_EXIT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Device {
    serial: String,
    state: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdbError {
    #[error("ADB is unavailable or returned an invalid result")]
    Unavailable,
    #[error("no online Android device is connected")]
    NoDevice,
    #[error("multiple Android devices require explicit selection")]
    DeviceSelectionRequired,
    #[error("the selected Android device is unauthorized, offline, missing, or replaced")]
    DeviceUnavailable,
    #[error("the selected ADB reverse port is already in use")]
    ReverseRuleExists,
    #[error("failed to create or remove the exact ADB reverse rule")]
    ReverseRule,
    #[error("the phone did not connect before the hard deadline")]
    ConnectionTimeout,
    #[error("an unexpected non-loopback peer connected")]
    InvalidPeer,
    #[error("the bounded transport session failed")]
    Transport,
}

pub trait AdbRunner {
    fn run(&mut self, args: &[&str]) -> io::Result<String>;

    fn arm_cleanup_guard(&self, _serial: &str) -> io::Result<Option<CleanupGuardian>> {
        Ok(None)
    }
}

/// Child-process guard used only to remove the fixed Developer USB reverse rule after parent exit.
pub struct CleanupGuardian {
    child: Child,
    input: Option<ChildStdin>,
    armed: bool,
}

impl CleanupGuardian {
    fn spawn(serial: &str) -> io::Result<Self> {
        if !valid_serial(serial) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ADB serial",
            ));
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["__adb-cleanup-guard", "--serial", serial])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        isolate_cleanup_guard(&mut command);
        let mut child = command.spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("cleanup guard pipe unavailable"))?;
        Ok(Self {
            child,
            input: Some(input),
            armed: true,
        })
    }

    fn disarm(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let mut input = self
            .input
            .take()
            .ok_or_else(|| io::Error::other("cleanup guard pipe unavailable"))?;
        input.write_all(b"D")?;
        input.flush()?;
        drop(input);
        self.armed = false;
        let started = Instant::now();
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if started.elapsed() >= CLEANUP_GUARD_EXIT_TIMEOUT {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cleanup guard did not exit",
                ));
            }
            thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }
}

#[cfg(unix)]
fn isolate_cleanup_guard(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(windows)]
fn isolate_cleanup_guard(command: &mut Command) {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

impl Drop for CleanupGuardian {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.try_wait();
    }
}

pub struct SystemAdb {
    executable: String,
    command_timeout: Duration,
}

impl SystemAdb {
    #[must_use]
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            command_timeout: DEFAULT_ADB_COMMAND_TIMEOUT,
        }
    }
}

impl Default for SystemAdb {
    fn default() -> Self {
        Self::new("adb")
    }
}

impl AdbRunner for SystemAdb {
    fn run(&mut self, args: &[&str]) -> io::Result<String> {
        let mut child = Command::new(&self.executable)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= self.command_timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ADB command timed out",
                ));
            }
            thread::sleep(ACCEPT_POLL_INTERVAL);
        };
        if !status.success() {
            return Err(io::Error::other("ADB command failed"));
        }
        let mut stdout = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("ADB output was unavailable"))?
            .read_to_end(&mut stdout)?;
        String::from_utf8(stdout).map_err(|_| io::Error::other("ADB output was not UTF-8"))
    }

    fn arm_cleanup_guard(&self, serial: &str) -> io::Result<Option<CleanupGuardian>> {
        CleanupGuardian::spawn(serial).map(Some)
    }
}

pub struct AdbReverseSession<R: AdbRunner> {
    runner: R,
    serial: String,
    reverse_spec: String,
    stream: DesktopStreamSession<TcpStream>,
    cleanup_guard: Option<CleanupGuardian>,
    rule_active: bool,
    closed: bool,
}

impl<R: AdbRunner> AdbReverseSession<R> {
    pub fn connect(
        mut runner: R,
        requested_serial: Option<&str>,
        connect_timeout: Duration,
        message_timeout: Duration,
        limits: TransportLimits,
        random: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, AdbError> {
        let serial = select_device(&mut runner, requested_serial)?;
        let reverse_spec = format!("tcp:{ANDROID_LOOPBACK_PORT}");
        reject_existing_rule(&mut runner, &serial, &reverse_spec)?;

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|_| AdbError::Unavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AdbError::Unavailable)?;
        let desktop_spec = format!(
            "tcp:{}",
            listener
                .local_addr()
                .map_err(|_| AdbError::Unavailable)?
                .port()
        );
        let Ok(mut cleanup_guard) = runner.arm_cleanup_guard(&serial) else {
            return Err(AdbError::ReverseRule);
        };
        if runner
            .run(&["-s", &serial, "reverse", &reverse_spec, &desktop_spec])
            .is_err()
        {
            cleanup_created_rule(&mut runner, &serial, &reverse_spec, cleanup_guard.as_mut());
            return Err(AdbError::ReverseRule);
        }

        let accepted = accept_before(&listener, connect_timeout);
        let (stream, peer) = match accepted {
            Ok(value) => value,
            Err(error) => {
                cleanup_created_rule(&mut runner, &serial, &reverse_spec, cleanup_guard.as_mut());
                return Err(error);
            }
        };
        if !peer.ip().is_loopback() {
            cleanup_created_rule(&mut runner, &serial, &reverse_spec, cleanup_guard.as_mut());
            return Err(AdbError::InvalidPeer);
        }
        let configured = (|| {
            stream
                .set_nonblocking(false)
                .map_err(|_| AdbError::Unavailable)?;
            stream
                .set_read_timeout(Some(message_timeout))
                .map_err(|_| AdbError::Unavailable)?;
            stream
                .set_write_timeout(Some(message_timeout))
                .map_err(|_| AdbError::Unavailable)?;
            ensure_same_online_device(&mut runner, &serial)?;
            DesktopStreamSession::new(stream, limits, random).map_err(|_| AdbError::Transport)
        })();
        let stream = match configured {
            Ok(stream) => stream,
            Err(error) => {
                cleanup_created_rule(&mut runner, &serial, &reverse_spec, cleanup_guard.as_mut());
                return Err(error);
            }
        };
        Ok(Self {
            runner,
            serial,
            reverse_spec,
            stream,
            cleanup_guard,
            rule_active: true,
            closed: false,
        })
    }

    #[must_use]
    pub fn selected_serial(&self) -> &str {
        &self.serial
    }

    fn remove_rule(&mut self) -> Result<(), AdbError> {
        if !self.rule_active {
            return Ok(());
        }
        remove_reverse_rule(&mut self.runner, &self.serial, &self.reverse_spec)?;
        self.rule_active = false;
        if let Some(guard) = self.cleanup_guard.as_mut() {
            guard.disarm().map_err(|_| AdbError::ReverseRule)?;
        }
        Ok(())
    }
}

impl<R: AdbRunner> DesktopTransport for AdbReverseSession<R> {
    fn exchange(
        &mut self,
        purpose: SessionPurpose,
        request: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::SessionClosed);
        }
        self.closed = true;
        let response = self.stream.exchange(purpose, request);
        let device_unchanged = ensure_same_online_device(&mut self.runner, &self.serial).is_ok();
        let rule_removed = self.remove_rule().is_ok();
        if !device_unchanged || !rule_removed {
            return Err(TransportError::Io);
        }
        response
    }

    fn cancel(&mut self) {
        self.closed = true;
        self.stream.cancel();
        let _ = self.remove_rule();
    }
}

impl<R: AdbRunner> Drop for AdbReverseSession<R> {
    fn drop(&mut self) {
        self.stream.cancel();
        let _ = self.remove_rule();
    }
}

fn accept_before(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), AdbError> {
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= timeout {
                    return Err(AdbError::ConnectionTimeout);
                }
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => return Err(AdbError::Unavailable),
        }
    }
}

fn select_device(
    runner: &mut impl AdbRunner,
    requested_serial: Option<&str>,
) -> Result<String, AdbError> {
    let devices = list_devices(runner)?;
    if let Some(serial) = requested_serial {
        if !valid_serial(serial) {
            return Err(AdbError::DeviceUnavailable);
        }
        return devices
            .into_iter()
            .find(|device| device.serial == serial && device.state == "device")
            .map(|device| device.serial)
            .ok_or(AdbError::DeviceUnavailable);
    }
    match devices.as_slice() {
        [] => Err(AdbError::NoDevice),
        [device] if device.state == "device" => Ok(device.serial.clone()),
        [_] => Err(AdbError::DeviceUnavailable),
        _ => Err(AdbError::DeviceSelectionRequired),
    }
}

fn ensure_same_online_device(runner: &mut impl AdbRunner, serial: &str) -> Result<(), AdbError> {
    let selected = select_device(runner, Some(serial))?;
    if selected == serial {
        Ok(())
    } else {
        Err(AdbError::DeviceUnavailable)
    }
}

fn list_devices(runner: &mut impl AdbRunner) -> Result<Vec<Device>, AdbError> {
    let output = runner
        .run(&["devices"])
        .map_err(|_| AdbError::Unavailable)?;
    parse_devices(&output)
}

fn parse_devices(output: &str) -> Result<Vec<Device>, AdbError> {
    let mut lines = output.lines();
    if lines.next().map(str::trim) != Some("List of devices attached") {
        return Err(AdbError::Unavailable);
    }
    let mut devices = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let serial = fields.next().ok_or(AdbError::Unavailable)?;
        let state = fields.next().ok_or(AdbError::Unavailable)?;
        if fields.next().is_some() || !valid_serial(serial) {
            return Err(AdbError::Unavailable);
        }
        devices.push(Device {
            serial: serial.to_owned(),
            state: state.to_owned(),
        });
    }
    Ok(devices)
}

fn valid_serial(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= 128
        && serial
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
}

fn reject_existing_rule(
    runner: &mut impl AdbRunner,
    serial: &str,
    reverse_spec: &str,
) -> Result<(), AdbError> {
    let output = runner
        .run(&["-s", serial, "reverse", "--list"])
        .map_err(|_| AdbError::Unavailable)?;
    if output.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() == 3 && fields[0] == serial && fields[1] == reverse_spec
    }) {
        Err(AdbError::ReverseRuleExists)
    } else {
        Ok(())
    }
}

fn remove_reverse_rule(
    runner: &mut impl AdbRunner,
    serial: &str,
    reverse_spec: &str,
) -> Result<(), AdbError> {
    runner
        .run(&["-s", serial, "reverse", "--remove", reverse_spec])
        .map(|_| ())
        .map_err(|_| AdbError::ReverseRule)
}

fn cleanup_created_rule(
    runner: &mut impl AdbRunner,
    serial: &str,
    reverse_spec: &str,
    guard: Option<&mut CleanupGuardian>,
) {
    if remove_reverse_rule(runner, serial, reverse_spec).is_ok() {
        if let Some(guard) = guard {
            let _ = guard.disarm();
        }
    }
}

/// Waits for the parent pipe and removes only the fixed Developer USB rule if the parent exits.
pub fn run_cleanup_guard(serial: &str) -> io::Result<()> {
    let stdin = io::stdin();
    cleanup_guard_from_reader(stdin.lock(), SystemAdb::default(), serial)
}

fn cleanup_guard_from_reader(
    mut input: impl io::Read,
    mut runner: impl AdbRunner,
    serial: &str,
) -> io::Result<()> {
    if !valid_serial(serial) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ADB serial",
        ));
    }
    let mut signal = [0_u8; 1];
    if matches!(input.read(&mut signal), Ok(1)) && signal == *b"D" {
        return Ok(());
    }
    remove_reverse_rule(&mut runner, serial, &format!("tcp:{ANDROID_LOOPBACK_PORT}"))
        .map_err(|_| io::Error::other("failed to remove ADB reverse rule after parent exit"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeRunner {
        outputs: VecDeque<io::Result<String>>,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl FakeRunner {
        fn with(output: &str) -> Self {
            Self {
                outputs: VecDeque::from([Ok(output.to_owned())]),
                calls: Arc::default(),
            }
        }
    }

    impl AdbRunner for FakeRunner {
        fn run(&mut self, args: &[&str]) -> io::Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|value| (*value).to_owned()).collect());
            self.outputs
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::other("unexpected command")))
        }
    }

    #[derive(Clone, Copy)]
    enum PhoneBehavior {
        Valid,
        WrongSession,
        Silent,
        NoConnect,
    }

    struct LoopbackRunner {
        behavior: PhoneBehavior,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        device_checks: usize,
        switch_device: bool,
    }

    impl LoopbackRunner {
        fn new(behavior: PhoneBehavior) -> Self {
            Self {
                behavior,
                calls: Arc::default(),
                device_checks: 0,
                switch_device: false,
            }
        }
    }

    impl AdbRunner for LoopbackRunner {
        fn run(&mut self, args: &[&str]) -> io::Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|value| (*value).to_owned()).collect());
            if args == ["devices"] {
                self.device_checks += 1;
                let serial = if self.switch_device && self.device_checks > 1 {
                    "phone-b"
                } else {
                    "phone-a"
                };
                return Ok(format!("List of devices attached\n{serial}\tdevice\n"));
            }
            if args.len() == 4 && args[0] == "-s" && args[2] == "reverse" && args[3] == "--list" {
                return Ok(String::new());
            }
            if args.len() == 5 && args[2] == "reverse" && args[3] == "tcp:47139" {
                if !matches!(self.behavior, PhoneBehavior::NoConnect) {
                    let port = args[4]
                        .strip_prefix("tcp:")
                        .unwrap()
                        .parse::<u16>()
                        .unwrap();
                    let behavior = self.behavior;
                    thread::spawn(move || emulate_phone(port, behavior));
                }
                return Ok(String::new());
            }
            if args == ["-s", "phone-a", "reverse", "--remove", "tcp:47139"] {
                return Ok(String::new());
            }
            Err(io::Error::other("unexpected ADB command"))
        }
    }

    fn emulate_phone(port: u16, behavior: PhoneBehavior) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        if matches!(behavior, PhoneBehavior::Silent) {
            thread::sleep(Duration::from_millis(100));
            return;
        }
        let mut header = [0_u8; 28];
        stream.read_exact(&mut header).unwrap();
        let length = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).unwrap();
        header[7] = 2;
        if matches!(behavior, PhoneBehavior::WrongSession) {
            header[8] ^= 1;
        }
        let response = b"phone response";
        header[24..].copy_from_slice(&u32::try_from(response.len()).unwrap().to_be_bytes());
        stream.write_all(&header).unwrap();
        stream.write_all(response).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(50));
        request.fill(0);
    }

    fn removal_count(calls: &Arc<Mutex<Vec<Vec<String>>>>) -> usize {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|args| args.as_slice() == ["-s", "phone-a", "reverse", "--remove", "tcp:47139"])
            .count()
    }

    #[test]
    fn loopback_exchange_succeeds_and_removes_exact_rule() {
        let runner = LoopbackRunner::new(PhoneBehavior::Valid);
        let calls = Arc::clone(&runner.calls);
        let mut session = AdbReverseSession::connect(
            runner,
            Some("phone-a"),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
            &mut rand_core::OsRng,
        )
        .unwrap_or_else(|error| panic!("{error:?}: {:?}", calls.lock().unwrap()));
        let response = session
            .exchange(SessionPurpose::Pairing, b"desktop request")
            .unwrap_or_else(|error| panic!("{error:?}: {:?}", calls.lock().unwrap()));
        assert_eq!(response.as_slice(), b"phone response");
        assert_eq!(removal_count(&calls), 1);
    }

    #[test]
    fn loopback_wrong_session_and_silent_phone_fail_and_cleanup() {
        for (behavior, timeout) in [
            (PhoneBehavior::WrongSession, Duration::from_secs(1)),
            (PhoneBehavior::Silent, Duration::from_millis(20)),
        ] {
            let runner = LoopbackRunner::new(behavior);
            let calls = Arc::clone(&runner.calls);
            let mut session = AdbReverseSession::connect(
                runner,
                Some("phone-a"),
                Duration::from_secs(1),
                timeout,
                TransportLimits::default(),
                &mut rand_core::OsRng,
            )
            .unwrap();
            assert!(
                session
                    .exchange(SessionPurpose::Pairing, b"desktop request")
                    .is_err()
            );
            assert_eq!(removal_count(&calls), 1);
        }
    }

    #[test]
    fn loopback_cancellation_removes_exact_rule() {
        let runner = LoopbackRunner::new(PhoneBehavior::Silent);
        let calls = Arc::clone(&runner.calls);
        let mut session = AdbReverseSession::connect(
            runner,
            Some("phone-a"),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
            &mut rand_core::OsRng,
        )
        .unwrap();
        session.cancel();
        assert_eq!(removal_count(&calls), 1);
    }

    #[test]
    fn connection_timeout_and_mid_session_device_switch_cleanup() {
        let runner = LoopbackRunner::new(PhoneBehavior::NoConnect);
        let calls = Arc::clone(&runner.calls);
        assert_eq!(
            AdbReverseSession::connect(
                runner,
                Some("phone-a"),
                Duration::from_millis(20),
                Duration::from_secs(1),
                TransportLimits::default(),
                &mut rand_core::OsRng,
            )
            .err()
            .unwrap(),
            AdbError::ConnectionTimeout
        );
        assert_eq!(removal_count(&calls), 1);

        let mut runner = LoopbackRunner::new(PhoneBehavior::Valid);
        runner.switch_device = true;
        let calls = Arc::clone(&runner.calls);
        assert_eq!(
            AdbReverseSession::connect(
                runner,
                Some("phone-a"),
                Duration::from_secs(1),
                Duration::from_secs(1),
                TransportLimits::default(),
                &mut rand_core::OsRng,
            )
            .err()
            .unwrap(),
            AdbError::DeviceUnavailable
        );
        assert_eq!(removal_count(&calls), 1);
    }

    #[test]
    fn selects_only_online_device_and_requires_choice_for_multiple() {
        let mut one = FakeRunner::with("List of devices attached\nphone-a\tdevice\n");
        assert_eq!(select_device(&mut one, None).unwrap(), "phone-a");

        let mut many = FakeRunner::with(
            "List of devices attached\nphone-a\tdevice\nphone-b\toffline\nphone-c\tunauthorized\n",
        );
        assert_eq!(
            select_device(&mut many, None),
            Err(AdbError::DeviceSelectionRequired)
        );
    }

    #[test]
    fn explicit_selection_fails_closed_for_offline_missing_and_malformed_serials() {
        for serial in ["phone-b", "missing", "bad serial", ""] {
            let mut runner =
                FakeRunner::with("List of devices attached\nphone-a\tdevice\nphone-b\toffline\n");
            assert_eq!(
                select_device(&mut runner, Some(serial)),
                Err(AdbError::DeviceUnavailable)
            );
        }
    }

    #[test]
    fn rejects_malformed_device_output_and_existing_exact_rule() {
        let mut malformed = FakeRunner::with("daemon chatter\nphone-a device\n");
        assert_eq!(list_devices(&mut malformed), Err(AdbError::Unavailable));

        let mut rules = FakeRunner::with("phone-a tcp:47139 tcp:50321\n");
        assert_eq!(
            reject_existing_rule(&mut rules, "phone-a", "tcp:47139"),
            Err(AdbError::ReverseRuleExists)
        );
    }

    #[test]
    fn does_not_confuse_another_device_or_port_rule() {
        let mut rules =
            FakeRunner::with("phone-b tcp:47139 tcp:50321\nphone-a tcp:47140 tcp:50322\n");
        reject_existing_rule(&mut rules, "phone-a", "tcp:47139").unwrap();
    }

    #[test]
    fn cleanup_removes_only_the_exact_selected_rule() {
        let mut runner = FakeRunner::with("");
        let calls = Arc::clone(&runner.calls);
        remove_reverse_rule(&mut runner, "phone-a", "tcp:47139").unwrap();
        assert_eq!(
            calls.lock().unwrap().last().unwrap(),
            &["-s", "phone-a", "reverse", "--remove", "tcp:47139"]
        );
    }

    #[test]
    fn cleanup_guard_removes_on_parent_eof() {
        let runner = FakeRunner::with("");
        let calls = Arc::clone(&runner.calls);
        cleanup_guard_from_reader(io::empty(), runner, "phone-a").unwrap();
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[vec!["-s", "phone-a", "reverse", "--remove", "tcp:47139"]]
        );
    }

    #[test]
    fn cleanup_guard_disarm_does_not_touch_adb() {
        let runner = FakeRunner::default();
        let calls = Arc::clone(&runner.calls);
        cleanup_guard_from_reader(&b"D"[..], runner, "phone-a").unwrap();
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_guard_rejects_malformed_serial_without_touching_adb() {
        let runner = FakeRunner::default();
        let calls = Arc::clone(&runner.calls);
        assert!(cleanup_guard_from_reader(io::empty(), runner, "bad serial").is_err());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_guard_process_uses_an_independent_process_group() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "cat >/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        isolate_cleanup_guard(&mut command);
        let mut child = command.spawn().unwrap();
        let child_id = child.id().to_string();

        let output = Command::new("ps")
            .args(["-o", "pgid=", "-p", &child_id])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), child_id);

        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }
}
