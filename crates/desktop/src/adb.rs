//! Developer-oriented ADB reverse transport for the Windows Alpha.
//!
//! ADB device properties are used only to select the requested transport endpoint. The protocol
//! layer still authenticates every message and binds it to a paired desktop.

#![allow(clippy::missing_errors_doc)]

use std::{
    io::{self, Read as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Command, Stdio},
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
}

pub struct AdbReverseSession<R: AdbRunner> {
    runner: R,
    serial: String,
    reverse_spec: String,
    stream: DesktopStreamSession<TcpStream>,
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
        if runner
            .run(&["-s", &serial, "reverse", &reverse_spec, &desktop_spec])
            .is_err()
        {
            let _ = remove_reverse_rule(&mut runner, &serial, &reverse_spec);
            return Err(AdbError::ReverseRule);
        }

        let accepted = accept_before(&listener, connect_timeout);
        let (stream, peer) = match accepted {
            Ok(value) => value,
            Err(error) => {
                let _ = remove_reverse_rule(&mut runner, &serial, &reverse_spec);
                return Err(error);
            }
        };
        if !peer.ip().is_loopback() {
            let _ = remove_reverse_rule(&mut runner, &serial, &reverse_spec);
            return Err(AdbError::InvalidPeer);
        }
        let configured = (|| {
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
                let _ = remove_reverse_rule(&mut runner, &serial, &reverse_spec);
                return Err(error);
            }
        };
        Ok(Self {
            runner,
            serial,
            reverse_spec,
            stream,
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
}
