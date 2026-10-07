//! Controls NETIO devices with firmware 5.0 or newer through their WebSocket API.
//!
//! [`Device`] is a blocking client: every call waits for the device's reply, so GUI
//! applications should use it from a separate thread.
//!
//! ```no_run
//! use ndiscover_control::{Device, OutputAction, Security};
//!
//! let mut device = Device::connect("192.168.1.10:80".parse()?, Security::Plain)?;
//! device.login("admin", "password")?;
//! for output in device.outputs()? {
//!     println!("{} {}: {}", output.id, output.name, if output.on { "on" } else { "off" });
//! }
//! device.set_output(1, OutputAction::Toggle)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod auth;

pub use auth::PasswordToken;

use native_tls::TlsConnector;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, HandshakeError, Message, WebSocket};

/// How long [`Device::connect`] waits for the connection and for each reply.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Path of the WebSocket API
const ENDPOINT: &str = "/emweb";

/// Pause between messages, the firmware needs it to keep up (value from PyNetioConf)
const SEND_INTERVAL: Duration = Duration::from_millis(35);

/// Errors when talking to a device.
// The derive macro is not imported, as its name would make doc links to `Error` ambiguous
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not connect to {0}")]
    Connect(SocketAddr, #[source] io::Error),
    #[error("could not set up TLS")]
    Tls(#[source] native_tls::Error),
    #[error("{0} has no WebSocket API, firmware 5.0 or newer is required")]
    NotSupported(SocketAddr),
    #[error("the device did not reply in time")]
    Timeout,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("the device refused the request: {}", describe(code, message))]
    Refused {
        code: String,
        message: Option<String>,
    },
    #[error("the device ended the connection: {0}")]
    Terminated(String),
    #[error("the firmware update has no download address")]
    NoDownloadUrl,
    #[error("could not generate the login token")]
    Random(#[source] getrandom::Error),
    #[error("the device sent an unexpected message")]
    Protocol(#[source] serde_json::Error),
    #[error("the connection to the device failed")]
    WebSocket(#[source] tungstenite::Error),
}

fn describe(code: &str, message: &Option<String>) -> String {
    match message {
        Some(message) => format!("{code} ({message})"),
        None => code.to_string(),
    }
}

impl From<tungstenite::Error> for Error {
    fn from(err: tungstenite::Error) -> Self {
        match err {
            tungstenite::Error::Io(err)
                if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Error::Timeout
            }
            err => Error::WebSocket(err),
        }
    }
}

/// How to connect to a device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    /// Plain WebSocket (`ws://`), what devices use by default
    #[default]
    Plain,
    /// WebSocket over TLS (`wss://`), for devices with HTTPS enabled.
    ///
    /// Devices use self-signed certificates, which cannot be verified, so any certificate is
    /// accepted. The connection is encrypted, but not protected against someone on the
    /// network pretending to be the device.
    Tls,
}

impl Security {
    /// Port the device's web interface, and so the WebSocket API, uses by default.
    pub fn default_port(self) -> u16 {
        match self {
            Security::Plain => 80,
            Security::Tls => 443,
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Security::Plain => "ws",
            Security::Tls => "wss",
        }
    }

    fn connector(self) -> Result<Connector, Error> {
        match self {
            Security::Plain => Ok(Connector::Plain),
            Security::Tls => TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map(Connector::NativeTls)
                .map_err(Error::Tls),
        }
    }
}

/// An output (socket) of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Number of the output, starting at 1
    pub id: u8,
    pub name: String,
    /// Whether the output is switched on
    pub on: bool,
}

/// What to do with an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputAction {
    On,
    Off,
    /// Switches the output to the opposite of its current state
    Toggle,
}

impl OutputAction {
    fn request(self) -> &'static str {
        match self {
            OutputAction::On => "on",
            OutputAction::Off => "off",
            OutputAction::Toggle => "toggle",
        }
    }
}

/// A firmware the device can update to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareUpdate {
    /// E.g. `Firmware 5.3.2`
    pub name: String,
    /// E.g. `5.3.2 29f4e889 (1.57)`
    pub version: String,
    /// The firmware including the low-level system (MCU)
    pub download_url: String,
    /// The firmware without the low-level system, what [`Device::install_firmware`] installs
    pub download_url_no_mcu: String,
    pub release_note: String,
}

/// What a firmware update check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareCheck {
    Available(FirmwareUpdate),
    UpToDate,
    /// The device has no answer yet, check again in a few seconds
    Pending,
}

/// Name of the firmware list entry when there is no newer firmware
const NO_NEW_FIRMWARE: &str = "No new firmware available";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirmwareItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    download_url: String,
    #[serde(default)]
    download_url_no_mcu: String,
    #[serde(default)]
    release_note_en: String,
}

impl FirmwareCheck {
    fn from_items(items: Vec<FirmwareItem>) -> Self {
        if items.iter().any(|item| item.name.trim() == NO_NEW_FIRMWARE) {
            return FirmwareCheck::UpToDate;
        }
        match items.into_iter().find(|item| !item.download_url.is_empty()) {
            Some(item) => FirmwareCheck::Available(FirmwareUpdate {
                name: item.name,
                version: item.version,
                download_url: item.download_url,
                download_url_no_mcu: item.download_url_no_mcu,
                release_note: item.release_note_en,
            }),
            None => FirmwareCheck::Pending,
        }
    }
}

/// Messages the device sends
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
enum ServerMessage {
    Reply {
        #[serde(rename = "reqId")]
        req_id: u16,
        status: Status,
        #[serde(default)]
        data: Value,
        error: Option<ReplyError>,
    },
    Pong {
        #[serde(rename = "reqId")]
        req_id: u16,
    },
    Terminate {
        #[serde(default)]
        reason: Value,
    },
    /// Events of subscriptions and anything newer firmware may add
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Status {
    Ok,
    Error,
}

#[derive(Deserialize)]
struct ReplyError {
    code: String,
    message: Option<String>,
}

impl From<Option<ReplyError>> for Error {
    fn from(error: Option<ReplyError>) -> Self {
        let Some(error) = error else {
            return Error::Refused {
                code: "Unknown".to_string(),
                message: None,
            };
        };
        if error.code == "InvalidCredentials" {
            return Error::InvalidCredentials;
        }
        // Messages come with a trailing " : "
        let message = error
            .message
            .map(|message| message.trim_end_matches([' ', ':']).to_string())
            .filter(|message| !message.is_empty());
        Error::Refused {
            code: error.code,
            message,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hello {
    public_key: String,
    local_timestamp: f64,
}

#[derive(Deserialize)]
struct Items<T> {
    #[serde(default = "Vec::new")]
    items: Vec<T>,
}

#[derive(Deserialize)]
struct OutputInfo {
    id: u8,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct OutputMeasure {
    id: u8,
    state: OutputState,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum OutputState {
    On,
    Off,
}

fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// A connection to a device.
///
/// Dropping it closes the connection, which also ends the login session on the device.
pub struct Device {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    /// The socket's TCP stream, to change its read timeout also when it is wrapped in TLS
    tcp: TcpStream,
    timeout: Duration,
    next_req_id: u16,
    last_send: Option<Instant>,
    public_key: String,
    /// Device clock minus the local clock, in seconds
    clock_offset: f64,
}

impl Device {
    /// Connects to the device at `address`, usually its IP address and
    /// [`Security::default_port`], waiting up to [`DEFAULT_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSupported`] for devices with firmware older than 5.0, or another
    /// [`Error`] if the connection fails.
    pub fn connect(address: SocketAddr, security: Security) -> Result<Self, Error> {
        Self::connect_timeout(address, security, DEFAULT_TIMEOUT)
    }

    /// Like [`Device::connect`], with `timeout` for the connection and for each reply.
    ///
    /// # Errors
    ///
    /// See [`Device::connect`].
    pub fn connect_timeout(
        address: SocketAddr,
        security: Security,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let stream = TcpStream::connect_timeout(&address, timeout)
            .map_err(|err| Error::Connect(address, err))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|err| Error::Connect(address, err))?;
        let tcp = stream
            .try_clone()
            .map_err(|err| Error::Connect(address, err))?;

        let url = format!("{}://{address}{ENDPOINT}", security.scheme());
        let (socket, _) =
            tungstenite::client_tls_with_config(url, stream, None, Some(security.connector()?))
                .map_err(|err| match err {
                    // Older firmware answers with an HTTP error, it has no WebSocket API
                    HandshakeError::Failure(tungstenite::Error::Http(_)) => {
                        Error::NotSupported(address)
                    }
                    HandshakeError::Failure(err) => err.into(),
                    HandshakeError::Interrupted(_) => Error::Timeout,
                })?;

        let mut device = Device {
            socket,
            tcp,
            timeout,
            next_req_id: 0,
            last_send: None,
            public_key: String::new(),
            clock_offset: 0.0,
        };
        let hello: Hello = serde_json::from_value(device.request(json!({ "type": "HELO" }))?)
            .map_err(Error::Protocol)?;
        device.public_key = hello.public_key;
        device.clock_offset = hello.local_timestamp - unix_time();
        Ok(device)
    }

    /// Logs in as `username` and returns a token to log in again without the password, see
    /// [`Device::login_with_token`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCredentials`] if the username or password is wrong.
    pub fn login(&mut self, username: &str, password: &str) -> Result<PasswordToken, Error> {
        let salt = auth::salt().map_err(Error::Random)?;
        let password_token = auth::password_token(username, password, &self.public_key, salt);
        self.login_with_token(username, &password_token)?;
        Ok(password_token)
    }

    /// Logs in as `username` with a token from an earlier [`Device::login`] to this device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCredentials`] if the token is not valid (anymore), for example
    /// because the password changed.
    pub fn login_with_token(
        &mut self,
        username: &str,
        password_token: &PasswordToken,
    ) -> Result<(), Error> {
        let device_time = unix_time() + self.clock_offset;
        let token = auth::auth_token(password_token, device_time);
        self.request(json!({ "type": "AUTH", "username": username, "token": token }))?;
        Ok(())
    }

    /// Returns the outputs of the device and whether they are on.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the request fails, [`Error::Refused`] if the user may not
    /// view outputs.
    pub fn outputs(&mut self) -> Result<Vec<Output>, Error> {
        let list: Items<OutputInfo> = self.read_topic("outputs/list")?;
        let measure: Items<OutputMeasure> = self.read_topic("outputs/measure")?;
        Ok(list
            .items
            .into_iter()
            .map(|output| Output {
                on: measure
                    .items
                    .iter()
                    .any(|m| m.id == output.id && m.state == OutputState::On),
                id: output.id,
                name: output.name,
            })
            .collect())
    }

    /// Switches output `id`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the request fails, [`Error::Refused`] if the user may not
    /// control outputs or there is no such output.
    pub fn set_output(&mut self, id: u8, action: OutputAction) -> Result<(), Error> {
        self.request(json!({
            "type": "SET",
            "topic": format!("outputs/id/{id}/ctrl"),
            "data": { "request": action.request() },
        }))?;
        Ok(())
    }

    /// Checks that the device is still there. Devices end connections that stay quiet for
    /// too long, the web interface pings every 10 seconds.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the device does not answer.
    pub fn ping(&mut self) -> Result<(), Error> {
        self.request(json!({ "type": "PING" }))?;
        Ok(())
    }

    /// Asks the device to look for a newer firmware on NETIO's servers and returns what it
    /// found. It only looks, it never installs anything.
    ///
    /// Devices do not always have the answer right away, so check again every few seconds
    /// while this returns [`FirmwareCheck::Pending`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the request fails, [`Error::Refused`] if the user may not
    /// change settings, which looking for firmware needs.
    pub fn check_firmware(&mut self) -> Result<FirmwareCheck, Error> {
        self.request(json!({
            "type": "SET",
            "topic": "system/firmwarelist",
            // A download URL in `updateFw` would install that firmware, empty only looks
            "data": { "getFirmwareList": true, "updateFw": "" },
        }))?;
        let list: Items<FirmwareItem> = self.read_topic("fwupdate/list")?;
        Ok(FirmwareCheck::from_items(list.items))
    }

    /// Starts installing `update`, found by [`Device::check_firmware`], without the low-level
    /// system, like the web interface's "Update device firmware".
    ///
    /// The device downloads the firmware and restarts, which ends this connection. Find it
    /// again with UDP Discover and connect anew once it has restarted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoDownloadUrl`] if the update has no download address, or another
    /// [`Error`] if the request fails, [`Error::Refused`] if the user may not change
    /// settings.
    pub fn install_firmware(&mut self, update: &FirmwareUpdate) -> Result<(), Error> {
        if update.download_url_no_mcu.is_empty() {
            return Err(Error::NoDownloadUrl);
        }
        self.request(json!({
            "type": "SET",
            "topic": "system/firmwarelist",
            "data": { "getFirmwareList": false, "updateFw": update.download_url_no_mcu },
        }))?;
        Ok(())
    }

    /// Reads the current value of `topic`
    fn read_topic<T: DeserializeOwned>(&mut self, topic: &str) -> Result<T, Error> {
        let data = self.request(json!({ "type": "SUBSCRIBE", "topic": topic }))?;
        // Only the current value is needed, not the events that would follow
        self.request(json!({ "type": "UNSUBSCRIBE", "topic": topic }))?;
        serde_json::from_value(data).map_err(Error::Protocol)
    }

    /// Sends `message` with a new request ID and returns the data of the reply
    fn request(&mut self, mut message: Value) -> Result<Value, Error> {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        message["reqId"] = req_id.into();

        if let Some(last_send) = self.last_send {
            let elapsed = last_send.elapsed();
            if elapsed < SEND_INTERVAL {
                thread::sleep(SEND_INTERVAL - elapsed);
            }
        }
        self.socket.send(Message::text(message.to_string()))?;
        self.last_send = Some(Instant::now());

        self.wait_for_reply(req_id)
    }

    fn wait_for_reply(&mut self, req_id: u16) -> Result<Value, Error> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout);
            }
            self.tcp
                .set_read_timeout(Some(remaining))
                .map_err(|err| Error::WebSocket(err.into()))?;

            // WebSocket level pings are answered by tungstenite
            let Message::Text(text) = self.socket.read()? else {
                continue;
            };
            match serde_json::from_str(&text).map_err(Error::Protocol)? {
                ServerMessage::Reply {
                    req_id: id,
                    status,
                    data,
                    error,
                } if id == req_id => {
                    return match status {
                        Status::Ok => Ok(data),
                        Status::Error => Err(error.into()),
                    };
                }
                ServerMessage::Pong { req_id: id } if id == req_id => return Ok(Value::Null),
                ServerMessage::Terminate { reason } => {
                    return Err(Error::Terminated(match reason {
                        Value::String(reason) => reason,
                        reason => reason.to_string(),
                    }));
                }
                // Replies to earlier requests and events
                _ => {}
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Lets the device end the session right away
        let _ = self.socket.close(None);
        let _ = self.socket.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(data: &str) -> FirmwareCheck {
        let list: Items<FirmwareItem> = serde_json::from_str(data).unwrap();
        FirmwareCheck::from_items(list.items)
    }

    // Replies of a device with firmware 5.x
    #[test]
    fn finds_new_firmware() {
        let data = r#"{
          "items":[
              {
               "name":"Firmware 5.3.2",
               "version":"5.3.2 29f4e889 (1.57)",
               "downloadUrl":"https://titan.netio.eu/ic/fw/Firmware%205.3.2",
               "downloadUrlNoMcu":"https://titan.netio.eu/ic/fw/Firmware%205.3.2?variant=no_mcu",
               "releaseNoteEn":"- Add Cooldown functionality into Condition and Rules - Fix M2M MQTT event behaviour - Fix Digital Input S0 counter improvement"
            }
          ]
        }"#;
        assert_eq!(
            check(data),
            FirmwareCheck::Available(FirmwareUpdate {
                name: "Firmware 5.3.2".into(),
                version: "5.3.2 29f4e889 (1.57)".into(),
                download_url: "https://titan.netio.eu/ic/fw/Firmware%205.3.2".into(),
                download_url_no_mcu: "https://titan.netio.eu/ic/fw/Firmware%205.3.2?variant=no_mcu"
                    .into(),
                release_note: "- Add Cooldown functionality into Condition and Rules - Fix M2M \
                               MQTT event behaviour - Fix Digital Input S0 counter improvement"
                    .into(),
            })
        );
    }

    #[test]
    fn finds_no_new_firmware() {
        let data = r#"{
          "items":[
              {
               "name":"No new firmware available",
               "version":"",
               "downloadUrl":"",
               "downloadUrlNoMcu":"",
               "releaseNoteEn":""
            }
          ]
        }"#;
        assert_eq!(check(data), FirmwareCheck::UpToDate);
    }

    #[test]
    fn waits_for_an_answer() {
        assert_eq!(check(r#"{"items":[]}"#), FirmwareCheck::Pending);
        assert_eq!(check("{}"), FirmwareCheck::Pending);
        assert_eq!(
            check(r#"{"items":[{"name":"","version":"","downloadUrl":""}]}"#),
            FirmwareCheck::Pending
        );
    }
}
