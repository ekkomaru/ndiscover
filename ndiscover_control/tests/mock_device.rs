//! Tests against a mock device that speaks the WebSocket API like firmware 5.3.2 does.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ndiscover_control::{
    Device, Error, FirmwareCheck, FirmwareUpdate, Output, OutputAction, Security,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tungstenite::Message;

const PUBLIC_KEY: &str = "<?xdf ax='F_A12' elm='sdF'?>";
const USERNAME: &str = "admin";
const PASSWORD: &str = "secret";
/// Download address of the firmware the mock offers, without the low-level system
const NEW_FIRMWARE_URL: &str = "https://titan.netio.eu/ic/fw/Firmware%205.4.1?variant=no_mcu";
/// The mock's clock is ahead, logins only work if the client uses the device clock
const CLOCK_OFFSET: u64 = 3600;

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn device_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + CLOCK_OFFSET
}

/// Checks a login token the way the device does
fn valid_token(username: &str, token: &str) -> bool {
    let Some((salt, hash)) = token.split_once('.') else {
        return false;
    };
    let password_hash = BASE64.encode(Sha256::digest(format!("{USERNAME}{PUBLIC_KEY}{PASSWORD}")));
    let password_token = sha256_hex(&format!("{salt}{password_hash}"));
    username == USERNAME && hash == sha256_hex(&format!("{}{password_token}", device_time() / 10))
}

fn reply(request: &Value, data: Value) -> Value {
    json!({ "type": "REPLY", "reqId": request["reqId"], "status": "OK", "data": data })
}

fn error(request: &Value, code: &str) -> Value {
    json!({
        "type": "REPLY",
        "reqId": request["reqId"],
        "status": "ERROR",
        "error": { "code": code, "message": "Something went wrong. : " },
    })
}

/// Serves one client like a device with three outputs
fn serve(stream: TcpStream) {
    let mut socket = tungstenite::accept(stream).unwrap();
    let mut outputs = [("Server", true), ("Router", false), ("", false)];
    let mut logged_in = false;
    let mut firmware_checks = 0;

    loop {
        let request: Value = match socket.read() {
            Ok(Message::Text(text)) => serde_json::from_str(&text).unwrap(),
            Ok(_) => continue,
            Err(_) => return,
        };
        let topic = request["topic"].as_str().unwrap_or_default();
        let response = match (request["type"].as_str().unwrap(), topic) {
            ("HELO", _) => reply(
                &request,
                json!({
                    "protocolVersion": "1.0.0",
                    "localTimestamp": device_time(),
                    "publicKey": PUBLIC_KEY,
                    "serverApiVersion": "2.0.0",
                }),
            ),
            ("AUTH", _) => {
                logged_in = valid_token(
                    request["username"].as_str().unwrap(),
                    request["token"].as_str().unwrap(),
                );
                if logged_in {
                    reply(&request, Value::Null)
                } else {
                    error(&request, "InvalidCredentials")
                }
            }
            ("PING", _) => json!({ "type": "PONG", "reqId": request["reqId"], "status": "OK" }),
            (_, _) if !logged_in => error(&request, "Unauthorized"),
            ("SUBSCRIBE", "outputs/list") => {
                // Events of other subscriptions can arrive before the reply
                let event = json!({ "type": "EVENT", "topic": "system/uptime", "data": {} });
                socket.send(Message::text(event.to_string())).unwrap();
                let items: Vec<_> = (1..)
                    .zip(&outputs)
                    .map(|(id, (name, _))| json!({ "id": id, "name": name, "socketType": "F" }))
                    .collect();
                reply(&request, json!({ "items": items }))
            }
            ("SUBSCRIBE", "outputs/state") => {
                let items: Vec<_> = (1..)
                    .zip(&outputs)
                    .map(|(id, (_, on))| {
                        json!({ "id": id, "state": if *on { "on" } else { "off" } })
                    })
                    .collect();
                reply(&request, json!({ "items": items }))
            }
            ("UNSUBSCRIBE", _) => reply(&request, Value::Null),
            ("SET", "system/firmwarelist") => {
                let data = &request["data"];
                if data["getFirmwareList"] == true {
                    // Anything else in `updateFw` would install firmware
                    assert_eq!(data["updateFw"], "");
                    firmware_checks += 1;
                } else {
                    // Only the offered firmware may be installed
                    assert_eq!(data["updateFw"], NEW_FIRMWARE_URL);
                    eprintln!("mock device: installing {}", data["updateFw"]);
                }
                // Replies without data, like devices do
                json!({ "type": "REPLY", "reqId": request["reqId"], "status": "OK" })
            }
            // Not ready on the first check, then a new firmware, then none
            ("SUBSCRIBE", "fwupdate/list") => {
                let items = match firmware_checks {
                    0 | 1 => json!([]),
                    2 => json!([{
                        "name": "Firmware 5.4.1",
                        "version": "5.4.1 3a1b2c3d (1.58)",
                        "downloadUrl": "https://titan.netio.eu/ic/fw/Firmware%205.4.1",
                        "downloadUrlNoMcu": NEW_FIRMWARE_URL,
                        "releaseNoteEn": "- Fix something",
                    }]),
                    _ => json!([{
                        "name": "No new firmware available",
                        "version": "",
                        "downloadUrl": "",
                        "downloadUrlNoMcu": "",
                        "releaseNoteEn": "",
                    }]),
                };
                reply(&request, json!({ "items": items }))
            }
            ("SET", topic) => {
                let id: Option<usize> = topic
                    .strip_prefix("outputs/id/")
                    .and_then(|rest| rest.strip_suffix("/ctrl"))
                    .and_then(|id| id.parse().ok());
                match id.and_then(|id| outputs.get_mut(id.wrapping_sub(1))) {
                    Some((_, on)) => {
                        *on = match request["data"]["request"].as_str().unwrap() {
                            "on" => true,
                            "off" => false,
                            "toggle" => !*on,
                            other => panic!("unexpected request {other}"),
                        };
                        reply(&request, Value::Null)
                    }
                    None => error(&request, "NotFound"),
                }
            }
            _ => error(&request, "UnknownTopic"),
        };
        socket.send(Message::text(response.to_string())).unwrap();
    }
}

/// Starts a mock device and returns its address
fn mock_device(serve: fn(TcpStream)) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            thread::spawn(move || serve(stream.unwrap()));
        }
    });
    address
}

fn output(id: u8, name: &str, on: bool) -> Output {
    Output {
        id,
        name: name.to_string(),
        on,
    }
}

#[test]
fn logs_in_and_switches_outputs() {
    let mut device = Device::connect(mock_device(serve), Security::Plain).unwrap();
    device.login(USERNAME, PASSWORD).unwrap();
    assert_eq!(
        device.outputs().unwrap(),
        [
            output(1, "Server", true),
            output(2, "Router", false),
            output(3, "", false)
        ]
    );

    device.set_output(1, OutputAction::Off).unwrap();
    device.set_output(2, OutputAction::On).unwrap();
    device.set_output(3, OutputAction::Toggle).unwrap();
    device.ping().unwrap();
    assert_eq!(
        device.outputs().unwrap(),
        [
            output(1, "Server", false),
            output(2, "Router", true),
            output(3, "", true)
        ]
    );
}

#[test]
fn rejects_wrong_password() {
    let mut device = Device::connect(mock_device(serve), Security::Plain).unwrap();
    assert!(matches!(
        device.login(USERNAME, "wrong"),
        Err(Error::InvalidCredentials)
    ));
}

#[test]
fn reports_refused_requests() {
    let mut device = Device::connect(mock_device(serve), Security::Plain).unwrap();
    let err = device.outputs().unwrap_err();
    assert!(
        matches!(&err, Error::Refused { code, .. } if code == "Unauthorized"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "the device refused the request: Unauthorized (Something went wrong.)"
    );

    device.login(USERNAME, PASSWORD).unwrap();
    assert!(matches!(
        device.set_output(9, OutputAction::On),
        Err(Error::Refused { code, .. }) if code == "NotFound"
    ));
}

#[test]
fn reports_old_firmware() {
    // Firmware before 5.0 only has the web interface
    let address = mock_device(|mut stream| {
        let mut request = [0; 1024];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    });
    assert!(matches!(
        Device::connect(address, Security::Plain),
        Err(Error::NotSupported(a)) if a == address
    ));
}

#[test]
fn times_out_when_device_does_not_reply() {
    let address = mock_device(|stream| {
        let mut socket = tungstenite::accept(stream).unwrap();
        while socket.read().is_ok() {}
    });
    assert!(matches!(
        Device::connect_timeout(address, Security::Plain, Duration::from_millis(300)),
        Err(Error::Timeout)
    ));
}

#[test]
fn logs_in_again_with_token() {
    let address = mock_device(serve);
    let password_token = Device::connect(address, Security::Plain)
        .unwrap()
        .login(USERNAME, PASSWORD)
        .unwrap();

    let mut device = Device::connect(address, Security::Plain).unwrap();
    device.login_with_token(USERNAME, &password_token).unwrap();
    assert_eq!(device.outputs().unwrap().len(), 3);

    let mut device = Device::connect(address, Security::Plain).unwrap();
    assert!(matches!(
        device.login_with_token("someone", &password_token),
        Err(Error::InvalidCredentials)
    ));
}

#[test]
fn tls_to_plain_device_fails_quickly() {
    // Runs the TLS setup and handshake, a device without HTTPS refuses it instead of hanging
    let address = mock_device(serve);
    let started = Instant::now();
    assert!(Device::connect_timeout(address, Security::Tls, Duration::from_secs(5)).is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn checks_for_firmware_updates() {
    let mut device = Device::connect(mock_device(serve), Security::Plain).unwrap();
    device.login(USERNAME, PASSWORD).unwrap();
    assert_eq!(device.check_firmware().unwrap(), FirmwareCheck::Pending);
    assert_eq!(
        device.check_firmware().unwrap(),
        FirmwareCheck::Available(FirmwareUpdate {
            name: "Firmware 5.4.1".into(),
            version: "5.4.1 3a1b2c3d (1.58)".into(),
            download_url: "https://titan.netio.eu/ic/fw/Firmware%205.4.1".into(),
            download_url_no_mcu: NEW_FIRMWARE_URL.into(),
            release_note: "- Fix something".into(),
        })
    );
    assert_eq!(device.check_firmware().unwrap(), FirmwareCheck::UpToDate);
}

#[test]
fn installs_firmware() {
    let mut device = Device::connect(mock_device(serve), Security::Plain).unwrap();
    device.login(USERNAME, PASSWORD).unwrap();
    device.check_firmware().unwrap();
    let FirmwareCheck::Available(mut update) = device.check_firmware().unwrap() else {
        panic!("the mock offers an update on the second check");
    };
    // The mock fails the test if anything else than the offered firmware is installed
    device.install_firmware(&update).unwrap();

    update.download_url_no_mcu.clear();
    assert!(matches!(
        device.install_firmware(&update),
        Err(Error::NoDownloadUrl)
    ));
}
