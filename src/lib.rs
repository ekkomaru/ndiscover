//! Finds NETIO devices on the local network using the NETIO UDP Discover protocol.
//!
//! Protocol description: <https://wiki.netio-products.com/index.php?title=NETIO_UDP_Discover>

use getifaddrs::{Interface, InterfaceFilter, InterfaceFlags};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "linux",
    target_os = "android",
    target_os = "illumos",
    target_os = "solaris",
))]
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use thiserror::Error;

/// UDP port the devices listen on for discover requests.
pub const REQUEST_PORT: u16 = 62387;

/// UDP port the devices broadcast their responses to, so discovery has to listen on it.
///
/// Discovery shares the port, so several discoveries can run at the same time.
pub const RESPONSE_PORT: u16 = 62386;

/// Shortest time [`discover`] waits for responses, shorter timeouts are raised to this.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(1000);

/// UDP Discover request payload
const DISCOVER_REQUEST: [u8; 3] = [0x01, 0xEC, 0x00];

/// First byte of every response, it is followed by two magic bytes that differ between devices
const RESPONSE_MARKER: u8 = 0x02;
const RESPONSE_HEADER_LEN: usize = 3;

/// Comfortably larger than any discover response
const RECEIVE_BUFFER_SIZE: usize = 2048;

/// Field types of the response TLV stream
#[derive(Clone, Copy)]
#[repr(u8)]
enum FType {
    FirmwareVersion = 0x01,
    Mac = 0x02,
    Ip = 0x03,
    Netmask = 0x04,
    Hostname = 0x05,
    Dhcp = 0x06,
    SetupState = 0x07,
    Result = 0x08,
    Product = 0x09,
    Manufacturer = 0x0A,
    Platform = 0x0B,
    Variant = 0x0C,
    Timeout = 0x0D,
    Gateway = 0x0E,
    Dns = 0x0F,
    PrettyPlatformName = 0x12,
    DeviceName = 0x13,
}

impl FType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(FType::FirmwareVersion),
            0x02 => Some(FType::Mac),
            0x03 => Some(FType::Ip),
            0x04 => Some(FType::Netmask),
            0x05 => Some(FType::Hostname),
            0x06 => Some(FType::Dhcp),
            0x07 => Some(FType::SetupState),
            0x08 => Some(FType::Result),
            0x09 => Some(FType::Product),
            0x0A => Some(FType::Manufacturer),
            0x0B => Some(FType::Platform),
            0x0C => Some(FType::Variant),
            0x0D => Some(FType::Timeout),
            0x0E => Some(FType::Gateway),
            0x0F => Some(FType::Dns),
            0x12 => Some(FType::PrettyPlatformName),
            0x13 => Some(FType::DeviceName),
            _ => None,
        }
    }
}

/// A device that answered UDP Discover.
///
/// Devices only report some of the fields, the ones they did not report are `None` and are
/// left out when serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NDiscoverDevice {
    /// Device name (DEVICE NAME)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Platform (PLATFORM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Hostname (HOSTNAME)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Firmware part of `full_version`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    /// MCU part of `full_version`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcu_version: Option<String>,
    /// Full version string as reported (FIRMWARE_VERSION)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_version: Option<String>,
    /// MAC address formatted as `aa:bb:cc:dd:ee:ff` (MAC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// IP address (IP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Ipv4Addr>,
    /// Netmask (NETMASK)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Ipv4Addr>,
    /// Default gateway (GATEWAY)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    /// DNS server (DNS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Ipv4Addr>,
    /// Whether the device uses DHCP (DHCP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
    /// Setup state (SETUP STATE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_state: Option<u8>,
    /// Result (RESULT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<u8>,
    /// Timeout (TIMEOUT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u8>,
    /// Variant (VARIANT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Manufacturer (MANUFACTURER)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// Product, e.g. `PowerPDU 8KF` (PRODUCT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Human readable platform name (PRETTY_PLATFORM_NAME)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pretty_platform_name: Option<String>,
}

/// Reasons a discover response could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("response is shorter than the {RESPONSE_HEADER_LEN}-byte header")]
    TooShort,
    #[error("not a discover response (first byte is {0:#04x}, expected 0x02)")]
    NotAResponse(u8),
    #[error("field {ftype:#04x} runs past the end of the response")]
    Truncated { ftype: u8 },
    #[error("field {ftype:#04x} is {len} bytes long, expected {expected}")]
    BadLength {
        ftype: u8,
        len: usize,
        expected: usize,
    },
    #[error("firmware version {0:?} is not in the \"<firmware> - <MCU>\" format")]
    BadFirmwareVersion(String),
}

/// Errors that stop a discovery.
#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("could not listen on UDP port {RESPONSE_PORT}")]
    Bind(#[source] io::Error),
    #[error("could not configure the UDP socket")]
    Socket(#[source] io::Error),
    #[error("could not list the local networks")]
    Networks(#[source] InterfaceError),
    #[error("no local network to send the discover request on")]
    NoNetwork,
    #[error("could not send the discover request to {0}")]
    Send(SocketAddrV4, #[source] io::Error),
    #[error("could not receive discover responses")]
    Receive(#[source] io::Error),
}

/// Errors when looking up local networks.
#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("could not list the network interfaces")]
    List(#[source] io::Error),
    #[error("no network interface named {0:?} with an IPv4 address")]
    NotFound(String),
    #[error("network interface {0:?} is down or does not support broadcast")]
    NoBroadcast(String),
}

/// Takes the value of a fixed length field
fn fixed<const N: usize>(ftype: FType, value: &[u8]) -> Result<[u8; N], ParseError> {
    value.try_into().map_err(|_| ParseError::BadLength {
        ftype: ftype as u8,
        len: value.len(),
        expected: N,
    })
}

fn text(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

fn ipv4(ftype: FType, value: &[u8]) -> Result<Ipv4Addr, ParseError> {
    fixed::<4>(ftype, value).map(Ipv4Addr::from)
}

fn byte(ftype: FType, value: &[u8]) -> Result<u8, ParseError> {
    fixed::<1>(ftype, value).map(|[b]| b)
}

impl NDiscoverDevice {
    /// Stores the value of one response field
    fn set_field(&mut self, ftype: FType, value: &[u8]) -> Result<(), ParseError> {
        match ftype {
            FType::FirmwareVersion => {
                // Keep the first version if a device reports more than one
                if self.full_version.is_some() {
                    return Ok(());
                }
                let full_version = text(value);
                let mut version_fields = full_version.split('-');
                let (Some(firmware), Some(mcu)) = (version_fields.next(), version_fields.next())
                else {
                    return Err(ParseError::BadFirmwareVersion(full_version));
                };
                self.firmware_version = Some(firmware.trim().to_string());
                self.mcu_version = Some(mcu.trim().to_string());
                self.full_version = Some(full_version);
            }
            FType::Mac => {
                let mac = fixed::<6>(ftype, value)?;
                self.mac_address = Some(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                ));
            }
            FType::Ip => self.ip_address = Some(ipv4(ftype, value)?),
            FType::Netmask => self.netmask = Some(ipv4(ftype, value)?),
            FType::Gateway => self.gateway = Some(ipv4(ftype, value)?),
            FType::Dns => self.dns = Some(ipv4(ftype, value)?),
            FType::Dhcp => self.dhcp = Some(byte(ftype, value)? != 0),
            FType::SetupState => self.setup_state = Some(byte(ftype, value)?),
            FType::Result => self.result = Some(byte(ftype, value)?),
            FType::Timeout => self.timeout = Some(byte(ftype, value)?),
            FType::Hostname => self.hostname = Some(text(value)),
            FType::Product => self.product = Some(text(value)),
            FType::Manufacturer => self.manufacturer = Some(text(value)),
            FType::Platform => self.model = Some(text(value)),
            FType::Variant => self.variant = Some(text(value)),
            FType::PrettyPlatformName => self.pretty_platform_name = Some(text(value)),
            FType::DeviceName => self.name = Some(text(value)),
        }
        Ok(())
    }
}

/// Parses one UDP Discover response into a device.
///
/// A response is the `0x02` marker, two magic bytes and a stream of fields, each made of a
/// type byte, a length byte and that many bytes of value. Field types not in the protocol
/// description are skipped.
///
/// # Errors
///
/// Returns a [`ParseError`] if the data is not a discover response or is malformed.
///
/// # Examples
///
/// The example response from the protocol description:
///
/// ```
/// use ndiscover_lib::parse_response;
/// use std::net::Ipv4Addr;
///
/// let response = [
///     0x02, 0xAB, 0x6B, // response marker and two magic bytes
///     0x03, 4, 192, 168, 101, 35, // IP
///     0x09, 6, b'N', b'e', b't', b'i', b'o', b'4', // PRODUCT
/// ];
///
/// let device = parse_response(&response)?;
/// assert_eq!(device.ip_address, Some(Ipv4Addr::new(192, 168, 101, 35)));
/// assert_eq!(device.product.as_deref(), Some("Netio4"));
/// assert_eq!(device.hostname, None);
/// # Ok::<(), ndiscover_lib::ParseError>(())
/// ```
pub fn parse_response(data: &[u8]) -> Result<NDiscoverDevice, ParseError> {
    if data.len() < RESPONSE_HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    if data[0] != RESPONSE_MARKER {
        return Err(ParseError::NotAResponse(data[0]));
    }

    let mut device = NDiscoverDevice::default();
    let mut fields = &data[RESPONSE_HEADER_LEN..];
    loop {
        let (ftype, value, rest) = match fields {
            [] => break,
            [ftype, len, rest @ ..] if rest.len() >= usize::from(*len) => {
                let (value, rest) = rest.split_at(usize::from(*len));
                (*ftype, value, rest)
            }
            [ftype, ..] => return Err(ParseError::Truncated { ftype: *ftype }),
        };
        if let Some(ftype) = FType::from_u8(ftype) {
            device.set_field(ftype, value)?;
        }
        fields = rest;
    }
    Ok(device)
}

/// Opens a broadcast socket on [`RESPONSE_PORT`] that other programs can listen on as well.
///
/// Responses are broadcast, so every socket sharing the port receives all of them.
fn response_socket() -> Result<UdpSocket, DiscoverError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(DiscoverError::Socket)?;
    socket
        .set_reuse_address(true)
        .map_err(DiscoverError::Socket)?;
    // macOS and the BSDs only share a port between sockets that all set SO_REUSEPORT
    #[cfg(all(
        unix,
        not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_os = "cygwin",
            target_os = "nuttx"
        ))
    ))]
    socket.set_reuse_port(true).map_err(DiscoverError::Socket)?;
    socket.set_broadcast(true).map_err(DiscoverError::Socket)?;

    let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RESPONSE_PORT);
    socket.bind(&address.into()).map_err(DiscoverError::Bind)?;
    Ok(socket.into())
}

/// A local IPv4 network, reached through one network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    /// Name of the network interface, e.g. `en0`
    pub interface: String,
    /// This computer's address in the network
    pub address: Ipv4Addr,
    /// Broadcast address of the network
    pub broadcast: Ipv4Addr,
    /// Index of the network interface, to send through it directly
    index: Option<u32>,
}

/// Turns interface addresses into the networks discovery can broadcast on
fn broadcast_networks(interfaces: impl Iterator<Item = Interface>) -> Vec<LocalNetwork> {
    interfaces
        .filter(|iface| {
            iface
                .flags
                .contains(InterfaceFlags::UP | InterfaceFlags::BROADCAST)
                && !iface.flags.contains(InterfaceFlags::LOOPBACK)
        })
        .filter_map(|iface| match (iface.address, iface.netmask) {
            (IpAddr::V4(address), Some(IpAddr::V4(netmask))) => Some(LocalNetwork {
                interface: iface.name,
                address,
                broadcast: address | !netmask,
                index: iface.index,
            }),
            _ => None,
        })
        .collect()
}

/// Returns the networks of all network interfaces that are up and support broadcast.
///
/// Loopback and point-to-point interfaces, such as most VPNs, are left out.
///
/// # Errors
///
/// Returns [`InterfaceError::List`] if the network interfaces cannot be listed.
pub fn local_networks() -> Result<Vec<LocalNetwork>, InterfaceError> {
    let interfaces = InterfaceFilter::new()
        .v4()
        .get()
        .map_err(InterfaceError::List)?;
    Ok(broadcast_networks(interfaces))
}

/// Returns the networks of the network interface called `name`.
///
/// # Errors
///
/// Returns an [`InterfaceError`] if there is no such interface with an IPv4 address, or it is
/// down or does not support broadcast (loopback and point-to-point interfaces such as VPNs).
pub fn interface_networks(name: &str) -> Result<Vec<LocalNetwork>, InterfaceError> {
    let interfaces: Vec<_> = InterfaceFilter::new()
        .name(name)
        .v4()
        .get()
        .map_err(InterfaceError::List)?
        .collect();
    if interfaces.is_empty() {
        return Err(InterfaceError::NotFound(name.to_string()));
    }
    let networks = broadcast_networks(interfaces.into_iter());
    if networks.is_empty() {
        return Err(InterfaceError::NoBroadcast(name.to_string()));
    }
    Ok(networks)
}

/// Opens a socket that sends through the network's interface, whatever the routing table says
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "linux",
    target_os = "android",
    target_os = "illumos",
    target_os = "solaris",
))]
fn interface_socket(network: &LocalNetwork) -> Option<UdpSocket> {
    let index = NonZeroU32::new(network.index?)?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    socket.set_broadcast(true).ok()?;
    // Can fail, e.g. without the needed privileges on Linux
    socket.bind_device_by_index_v4(Some(index)).ok()?;
    Some(socket.into())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "linux",
    target_os = "android",
    target_os = "illumos",
    target_os = "solaris",
)))]
fn interface_socket(_network: &LocalNetwork) -> Option<UdpSocket> {
    None
}

fn send_request(socket: &UdpSocket, broadcast: Ipv4Addr) -> Result<(), DiscoverError> {
    let target = SocketAddrV4::new(broadcast, REQUEST_PORT);
    socket
        .send_to(&DISCOVER_REQUEST, target)
        .map(drop)
        .map_err(|err| DiscoverError::Send(target, err))
}

/// Sends the request on every network, it is enough if it went out on one of them.
///
/// The limited broadcast address (255.255.255.255) reaches also devices with an IP address
/// outside the network, but the routing table sends it to the interface with the default
/// route, which is a VPN's when one is on. So it is sent through each network's interface
/// where possible, and to the network's broadcast address otherwise.
fn send_on_networks(socket: &UdpSocket, networks: &[LocalNetwork]) -> Result<(), DiscoverError> {
    if networks.is_empty() {
        return Err(DiscoverError::NoNetwork);
    }
    let mut sent = false;
    let mut first_error = None;
    let mut directed = false;
    for network in networks {
        let result = match interface_socket(network) {
            Some(interface_socket) => send_request(&interface_socket, Ipv4Addr::BROADCAST),
            None => {
                directed = true;
                send_request(socket, network.broadcast)
            }
        };
        match result {
            Ok(()) => sent = true,
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    if directed {
        // Reaches devices outside the networks when the default route allows it, the
        // networks themselves got the request already
        let _ = send_request(socket, Ipv4Addr::BROADCAST);
    }
    match first_error {
        Some(err) if !sent => Err(err),
        _ => Ok(()),
    }
}

/// Sends a UDP Discover request on `networks` and returns the devices that respond within
/// `timeout`.
///
/// Invalid responses are skipped, use [`discover_with`] to see them or to handle devices as
/// they respond.
///
/// # Errors
///
/// Returns a [`DiscoverError`] if the request cannot be sent or receiving fails, for example
/// when another program holds [`RESPONSE_PORT`] without sharing it.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// let networks = ndiscover_lib::local_networks()?;
/// let devices = ndiscover_lib::discover(&networks, Duration::from_secs(2))?;
/// for device in devices {
///     println!("{:?} at {:?}", device.name, device.ip_address);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn discover(
    networks: &[LocalNetwork],
    timeout: Duration,
) -> Result<Vec<NDiscoverDevice>, DiscoverError> {
    let mut devices = Vec::new();
    discover_with(networks, timeout, |_, response| {
        if let Ok(device) = response {
            devices.push(device);
        }
    })?;
    Ok(devices)
}

/// Sends a UDP Discover request on `networks` and calls `on_response` for every device that
/// responds within `timeout`, as soon as its response arrives.
///
/// `on_response` gets the address the response came from and the parsed device, or the
/// reason the response is invalid. Each address is reported once, even though devices send
/// their response several times. The timeout is the total time to wait and is raised to
/// [`MIN_TIMEOUT`] if shorter.
///
/// # Errors
///
/// Returns a [`DiscoverError`] if the request cannot be sent on any of the networks or
/// receiving fails.
pub fn discover_with<F>(
    networks: &[LocalNetwork],
    timeout: Duration,
    mut on_response: F,
) -> Result<(), DiscoverError>
where
    F: FnMut(SocketAddr, Result<NDiscoverDevice, ParseError>),
{
    let socket = response_socket()?;
    let deadline = Instant::now() + timeout.max(MIN_TIMEOUT);
    send_on_networks(&socket, networks)?;

    let mut buffer = [0; RECEIVE_BUFFER_SIZE];
    let mut responders = HashSet::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(DiscoverError::Socket)?;

        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                if responders.insert(from) {
                    on_response(from, parse_response(&buffer[..len]));
                }
            }
            // Timeouts end the loop through the deadline check. Windows reports ICMP errors
            // caused by earlier sends as reset/refused, those don't affect other responses.
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock
                        | ErrorKind::TimedOut
                        | ErrorKind::Interrupted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionRefused
                ) => {}
            Err(err) => return Err(DiscoverError::Receive(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a response with the given fields
    fn response(fields: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = vec![0x02, 0xEC, 0x00];
        for (ftype, value) in fields {
            data.push(*ftype);
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
        data
    }

    const FIRMWARE: &[u8] = b"5.3.2 - 1.57(1.54) - 0  4k (rev.29f4e889/2026-09-09)";

    /// Response sent by a NETIO PowerDIN
    fn power_din_response() -> Vec<u8> {
        response(&[
            (0x09, b"PowerDIN"),
            (0x01, FIRMWARE),
            (0x02, &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            (0x03, &[192, 168, 1, 10]),
            (0x04, &[255, 255, 255, 0]),
            (0x0E, &[192, 168, 1, 1]),
            (0x05, b"Test PowerDIN"),
            (0x13, b"Test PowerDIN"),
            (0x06, &[1]),
            (0x07, &[1]),
        ])
    }

    #[test]
    fn parses_device_response() {
        let device = parse_response(&power_din_response()).unwrap();
        assert_eq!(
            device,
            NDiscoverDevice {
                name: Some("Test PowerDIN".into()),
                hostname: Some("Test PowerDIN".into()),
                product: Some("PowerDIN".into()),
                firmware_version: Some("5.3.2".into()),
                mcu_version: Some("1.57(1.54)".into()),
                full_version: Some(String::from_utf8(FIRMWARE.to_vec()).unwrap()),
                mac_address: Some("02:00:00:00:00:01".into()),
                ip_address: Some(Ipv4Addr::new(192, 168, 1, 10)),
                netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                dhcp: Some(true),
                setup_state: Some(1),
                ..Default::default()
            }
        );
    }

    #[test]
    fn parses_all_field_types() {
        let device = parse_response(&response(&[
            (0x08, &[3]),
            (0x0A, b"NETIO products a.s."),
            (0x0B, b"4k"),
            (0x0C, b"EU"),
            (0x0D, &[30]),
            (0x0F, &[8, 8, 8, 8]),
            (0x12, b"NETIO PowerDIN"),
            (0x06, &[0]),
        ]))
        .unwrap();
        assert_eq!(device.result, Some(3));
        assert_eq!(device.manufacturer.as_deref(), Some("NETIO products a.s."));
        assert_eq!(device.model.as_deref(), Some("4k"));
        assert_eq!(device.variant.as_deref(), Some("EU"));
        assert_eq!(device.timeout, Some(30));
        assert_eq!(device.dns, Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            device.pretty_platform_name.as_deref(),
            Some("NETIO PowerDIN")
        );
        assert_eq!(device.dhcp, Some(false));
    }

    #[test]
    fn accepts_any_magic_bytes() {
        let mut data = power_din_response();
        data[1] = 0xAB;
        data[2] = 0x6B;
        assert!(parse_response(&data).is_ok());
    }

    #[test]
    fn skips_unknown_field_types() {
        let device = parse_response(&response(&[
            (0x10, &[0x03, 4, 10, 0, 0, 1]),
            (0x03, &[192, 168, 1, 10]),
            (0x11, &[]),
        ]))
        .unwrap();
        assert_eq!(device.ip_address, Some(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn keeps_first_firmware_version() {
        let device = parse_response(&response(&[
            (0x01, b"5.4.0 - 1.56(1.55)"),
            (0x01, b"1.0.0 - 2.0"),
            (0x03, &[192, 168, 1, 10]),
        ]))
        .unwrap();
        assert_eq!(device.firmware_version.as_deref(), Some("5.4.0"));
        assert_eq!(device.ip_address, Some(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn rejects_short_response() {
        assert_eq!(parse_response(&[]), Err(ParseError::TooShort));
        assert_eq!(parse_response(&[0x02, 0xEC]), Err(ParseError::TooShort));
    }

    #[test]
    fn rejects_other_messages() {
        assert_eq!(
            parse_response(&DISCOVER_REQUEST),
            Err(ParseError::NotAResponse(0x01))
        );
    }

    #[test]
    fn rejects_truncated_fields() {
        let mut data = power_din_response();
        data.truncate(data.len() - 1);
        assert_eq!(
            parse_response(&data),
            Err(ParseError::Truncated { ftype: 0x07 })
        );

        let mut data = power_din_response();
        data.push(0x03);
        assert_eq!(
            parse_response(&data),
            Err(ParseError::Truncated { ftype: 0x03 })
        );
    }

    #[test]
    fn rejects_wrong_field_lengths() {
        assert_eq!(
            parse_response(&response(&[(0x03, &[192, 168, 1])])),
            Err(ParseError::BadLength {
                ftype: 0x03,
                len: 3,
                expected: 4
            })
        );
        assert_eq!(
            parse_response(&response(&[(0x02, &[1, 2, 3, 4, 5])])),
            Err(ParseError::BadLength {
                ftype: 0x02,
                len: 5,
                expected: 6
            })
        );
        assert_eq!(
            parse_response(&response(&[(0x06, &[])])),
            Err(ParseError::BadLength {
                ftype: 0x06,
                len: 0,
                expected: 1
            })
        );
    }

    #[test]
    fn rejects_firmware_version_without_mcu() {
        assert_eq!(
            parse_response(&response(&[(0x01, b"5.4.0")])),
            Err(ParseError::BadFirmwareVersion("5.4.0".into()))
        );
    }

    #[test]
    fn leaves_missing_fields_out_of_json() {
        let device = parse_response(&response(&[(0x03, &[192, 168, 1, 10])])).unwrap();
        assert_eq!(
            serde_json::to_string(&device).unwrap(),
            r#"{"ip_address":"192.168.1.10"}"#
        );
    }
}
