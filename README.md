# ndiscover

Find and manage NETIO power distribution devices on your local network.

ndiscover finds NETIO devices with NETIO's [UDP Discover protocol][udp-discover] and lists them in a
command-line tool or a desktop app. The desktop app can also log in to devices with firmware 5.0 or
newer, switch their outputs and install firmware updates.

## Features

- **Discovery on every local network at once**, also while a VPN routes all traffic through itself
- **Command-line tool** with plain, detailed and JSON output
- **Desktop app**
  - scans when it starts, and every few seconds if you like
  - links to each device's web interface
  - shows the full firmware version on hover, with a button to copy it
  - logs in over plain (`ws://`) or secure (`wss://`) WebSocket connections
  - switches outputs with one checkbox per output
  - remembers logins and logs in again automatically
  - checks for firmware updates and installs them
- **Rust libraries** for discovery (`ndiscover_lib`) and device control (`ndiscover_control`)

## Requirements

- Rust 1.88 or newer
- Logging in to devices and switching their outputs needs firmware 5.0 or newer. Discovery works
  with all devices that support UDP Discover.
- On Linux, the desktop app needs the system libraries [eframe][eframe] builds against, and OpenSSL
  (`libssl-dev` and `pkg-config` on Debian and Ubuntu).

ndiscover is developed and tested on macOS. Linux and Windows are supported by the code but not
tested yet.

## Command-line tool

```sh
cargo install --path .
ndiscover-cli
```

| Option                    | Description                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| `-i, --interface <IFACE>` | Only search the networks of this interface, e.g. `en0` or `eth0`. Default: all local networks |
| `-t, --timeout <MS>`      | How long to wait for answers, in milliseconds. Default: 5000, minimum: 1000                   |
| `-d, --detailed`          | Print every detail the devices report                                                         |
| `--json`                  | Print the devices as JSON                                                                     |

```text
$ ndiscover-cli
Found device - Rack PDU:PowerPDU 8KF @ http://192.168.1.20
Found device - Office PDU:PowerPDU 4C @ http://192.168.1.21
```

With `--json`, details a device doesn't report are left out:

```json
{
  "devices": [
    {
      "name": "Rack PDU",
      "hostname": "Rack-PDU",
      "firmware_version": "5.4.0",
      "mcu_version": "1.56(1.55)",
      "full_version": "5.4.0 - 1.56(1.55) - 0  4k (rev.2a299831/2026-09-16)",
      "mac_address": "24:a4:2c:00:00:01",
      "ip_address": "192.168.1.20",
      "netmask": "255.255.255.0",
      "dhcp": true,
      "setup_state": 1,
      "product": "PowerPDU 8KF"
    }
  ]
}
```

The tool exits with 0 when the search worked, also if it found nothing, and with 1 when it failed,
for example because the network could not be reached.

## Desktop app

```sh
cargo install --path . --features gui
ndiscover
```

Or run it straight from the source: `cargo run --release --features gui --bin ndiscover`.

- **Finding devices:** the app scans when it starts. Use **Scan** to scan again, or turn on
  **Scan every** to scan regularly. Click an address to open the device's web interface.
- **Logging in:** click **Control** next to a device. Tick **Secure connection (wss)** for devices
  with HTTPS enabled. With **Remember login**, the app logs in again by itself the next time it
  finds the device.
- **Switching outputs:** once logged in, each output has a checkbox, green when the output is on.
  Hover over a checkbox to see the output's name. **Log out** ends the session and forgets the saved
  login.
- **Firmware updates:** after logging in, the app asks the device whether newer firmware is
  available. If it is, the firmware version turns orange with a **!**. Hover over it for the release
  notes and an **Update** button. The device is greyed out while it updates and comes back once it
  has restarted.
- **Settings:** **Show full firmware version** lists the whole version a device reports instead
  of only the firmware part. Settings are saved in `settings.json`, in the same folder as the saved
  logins. Starting the app with `-d, --detailed` shows the full version for that run, whatever the
  setting says.

### Saved logins

Saved logins are kept per device in `logins.json`:

| System  | Folder                                    |
| ------- | ----------------------------------------- |
| macOS   | `~/Library/Application Support/ndiscover` |
| Linux   | `~/.local/share/ndiscover`                |
| Windows | `%LOCALAPPDATA%\ndiscover`                |

The file holds a token made from the password, not the password itself. The token only works for
that device, but it does give access to it, so the file is readable by your user account only.
Devices with a saved plain login are logged in to as soon as they are found. Devices with a saved
secure login log in when you click **Control**.

### macOS app bundle

```sh
./scripts/macos-app.sh
```

This builds `target/release/bundle/ndiscover.app`, which you can move to `/Applications`. To give it
an icon, put a square PNG of 1024 × 1024 pixels at `assets/icon.png`.

The first time the app scans, macOS asks whether ndiscover may find devices on local networks. The
app needs that permission to work. You can change it later in System Settings → Privacy & Security →
Local Network.

The app is signed only for the Mac that built it. To share it with others, it needs to be signed
with an Apple Developer ID and notarized.

## Libraries

`ndiscover_lib` (in this package) finds devices:

```rust
use std::time::Duration;

let networks = ndiscover_lib::local_networks()?;
for device in ndiscover_lib::discover(&networks, Duration::from_secs(2))? {
    println!("{:?} at {:?}", device.name, device.ip_address);
}
```

`ndiscover_control` (in the `ndiscover_control` folder) controls devices with firmware 5.0 or newer:

```rust
use ndiscover_control::{Device, OutputAction, Security};

let mut device = Device::connect("192.168.1.20:80".parse()?, Security::Plain)?;
device.login("admin", "password")?;
for output in device.outputs()? {
    println!("{} {}: {}", output.id, output.name, if output.on { "on" } else { "off" });
}
device.set_output(1, OutputAction::Toggle)?;
```

`cargo doc --workspace --open` shows the full documentation.

## Security notes

- **Discovery** uses unauthenticated UDP broadcasts, so any device on the network can answer.
- **Plain connections** (`ws://`), the devices' default, are not encrypted. The password is never
  sent, though: logging in sends a salted hash that is only valid for a few seconds.
- **Secure connections** (`wss://`) accept any certificate, because devices use self-signed ones.
  The connection is encrypted but not protected against someone on the network posing as the
  device.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --features gui
```

| Path                   | Contents                                          |
| ---------------------- | ------------------------------------------------- |
| `src/lib.rs`           | `ndiscover_lib`: UDP Discover                     |
| `src/main.rs`          | `ndiscover-cli`                                   |
| `src/gui/`             | `ndiscover`, the desktop app (`gui` feature)      |
| `ndiscover_control/`   | `ndiscover_control`: logins, outputs and firmware |
| `scripts/macos-app.sh` | Builds the macOS app bundle                       |

The device protocols are described in NETIO's [UDP Discover documentation][udp-discover] and
implemented in Python by [PyNetioConf][pynetioconf].

[udp-discover]: https://wiki.netio-products.com/index.php?title=NETIO_UDP_Discover
[pynetioconf]: https://github.com/netioproducts/PyNetioConf
[eframe]: https://github.com/emilk/egui/tree/main/crates/eframe
