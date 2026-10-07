use clap::Parser;
use ndiscover_lib::{
    MIN_TIMEOUT, NDiscoverDevice, discover_with, interface_networks, local_networks,
};
use serde::Serialize;
use std::error::Error;
use std::fmt::Display;
use std::process::ExitCode;
use std::time::Duration;

/// A CLI tool to find available NETIO devices on a specified network using the UDP Discover protocol.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Interface to send the UDP discover on.
    ///
    /// Without it, the UDP discover is sent on all local networks, the networks of all
    /// interfaces that support broadcast.
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    /// Timeout in milliseconds (minimum 1000).
    #[arg(short, long, value_name = "MS", default_value_t = 5000)]
    timeout: u64,

    /// Adds detailed information to each device (has no effect on --json).
    #[arg(short, long)]
    detailed: bool,

    /// Outputs json with a list of devices (has all details, regardless of --detailed).
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct DeviceList<'a> {
    devices: &'a [NDiscoverDevice],
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", error_chain(err.as_ref()));
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), Box<dyn Error>> {
    let networks = match &args.interface {
        Some(name) => interface_networks(name)?,
        None => local_networks()?,
    };

    let mut timeout = Duration::from_millis(args.timeout);
    if timeout < MIN_TIMEOUT {
        eprintln!(
            "warning: timeout raised to the minimum of {} ms",
            MIN_TIMEOUT.as_millis()
        );
        timeout = MIN_TIMEOUT;
    }

    let mut devices = Vec::new();
    discover_with(&networks, timeout, |from, response| match response {
        Ok(device) => {
            // JSON is printed all at once when discovery is done
            if !args.json {
                if args.detailed {
                    print_detailed(&device);
                } else {
                    println!("Found device - {}", summary(&device));
                }
            }
            devices.push(device);
        }
        Err(err) => eprintln!(
            "warning: skipping invalid response from {}: {err}",
            from.ip()
        ),
    })?;

    if args.json {
        let json = serde_json::to_string_pretty(&DeviceList { devices: &devices })?;
        println!("{json}");
    } else if devices.is_empty() {
        eprintln!("No devices found.");
    }
    Ok(())
}

/// Joins an error with all its causes, e.g. "could not listen on UDP port 62386: Address already in use"
fn error_chain(err: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(err), |&err| err.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn or_unknown<T: Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| "unknown".to_string(), ToString::to_string)
}

fn summary(device: &NDiscoverDevice) -> String {
    format!(
        "{}:{} @ http://{}",
        or_unknown(&device.name),
        or_unknown(&device.product),
        or_unknown(&device.ip_address)
    )
}

fn print_field<T: Display>(label: &str, value: &Option<T>) {
    if let Some(value) = value {
        println!("{label}: {value}");
    }
}

/// Prints every field the device reported
fn print_detailed(device: &NDiscoverDevice) {
    println!("Device - {}", summary(device));
    print_field("Hostname", &device.hostname);
    print_field("Model", &device.model);
    print_field("Platform", &device.pretty_platform_name);
    print_field("Variant", &device.variant);
    print_field("Manufacturer", &device.manufacturer);
    print_field("Firmware", &device.firmware_version);
    print_field("MCU", &device.mcu_version);
    print_field("Version", &device.full_version);
    print_field("MAC", &device.mac_address);
    print_field("Netmask", &device.netmask);
    print_field("Gateway", &device.gateway);
    print_field("DNS", &device.dns);
    print_field("DHCP", &device.dhcp);
    print_field("Setup state", &device.setup_state);
    print_field("Result", &device.result);
    print_field("Timeout", &device.timeout);
    println!();
}
