// Prevents an additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod control;
mod saved;
mod settings;

use chrono::{DateTime, Local};
use clap::Parser;
use control::DeviceControl;
use eframe::egui;
use ndiscover_control::Security;
use ndiscover_lib::{DiscoverError, NDiscoverDevice, ParseError, discover_with, local_networks};
use saved::{SavedLogin, SavedLogins};
use settings::Settings;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

const SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// Allowed autoscan intervals in seconds, the shortest leaves a pause between scans
const AUTO_SCAN_SECONDS: RangeInclusive<u32> = 5..=3600;
const DEFAULT_AUTO_SCAN_SECONDS: u32 = 30;

/// How long the Copy button of the firmware version says "Copied"
const COPIED_FEEDBACK: Duration = Duration::from_secs(2);

/// While a device installs firmware, scans run this often to see when it is back
const UPDATE_SCAN_INTERVAL: Duration = Duration::from_secs(30);
/// A firmware update that takes longer probably failed
const UPDATE_LIMIT: Duration = Duration::from_secs(15 * 60);

/// Desktop app that finds NETIO devices on the local network and controls them.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Shows the full firmware version in the device list.
    #[arg(short, long)]
    detailed: bool,
}

/// What the scan thread reports back to the UI
enum ScanEvent {
    Device(Box<NDiscoverDevice>),
    Invalid(SocketAddr, ParseError),
    Finished(Result<(), DiscoverError>),
}

/// Scanning repeatedly
struct AutoScan {
    enabled: bool,
    /// Time from the start of one scan to the start of the next
    seconds: u32,
}

impl Default for AutoScan {
    fn default() -> Self {
        AutoScan {
            enabled: false,
            seconds: DEFAULT_AUTO_SCAN_SECONDS,
        }
    }
}

/// A device installing new firmware
struct Updating {
    title: String,
    started: Instant,
    /// Firmware before the update, the update is done when the device reports another one
    version: Option<String>,
    /// The device did not answer a scan since the update started, it is restarting
    went_silent: bool,
}

#[derive(Default)]
struct App {
    /// Devices found by the last scan, sorted by IP address
    devices: Vec<NDiscoverDevice>,
    /// Events of the running scan, `None` when no scan is running
    scan: Option<Receiver<ScanEvent>>,
    /// Devices that answered the running scan, by [`device_key`]
    answered: HashSet<String>,
    /// When the last scan started, autoscan counts from it
    scan_started: Option<Instant>,
    auto_scan: AutoScan,
    /// When the last scan finished, `None` before the first one
    last_scan: Option<DateTime<Local>>,
    /// Why the last scan failed
    error: Option<String>,
    /// Skipped responses and other problems of the last scan
    warnings: Vec<String>,
    /// Devices being logged in to or logged in to
    controls: Vec<DeviceControl>,
    /// Saved logins that were not used yet. Found devices with a plain connection are logged
    /// in to automatically, the others when the user asks for it.
    saved_logins: SavedLogins,
    /// Firmware version copied last and when, for the Copy button's feedback
    copied: Option<(String, Instant)>,
    /// Devices installing new firmware, by [`device_key`]
    updating: HashMap<String, Updating>,
    /// Device whose firmware update waits for the user's confirmation
    confirm_update: Option<Ipv4Addr>,
    /// Number of saved logins while the user is asked whether to forget them
    confirm_forget: Option<usize>,
    /// Settings saved for the next start
    settings: Settings,
    /// Whether the settings window is open
    settings_open: bool,
    /// The full firmware version was asked for with --detailed, whatever the settings say
    detailed_flag: bool,
}

impl App {
    /// Shows the full firmware version instead of only the firmware part
    fn detailed(&self) -> bool {
        self.settings.detailed || self.detailed_flag
    }

    /// Starts a scan on a background thread so the window stays responsive
    fn start_scan(&mut self, ctx: &egui::Context) {
        // The devices of the last scan stay listed, so the list does not flicker on every scan
        self.answered.clear();
        self.scan_started = Some(Instant::now());
        self.error = None;
        self.warnings.clear();
        self.saved_logins = saved::load_all().unwrap_or_else(|err| {
            self.warnings.push(format!(
                "Could not read the saved logins: {}",
                error_chain(&err)
            ));
            SavedLogins::new()
        });

        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            // Sent on every local network, so a VPN with the default route does not get it
            let result = local_networks()
                .map_err(DiscoverError::Networks)
                .and_then(|networks| {
                    discover_with(&networks, SCAN_TIMEOUT, |from, response| {
                        let event = match response {
                            Ok(device) => ScanEvent::Device(Box::new(device)),
                            Err(err) => ScanEvent::Invalid(from, err),
                        };
                        // The UI is gone if sending fails, nothing left to do then
                        let _ = sender.send(event);
                        ctx.request_repaint();
                    })
                });
            let _ = sender.send(ScanEvent::Finished(result));
            ctx.request_repaint();
        });
        self.scan = Some(receiver);
    }

    /// Lists a found device, logging in to it if its login is saved for a plain connection
    fn add_device(&mut self, device: NDiscoverDevice, ctx: &egui::Context) {
        let key = device_key(&device);
        // An updating device is back once it restarted or reports the new firmware
        if self
            .updating
            .get(&key)
            .is_some_and(|updating| updating.went_silent || device.full_version != updating.version)
        {
            self.updating.remove(&key);
        }

        if !self.updating.contains_key(&key)
            && let (Some(ip), Some(mac)) = (device.ip_address, &device.mac_address)
            && controllable(&device)
            && self
                .saved_logins
                .get(mac)
                .is_some_and(|login| login.security == Security::Plain)
        {
            let login = self.saved_logins.remove(mac);
            let title = device_title(&device, ip);
            self.open_control(title, ip, Some(mac.clone()), login, ctx);
        }
        // Replaces the device's row from an earlier scan
        self.devices.retain(|listed| device_key(listed) != key);
        self.answered.insert(key);
        let index = self
            .devices
            .partition_point(|d| d.ip_address < device.ip_address);
        self.devices.insert(index, device);
    }

    /// Removes the devices that did not answer the scan, except for updating ones, which are
    /// restarting
    fn remove_silent_devices(&mut self) {
        for (key, updating) in &mut self.updating {
            if !self.answered.contains(key) {
                updating.went_silent = true;
            }
        }
        self.updating.retain(|_, updating| {
            let late = updating.started.elapsed() >= UPDATE_LIMIT;
            if late {
                self.warnings.push(format!(
                    "The firmware update of {} did not finish within {} minutes",
                    updating.title,
                    UPDATE_LIMIT.as_secs() / 60
                ));
            }
            !late
        });
        self.devices.retain(|device| {
            let key = device_key(device);
            self.answered.contains(&key) || self.updating.contains_key(&key)
        });
    }

    /// Takes in what the scan thread reported since the last frame
    fn receive_scan_events(&mut self, ctx: &egui::Context) {
        let Some(receiver) = self.scan.take() else {
            return;
        };
        let mut finished = false;
        loop {
            match receiver.try_recv() {
                Ok(ScanEvent::Device(device)) => self.add_device(*device, ctx),
                Ok(ScanEvent::Invalid(from, err)) => {
                    self.warnings.push(format!(
                        "Skipped invalid response from {}: {err}",
                        from.ip()
                    ));
                }
                Ok(ScanEvent::Finished(result)) => {
                    match result {
                        Ok(()) => self.remove_silent_devices(),
                        Err(err) => self.error = Some(scan_error(&err)),
                    }
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        if finished {
            self.last_scan = Some(Local::now());
        } else {
            self.scan = Some(receiver);
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let scanning = self.scan.is_some();
            if ui
                .add_enabled(!scanning, egui::Button::new("Scan"))
                .clicked()
            {
                self.start_scan(ui.ctx());
            }
            ui.checkbox(&mut self.auto_scan.enabled, "Scan every");
            ui.add(
                egui::DragValue::new(&mut self.auto_scan.seconds)
                    .range(AUTO_SCAN_SECONDS)
                    .suffix(" s"),
            );
            ui.separator();

            if scanning {
                ui.spinner();
                ui.label("Scanning…");
            } else if let Some(last_scan) = self.last_scan {
                if self.error.is_none() {
                    ui.label(match self.devices.len() {
                        1 => "Found 1 device".to_string(),
                        count => format!("Found {count} devices"),
                    });
                }
                ui.weak(format!("Last scan {}", scan_time(last_scan)));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Settings").clicked() {
                    self.settings_open = !self.settings_open;
                }
                if ui
                    .button("Forget saved devices")
                    .on_hover_text("Deletes all saved logins")
                    .clicked()
                {
                    match saved::load_all() {
                        Ok(logins) => self.confirm_forget = Some(logins.len()),
                        Err(err) => self.warnings.push(format!(
                            "Could not read the saved logins: {}",
                            error_chain(&err)
                        )),
                    }
                }
            });
        });
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut changed = false;
        egui::Window::new("Settings")
            .open(&mut self.settings_open)
            .collapsible(false)
            .resizable(false)
            // Under the Settings button, clear of the scan controls
            .anchor(egui::Align2::RIGHT_TOP, [-8.0, 40.0])
            .show(ctx, |ui| {
                let label = "Show full firmware version";
                if self.detailed_flag {
                    ui.add_enabled(false, egui::Checkbox::new(&mut true, label))
                        .on_disabled_hover_text("Turned on with --detailed");
                } else {
                    changed |= ui
                        .checkbox(&mut self.settings.detailed, label)
                        .on_hover_text(
                            "Shows the whole version a device reports in the device list",
                        )
                        .changed();
                }
            });
        if changed && let Err(err) = settings::save(&self.settings) {
            self.warnings.push(format!(
                "Could not save the settings: {}",
                error_chain(&err)
            ));
        }
    }

    /// Asks before deleting all saved logins
    fn confirm_forget(&mut self, ctx: &egui::Context) {
        let Some(count) = self.confirm_forget else {
            return;
        };
        let mut forget = false;
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("confirm forget")).show(ctx, |ui| {
            ui.set_max_width(420.0);
            ui.heading("Forget saved devices");
            if count == 0 {
                ui.label("No devices have a saved login.");
                ui.add_space(8.0);
                close = ui.button("Close").clicked();
                return;
            }
            ui.label(match count {
                1 => "This deletes the saved login of 1 device.".to_string(),
                count => format!("This deletes the saved logins of {count} devices."),
            });
            ui.label(
                "Devices you are logged in to stay logged in until you log out or close the \
                 app, but are no longer logged in to automatically.",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                forget = ui.button("Forget").clicked();
                close = ui.button("Cancel").clicked();
            });
        });
        if forget {
            self.saved_logins.clear();
            if let Err(err) = saved::forget_all() {
                self.warnings.push(format!(
                    "Could not delete the saved logins: {}",
                    error_chain(&err)
                ));
            }
        }
        if forget || close || modal.should_close() {
            self.confirm_forget = None;
        }
    }

    /// Logs in to the device at `ip` with `saved`, or opens its login window, unless that
    /// happened already
    fn open_control(
        &mut self,
        title: String,
        ip: Ipv4Addr,
        mac: Option<String>,
        saved: Option<SavedLogin>,
        ctx: &egui::Context,
    ) {
        if !self.controls.iter().any(|control| control.ip() == ip) {
            let control = DeviceControl::new(title, IpAddr::V4(ip), mac, saved, ctx);
            self.controls.push(control);
        }
    }

    fn device_list(&mut self, ui: &mut egui::Ui) {
        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        for warning in &self.warnings {
            ui.colored_label(ui.visuals().warn_fg_color, warning);
        }

        if self.devices.is_empty() {
            if self.scan.is_none() {
                ui.weak(if self.last_scan.is_some() {
                    "No devices found."
                } else {
                    "Press Scan to look for NETIO devices on the network."
                });
            }
            return;
        }

        let mut open_control = None;
        let mut log_out = None;
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("devices")
                .num_columns(6)
                .striped(true)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    for header in ["Name", "Product", "Address", "MAC", "Firmware", "Outputs"] {
                        ui.strong(header);
                    }
                    ui.end_row();

                    for device in &self.devices {
                        if self.updating.contains_key(&device_key(device)) {
                            updating_row(ui, device);
                            ui.end_row();
                            continue;
                        }
                        ui.label(or_dash(&device.name));
                        ui.label(or_dash(&device.product));
                        match device.ip_address {
                            Some(ip) => ui.hyperlink_to(ip.to_string(), format!("http://{ip}")),
                            None => ui.label("–"),
                        };
                        ui.monospace(or_dash(&device.mac_address));
                        let control = device
                            .ip_address
                            .and_then(|ip| self.controls.iter().find(|c| c.ip() == ip));
                        let update = control.and_then(DeviceControl::firmware_update).cloned();
                        let can_install = control.is_some_and(DeviceControl::can_install_firmware);
                        let version = match &device.full_version {
                            Some(full_version) if self.detailed() => full_version,
                            _ => or_dash(&device.firmware_version),
                        };
                        let firmware = match update {
                            Some(_) => ui.label(
                                egui::RichText::new(format!("{version} !"))
                                    .color(ui.visuals().warn_fg_color),
                            ),
                            None => ui.label(version),
                        };
                        // Not while the update confirmation is open, it would cover it
                        if self.confirm_update.is_none()
                            && (update.is_some() || device.full_version.is_some())
                        {
                            // Has a button, so it stays open when the pointer moves onto it
                            firmware.on_hover_ui(|ui| {
                                ui.style_mut().interaction.selectable_labels = true;
                                if let Some(update) = &update {
                                    ui.colored_label(
                                        ui.visuals().warn_fg_color,
                                        format!("New firmware available: {}", update.name),
                                    );
                                    ui.label(format!("Version {}", update.version));
                                    if !update.release_note.is_empty() {
                                        ui.weak(&update.release_note);
                                    }
                                    if ui
                                        .add_enabled(can_install, egui::Button::new("Update"))
                                        .clicked()
                                    {
                                        self.confirm_update = device.ip_address;
                                    }
                                    ui.separator();
                                }
                                if let Some(full_version) = &device.full_version {
                                    ui.label(full_version);
                                    let copied = self.copied.as_ref().is_some_and(|(text, at)| {
                                        text == full_version && at.elapsed() < COPIED_FEEDBACK
                                    });
                                    if ui.button(if copied { "Copied" } else { "Copy" }).clicked() {
                                        ui.ctx().copy_text(full_version.clone());
                                        ui.ctx().request_repaint_after(COPIED_FEEDBACK);
                                        self.copied = Some((full_version.clone(), Instant::now()));
                                    }
                                }
                            });
                        }
                        if let Some(ip) = device.ip_address {
                            let control =
                                self.controls.iter_mut().find(|control| control.ip() == ip);
                            match control {
                                Some(control) if control.logged_in() => {
                                    if control.output_checkboxes(ui) {
                                        log_out = Some(ip);
                                    }
                                }
                                Some(control) if control.resuming() => {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.weak("Logging in…");
                                    });
                                }
                                _ => {
                                    if ui
                                        .add_enabled(
                                            controllable(device),
                                            egui::Button::new("Control"),
                                        )
                                        .on_disabled_hover_text("Needs firmware 5.0 or newer")
                                        .clicked()
                                    {
                                        let title = device_title(device, ip);
                                        open_control =
                                            Some((title, ip, device.mac_address.clone()));
                                    }
                                }
                            }
                        }
                        ui.end_row();
                    }
                });
        });
        if let Some((title, ip, mac)) = open_control {
            let saved = mac.as_ref().and_then(|mac| self.saved_logins.remove(mac));
            self.open_control(title, ip, mac, saved, ui.ctx());
        }
        if let Some(ip) = log_out
            && let Some(index) = self.controls.iter().position(|c| c.ip() == ip)
        {
            self.controls.remove(index).log_out();
        }
    }

    /// Marks the devices that accepted a firmware update as updating, their controls are done
    fn start_updates(&mut self) {
        let installing: Vec<IpAddr> = self
            .controls
            .iter()
            .filter(|control| control.installing())
            .map(DeviceControl::ip)
            .collect();
        for ip in installing {
            self.controls.retain(|control| control.ip() != ip);
            if let Some(device) = self
                .devices
                .iter()
                .find(|device| device.ip_address.map(IpAddr::V4) == Some(ip))
            {
                let updating = Updating {
                    title: device_title(device, device.ip_address.expect("found by IP")),
                    started: Instant::now(),
                    version: device.full_version.clone(),
                    went_silent: false,
                };
                self.updating.insert(device_key(device), updating);
            }
        }
    }

    /// Asks before installing firmware, the device restarts
    fn confirm_update(&mut self, ctx: &egui::Context) {
        let Some(ip) = self.confirm_update else {
            return;
        };
        let title = self
            .devices
            .iter()
            .find(|device| device.ip_address == Some(ip))
            .map_or_else(|| ip.to_string(), |device| device_title(device, ip));
        let Some(control) = self
            .controls
            .iter_mut()
            .find(|control| control.ip() == ip && control.can_install_firmware())
        else {
            self.confirm_update = None;
            return;
        };
        let update = control.firmware_update().expect("can install").clone();

        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("confirm firmware update")).show(ctx, |ui| {
            ui.set_max_width(420.0);
            ui.heading("Update firmware");
            ui.label(format!(
                "Update {title} to {} ({})?",
                update.name, update.version
            ));
            ui.label(
                "The device downloads the firmware and restarts. It is unavailable until it is \
                 back, which can take several minutes.",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Update").clicked() {
                    control.install_firmware();
                    close = true;
                }
                close |= ui.button("Cancel").clicked();
            });
        });
        if close || modal.should_close() {
            self.confirm_update = None;
        }
    }

    /// Starts the next scan when autoscan is on and it is time
    fn auto_scan(&mut self, ctx: &egui::Context) {
        if self.scan.is_some() {
            return;
        }
        // Updating devices are looked for, to know when they are back
        let interval = match (self.auto_scan.enabled, self.updating.is_empty()) {
            (false, true) => return,
            (false, false) => UPDATE_SCAN_INTERVAL,
            (true, true) => Duration::from_secs(self.auto_scan.seconds.into()),
            (true, false) => {
                UPDATE_SCAN_INTERVAL.min(Duration::from_secs(self.auto_scan.seconds.into()))
            }
        };
        let wait = self.scan_started.map_or(Duration::ZERO, |started| {
            interval.saturating_sub(started.elapsed())
        });
        if wait.is_zero() {
            self.start_scan(ctx);
        } else {
            ctx.request_repaint_after(wait);
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_scan_events(ctx);
        for control in &mut self.controls {
            control.receive();
        }
        self.start_updates();
        self.auto_scan(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui);
            ui.add_space(4.0);
        });
        egui::CentralPanel::default().show(ui, |ui| self.device_list(ui));

        let ctx = ui.ctx().clone();
        self.controls
            .retain_mut(|control| control.logged_in() || control.login_window(&ctx));
        self.confirm_update(&ctx);
        self.confirm_forget(&ctx);
        self.settings_window(&ctx);
    }
}

/// Devices with firmware 5.0 or newer have the WebSocket API to control them
fn controllable(device: &NDiscoverDevice) -> bool {
    device
        .firmware_version
        .as_deref()
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 5)
}

/// Row of a device that installs firmware, it cannot be used until it is back
fn updating_row(ui: &mut egui::Ui, device: &NDiscoverDevice) {
    ui.weak(or_dash(&device.name));
    ui.weak(or_dash(&device.product));
    ui.weak(
        device
            .ip_address
            .map_or("–".to_string(), |ip| ip.to_string()),
    );
    ui.weak(or_dash(&device.mac_address));
    ui.horizontal(|ui| {
        ui.spinner();
        ui.weak("Updating firmware…");
    });
}

/// Identifies a device across scans: by MAC address, as the IP address can change
fn device_key(device: &NDiscoverDevice) -> String {
    match (&device.mac_address, device.ip_address) {
        (Some(mac), _) => mac.clone(),
        (None, Some(ip)) => ip.to_string(),
        (None, None) => String::new(),
    }
}

fn device_title(device: &NDiscoverDevice, ip: Ipv4Addr) -> String {
    match &device.name {
        Some(name) => format!("{name} ({ip})"),
        None => ip.to_string(),
    }
}

/// Time of a scan, with the date unless it was today
fn scan_time(time: DateTime<Local>) -> String {
    let format = if time.date_naive() == Local::now().date_naive() {
        "%H:%M:%S"
    } else {
        "%Y-%m-%d %H:%M:%S"
    };
    time.format(format).to_string()
}

fn or_dash(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("–")
}

/// Describes why a scan failed, with a hint where the cause is known
fn scan_error(err: &DiscoverError) -> String {
    let message = error_chain(err);
    // What macOS answers while the app may not access the local network, e.g. while it asks
    // the user for permission on the first scan
    if cfg!(target_os = "macos")
        && matches!(err, DiscoverError::Send(_, err) if err.kind() == io::ErrorKind::HostUnreachable)
    {
        return format!(
            "{message}\nIf macOS asked whether ndiscover may find devices on local networks, \
             allow it and scan again. You can change this in System Settings > Privacy & \
             Security > Local Network."
        );
    }
    message
}

/// Joins an error with all its causes, e.g. "could not listen on UDP port 62386: Address already in use"
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    std::iter::successors(Some(err), |&err| err.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn main() -> eframe::Result {
    let args = Args::parse();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 460.0])
            .with_min_inner_size([420.0, 240.0])
            // An empty icon keeps eframe from setting its own at runtime, so the app shows the
            // icon of its bundle, see scripts/macos-app.sh
            .with_icon(egui::IconData::default()),
        ..Default::default()
    };
    eframe::run_native(
        "ndiscover",
        options,
        Box::new(|cc| {
            let mut app = App {
                detailed_flag: args.detailed,
                ..App::default()
            };
            // Looks for devices right away
            app.start_scan(&cc.egui_ctx);
            // After the scan started, which clears the warnings
            app.settings = settings::load().unwrap_or_else(|err| {
                app.warnings.push(format!(
                    "Could not read the settings: {}",
                    error_chain(&err)
                ));
                Settings::default()
            });
            Ok(Box::new(app))
        }),
    )
}
