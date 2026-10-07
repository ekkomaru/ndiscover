//! Logging in to a device and switching its outputs.

use crate::error_chain;
use crate::saved::{self, SavedLogin};
use eframe::egui;
use ndiscover_control::{Device, FirmwareCheck, FirmwareUpdate, Output, OutputAction, Security};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// How often the output states are read while idle. This also keeps the session open, the
/// web interface pings as often.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Devices do not always answer the firmware check right away, it is repeated this often
/// until they do
const FIRMWARE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Gives up on the firmware check after this long, e.g. when the device cannot reach the
/// internet
const FIRMWARE_CHECK_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Checkbox fill of outputs that are on
const ON_COLOR: egui::Color32 = egui::Color32::from_rgb(46, 160, 67);
const ON_HOVER_COLOR: egui::Color32 = egui::Color32::from_rgb(64, 184, 86);

enum Command {
    Login {
        username: String,
        password: String,
        security: Security,
        remember: bool,
    },
    /// Logs in with a saved login
    Resume(SavedLogin),
    Set {
        id: u8,
        on: bool,
    },
    /// Starts installing the firmware, the session ends once the device accepted it
    InstallFirmware(FirmwareUpdate),
    /// Forgets the saved login and ends the session
    LogOut,
}

/// Why a command failed
struct Failure {
    message: String,
    /// The login is not valid (anymore), the login window shows again
    logged_out: bool,
}

/// What the session thread sends back, always with the current outputs so the UI shows the
/// real state
enum Update {
    /// Reply to a command
    Done(Result<Vec<Output>, Failure>),
    /// Periodic refresh while idle
    Refreshed(Result<Vec<Output>, Failure>),
    /// Logged in, but the login could not be saved
    NotSaved(String),
    /// Result of the firmware check, `None` when the firmware is up to date
    Firmware(Option<FirmwareUpdate>),
    /// The firmware check failed or gave no answer
    FirmwareUnknown(String),
    /// Whether the device accepted the firmware update
    Installing(Result<(), String>),
}

/// The firmware check that runs after logging in
struct FirmwarePolling {
    started: Instant,
    next: Instant,
}

/// Owns the connection on a background thread, so the window stays responsive
struct Session {
    ip: IpAddr,
    /// Saved logins are keyed by MAC address, nothing is saved without one
    mac: Option<String>,
    device: Option<Device>,
    /// What the session logs in with, saved or not
    login: Option<SavedLogin>,
    firmware_polling: Option<FirmwarePolling>,
}

impl Session {
    /// Returns the connection, logging in again if it was lost
    fn device(&mut self) -> Result<&mut Device, ndiscover_control::Error> {
        if self.device.is_none() {
            let Some(login) = &self.login else {
                unreachable!("outputs are only used after logging in");
            };
            let address = SocketAddr::new(self.ip, login.security.default_port());
            let mut device = Device::connect(address, login.security)?;
            device.login_with_token(&login.username, &login.token)?;
            self.device = Some(device);
        }
        Ok(self.device.as_mut().expect("connected above"))
    }

    fn execute(
        &mut self,
        command: Command,
        updates: &Sender<Update>,
    ) -> Result<Vec<Output>, ndiscover_control::Error> {
        match command {
            Command::Login {
                username,
                password,
                security,
                remember,
            } => {
                let address = SocketAddr::new(self.ip, security.default_port());
                let mut device = Device::connect(address, security)?;
                let token = device.login(&username, &password)?;
                let login = SavedLogin {
                    username,
                    token,
                    security,
                };
                if let Some(mac) = &self.mac {
                    if !remember {
                        saved::forget(mac);
                    } else if let Err(err) = saved::save(mac, &login) {
                        let message = format!("Could not save the login: {}", error_chain(&err));
                        let _ = updates.send(Update::NotSaved(message));
                    }
                }
                self.device = Some(device);
                self.login = Some(login);
            }
            Command::Resume(login) => {
                self.device = None;
                self.login = Some(login);
            }
            Command::Set { id, on } => {
                let action = if on {
                    OutputAction::On
                } else {
                    OutputAction::Off
                };
                self.device()?.set_output(id, action)?;
            }
            Command::InstallFirmware(_) | Command::LogOut => {
                unreachable!("handled by the session loop")
            }
        }
        self.device()?.outputs()
    }

    fn failure(&mut self, err: ndiscover_control::Error) -> Failure {
        // Connect again next time
        self.device = None;
        let logged_out = matches!(err, ndiscover_control::Error::InvalidCredentials);
        if logged_out
            && self.login.take().is_some()
            && let Some(mac) = &self.mac
        {
            // A saved login that stopped working, for example after a password change
            saved::forget(mac);
        }
        Failure {
            message: error_chain(&err),
            logged_out,
        }
    }

    /// Checks for a newer firmware once, returns what to tell the window if the check is over
    fn check_firmware(&mut self) -> Option<Update> {
        let mut polling = self.firmware_polling.take()?;
        // Stops when logged out meanwhile
        self.login.as_ref()?;
        match self.device().and_then(Device::check_firmware) {
            Ok(FirmwareCheck::Available(update)) => return Some(Update::Firmware(Some(update))),
            Ok(FirmwareCheck::UpToDate) => return Some(Update::Firmware(None)),
            Ok(FirmwareCheck::Pending) => {}
            // E.g. the user may not change settings, asking again does not help
            Err(err @ ndiscover_control::Error::Refused { .. }) => {
                return Some(Update::FirmwareUnknown(format!(
                    "Could not check for new firmware: {}",
                    error_chain(&err)
                )));
            }
            Err(err) => {
                let failure = self.failure(err);
                if failure.logged_out {
                    return Some(Update::Refreshed(Err(failure)));
                }
                // Connection problems show up in the refresh, the check is tried again
            }
        }
        if polling.started.elapsed() >= FIRMWARE_CHECK_LIMIT {
            return Some(Update::FirmwareUnknown(
                "The device did not tell whether there is new firmware".to_string(),
            ));
        }
        polling.next = Instant::now() + FIRMWARE_CHECK_INTERVAL;
        self.firmware_polling = Some(polling);
        None
    }

    fn run(mut self, commands: Receiver<Command>, updates: Sender<Update>, ctx: egui::Context) {
        let send = |update| {
            let sent = updates.send(update).is_ok();
            ctx.request_repaint();
            sent
        };
        let mut next_refresh = Instant::now() + REFRESH_INTERVAL;
        loop {
            if self
                .firmware_polling
                .as_ref()
                .is_some_and(|polling| polling.next <= Instant::now())
                && let Some(update) = self.check_firmware()
                && !send(update)
            {
                return;
            }
            if next_refresh <= Instant::now() {
                next_refresh = Instant::now() + REFRESH_INTERVAL;
                if self.login.is_some() {
                    let outputs = self.device().and_then(Device::outputs);
                    if !send(Update::Refreshed(outputs.map_err(|e| self.failure(e)))) {
                        return;
                    }
                }
            }

            let mut wake = next_refresh;
            if let Some(polling) = &self.firmware_polling {
                wake = wake.min(polling.next);
            }
            let command =
                match commands.recv_timeout(wake.saturating_duration_since(Instant::now())) {
                    Ok(Command::LogOut) => {
                        if let Some(mac) = &self.mac {
                            saved::forget(mac);
                        }
                        return;
                    }
                    Ok(Command::InstallFirmware(update)) => {
                        let result = self
                            .device()
                            .and_then(|device| device.install_firmware(&update))
                            .map_err(|err| self.failure(err).message);
                        let started = result.is_ok();
                        // The device restarts, which ends this session
                        if !send(Update::Installing(result)) || started {
                            return;
                        }
                        continue;
                    }
                    Ok(command) => command,
                    Err(RecvTimeoutError::Timeout) => continue,
                    // The device's control was dropped, dropping the device ends the session
                    Err(RecvTimeoutError::Disconnected) => return,
                };
            let logs_in = matches!(command, Command::Login { .. } | Command::Resume(_));
            let result = self.execute(command, &updates).map_err(|e| self.failure(e));
            if logs_in && result.is_ok() {
                let now = Instant::now();
                self.firmware_polling = Some(FirmwarePolling {
                    started: now,
                    next: now,
                });
            }
            // The outputs were just read
            next_refresh = Instant::now() + REFRESH_INTERVAL;
            if !send(Update::Done(result)) {
                return;
            }
        }
    }
}

/// Login window and output checkboxes of one device
pub struct DeviceControl {
    title: String,
    ip: IpAddr,
    mac: Option<String>,
    commands: Sender<Command>,
    updates: Receiver<Update>,
    username: String,
    password: String,
    security: Security,
    remember: bool,
    /// The username field gets focus when the login window opens
    focus_username: bool,
    /// The login window is shown, it is not while logging in with a saved login
    show_login: bool,
    /// `Some` once logged in
    outputs: Option<Vec<Output>>,
    /// A command is running
    busy: bool,
    /// Output being switched, shown with its new state until the device confirms it
    pending: Option<(u8, bool)>,
    error: Option<String>,
    /// Problem that does not affect controlling the device
    notice: Option<String>,
    /// Newer firmware the device can update to
    firmware_update: Option<FirmwareUpdate>,
    /// The device accepted the firmware update and is restarting
    installing: bool,
}

impl DeviceControl {
    /// Logs in with `saved` right away, otherwise shows the login window
    pub fn new(
        title: String,
        ip: IpAddr,
        mac: Option<String>,
        saved: Option<SavedLogin>,
        ctx: &egui::Context,
    ) -> Self {
        let (commands, command_receiver) = mpsc::channel();
        let (update_sender, updates) = mpsc::channel();
        let session = Session {
            ip,
            mac: mac.clone(),
            device: None,
            login: None,
            firmware_polling: None,
        };
        let ctx = ctx.clone();
        thread::spawn(move || session.run(command_receiver, update_sender, ctx));

        let mut control = DeviceControl {
            title,
            ip,
            mac,
            commands,
            updates,
            username: String::new(),
            password: String::new(),
            security: Security::Plain,
            remember: true,
            focus_username: true,
            show_login: saved.is_none(),
            outputs: None,
            busy: false,
            pending: None,
            error: None,
            notice: None,
            firmware_update: None,
            installing: false,
        };
        if let Some(login) = saved {
            control.username = login.username.clone();
            control.security = login.security;
            control.send(Command::Resume(login));
        }
        control
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn firmware_update(&self) -> Option<&FirmwareUpdate> {
        self.firmware_update.as_ref()
    }

    pub fn can_install_firmware(&self) -> bool {
        self.logged_in()
            && !self.busy
            && self
                .firmware_update
                .as_ref()
                .is_some_and(|update| !update.download_url_no_mcu.is_empty())
    }

    pub fn install_firmware(&mut self) {
        if let Some(update) = self.firmware_update.clone() {
            self.send(Command::InstallFirmware(update));
        }
    }

    /// The device accepted the firmware update, it restarts and this control is done
    pub fn installing(&self) -> bool {
        self.installing
    }

    pub fn logged_in(&self) -> bool {
        self.outputs.is_some()
    }

    /// Logging in with a saved login, there is no login window meanwhile
    pub fn resuming(&self) -> bool {
        !self.logged_in() && !self.show_login
    }

    /// Ends the session and forgets the saved login
    pub fn log_out(self) {
        let _ = self.commands.send(Command::LogOut);
    }

    fn send(&mut self, command: Command) {
        self.busy = true;
        self.error = None;
        // The session thread only stops once this is dropped
        let _ = self.commands.send(command);
    }

    /// Takes in what the session thread sent since the last frame
    pub fn receive(&mut self) {
        while let Ok(update) = self.updates.try_recv() {
            let result = match update {
                Update::Done(result) => {
                    self.busy = false;
                    self.pending = None;
                    result
                }
                Update::Refreshed(result) => result,
                Update::NotSaved(message) | Update::FirmwareUnknown(message) => {
                    self.notice = Some(message);
                    continue;
                }
                Update::Firmware(update) => {
                    self.firmware_update = update;
                    continue;
                }
                Update::Installing(result) => {
                    self.busy = false;
                    match result {
                        Ok(()) => self.installing = true,
                        Err(message) => {
                            self.error = Some(format!("Could not update the firmware: {message}"));
                        }
                    }
                    continue;
                }
            };
            match result {
                Ok(outputs) => {
                    self.outputs = Some(outputs);
                    self.show_login = false;
                    self.error = None;
                }
                Err(failure) => {
                    if failure.logged_out {
                        self.outputs = None;
                    }
                    if !self.logged_in() && !self.show_login {
                        self.show_login = true;
                        self.focus_username = true;
                    }
                    self.error = Some(failure.message);
                }
            }
        }
    }

    /// Shows the login window if needed, returns `false` once it was closed
    pub fn login_window(&mut self, ctx: &egui::Context) -> bool {
        if !self.show_login {
            return true;
        }
        let mut open = true;
        egui::Window::new(&self.title)
            .id(egui::Id::new(("login", self.ip)))
            .open(&mut open)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| self.login_form(ui));
        open
    }

    fn login_form(&mut self, ui: &mut egui::Ui) {
        let mut submit = false;
        egui::Grid::new("login").num_columns(2).show(ui, |ui| {
            ui.label("Username");
            let username = ui.text_edit_singleline(&mut self.username);
            if std::mem::take(&mut self.focus_username) {
                username.request_focus();
            }
            ui.end_row();

            ui.label("Password");
            let password = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
            submit = password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.end_row();
        });

        let mut secure = self.security == Security::Tls;
        ui.checkbox(&mut secure, "Secure connection (wss)")
            .on_hover_text("For devices with HTTPS enabled");
        self.security = if secure {
            Security::Tls
        } else {
            Security::Plain
        };
        if self.mac.is_some() {
            ui.checkbox(&mut self.remember, "Remember login")
                .on_hover_text(
                    "Saved in the app data folder, without the password. Devices with a \
                     plain connection are logged in to automatically when found.",
                );
        }

        ui.horizontal(|ui| {
            let can_log_in = !self.busy && !self.username.is_empty();
            submit |= ui
                .add_enabled(can_log_in, egui::Button::new("Log in"))
                .clicked();
            if self.busy {
                ui.spinner();
            }
            if submit && can_log_in {
                // Not kept in the window once sent
                let password = std::mem::take(&mut self.password);
                self.send(Command::Login {
                    username: self.username.clone(),
                    password,
                    security: self.security,
                    remember: self.remember,
                });
            }
        });

        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
    }

    /// Shows a checkbox per output, green when on. Returns `true` when the user logs out.
    pub fn output_checkboxes(&mut self, ui: &mut egui::Ui) -> bool {
        let Some(outputs) = &self.outputs else {
            return false;
        };
        let mut switch = None;
        let mut log_out = false;
        ui.horizontal(|ui| {
            for output in outputs {
                let mut on = match self.pending {
                    Some((id, on)) if id == output.id => on,
                    _ => output.on,
                };
                let name = if output.name.is_empty() {
                    format!("Output {}", output.id)
                } else {
                    output.name.clone()
                };
                let response = ui.scope(|ui| {
                    if on {
                        let widgets = &mut ui.visuals_mut().widgets;
                        widgets.inactive.bg_fill = ON_COLOR;
                        widgets.noninteractive.bg_fill = ON_COLOR;
                        widgets.active.bg_fill = ON_COLOR;
                        widgets.hovered.bg_fill = ON_HOVER_COLOR;
                    }
                    let checkbox = egui::Checkbox::new(&mut on, output.id.to_string());
                    ui.add_enabled(!self.busy, checkbox)
                });
                if response
                    .inner
                    .on_hover_text(&name)
                    .on_disabled_hover_text(&name)
                    .changed()
                {
                    switch = Some((output.id, on));
                }
            }
            log_out = ui
                .button("Log out")
                .on_hover_text("Ends the session and forgets the saved login")
                .clicked();
            // After the button so it does not move while switching
            if self.busy {
                ui.spinner();
            }
            let problems: Vec<&str> = [&self.error, &self.notice]
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            if !problems.is_empty() {
                ui.colored_label(ui.visuals().warn_fg_color, "⚠")
                    .on_hover_text(problems.join("\n"));
            }
        });

        if let Some((id, on)) = switch {
            self.pending = Some((id, on));
            self.send(Command::Set { id, on });
        }
        log_out
    }
}
