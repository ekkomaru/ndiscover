//! Logins saved in the app data folder, so recognized devices can be logged in to again.
//!
//! Logins are keyed by MAC address, which stays the same when a device gets a new IP
//! address. They hold a password token instead of the password: it only works on that
//! device and does not reveal the password itself. It does give access to the device, so
//! the file is only readable by the user.

use ndiscover_control::{PasswordToken, Security};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

#[derive(Clone, Serialize, Deserialize)]
pub struct SavedLogin {
    pub username: String,
    pub token: PasswordToken,
    pub security: Security,
}

/// Saved logins by MAC address
pub type SavedLogins = HashMap<String, SavedLogin>;

/// Sessions save and forget logins from their own threads
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// Folder of the app's files
pub fn app_folder() -> io::Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no app data folder"))?;
    Ok(data_dir.join("ndiscover"))
}

fn path() -> io::Result<PathBuf> {
    Ok(app_folder()?.join("logins.json"))
}

fn read(path: &Path) -> io::Result<SavedLogins> {
    match fs::read(path) {
        Ok(data) => Ok(serde_json::from_slice(&data)?),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(SavedLogins::new()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let dir = path.parent().expect("the file is in the app's folder");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// The app data folder is private to the user on Windows
#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<File> {
    fs::create_dir_all(path.parent().expect("the file is in the app's folder"))?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn write(path: &Path, logins: &SavedLogins) -> io::Result<()> {
    // Written to a new file that replaces the old one, so a crash cannot leave a half
    // written file behind
    let temporary = path.with_extension("json.tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = create_private(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(logins)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

/// Changes the saved logins, `change` returns whether it changed anything
fn update(change: impl FnOnce(&mut SavedLogins) -> bool) -> io::Result<()> {
    let _lock = FILE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let path = path()?;
    let mut logins = read(&path)?;
    if change(&mut logins) {
        write(&path, &logins)?;
    }
    Ok(())
}

pub fn load_all() -> io::Result<SavedLogins> {
    let _lock = FILE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    read(&path()?)
}

pub fn save(mac: &str, login: &SavedLogin) -> io::Result<()> {
    update(|logins| {
        logins.insert(mac.to_string(), login.clone());
        true
    })
}

pub fn forget_all() -> io::Result<()> {
    update(|logins| {
        let changed = !logins.is_empty();
        logins.clear();
        changed
    })
}

pub fn forget(mac: &str) {
    // Best effort, the login is not used again by this session either way
    let _ = update(|logins| logins.remove(mac).is_some());
}
