//! Settings of the app, saved in the app data folder next to the saved logins.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

/// Settings missing from the file, e.g. ones added by a newer version, get their default
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Shows the full firmware version in the device list
    pub detailed: bool,
}

fn path() -> io::Result<PathBuf> {
    Ok(crate::saved::app_folder()?.join("settings.json"))
}

pub fn load() -> io::Result<Settings> {
    match fs::read(path()?) {
        Ok(data) => Ok(serde_json::from_slice(&data)?),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(Settings::default()),
        Err(err) => Err(err),
    }
}

pub fn save(settings: &Settings) -> io::Result<()> {
    let path = path()?;
    fs::create_dir_all(path.parent().expect("the file is in the app's folder"))?;
    // Written to a new file that replaces the old one, so a crash cannot leave a half written
    // file behind
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(settings)?)?;
    fs::rename(&temporary, &path)
}
