//! Login token of the WebSocket API.
//!
//! The password never leaves the client: the device sends a public key, the client hashes
//! the password with it and proves it knows the hash with a token that is only valid for the
//! current 10 second window of the device clock.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Proof of knowing a user's password, without the password.
///
/// [`Device::login`](crate::Device::login) returns it so the login can be repeated with
/// [`Device::login_with_token`](crate::Device::login_with_token) without keeping the password.
/// It grants the same access as the password, so store it as securely. It stops working when
/// the password changes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordToken {
    salt: String,
    hash: String,
}

impl fmt::Debug for PasswordToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordToken(..)")
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The password hash the device knows the user by
fn password_hash(username: &str, password: &str, public_key: &str) -> String {
    BASE64.encode(Sha256::digest(format!("{username}{public_key}{password}")))
}

/// Random salt that makes every token unique
pub(crate) fn salt() -> Result<String, getrandom::Error> {
    Ok(sha256_hex(&getrandom::u64()?.to_string()))
}

pub(crate) fn password_token(
    username: &str,
    password: &str,
    public_key: &str,
    salt: String,
) -> PasswordToken {
    let hash = sha256_hex(&format!(
        "{salt}{}",
        password_hash(username, password, public_key)
    ));
    PasswordToken { salt, hash }
}

/// Builds the `AUTH` token for `device_time`, in seconds since the Unix epoch by the device
/// clock
pub(crate) fn auth_token(password_token: &PasswordToken, device_time: f64) -> String {
    let time_mark = (device_time / 10.0).floor() as i64;
    format!(
        "{}.{}",
        password_token.salt,
        sha256_hex(&format!("{time_mark}{}", password_token.hash))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public key as sent by a PowerDIN with firmware 5.3.2. The expected values were computed
    // with the functions of PyNetioConf's ws_api module.
    const PUBLIC_KEY: &str = "<?xdf ax='F_A12' elm='sdF'?>";

    #[test]
    fn hashes_password_like_pynetioconf() {
        assert_eq!(
            password_hash("admin", "secret", PUBLIC_KEY),
            "NIFm8R/zo3wF7gnSsY5UDbvdz3fz1R+44cN0R0w+IQ4="
        );
    }

    fn token(device_time: f64) -> String {
        let password_token = password_token("admin", "secret", PUBLIC_KEY, "salt123".into());
        auth_token(&password_token, device_time)
    }

    #[test]
    fn builds_token_like_pynetioconf() {
        let expected = "salt123.1347012541d22387b56cbbe89086b93dd2cbd0059a8a1c13fb0f87532a5dc942";
        assert_eq!(token(1791327793.0), expected);
        // Same 10 second window
        assert_eq!(token(1791327799.9), expected);
        assert_ne!(token(1791327800.0), expected);
    }

    #[test]
    fn hides_token_in_debug_output() {
        let password_token = password_token("admin", "secret", PUBLIC_KEY, "salt123".into());
        assert_eq!(format!("{password_token:?}"), "PasswordToken(..)");
    }

    #[test]
    fn salts_differ() {
        let first = salt().unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, salt().unwrap());
    }
}
