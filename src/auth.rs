//! Proxy credentials, with a password-masking `Debug` implementation.

use std::fmt;

use crate::util::MASK;

/// Credentials for a proxy endpoint (HTTP Basic only).
///
/// Negotiate/NTLM/SSPI out of scope. When `password()` is `None`,
/// [`password_state`](Self::password_state) says why. Manual [`Debug`] masks secrets.
///
/// ```
/// # use proxy_watch::ProxyAuth;
/// let auth = ProxyAuth::new("alice", Some("hunter2"));
/// assert!(!format!("{auth:?}").contains("hunter2"));
/// assert_eq!(auth.password(), Some("hunter2"));
/// ```
///
/// Colon in username is masked from the first colon:
///
/// ```
/// # use proxy_watch::ProxyAuth;
/// let auth = ProxyAuth::from_username("alice:hunter2");
/// assert!(!format!("{auth:?}").contains("hunter2"));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProxyAuth {
    username: String,
    password: Option<String>,
    // Why `password` is `None`: never `Present`, and `Absent` while `password` is `Some`, so
    // the derived `PartialEq` and `Hash` see no difference `password_state` hides.
    missing: PasswordState,
}

/// Whether [`ProxyAuth::password`] has a value, and why not when it has none.
///
/// ```
/// # use proxy_watch::{PasswordState, ProxyAuth};
/// assert_eq!(ProxyAuth::new("alice", Some("hunter2")).password_state(), PasswordState::Present);
/// assert_eq!(ProxyAuth::from_username("alice").password_state(), PasswordState::Absent);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PasswordState {
    /// The source provided a password, and [`ProxyAuth::password`] returns it.
    Present,
    /// The source holds no password for this user: `http://alice@proxy/`, or a GNOME
    /// `authentication-password` that is empty.
    Absent,
    /// The source may hold one, and this crate does not read it. GNOME's
    /// `authentication-password`: a plaintext secret in dconf that every reader of the
    /// configuration would otherwise carry.
    NotRead,
    /// The password lives in the macOS keychain, which this crate does not open. System
    /// Configuration carries the user name only.
    InKeychain,
}

impl ProxyAuth {
    /// Create credentials from a user name and an optional password.
    #[must_use]
    pub fn new(username: impl Into<String>, password: Option<impl Into<String>>) -> Self {
        Self {
            username: username.into(),
            password: password.map(Into::into),
            missing: PasswordState::Absent,
        }
    }

    /// User name only; [`password_state`](Self::password_state) is
    /// [`Absent`](PasswordState::Absent).
    #[must_use]
    pub fn from_username(username: impl Into<String>) -> Self {
        Self::new(username, None::<String>)
    }

    // Mark a missing password as one the source holds and this crate did not read.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "linux-gnome")),
        allow(dead_code)
    )]
    pub(crate) fn password_not_read(mut self) -> Self {
        if self.password.is_none() {
            self.missing = PasswordState::NotRead;
        }
        self
    }

    // Mark a missing password as one kept in the macOS keychain.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn password_in_keychain(mut self) -> Self {
        if self.password.is_none() {
            self.missing = PasswordState::InKeychain;
        }
        self
    }

    /// The user name.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password, if the source provided one.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Whether a password is present (without exposing it).
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// [`Present`](PasswordState::Present) when [`password`](Self::password) has a value,
    /// else why it has none.
    #[must_use]
    pub fn password_state(&self) -> PasswordState {
        match self.password {
            Some(_) => PasswordState::Present,
            None => self.missing,
        }
    }
}

impl fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Colon-in-username: mask like a password that arrived unsplit.
        let username = match self.username.split_once(':') {
            Some((user, _)) => std::borrow::Cow::Owned(format!("{user}:{MASK}")),
            None => std::borrow::Cow::Borrowed(self.username.as_str()),
        };
        f.debug_struct("ProxyAuth")
            .field("username", &username)
            .field("password", &self.password.as_ref().map(|_| MASK))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // What the doctests above hold is that the secret does not appear; this test holds the
    // rest of the line, and nothing else notices the printed label going from `username` to
    // `user`. This type's labels are named after the accessors a caller reads the values
    // with: a dump whose labels do not match `username()` and `password()` is a dump the
    // reader has to guess at. The masking itself is `debug_masking`'s registry's business;
    // the framing is this test's.
    #[test]
    fn the_auth_debug_names_its_fields_after_the_accessors() {
        assert_eq!(
            format!("{:?}", ProxyAuth::new("alice", Some("hunter2"))),
            format!("ProxyAuth {{ username: \"alice\", password: Some({MASK:?}) }}")
        );
        // The colon spelling: everything from the first colon is a password that arrived
        // unsplit, so the field still holds a user name and is still labelled one.
        assert_eq!(
            format!("{:?}", ProxyAuth::from_username("alice:hunter2")),
            format!("ProxyAuth {{ username: \"alice:{MASK}\", password: None }}")
        );
    }

    // A password that is there outranks any reason recorded for its absence.
    #[test]
    fn a_present_password_is_present_whatever_was_marked() {
        let marked = ProxyAuth::new("alice", Some("hunter2")).password_in_keychain();
        assert_eq!(marked.password_state(), PasswordState::Present);
        let marked = ProxyAuth::new("alice", Some("hunter2")).password_not_read();
        assert_eq!(marked.password_state(), PasswordState::Present);
        assert_eq!(marked, ProxyAuth::new("alice", Some("hunter2")));
        assert_eq!(
            ProxyAuth::from_username("alice")
                .password_in_keychain()
                .password_state(),
            PasswordState::InKeychain
        );
    }
}
