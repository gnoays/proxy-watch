//! Proxy credentials, with a password-masking `Debug` implementation.

use std::fmt;

use crate::util::MASK;

/// Credentials for a proxy endpoint (HTTP Basic only).
///
/// Negotiate/NTLM/SSPI out of scope. `password()` → `None` is ambiguous (unset, unread
/// GNOME field, macOS 15+ keychain). Manual [`Debug`] masks secrets.
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
}

impl ProxyAuth {
    /// Create credentials from a user name and an optional password.
    #[must_use]
    pub fn new(username: impl Into<String>, password: Option<impl Into<String>>) -> Self {
        Self {
            username: username.into(),
            password: password.map(Into::into),
        }
    }

    /// User name only (e.g. macOS `HTTPUser` with password in the keychain).
    #[must_use]
    pub fn from_username(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: None,
        }
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
    // with — a dump whose labels do not match `username()` and `password()` is a dump the
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
}
