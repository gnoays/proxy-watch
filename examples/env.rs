//! `ProxyEnv` reads the `*_proxy` environment variables once, as a static snapshot.
//!
//! Unlike `ProxyWatcher`, `ProxyEnv` does **not** implement `Stream`:
//! environment variables cannot be changed from outside the process, so there is
//! nothing to watch. Run with:
//!
//! ```text
//! http_proxy=http://proxy.example:8080 no_proxy=localhost,*.internal cargo run --example env
//! ```

use proxy_watch::ProxyEnv;

fn main() -> Result<(), proxy_watch::Error> {
    let env = ProxyEnv::from_env()?;

    // Both questions, because neither answers alone: `is_empty` counts scheme variables and
    // values that failed to parse, and a lone `no_proxy` leaves it `true` while still being
    // something the environment asked for.
    if env.is_empty() && !env.is_configured() {
        println!("no *_proxy variables set");
    } else {
        println!("effective: {:?}", env.to_mode());
    }

    Ok(())
}
