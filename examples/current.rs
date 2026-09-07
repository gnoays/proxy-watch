//! Minimal example: read the current proxy configuration once and exit.
//!
//! `read()` performs exactly the read `ProxyWatcher::new()` does during construction, and
//! stops there: no thread, and no change-notification route to arm. That last part is what
//! makes it the right call here — arming can fail on a machine whose settings still read
//! fine, and a program that only wants the settings should not inherit that failure. Run
//! with:
//!
//! ```text
//! cargo run --example current
//! ```

use proxy_watch::read;

fn main() -> Result<(), proxy_watch::Error> {
    let config = read()?;

    println!("effective: {:?}", config.effective);
    for (source, mode) in &config.sources {
        println!("  {source:?} -> {mode:?}");
    }

    Ok(())
}
