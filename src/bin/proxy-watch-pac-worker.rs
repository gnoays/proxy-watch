//! The worker process a `proxy_watch::pac::SubprocessEvaluator` starts: one PAC evaluation
//! over standard input and output, then exit.

#[cfg(pac_quickjs)]
fn main() -> std::process::ExitCode {
    proxy_watch::pac::serve_worker()
}

// Android and iOS build `pac-quickjs` without its engine, so there is nothing to serve.
#[cfg(not(pac_quickjs))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
