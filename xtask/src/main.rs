//! Runs the repository's prose and documentation gates.

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("audit-docs"), None) => run_audit_tests(),
        _ => {
            eprintln!("usage: cargo xtask audit-docs");
            ExitCode::FAILURE
        }
    }
}

fn run_audit_tests() -> ExitCode {
    let status = Command::new(env!("CARGO"))
        .args([
            "test",
            "--package",
            "proxy-watch-repo-audit",
            "--tests",
            "--",
            "--test-threads=1",
        ])
        .status();
    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("failed to start cargo for repository audit: {error}");
            ExitCode::FAILURE
        }
    }
}
