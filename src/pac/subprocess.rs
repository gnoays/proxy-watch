//! `pac-subprocess`: PAC evaluation in a worker process the caller names, killed at the
//! deadline.
//!
//! The parent side ([`SubprocessEvaluator`]) runs no JavaScript and needs no engine feature.
//! The worker side (`serve_worker`, which needs the QuickJS engine too) is what the
//! `proxy-watch-pac-worker` binary runs. Both halves are this module, so a worker built from
//! the same release speaks the same protocol; the version in the header catches the rest.
//!
//! Once it has read a script, the worker is treated as untrusted: the script may have taken
//! it over. The worker returns the raw string `FindProxyForURL` produced, and the parent
//! parses it. The worker resolves no names itself: each lookup is a request the parent
//! answers under its own [`PacPolicy`], so a worker cannot widen DNS access or the
//! internal-address filter by lying about the policy.
//!
//! Before it reads a script, the worker confines itself and reports whether it could. That
//! report is trusted, and only the worker binary vouches for it, so the confinement holds
//! for a worker from this release and not for an arbitrary executable the caller names. On
//! Linux (x86-64 and AArch64) the confinement is a seccomp filter: the worker keeps its pipes
//! to the parent, memory, the clock and randomness, and any other system call kills it, so a
//! worker a memory-safety bug has taken over cannot open a file or a socket. Elsewhere the
//! worker cannot confine itself, and the parent sends it no script unless
//! [`SubprocessEvaluator::allow_unsandboxed`] says to.
//!
//! Wire format, both directions: an 8-byte header (`PWPAC\0` and a little-endian `u16`
//! version), then frames. A frame is a little-endian `u32` body length, a tag byte, and
//! fields, each a little-endian `u32` length and UTF-8 bytes.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Instant, UNIX_EPOCH};

use url::Url;

use crate::error::Error;
use crate::resolve::ProxyStep;

use super::policy::PacPolicy;
use super::result::parse_find_proxy_result;
use super::{PacEvaluator, PacScript, budget, hostfn};

const MAGIC: [u8; 6] = *b"PWPAC\0";
const VERSION: u16 = 2;

// Parent to worker.
const EVALUATE: u8 = 1;
const ANSWER: u8 = 2;
// Worker to parent.
const LOOKUP: u8 = 3;
const DONE: u8 = 4;
const FAILED: u8 = 5;
const SANDBOX: u8 = 6;

// The `SANDBOX` field of a worker under its seccomp filter. Any other value is the reason it
// is not confined.
const SECCOMP: &str = "seccomp";

// The largest frame the parent reads from a worker. A `FindProxyForURL` answer or an error
// message is far smaller; a worker announcing more is broken or hostile, and the parent
// refuses it before allocating. That also caps an answer at 1 MiB, where the in-process
// engine passes any length on.
const MAX_WORKER_FRAME: usize = 1024 * 1024;

// Memory a worker may commit (Windows, a Job Object) or map (Linux, `RLIMIT_AS`). QuickJS
// already stops a script at 64 MiB of heap; these catch growth outside its accounting. Address
// space counts every mapped library and reservation, hence the larger Linux figure. macOS
// ignores `RLIMIT_AS`, so there the QuickJS heap limit is the only one.
// Limitation: fixed limits; a `SubprocessEvaluator` knob when a real script needs more.
#[cfg(windows)]
const WORKER_COMMIT_LIMIT: usize = 512 * 1024 * 1024;
#[cfg(target_os = "linux")]
const WORKER_ADDRESS_SPACE_LIMIT: u64 = 1024 * 1024 * 1024;

/// [`PacEvaluator`] that runs each evaluation in a fresh worker process and kills it at the
/// deadline.
///
/// `worker` is the absolute path of a `proxy-watch-pac-worker` binary from this same release
/// (built with the `pac-subprocess` and `pac-quickjs` features). A relative path is refused
/// with [`Error::Io`] at evaluation: a bare name would be looked up on the `PATH`, and whoever
/// controls the lookup would choose the program that sees every script and URL.
///
/// Of [`PacPolicy`]'s settings, the timeout covers the whole evaluation (starting the
/// worker, running the script, and every name lookup it asks for) and a worker still
/// running at the deadline is killed. DNS and the internal-address filter are applied here
/// in the parent. `myIpAddress`, the clock and the UTC offset are handed to the worker. The
/// worker runs QuickJS with a 64 MiB heap, and on Windows and Linux the process has an OS
/// memory limit as well.
///
/// Each running worker holds one of the process-wide evaluation slots QuickJS uses too, so
/// [`Error::PacSaturated`] bounds worker processes as it bounds threads. A name lookup still
/// running at the deadline keeps its slot until it returns.
///
/// The worker starts with an empty environment (Windows keeps `SystemRoot`) and its own
/// directory as the working directory, and its standard error is discarded.
///
/// On Linux (x86-64 and AArch64) the worker runs the script under a seccomp filter that
/// leaves it no system call to open a file, a socket or a process. The parent knows this
/// only from the worker's own report, so the guarantee is the worker binary's. On other
/// platforms, or where the kernel refuses the filter, the worker is unconfined, and
/// evaluation fails with [`Error::Io`] ([`io::ErrorKind::PermissionDenied`]) before the
/// script is sent, unless [`allow_unsandboxed`](Self::allow_unsandboxed) was called. A
/// worker the filter kills fails the evaluation with [`Error::PacEvaluation`].
#[derive(Debug, Clone)]
pub struct SubprocessEvaluator {
    worker: PathBuf,
    policy: PacPolicy,
    allow_unsandboxed: bool,
}

impl SubprocessEvaluator {
    /// An evaluator that starts `worker` for each evaluation and runs scripts under `policy`.
    #[must_use]
    pub fn new(worker: impl Into<PathBuf>, policy: PacPolicy) -> Self {
        Self {
            worker: worker.into(),
            policy,
            allow_unsandboxed: false,
        }
    }

    /// Also run scripts in a worker that could not confine itself: everywhere but Linux on
    /// x86-64 and AArch64, any worker. The worker keeps the memory limit and the deadline,
    /// but one a memory-safety bug has taken over can reach the network and the files of
    /// the user it runs as.
    #[must_use]
    pub fn allow_unsandboxed(mut self) -> Self {
        self.allow_unsandboxed = true;
        self
    }

    /// The worker binary this evaluator starts.
    #[must_use]
    pub fn worker(&self) -> &Path {
        &self.worker
    }

    /// The policy this evaluator applies.
    #[must_use]
    pub fn policy(&self) -> &PacPolicy {
        &self.policy
    }
}

impl PacEvaluator for SubprocessEvaluator {
    fn evaluate(&self, script: &PacScript, url: &Url, host: &str) -> Result<Vec<ProxyStep>, Error> {
        let url = crate::pac::sanitize_url(url);
        let timeout = self.policy.timeout();
        if let Some(timeout) = timeout.filter(|timeout| timeout.is_zero()) {
            return Err(Error::PacTimeout { timeout });
        }
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        // Shared with the conversation thread and freed when both let go: this side holds it
        // until the worker is reaped, the thread until a name lookup it is in finishes.
        let slot =
            Arc::new(
                budget::SLOTS
                    .acquire(deadline)
                    .ok_or_else(|| Error::PacSaturated {
                        timeout: timeout.unwrap_or_default(),
                        limit: budget::SLOTS.limit(),
                    })?,
            );

        let mut worker = Worker::start(&self.worker)?;
        let request = evaluate_request(script.source(), url.as_str(), host, &self.policy);
        let (input, output) = worker.pipes();
        let policy = self.policy;
        let allow_unsandboxed = self.allow_unsandboxed;
        let (sender, receiver) = mpsc::sync_channel(1);
        // The conversation runs on its own thread so that this one can kill the worker at
        // the deadline whatever the conversation is blocked on. Killing closes the pipes,
        // which ends the thread, unless it is inside a name lookup, which then finishes on
        // its own.
        let thread_slot = Arc::clone(&slot);
        let spawned = thread::Builder::new()
            .name("proxy-watch-pac-worker".to_owned())
            .spawn(move || {
                let _slot = thread_slot;
                let _ = sender.send(converse(
                    output,
                    input,
                    &request,
                    &policy,
                    allow_unsandboxed,
                ));
            });
        if let Err(source) = spawned {
            return Err(Error::io("spawning the PAC worker thread", source));
        }

        let outcome = match deadline {
            Some(deadline) => {
                receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match outcome {
            Ok(Ok(raw)) => parse_find_proxy_result(&raw),
            Ok(Err(error)) => {
                #[cfg(target_os = "linux")]
                if worker.killed_by_seccomp() {
                    return Err(Error::pac_evaluation(
                        "the PAC worker's seccomp filter killed it: the script led it to a \
                         system call outside what an evaluation needs",
                    ));
                }
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => Err(Error::PacTimeout {
                timeout: timeout.unwrap_or_default(),
            }),
            Err(RecvTimeoutError::Disconnected) => Err(Error::pac_evaluation(
                "the PAC worker thread ended without producing a result",
            )),
        }
    }
}

// A started worker process, killed and reaped on drop, also after it answered: it has
// nothing left to do, and waiting for it to exit on its own would let a hostile one keep
// its slot, which `evaluate` drops only after this.
struct Worker {
    child: Child,
    // Held until the worker is reaped. Closing it kills anything still in the job.
    #[cfg(windows)]
    _job: Option<job::Job>,
}

impl Worker {
    fn start(path: &Path) -> Result<Self, Error> {
        // A relative path would also be resolved against the worker's own directory, set
        // below, rather than the caller's.
        if !path.is_absolute() {
            return Err(Error::io(
                "starting the PAC worker",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the worker path is not absolute",
                ),
            ));
        }
        let mut command = Command::new(path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        #[cfg(windows)]
        if let Some(value) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", value);
        }
        if let Some(directory) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            command.current_dir(directory);
        }
        #[cfg(target_os = "linux")]
        limit_address_space(&mut command);

        let child = command
            .spawn()
            .map_err(|source| Error::io("starting the PAC worker", source))?;
        // The worker reads its request before it runs anything it was sent, and the request
        // is written only after this returns, so no script runs outside the job.
        #[cfg(windows)]
        let mut child = child;
        #[cfg(windows)]
        let _job = match job::confine(&child) {
            Ok(job) => Some(job),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::io("limiting the PAC worker's memory", source));
            }
        };
        Ok(Self {
            child,
            #[cfg(windows)]
            _job,
        })
    }

    fn pipes(&mut self) -> (std::process::ChildStdin, std::process::ChildStdout) {
        let (Some(input), Some(output)) = (self.child.stdin.take(), self.child.stdout.take())
        else {
            unreachable!("both pipes are requested in `start` and taken once");
        };
        (input, output)
    }

    // Whether the worker died of `SIGSYS`, which the seccomp filter sends. Called once the
    // conversation has failed: a worker still running is killed, which then reads as `false`.
    #[cfg(target_os = "linux")]
    fn killed_by_seccomp(&mut self) -> bool {
        use std::os::unix::process::ExitStatusExt;

        let _ = self.child.kill();
        self.child
            .wait()
            .is_ok_and(|status| status.signal() == Some(libc::SIGSYS))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn limit_address_space(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    let limit = libc::rlimit {
        rlim_cur: WORKER_ADDRESS_SPACE_LIMIT as libc::rlim_t,
        rlim_max: WORKER_ADDRESS_SPACE_LIMIT as libc::rlim_t,
    };
    // SAFETY: `setrlimit` is async-signal-safe, and the closure touches nothing else between
    // `fork` and `exec`. Lowering the hard limit too keeps the worker from raising it back.
    unsafe {
        command.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_AS, &limit) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

#[cfg(windows)]
mod job {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows::core::PCWSTR;

    use super::WORKER_COMMIT_LIMIT;

    pub(super) struct Job(HANDLE);

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: the handle came from `CreateJobObjectW` and is closed once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    // An unnamed job with the worker in it: a commit limit, and the worker killed when the
    // last handle closes, including the parent dying before it could kill the worker.
    pub(super) fn confine(child: &Child) -> io::Result<Job> {
        let error = |error: windows::core::Error| io::Error::from_raw_os_error(error.code().0);
        // SAFETY: no attributes and no name; the handle is owned by the returned `Job`.
        let job = Job(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(error)?);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.ProcessMemoryLimit = WORKER_COMMIT_LIMIT;
        // SAFETY: `limits` is the structure the information class names, with its size.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of_val(&limits)).expect("a fixed-size structure"),
            )
        }
        .map_err(error)?;
        // SAFETY: `child` is alive; it is reaped only after the job is dropped.
        unsafe { AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle())) }.map_err(error)?;
        Ok(job)
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;
        use std::time::{Duration, Instant};

        use windows::Win32::System::JobObjects::{IsProcessInJob, QueryInformationJobObject};

        use super::super::Worker;
        use super::*;

        // `cmd.exe` with its standard input held open waits on it, so it stays alive until
        // something kills it.
        #[test]
        fn a_worker_runs_under_its_commit_limit_and_dies_with_its_job() {
            let cmd = Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\cmd.exe");
            let mut worker = Worker::start(&cmd).unwrap();
            let job = worker._job.take().unwrap();

            let mut inside = windows::core::BOOL(0);
            // SAFETY: both handles are open, and `inside` outlives the call.
            unsafe {
                IsProcessInJob(
                    HANDLE(worker.child.as_raw_handle()),
                    Some(job.0),
                    &mut inside,
                )
            }
            .unwrap();
            assert!(inside.as_bool());
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: `limits` is the structure the information class names, with its size.
            unsafe {
                QueryInformationJobObject(
                    Some(job.0),
                    JobObjectExtendedLimitInformation,
                    (&raw mut limits).cast(),
                    u32::try_from(size_of_val(&limits)).unwrap(),
                    None,
                )
            }
            .unwrap();
            assert!(
                limits
                    .BasicLimitInformation
                    .LimitFlags
                    .contains(JOB_OBJECT_LIMIT_PROCESS_MEMORY)
            );
            assert_eq!(limits.ProcessMemoryLimit, WORKER_COMMIT_LIMIT);

            // Closing the job alone kills the worker: the parent dying does no more.
            drop(job);
            let started = Instant::now();
            while worker.child.try_wait().unwrap().is_none() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "the worker outlived its job"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

// The request frame's fields: script, URL, host, `myIpAddress`, UTC offset, and the pinned
// clock in signed nanoseconds since the epoch (empty for the real clock). DNS and the
// internal-address filter stay out: the parent applies them.
fn evaluate_request(script: &str, url: &str, host: &str, policy: &PacPolicy) -> Vec<Vec<u8>> {
    let now = policy
        .now()
        .map_or_else(String::new, |now| match now.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_nanos().to_string(),
            Err(before) => format!("-{}", before.duration().as_nanos()),
        });
    [
        script.to_owned(),
        url.to_owned(),
        host.to_owned(),
        policy.my_ip_address().to_string(),
        policy.local_utc_offset().to_string(),
        now,
    ]
    .map(String::into_bytes)
    .into()
}

// The parent's half: check the worker's confinement, send the request, answer lookups under
// `policy`, return the raw answer. An unconfined worker is refused before the request, which
// carries the script, is written.
fn converse(
    mut from_worker: impl Read,
    mut to_worker: impl Write,
    request: &[Vec<u8>],
    policy: &PacPolicy,
    allow_unsandboxed: bool,
) -> Result<String, Error> {
    let broken = |error: io::Error| {
        Error::pac_evaluation(format!("the PAC worker broke the protocol: {error}"))
    };
    let unexpected = |tag: u8, fields: &[String]| {
        broken(invalid(format!(
            "unexpected frame {tag} with {} fields",
            fields.len()
        )))
    };
    write_header(&mut to_worker).map_err(broken)?;
    read_header(&mut from_worker).map_err(broken)?;
    match read_frame(&mut from_worker, MAX_WORKER_FRAME).map_err(broken)? {
        (SANDBOX, fields) if fields.len() == 1 => {
            if fields[0] != SECCOMP && !allow_unsandboxed {
                return Err(Error::io(
                    "starting the PAC worker",
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "the worker is not sandboxed ({}), and the evaluator does not \
                             allow that",
                            fields[0]
                        ),
                    ),
                ));
            }
        }
        (tag, fields) => return Err(unexpected(tag, &fields)),
    }
    write_frame(&mut to_worker, EVALUATE, request).map_err(broken)?;
    loop {
        let (tag, mut fields) = read_frame(&mut from_worker, MAX_WORKER_FRAME).map_err(broken)?;
        match (tag, fields.len()) {
            (LOOKUP, 1) => {
                let host = fields.remove(0);
                let answer = hostfn::resolve_ipv4(&host, policy)
                    .map_or_else(Vec::new, |address| address.to_string().into_bytes());
                write_frame(&mut to_worker, ANSWER, &[answer]).map_err(broken)?;
            }
            (DONE, 1) => return Ok(fields.remove(0)),
            (FAILED, 1) => return Err(Error::pac_evaluation(fields.remove(0))),
            _ => return Err(unexpected(tag, &fields)),
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn write_header(to: &mut impl Write) -> io::Result<()> {
    to.write_all(&MAGIC)?;
    to.write_all(&VERSION.to_le_bytes())?;
    to.flush()
}

fn read_header(from: &mut impl Read) -> io::Result<()> {
    let mut header = [0u8; 8];
    from.read_exact(&mut header)?;
    if header[..6] != MAGIC {
        return Err(invalid("not a PAC worker"));
    }
    let version = u16::from_le_bytes([header[6], header[7]]);
    if version != VERSION {
        return Err(invalid(format!(
            "protocol version {version}, expected {VERSION}; the worker is from another release"
        )));
    }
    Ok(())
}

fn write_frame(to: &mut impl Write, tag: u8, fields: &[impl AsRef<[u8]>]) -> io::Result<()> {
    let length = |len: usize| {
        u32::try_from(len)
            .map(u32::to_le_bytes)
            .map_err(|_| invalid("a frame too large to send"))
    };
    let mut body = vec![tag];
    for field in fields {
        let field = field.as_ref();
        body.extend(length(field.len())?);
        body.extend(field);
    }
    to.write_all(&length(body.len())?)?;
    to.write_all(&body)?;
    to.flush()
}

// A frame of at most `max` bytes, split into its tag and UTF-8 fields.
fn read_frame(from: &mut impl Read, max: usize) -> io::Result<(u8, Vec<String>)> {
    let mut length = [0u8; 4];
    from.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > max {
        return Err(invalid(format!("a frame of {length} bytes")));
    }
    let mut body = vec![0u8; length];
    from.read_exact(&mut body)?;

    let (&tag, mut rest) = body.split_first().expect("length is not zero");
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (size, tail) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| invalid("a truncated field length"))?;
        let size = u32::from_le_bytes(*size) as usize;
        if size > tail.len() {
            return Err(invalid("a field longer than its frame"));
        }
        let (field, tail) = tail.split_at(size);
        fields.push(
            String::from_utf8(field.to_vec()).map_err(|_| invalid("a field that is not UTF-8"))?,
        );
        rest = tail;
    }
    Ok((tag, fields))
}

#[cfg(pac_quickjs)]
pub use self::worker::serve_worker;

// The worker's half. The lookup hook lives in a thread local because `hostfn` is reached from
// inside the engine, and the worker evaluates on its main thread only.
#[cfg(pac_quickjs)]
mod worker {
    use std::cell::RefCell;
    use std::io::{self, StdinLock, StdoutLock};
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::ExitCode;
    use std::time::Duration;

    use super::*;

    thread_local! {
        static PARENT: RefCell<Option<(StdinLock<'static>, StdoutLock<'static>)>> =
            const { RefCell::new(None) };
    }

    /// Run one evaluation for a [`SubprocessEvaluator`] over standard input and output, then
    /// return. This is the whole of the `proxy-watch-pac-worker` binary; a program that embeds
    /// the worker elsewhere calls it the same way, as the first and only thing its `main` does.
    ///
    /// Exits with failure when the parent is not a [`SubprocessEvaluator`] of this release or
    /// hangs up; the parent reads that as a worker that produced no answer.
    #[must_use]
    pub fn serve_worker() -> ExitCode {
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let sandbox = confine();
        let request = write_header(&mut output)
            .and_then(|()| write_frame(&mut output, SANDBOX, &[sandbox]))
            .and_then(|()| read_header(&mut input))
            .and_then(|()| read_frame(&mut input, usize::MAX))
            .and_then(|frame| match frame {
                (EVALUATE, fields) if fields.len() == 6 => Ok(fields),
                _ => Err(invalid("the first frame is not a request")),
            })
            .and_then(|fields| Ok((policy(&fields)?, fields)));
        let Ok((policy, fields)) = request else {
            return ExitCode::FAILURE;
        };

        PARENT.set(Some((input, output)));
        let result =
            super::super::quickjs::run_raw(&fields[0], &fields[1], &fields[2], policy, None);
        let Some((_, mut output)) = PARENT.take() else {
            return ExitCode::FAILURE;
        };
        let sent = match result {
            Ok(raw) => write_frame(&mut output, DONE, &[raw]),
            // The reason alone: the parent wraps it in `Error::PacEvaluation` again, and the
            // `Display` form would arrive with the prefix twice and its tail cut by the
            // second length cap.
            Err(Error::PacEvaluation { reason }) => write_frame(&mut output, FAILED, &[reason]),
            Err(error) => write_frame(&mut output, FAILED, &[error.to_string()]),
        };
        if sent.is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }

    // What the worker reports in its `SANDBOX` frame: `SECCOMP` once the filter is on, or why
    // it is not.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn confine() -> String {
        match super::seccomp::confine() {
            Ok(()) => SECCOMP.to_owned(),
            Err(error) => format!("the kernel refused the seccomp filter: {error}"),
        }
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    fn confine() -> String {
        "the worker has no sandbox on this platform".to_owned()
    }

    // The worker's policy: what the host functions read besides DNS. No timeout here: the
    // parent kills the worker at its deadline, and that also covers a lookup in flight.
    fn policy(fields: &[String]) -> io::Result<PacPolicy> {
        let bad = |what: &str| invalid(format!("an unreadable {what}"));
        let my_ip: IpAddr = fields[3].parse().map_err(|_| bad("myIpAddress"))?;
        let offset: i32 = fields[4].parse().map_err(|_| bad("UTC offset"))?;
        let mut policy = PacPolicy::new()
            .with_timeout(None)
            .with_my_ip_address(my_ip)
            .with_local_utc_offset(offset);
        if !fields[5].is_empty() {
            let (negative, digits) = match fields[5].strip_prefix('-') {
                Some(digits) => (true, digits),
                None => (false, fields[5].as_str()),
            };
            let nanos: u128 = digits.parse().map_err(|_| bad("clock"))?;
            let offset = Duration::new(
                u64::try_from(nanos / 1_000_000_000).map_err(|_| bad("clock"))?,
                (nanos % 1_000_000_000) as u32,
            );
            let now = if negative {
                UNIX_EPOCH.checked_sub(offset)
            } else {
                UNIX_EPOCH.checked_add(offset)
            };
            policy = policy.with_now(now.ok_or_else(|| bad("clock"))?);
        }
        Ok(policy)
    }

    // `Some` answer from the parent inside a worker, `None` anywhere else. A parent that
    // hangs up or answers with anything but an address ends the worker: there is no parent
    // connection left to report to.
    pub(in crate::pac) fn ask_parent(host: &str) -> Option<Option<Ipv4Addr>> {
        PARENT.with_borrow_mut(|parent| {
            let (input, output) = parent.as_mut()?;
            let answer = write_frame(output, LOOKUP, &[host])
                .and_then(|()| read_frame(input, usize::MAX))
                .and_then(|frame| match frame {
                    (ANSWER, fields) if fields.len() == 1 && fields[0].is_empty() => Ok(None),
                    (ANSWER, fields) if fields.len() == 1 => fields[0]
                        .parse()
                        .map(Some)
                        .map_err(|_| invalid("an unreadable address")),
                    _ => Err(invalid("a reply that is not an answer")),
                });
            match answer {
                Ok(answer) => Some(answer),
                Err(_) => std::process::exit(1),
            }
        })
    }
}

#[cfg(pac_quickjs)]
pub(super) use self::worker::ask_parent;

// The worker's seccomp filter. What an evaluation needs is its pipes to the parent
// (standard input to read, standard output and error to write), memory, the signal calls
// std's own handlers make, the clock and randomness; any other call kills the whole process
// with `SIGSYS`. Killing rather than failing the call matters: std's `SIGSEGV` handler
// reinstalls the default action and returns to fault again, so a refused `rt_sigaction`
// would turn that into a loop that no deadline ends when the policy has none.
#[cfg(all(
    pac_quickjs,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod seccomp {
    use std::io;

    use libc::{
        BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_ALLOW,
        SECCOMP_RET_KILL_PROCESS, c_long, sock_filter, sock_fprog,
    };

    // `AUDIT_ARCH_*`, which `libc` does not carry.
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7;

    // Offsets into `seccomp_data`. Both architectures are little-endian, so an argument's low
    // half comes first; the kernel reads a file descriptor as `unsigned int`, so the low half
    // is all of it.
    const NR: u32 = 0;
    const ARCH_AT: u32 = 4;
    const fn argument(index: u32) -> u32 {
        16 + 8 * index
    }

    const ALLOWED: &[c_long] = &[
        libc::SYS_exit_group,
        libc::SYS_exit,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mprotect,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_time,
        libc::SYS_getrandom,
    ];

    // Calls allowed only with one of the listed values as the given argument.
    const WITH_ARGUMENT: &[(c_long, u32, &[u32])] = &[
        (libc::SYS_read, 0, &[0]),
        (libc::SYS_write, 0, &[1, 2]),
        (libc::SYS_writev, 0, &[1, 2]),
        // Anonymous memory only (descriptor -1): a mapping of an inherited file would read it.
        (libc::SYS_mmap, 4, &[u32::MAX]),
    ];

    fn statement(code: u32, k: u32) -> sock_filter {
        jump(code, k, 0, 0)
    }

    fn jump(code: u32, k: u32, jt: usize, jf: usize) -> sock_filter {
        let offset = |n: usize| u8::try_from(n).expect("a short filter");
        sock_filter {
            code: u16::try_from(code).expect("a BPF opcode"),
            jt: offset(jt),
            jf: offset(jf),
            k,
        }
    }

    pub(super) fn filter() -> Vec<sock_filter> {
        let load = |at: u32| statement(BPF_LD | BPF_W | BPF_ABS, at);
        let equal = |k: u32, jt: usize, jf: usize| jump(BPF_JMP | BPF_JEQ | BPF_K, k, jt, jf);
        let allow = statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        let kill = statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        let mut program = vec![load(ARCH_AT), equal(ARCH, 1, 0), kill, load(NR)];
        // x32 calls share x86-64's architecture value and set this bit in the number.
        if cfg!(target_arch = "x86_64") {
            program.extend([jump(BPF_JMP | BPF_JGE | BPF_K, 0x4000_0000, 0, 1), kill]);
        }
        for &call in ALLOWED {
            program.extend([equal(call as u32, 0, 1), allow]);
        }
        for &(call, index, values) in WITH_ARGUMENT {
            let count = values.len();
            program.extend([equal(call as u32, 0, count + 3), load(argument(index))]);
            for (position, &value) in values.iter().enumerate() {
                program.push(equal(value, count - position, 0));
            }
            program.extend([kill, allow]);
        }
        program.push(kill);
        program
    }

    // Applied to every thread of the process (`TSYNC`): `serve_worker` may run in a program
    // that has started others.
    pub(super) fn install(program: &[sock_filter]) -> io::Result<()> {
        let program = sock_fprog {
            len: u16::try_from(program.len()).expect("a short filter"),
            filter: program.as_ptr().cast_mut(),
        };
        // SAFETY: `prctl` takes plain integers here. `seccomp` reads `program`, which points
        // at a live slice of the length it names, and keeps its own copy.
        let result = unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::syscall(
                libc::SYS_seccomp,
                libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &raw const program,
            )
        };
        match result {
            0 => Ok(()),
            -1 => Err(io::Error::last_os_error()),
            thread => Err(io::Error::other(format!(
                "thread {thread} could not take the filter"
            ))),
        }
    }

    unsafe extern "C" {
        fn tzset();
    }

    // `Date`'s local time reads the zone file the first time it is needed, and the filter
    // forbids opening it, so it is read here first.
    pub(super) fn confine() -> io::Result<()> {
        // SAFETY: `tzset` takes no arguments and serializes itself; it reads the
        // environment, which the worker does not write.
        unsafe { tzset() };
        install(&filter())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use super::*;

    // A confined worker saying `frames` after its header and `SANDBOX` frame.
    fn from_worker(frames: &[(u8, &[&str])]) -> Vec<u8> {
        let confined: &[(u8, &[&str])] = &[(SANDBOX, &[SECCOMP])];
        from_unconfined(&[confined, frames].concat())
    }

    fn from_unconfined(frames: &[(u8, &[&str])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_header(&mut bytes).unwrap();
        for (tag, fields) in frames {
            write_frame(&mut bytes, *tag, fields).unwrap();
        }
        bytes
    }

    fn talk(worker_said: Vec<u8>, policy: &PacPolicy) -> (Result<String, Error>, Vec<u8>) {
        talk_allowing(worker_said, policy, false)
    }

    fn talk_allowing(
        worker_said: Vec<u8>,
        policy: &PacPolicy,
        allow_unsandboxed: bool,
    ) -> (Result<String, Error>, Vec<u8>) {
        let mut sent = Vec::new();
        let request = evaluate_request("script", "http://example.net/", "example.net", policy);
        let result = converse(
            Cursor::new(worker_said),
            &mut sent,
            &request,
            policy,
            allow_unsandboxed,
        );
        (result, sent)
    }

    fn broken(result: Result<String, Error>) -> String {
        match result {
            Err(Error::PacEvaluation { reason }) => reason,
            other => panic!("expected a protocol failure, got {other:?}"),
        }
    }

    // The worker inherits none of the parent's environment but `SystemRoot`. `cmd.exe` sets
    // `COMSPEC`, `PATHEXT` and `PROMPT` itself when it finds them missing.
    #[cfg(windows)]
    #[test]
    fn a_worker_starts_with_an_empty_environment() {
        let cmd = Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\cmd.exe");
        let mut worker = Worker::start(&cmd).unwrap();
        let (mut input, mut output) = worker.pipes();
        input.write_all(b"set\r\nexit\r\n").unwrap();
        drop(input);
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        let mut names: Vec<&str> = said
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .filter(|name| !["COMSPEC", "PATHEXT", "PROMPT"].contains(name))
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["SystemRoot"], "{said}");
    }

    #[test]
    fn an_answer_is_returned_raw_and_a_failure_as_an_evaluation_error() {
        let policy = PacPolicy::new();
        let (result, _) = talk(from_worker(&[(DONE, &["PROXY a:1; DIRECT"])]), &policy);
        assert_eq!(result.unwrap(), "PROXY a:1; DIRECT");
        let (result, _) = talk(from_worker(&[(FAILED, &["boom"])]), &policy);
        assert!(broken(result).contains("boom"));
    }

    // The parent answers under its own policy, whatever the worker would have liked. The
    // three policies split one lookup three ways, so an answer given under any policy but
    // the one passed in shows. The address is a literal, so no row asks real DNS.
    #[test]
    fn a_lookup_is_answered_under_the_parent_policy() {
        let dns = PacPolicy::new().with_dns_resolution(true);
        for (policy, answer) in [
            (PacPolicy::new(), ""),
            (dns, ""),
            (dns.with_internal_addresses(true), "127.0.0.1"),
        ] {
            let said = from_worker(&[(LOOKUP, &["127.0.0.1"]), (DONE, &["DIRECT"])]);
            let (result, sent) = talk(said, &policy);
            assert_eq!(result.unwrap(), "DIRECT");
            let mut sent = Cursor::new(sent);
            read_header(&mut sent).unwrap();
            assert_eq!(read_frame(&mut sent, usize::MAX).unwrap().0, EVALUATE);
            assert_eq!(
                read_frame(&mut sent, usize::MAX).unwrap(),
                (ANSWER, vec![answer.to_owned()]),
                "{policy:?}"
            );
        }
    }

    #[test]
    fn a_worker_that_breaks_the_protocol_is_an_evaluation_error() {
        let policy = PacPolicy::new();
        // Another program entirely.
        assert!(
            broken(talk(b"Microsoft Windows\r\n".to_vec(), &policy).0).contains("not a PAC worker")
        );
        // Another release.
        let mut other = MAGIC.to_vec();
        other.extend((VERSION + 1).to_le_bytes());
        assert!(broken(talk(other, &policy).0).contains(&format!("version {}", VERSION + 1)));
        // No word on its confinement before its answer.
        assert!(
            broken(talk(from_unconfined(&[(DONE, &["DIRECT"])]), &policy).0)
                .contains("unexpected frame")
        );
        // Exits without answering.
        assert!(!broken(talk(from_worker(&[]), &policy).0).is_empty());
        // A length the parent must not allocate.
        let mut huge = from_worker(&[]);
        huge.extend(u32::MAX.to_le_bytes());
        assert!(broken(talk(huge, &policy).0).contains("4294967295 bytes"));
        // A frame cut short.
        let mut cut = from_worker(&[(DONE, &["DIRECT"])]);
        cut.pop();
        assert!(!broken(talk(cut, &policy).0).is_empty());
        // Unknown tags, a request tag coming back, and a wrong field count.
        for said in [
            from_worker(&[(9, &["x"])]),
            from_worker(&[(EVALUATE, &["x"])]),
            from_worker(&[(DONE, &["a", "b"])]),
        ] {
            assert!(broken(talk(said, &policy).0).contains("unexpected frame"));
        }
        // A field that is not UTF-8.
        let mut bytes = from_worker(&[]);
        write_frame(&mut bytes, DONE, &[[0xffu8]]).unwrap();
        assert!(broken(talk(bytes, &policy).0).contains("UTF-8"));
    }

    // Refused with only the header sent, so the script never reaches the worker; allowed, the
    // conversation goes on as with a confined one.
    #[test]
    fn an_unconfined_worker_gets_the_script_only_when_allowed() {
        let policy = PacPolicy::new();
        let said = from_unconfined(&[(SANDBOX, &["no sandbox here"]), (DONE, &["DIRECT"])]);

        let (result, sent) = talk(said.clone(), &policy);
        match result {
            Err(Error::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
                assert!(source.to_string().contains("no sandbox here"), "{source}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let mut header = Vec::new();
        write_header(&mut header).unwrap();
        assert_eq!(sent, header);

        let (result, sent) = talk_allowing(said, &policy, true);
        assert_eq!(result.unwrap(), "DIRECT");
        let mut sent = Cursor::new(sent);
        read_header(&mut sent).unwrap();
        assert_eq!(read_frame(&mut sent, usize::MAX).unwrap().0, EVALUATE);
    }

    // Each case runs in a child forked after the filter is built: it installs the filter,
    // makes one call through `syscall`, and exits. Only raw calls happen between `fork` and
    // `_exit`.
    #[cfg(all(
        pac_quickjs,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn the_seccomp_filter_kills_every_call_it_does_not_allow() {
        let program = seccomp::filter();
        let status_after = |call: &dyn Fn()| {
            // SAFETY: the child makes raw system calls only and leaves through `_exit`.
            unsafe {
                let pid = libc::fork();
                assert!(pid >= 0, "{}", io::Error::last_os_error());
                if pid == 0 {
                    if seccomp::install(&program).is_err() {
                        libc::_exit(2);
                    }
                    call();
                    libc::_exit(0);
                }
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                status
            }
        };
        let survives =
            |status: libc::c_int| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        let killed = |status: libc::c_int| {
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS
        };
        let null = std::ptr::null_mut::<libc::c_void>();

        // SAFETY (each closure): the calls take plain integers or null, with zero lengths.
        let allowed: [&dyn Fn(); 4] = [
            &|| {},
            &|| unsafe {
                libc::syscall(libc::SYS_read, 0, null, 0);
            },
            &|| unsafe {
                libc::syscall(libc::SYS_write, 2, null, 0);
            },
            &|| unsafe {
                libc::syscall(
                    libc::SYS_mmap,
                    null,
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
            },
        ];
        for (index, call) in allowed.into_iter().enumerate() {
            let status = status_after(call);
            assert!(survives(status), "allowed call {index}: status {status:#x}");
        }

        let refused: [&dyn Fn(); 5] = [
            &|| unsafe {
                libc::syscall(libc::SYS_getpid);
            },
            &|| unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/".as_ptr(),
                    libc::O_RDONLY,
                );
            },
            &|| unsafe {
                libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
            },
            // A descriptor other than the pipes to the parent.
            &|| unsafe {
                libc::syscall(libc::SYS_write, 3, null, 0);
            },
            &|| unsafe {
                libc::syscall(
                    libc::SYS_mmap,
                    null,
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    0,
                    0,
                );
            },
        ];
        for (index, call) in refused.into_iter().enumerate() {
            let status = status_after(call);
            assert!(killed(status), "refused call {index}: status {status:#x}");
        }
    }

    #[test]
    fn a_pinned_clock_before_the_epoch_is_sent_signed() {
        let policy = PacPolicy::new().with_now(UNIX_EPOCH - Duration::from_millis(1500));
        let request = evaluate_request("", "", "", &policy);
        assert_eq!(request[5], b"-1500000000");
    }
}
