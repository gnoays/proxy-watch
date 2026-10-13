//! The wall-clock budget and the process-wide evaluation-thread limit that in-process evaluation and
//! `pac-subprocess` workers share.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Condvar, LazyLock, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::resolve::ProxyStep;

// Run `job` on an evaluation thread of `slots` and give up on it after `timeout`. `job` is
// handed the deadline (`None` for a budget no `Instant` can reach) so an engine that can
// interrupt a script stops it there; one that cannot ignores it.
//
// The thread is one left idle by an earlier evaluation where there is one, else a new one.
// Reusing it is most of the saving: QuickJS sets up a runtime on a thread just made in about
// twice the time it takes on one that has run before, on top of the spawn. Each evaluation
// still builds its own runtime, so nothing of one script reaches the next.
//
// A zero `timeout` means "no budget at all" here, not "unlimited", and is answered before
// the thread exists. Letting it through would spawn the script and then `recv_timeout`
// would return at once, leaving untrusted code running on a thread nothing is waiting on: a
// budget of nothing has to buy nothing, not an unsupervised run.
// [`super::winhttp::WinHttpPacResolver`] refuses zero too, for a reason of its own
// (`WinHttpSetTimeouts` reads it as infinite), and one step earlier: at construction rather
// than per evaluation.
//
// Giving up on the answer does not stop the thread. Each engine says in its own `evaluate`
// what ends a script left running; whatever it is, the thread count is bounded here: every
// evaluation holds one of `slots` from before it is handed to a thread until its script
// ends, and a call that finds them all taken waits out of the same `timeout` for one to come
// free. Counting only the threads already abandoned would not bound anything: a burst of
// calls all start, then all time out together. An abandoned thread returns to the idle ones
// only when its script ends. A new thread is made only when no thread of `slots` is idle, so
// the evaluation threads, idle ones included, stay within `limit` less the slots the
// `pac-subprocess` conversations hold when one is made; conversations that start later can
// take the slots the idle threads left, so the two together reach at most twice `limit`
// until the idle threads linger out. A thread that has just left the list to end is not
// counted for the moment it takes to end.
// `pac-subprocess` alone uses the slots and not this: it kills its worker instead.
#[cfg_attr(not(pac_quickjs), allow(dead_code))]
pub(super) fn run_with_timeout<F>(
    timeout: Duration,
    slots: &'static Slots,
    job: F,
) -> Result<Vec<ProxyStep>, Error>
where
    F: FnOnce(Option<Instant>) -> Result<Vec<ProxyStep>, Error> + Send + 'static,
{
    if timeout.is_zero() {
        return Err(Error::PacTimeout { timeout });
    }

    let deadline = Instant::now().checked_add(timeout);
    let slot = slots.acquire(deadline).ok_or(Error::PacSaturated {
        timeout,
        limit: slots.limit,
    })?;

    let (sender, receiver) = mpsc::sync_channel(1);
    slots.dispatch(Job {
        run: Box::new(move || job(deadline)),
        reply: sender,
        slot,
    })?;

    let left = deadline.map_or(timeout, |deadline| {
        deadline.saturating_duration_since(Instant::now())
    });
    match receiver.recv_timeout(left) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(Error::PacTimeout { timeout }),
        Err(RecvTimeoutError::Disconnected) => Err(Error::pac_evaluation(
            "the PAC evaluation thread ended without producing a result",
        )),
    }
}

// Process-wide rather than per evaluator: `pac::evaluate_with_host` builds a fresh evaluator
// for every call, so a per-evaluator count would never exceed one. Shared by the
// QuickJS evaluation threads and the `pac-subprocess` conversation threads, so the limit is
// on evaluations running in the process, whichever evaluator each one serves. Idle QuickJS
// threads run nothing and hold no slot. The
// floor of 4 keeps one never-ending script from taking the only slot on a single-core
// machine. The limit is fixed: a caller whose legitimate scripts sit in slow DNS long enough
// to fill it would need it on `PacPolicy`, and none has asked.
pub(super) static SLOTS: LazyLock<Slots> = LazyLock::new(|| {
    Slots::new(thread::available_parallelism().map_or(4, |cores| cores.get().max(4)))
});

pub(super) struct Slots {
    limit: usize,
    taken: Mutex<usize>,
    freed: Condvar,
    // The evaluation threads waiting for work.
    idle: Mutex<Vec<Idle>>,
    // How long an idle evaluation thread waits for work before it ends.
    linger: Duration,
}

// How long an idle evaluation thread stays. Long enough to carry a client that routes a
// request every few seconds; short enough that a process that stops routing gets its
// threads back.
const LINGER: Duration = Duration::from_secs(30);

// Evaluation thread ids, for an idle thread to find itself in `Slots::idle`.
static NEXT_THREAD: AtomicU64 = AtomicU64::new(0);

// An idle evaluation thread: its id, the process it runs in, and the way to hand it a job.
// A child of `fork` inherits the list but none of the threads, so an entry of another process
// is dropped rather than handed a job no thread would run, which would time out and keep
// its slot.
struct Idle {
    id: u64,
    process: u32,
    sender: SyncSender<Job>,
}

// One evaluation for a thread to run, and the slot it holds until it ends.
pub(super) struct Job {
    run: Box<dyn FnOnce() -> Result<Vec<ProxyStep>, Error> + Send>,
    reply: SyncSender<Result<Vec<ProxyStep>, Error>>,
    slot: Slot,
}

impl Slots {
    pub(super) const fn new(limit: usize) -> Self {
        Self::lingering(limit, LINGER)
    }

    const fn lingering(limit: usize, linger: Duration) -> Self {
        Self {
            limit,
            taken: Mutex::new(0),
            freed: Condvar::new(),
            idle: Mutex::new(Vec::new()),
            linger,
        }
    }

    // Hand `job` to an idle evaluation thread, or to a new one when none is idle.
    fn dispatch(&'static self, mut job: Job) -> Result<(), Error> {
        loop {
            let idle = self
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            let Some(idle) = idle else { break };
            if idle.process != std::process::id() {
                continue;
            }
            // An idle thread is waiting on its receiver, and its channel is empty; a send
            // that fails all the same leaves the job for the next thread.
            match idle.sender.send(job) {
                Ok(()) => return Ok(()),
                Err(mpsc::SendError(back)) => job = back,
            }
        }
        let id = NEXT_THREAD.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::sync_channel(1);
        // Room for one, and the receiver is this function's until the thread takes it.
        let _ = sender.send(job);
        // A failed spawn drops the closure, and with it the job and its slot.
        thread::Builder::new()
            .name("proxy-watch-pac".to_owned())
            .spawn(move || self.work(id, &sender, &receiver))
            .map(drop)
            .map_err(|source| Error::io("spawning the PAC evaluation thread", source))
    }

    // An evaluation thread: run each job handed to it, then wait `linger` for the next.
    // It joins the idle ones before it frees the job's slot, so a call that takes that
    // slot finds this thread instead of making another, and before it answers. A job that
    // panics ends the thread, which is not among the idle ones while it runs; its caller
    // reads the dropped reply as a thread that ended without a result.
    fn work(&'static self, id: u64, sender: &SyncSender<Job>, receiver: &Receiver<Job>) {
        let mut next = receiver.recv().ok();
        while let Some(Job { run, reply, slot }) = next {
            let result = run();
            self.idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Idle {
                    id,
                    process: std::process::id(),
                    sender: sender.clone(),
                });
            drop(slot);
            // Last, so the caller's next evaluation finds this thread idle. The receiver may
            // already be gone; the send failing is the normal outcome of a timeout and is
            // not an error here.
            let _ = reply.send(result);
            next = match receiver.recv_timeout(self.linger) {
                Ok(job) => Some(job),
                Err(_) => {
                    let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
                    match idle.iter().position(|idle| idle.id == id) {
                        Some(at) => {
                            idle.swap_remove(at);
                            None
                        }
                        // A call took this thread off the list as it lingered out, and its
                        // job is on the way.
                        None => {
                            drop(idle);
                            receiver.recv().ok()
                        }
                    }
                }
            };
        }
    }

    #[cfg(feature = "pac-subprocess")]
    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    // A slot, or `None` once `deadline` passes with every slot still taken.
    pub(super) fn acquire(&'static self, deadline: Option<Instant>) -> Option<Slot> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        while *taken >= self.limit {
            taken = match deadline {
                None => self
                    .freed
                    .wait(taken)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    self.freed
                        .wait_timeout(taken, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
        *taken += 1;
        Some(Slot(self))
    }
}

// Released on drop, which covers a script that returns, one that throws, a panic that
// unwinds the evaluation thread, and a spawn that fails and drops the closure holding it.
pub(super) struct Slot(&'static Slots);

impl Drop for Slot {
    fn drop(&mut self) {
        *self.0.taken.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
        self.0.freed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A thread keeps its slot past the timeout that abandons it, so the second call finds
    // the only slot taken and gets `PacSaturated` without spawning; the third, given room to
    // wait, runs once the first job ends. `ONE` is this test's own, so the evaluations other
    // tests leave running do not count against it.
    #[test]
    fn a_call_waits_for_a_slot_and_gives_up_when_none_comes_free() {
        static ONE: Slots = Slots::new(1);
        let slow = |_| {
            thread::sleep(Duration::from_millis(300));
            Ok(vec![ProxyStep::Direct])
        };
        let quick = |_| Ok(vec![ProxyStep::Direct]);

        let first = run_with_timeout(Duration::from_millis(10), &ONE, slow).unwrap_err();
        assert!(matches!(first, Error::PacTimeout { .. }), "{first:?}");
        let second = run_with_timeout(Duration::from_millis(10), &ONE, quick).unwrap_err();
        assert!(
            matches!(second, Error::PacSaturated { limit: 1, .. }),
            "{second:?}"
        );
        assert_eq!(
            run_with_timeout(Duration::from_secs(120), &ONE, quick).unwrap(),
            vec![ProxyStep::Direct]
        );
    }

    // The thread each evaluation of `slots` ran on.
    fn thread_of(slots: &'static Slots) -> thread::ThreadId {
        let (sender, receiver) = mpsc::channel();
        run_with_timeout(Duration::from_secs(120), slots, move |_| {
            sender.send(thread::current().id()).unwrap();
            Ok(vec![ProxyStep::Direct])
        })
        .unwrap();
        receiver.recv().unwrap()
    }

    #[test]
    fn an_evaluation_runs_on_the_thread_the_one_before_it_left_idle() {
        static FOUR: Slots = Slots::new(4);
        let first = thread_of(&FOUR);
        assert_ne!(first, thread::current().id());
        // Many in a row: a thread that answered before it went idle would lose a race to
        // the next call now and then, not every time.
        for _ in 0..200 {
            assert_eq!(thread_of(&FOUR), first);
        }
    }

    #[test]
    fn an_idle_thread_ends_after_lingering() {
        static BRIEF: Slots = Slots::lingering(4, Duration::from_millis(50));
        let first = thread_of(&BRIEF);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !BRIEF.idle.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the idle thread is still listed");
            thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(thread_of(&BRIEF), first);
    }

    // An idle entry left by the parent of a `fork` names a thread the child does not have.
    // Here the entry is made by hand with another process's id and a receiver no thread
    // reads; handed the job, the evaluation would time out.
    #[test]
    fn an_idle_thread_of_another_process_is_not_handed_work() {
        static ONE: Slots = Slots::new(1);
        let (sender, _unread) = mpsc::sync_channel(1);
        ONE.idle.lock().unwrap().push(Idle {
            id: u64::MAX,
            process: std::process::id().wrapping_add(1),
            sender,
        });
        let quick = |_| Ok(vec![ProxyStep::Direct]);
        assert_eq!(
            run_with_timeout(Duration::from_secs(5), &ONE, quick).unwrap(),
            vec![ProxyStep::Direct]
        );
    }

    // A thread joins the idle ones before it frees its slot. The other way round, a call
    // can take the freed slot, find no thread idle and make one past the limit.
    #[test]
    fn concurrent_evaluations_never_use_more_threads_than_slots() {
        static TWO: Slots = Slots::new(2);
        let seen = std::sync::Arc::new(Mutex::new(std::collections::HashSet::new()));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let seen = seen.clone();
                thread::spawn(move || {
                    for _ in 0..200 {
                        let id = thread_of(&TWO);
                        seen.lock().unwrap().insert(id);
                    }
                })
            })
            .collect();
        for caller in callers {
            caller.join().unwrap();
        }
        let threads = seen.lock().unwrap().len();
        assert!(threads <= 2, "{threads} evaluation threads for 2 slots");
    }
}
