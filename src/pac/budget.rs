//! The wall-clock budget and the process-wide evaluation-thread limit that in-process evaluation and
//! `pac-subprocess` workers share.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Condvar, LazyLock, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::resolve::ProxyStep;

// Run `job` on a throw-away thread and give up on it after `timeout`. `job` is handed the
// deadline (`None` for a budget no `Instant` can reach) so an engine that can interrupt a
// script stops it there; one that cannot ignores it.
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
// evaluation thread holds one of `slots` from before it is spawned until its script ends,
// and a call that finds them all taken waits out of the same `timeout` for one to come free.
// Counting only the threads already abandoned would not bound anything: a burst of calls
// all start, then all time out together.
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
    thread::Builder::new()
        .name("proxy-watch-pac".to_owned())
        .spawn(move || {
            let _slot = slot;
            // The receiver may already be gone; the send failing is the normal outcome
            // of a timeout and is not an error here.
            let _ = sender.send(job(deadline));
        })
        .map_err(|source| Error::io("spawning the PAC evaluation thread", source))?;

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
// on threads in the process, whichever evaluator each one serves. The
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
}

impl Slots {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            limit,
            taken: Mutex::new(0),
            freed: Condvar::new(),
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
}
