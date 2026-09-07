//! Tokio bridge: single-consumer [`ProxyWatcher`] → multi-consumer [`tokio::sync::watch`].
//! Behind the off-by-default `tokio` feature.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

use futures_core::Stream;
use tokio::sync::watch;

use crate::config::ProxyConfig;
use crate::watch::{ProxyWatcher, WatchEvent};

/// Drive `watcher` into a [`tokio::sync::watch`] channel (clone [`watch::Receiver`] for fan-out).
///
/// Starts at [`ProxyWatcher::current`]. Errors dropped; identical snapshots not republished;
/// last receiver drop ends the task. Panics outside a tokio runtime.
///
/// **Configuration only.** [`WatchEvent`] also carries [`WatchHealth`](crate::WatchHealth),
/// and this channel
/// drops it: a route that dies without changing the configuration publishes nothing here.
/// Read liveness from [`ProxyWatcher::state`], or poll the [`Stream`] directly, and use
/// this for fanning the configuration out to many tasks.
///
/// ```no_run
/// # async fn example() -> Result<(), proxy_watch::Error> {
/// let mut rx = proxy_watch::watch_channel(proxy_watch::ProxyWatcher::new()?);
/// let mirror = rx.clone();
/// tokio::spawn(async move {
///     println!("another task sees {:?}", mirror.borrow().effective);
/// });
///
/// while rx.changed().await.is_ok() {
///     println!("changed to {:?}", rx.borrow_and_update().effective);
/// }
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn watch_channel(watcher: ProxyWatcher) -> watch::Receiver<ProxyConfig> {
    bridge(watcher.current(), watcher)
}

// Generic over the stream so tests need no platform backend.
fn bridge<S>(initial: ProxyConfig, stream: S) -> watch::Receiver<ProxyConfig>
where
    S: Stream<Item = WatchEvent> + Unpin + Send + 'static,
{
    let (sender, receiver) = watch::channel(initial);
    let mut stream = stream;
    tokio::spawn(async move {
        // End as soon as the last receiver drops (do not wait for a change that may never come).
        let mut closed = pin!(sender.closed());
        loop {
            let next = poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                Pin::new(&mut stream).poll_next(cx)
            })
            .await;
            let Some(item) = next else {
                break;
            };
            // A health-only snapshot repeats the configuration it already published, so
            // the equality filter below drops it without a special case.
            if let WatchEvent::Snapshot { state } = item {
                let config = state.config;
                sender.send_if_modified(|current| {
                    if *current == config {
                        return false;
                    }
                    *current = config;
                    true
                });
            }
        }
    });
    receiver
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Context;

    use super::*;

    use crate::config::ProxyConfigSource;
    use crate::error::Error;
    use crate::mode::ProxyMode;
    use crate::watch::{WatchHealth, WatchState};

    // The health half the bridge is contracted to ignore, as a baseline the events below
    // share — except the last, which departs from it deliberately. That one is the event
    // that shows anything reaching a receiver got there through the config: it moves the
    // health and nothing else, and no receiver wakes.
    fn live() -> WatchHealth {
        WatchHealth {
            degraded: Vec::new(),
            has_live_notifications: true,
            poll_interval: None,
            stopped: false,
        }
    }

    fn snapshot(config: ProxyConfig) -> WatchEvent {
        WatchEvent::Snapshot {
            state: WatchState {
                config,
                health: live(),
            },
        }
    }

    // The configuration an error carries is a real snapshot, and one the bridge is
    // contracted to drop along with the error. It differs from every other configuration
    // here so that dropping it is something a receiver can tell from not dropping it.
    fn failure(error: Error) -> WatchEvent {
        WatchEvent::Error {
            error,
            state: WatchState {
                config: ProxyConfig::from_source(ProxyConfigSource::Env, ProxyMode::Direct),
                health: live(),
            },
        }
    }

    // A stream the test feeds one event at a time. The bridge consumes everything already
    // waiting in a single poll, so a stream handing out a canned list cannot show what any
    // one event did — the receiver first looks after the last of them has been folded in.
    struct Fed(tokio::sync::mpsc::UnboundedReceiver<WatchEvent>);

    impl Stream for Fed {
        type Item = WatchEvent;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.0.poll_recv(cx)
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    }

    #[test]
    fn changes_reach_every_receiver_and_noise_is_filtered() {
        let initial = ProxyConfig::direct();
        let changed =
            ProxyConfig::from_source(ProxyConfigSource::Registry, ProxyMode::WpadAutoDetect);

        runtime().block_on(async {
            let (events, stream) = tokio::sync::mpsc::unbounded_channel();
            let mut receiver = bridge(initial.clone(), Fed(stream));
            let clone = receiver.clone();

            // The initial value is available before the task has even run.
            assert_eq!(*receiver.borrow(), initial);

            // The watcher re-emits the current value at subscription time.
            events.send(snapshot(initial.clone())).unwrap();
            events.send(snapshot(changed.clone())).unwrap();

            receiver.changed().await.expect("a change is published");
            assert_eq!(*receiver.borrow_and_update(), changed);
            // Every clone sees it too.
            assert_eq!(*clone.borrow(), changed);

            // What the bridge must publish nothing for, sent once the receiver has caught
            // up with everything before it — anything sent earlier is folded into the
            // change above by the channel and shows nothing.
            //
            // A transient failure must not disturb the channel, and a route that died
            // without the configuration moving must not either: this bridge carries the
            // configuration alone.
            events.send(failure(Error::Unsupported)).unwrap();
            events
                .send(WatchEvent::Snapshot {
                    state: WatchState {
                        config: changed.clone(),
                        health: WatchHealth {
                            degraded: vec![ProxyConfigSource::GroupPolicy],
                            ..live()
                        },
                    },
                })
                .unwrap();
            tokio::task::yield_now().await;
            assert!(
                !receiver
                    .has_changed()
                    .expect("the stream is still open, so the channel is too"),
                "neither an error nor a health-only snapshot may publish a configuration"
            );

            // Nothing left to read from ends the task, and with it the sender.
            drop(events);
            assert!(receiver.changed().await.is_err());
        });
    }

    // A watcher that never reports anything, and says when it is dropped.
    struct Idle(Arc<AtomicBool>);

    impl Stream for Idle {
        type Item = WatchEvent;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for Idle {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    // The watcher owns an OS thread and a change notification, so the bridge must let
    // go of it as soon as nobody is listening — without waiting for a configuration
    // change that may never come.
    #[test]
    fn dropping_the_last_receiver_releases_the_watcher() {
        let dropped = Arc::new(AtomicBool::new(false));

        runtime().block_on(async {
            let receiver = bridge(ProxyConfig::direct(), Idle(Arc::clone(&dropped)));
            drop(receiver);
            // Let the task run; it has no snapshot to wait for.
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            assert!(
                dropped.load(Ordering::SeqCst),
                "the bridge task must end once the last receiver is gone"
            );
        });
    }
}
