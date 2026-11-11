// SPDX-License-Identifier: MIT

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::NetlinkProtoError;

/// State shared between a [`Connection`](crate::Connection) and its
/// [`ConnectionHandle`](crate::ConnectionHandle).
///
/// The `Connection` records why it stopped, so that handles can observe the
/// terminal error through
/// [`ConnectionHandle::closed`](crate::ConnectionHandle::closed).
#[derive(Debug)]
pub(crate) struct Shared {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    terminal: Terminal,
    wakers: Vec<Waker>,
}

#[derive(Debug)]
enum Terminal {
    Running,
    Closed {
        error: Option<Arc<NetlinkProtoError>>,
    },
}

impl Shared {
    pub(crate) fn new() -> Self {
        Shared {
            state: Mutex::new(State {
                terminal: Terminal::Running,
                wakers: Vec::new(),
            }),
        }
    }

    /// Record that the connection terminated, waking every observer.
    ///
    /// Only the first call has an effect; subsequent calls (for instance from
    /// `Connection::drop`) are ignored.
    pub(crate) fn set_closed(&self, error: Option<NetlinkProtoError>) {
        let mut state = self.lock();
        if !matches!(&state.terminal, Terminal::Running) {
            return;
        }
        state.terminal = Terminal::Closed {
            error: error.map(Arc::new),
        };
        for waker in state.wakers.drain(..) {
            waker.wake();
        }
    }

    fn poll_closed(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Arc<NetlinkProtoError>>> {
        let mut state = self.lock();
        match &state.terminal {
            Terminal::Running => {
                if !state.wakers.iter().any(|waker| waker.will_wake(cx.waker()))
                {
                    state.wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
            Terminal::Closed { error } => Poll::Ready(error.clone()),
        }
    }

    /// The error that made the connection stop, if one is known.
    pub(crate) fn terminal_error(&self) -> Option<NetlinkProtoError> {
        let state = self.lock();
        match &state.terminal {
            Terminal::Closed { error: Some(error) } => Some(error.duplicate()),
            _ => None,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Future completed once the connection has terminated.
///
/// It resolves to the terminal error, or `None` if the connection shut down
/// cleanly (or was dropped without completing).
pub(crate) struct Closed {
    shared: Arc<Shared>,
}

impl Closed {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Closed { shared }
    }
}

impl Future for Closed {
    type Output = Option<Arc<NetlinkProtoError>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.shared.poll_closed(cx)
    }
}
