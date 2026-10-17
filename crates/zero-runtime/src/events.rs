//! Live events, for a host that shows what the server is doing as it happens
//! (a panel's live log).
//!
//! How this works. Events go out on a broadcast channel; a host subscribes
//! ([`Events::subscribe`], or `GET /events` on the management API, which
//! streams them as server-sent events). With nobody subscribed an event is
//! never even built, so a server nobody watches pays one atomic load per
//! event site. A subscriber that falls more than [`CAPACITY`] events behind
//! loses the oldest and is told how many it missed; the server never waits
//! for a slow reader.
//!
//! The rules it keeps: an event carries what the per-account figures already
//! expose and nothing more. A client address appears only when address
//! tracking is on ([`crate::accounts::Accounts::set_track_addresses`]), and
//! no event names a destination.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

/// How many events a subscriber may fall behind before it loses the oldest.
pub const CAPACITY: usize = 1024;

/// What happened.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// An account opened a session on an inbound.
    SessionOpened {
        email: String,
        inbound: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<IpAddr>,
    },
    /// An account's session closed. `ended` is true when the server ended it
    /// (the account was removed, changed or told to end).
    SessionClosed {
        email: String,
        inbound: String,
        uplink: u64,
        downlink: u64,
        seconds: f64,
        ended: bool,
    },
    /// A connection to an inbound failed before or while it was served: an
    /// unknown credential, a malformed request, a broken transport.
    SessionFailed { inbound: String, error: String },
    /// Accounts were added to (or replaced on) an inbound at run time.
    AccountsAdded {
        inbound: String,
        emails: Vec<String>,
    },
    /// Accounts were removed from an inbound at run time.
    AccountsRemoved {
        inbound: String,
        emails: Vec<String>,
    },
    /// An account's sessions were ended on request.
    SessionsEnded { email: String, sessions: usize },
    /// An account's speed limit changed, in bytes per second (0 = none).
    LimitChanged {
        email: String,
        uplink: u64,
        downlink: u64,
    },
    /// A whole new configuration was installed.
    Reloaded { generation: u64, ended: usize },
    /// Inbounds were added, removed or replaced without a restart.
    InboundsChanged {
        added: Vec<String>,
        removed: Vec<String>,
    },
}

/// An event and when it happened.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Record {
    /// Milliseconds since the Unix epoch.
    pub at: u64,
    #[serde(flatten)]
    pub event: Event,
}

/// The channel events go out on. One per server, in [`crate::server::Stats`].
pub struct Events {
    sender: broadcast::Sender<Record>,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            sender: broadcast::channel(CAPACITY).0,
        }
    }
}

impl std::fmt::Debug for Events {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Events")
            .field("subscribers", &self.sender.receiver_count())
            .finish()
    }
}

impl Events {
    /// Receive every event from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Record> {
        self.sender.subscribe()
    }

    /// Whether anyone is listening; event sites check this before doing any
    /// work to describe what happened.
    pub fn watched(&self) -> bool {
        self.sender.receiver_count() > 0
    }

    /// Send the event `make` builds, if anyone is listening.
    pub fn emit(&self, make: impl FnOnce() -> Event) {
        if !self.watched() {
            return;
        }
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let _ = self.sender.send(Record { at, event: make() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_built_without_a_subscriber() {
        let events = Events::default();
        events.emit(|| panic!("built an event nobody receives"));
    }

    #[tokio::test]
    async fn subscribers_receive_events_as_json() {
        let events = Events::default();
        let mut receiver = events.subscribe();
        events.emit(|| Event::SessionsEnded {
            email: "a@p".into(),
            sessions: 2,
        });
        let record = receiver.recv().await.unwrap();
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["event"], "sessions_ended");
        assert_eq!(json["email"], "a@p");
        assert_eq!(json["sessions"], 2);
        assert!(json["at"].as_u64().unwrap() > 0);
    }
}
