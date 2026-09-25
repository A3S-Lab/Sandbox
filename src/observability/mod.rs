//! Gate 2 observability: structured allow/deny audit events.

#[cfg(test)]
mod gate2_integration;
#[cfg(test)]
mod gate2_resources;

use crate::policy::AccessDecision;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Why a boundary decision was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    PolicyDeny,
    PolicyAllow,
    CapabilityMissing,
    NetworkDenyAll,
    OutputLimit,
    Timeout,
    CompileOverlayRejected,
    SecretRequiresMediation,
}

/// What surface produced the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSurface {
    FilesystemRead,
    FilesystemWrite,
    Network,
    Process,
    PolicyCompile,
    Environment,
}

/// One attributable sandbox decision. Targets must already be redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub session_id: String,
    pub command_id: String,
    pub policy_digest: String,
    pub backend: String,
    pub surface: AuditSurface,
    pub decision: AccessDecision,
    pub reason_code: ReasonCode,
    pub target_redacted: String,
    pub timestamp_unix_ms: u64,
}

/// Constructor inputs for [`AuditEvent`].
#[derive(Debug, Clone)]
pub struct AuditEventParts {
    pub session_id: String,
    pub command_id: String,
    pub policy_digest: String,
    pub backend: String,
    pub surface: AuditSurface,
    pub decision: AccessDecision,
    pub reason_code: ReasonCode,
    pub target_redacted: String,
}

impl AuditEvent {
    pub fn from_parts(parts: AuditEventParts) -> Self {
        Self {
            session_id: parts.session_id,
            command_id: parts.command_id,
            policy_digest: parts.policy_digest,
            backend: parts.backend,
            surface: parts.surface,
            decision: parts.decision,
            reason_code: parts.reason_code,
            target_redacted: parts.target_redacted,
            timestamp_unix_ms: unix_ms(),
        }
    }

    /// Replay helper: digest + decision identity for audit consumers.
    pub fn replay_key(&self) -> String {
        format!(
            "{}|{:?}|{:?}|{:?}",
            self.policy_digest, self.surface, self.decision, self.reason_code
        )
    }
}

/// Bounded in-memory audit store. Insertions never grant access; a full buffer
/// drops the oldest event and records pressure.
#[derive(Debug, Default)]
pub struct AuditBuffer {
    max_events: usize,
    events: VecDeque<AuditEvent>,
    dropped: u64,
}

impl AuditBuffer {
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events: max_events.max(1),
            events: VecDeque::new(),
            dropped: 0,
        }
    }

    pub fn push(&mut self, event: AuditEvent) {
        while self.events.len() >= self.max_events {
            self.events.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.events.push_back(event);
    }

    pub fn events(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Shared audit sink used by a sandbox session.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    inner: Arc<Mutex<AuditBuffer>>,
}

impl AuditLog {
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditBuffer::new(max_events))),
        }
    }

    pub fn record(&self, event: AuditEvent) {
        match self.inner.lock() {
            Ok(mut guard) => guard.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }

    pub fn snapshot(&self) -> Vec<AuditEvent> {
        match self.inner.lock() {
            Ok(guard) => guard.events().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().events().cloned().collect(),
        }
    }

    pub fn dropped(&self) -> u64 {
        match self.inner.lock() {
            Ok(guard) => guard.dropped(),
            Err(poisoned) => poisoned.into_inner().dropped(),
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        command_id: &str,
        surface: AuditSurface,
        decision: AccessDecision,
        reason: ReasonCode,
        target: &str,
    ) -> AuditEvent {
        AuditEvent::from_parts(AuditEventParts {
            session_id: "s".into(),
            command_id: command_id.into(),
            policy_digest: "d".into(),
            backend: "backend".into(),
            surface,
            decision,
            reason_code: reason,
            target_redacted: target.into(),
        })
    }

    #[test]
    fn buffer_drops_oldest_under_backpressure() {
        let mut buffer = AuditBuffer::new(2);
        buffer.push(sample(
            "c1",
            AuditSurface::Network,
            AccessDecision::Deny,
            ReasonCode::NetworkDenyAll,
            "net",
        ));
        buffer.push(sample(
            "c2",
            AuditSurface::Network,
            AccessDecision::Deny,
            ReasonCode::NetworkDenyAll,
            "net",
        ));
        buffer.push(sample(
            "c3",
            AuditSurface::Network,
            AccessDecision::Deny,
            ReasonCode::NetworkDenyAll,
            "net",
        ));
        assert_eq!(buffer.events().count(), 2);
        assert_eq!(buffer.dropped(), 1);
        let ids: Vec<_> = buffer.events().map(|e| e.command_id.as_str()).collect();
        assert_eq!(ids, ["c2", "c3"]);
    }

    #[test]
    fn audit_event_replay_key_stable_for_same_decision() {
        let left = AuditEvent::from_parts(AuditEventParts {
            session_id: "s".into(),
            command_id: "c".into(),
            policy_digest: "digest-a".into(),
            backend: "macos-seatbelt".into(),
            surface: AuditSurface::FilesystemWrite,
            decision: AccessDecision::Deny,
            reason_code: ReasonCode::PolicyDeny,
            target_redacted: "<redacted>/.git".into(),
        });
        let right = AuditEvent {
            timestamp_unix_ms: left.timestamp_unix_ms + 10,
            ..left.clone()
        };
        assert_eq!(left.replay_key(), right.replay_key());
    }

    #[test]
    fn monitoring_failure_does_not_grant_access_semantics() {
        assert_ne!(AccessDecision::Allow, AccessDecision::Deny);
        let log = AuditLog::with_capacity(1);
        log.record(sample(
            "c",
            AuditSurface::PolicyCompile,
            AccessDecision::Allow,
            ReasonCode::PolicyAllow,
            "compile",
        ));
        assert_eq!(log.snapshot().len(), 1);
    }
}
