//! Bounded fresh process identity and name evidence for termination gates.

use crate::observation::{
    PROTECTION_NAME_MAX_BYTES, PROTECTION_SCOPE_MAX_BYTES, PROTECTION_SCOPE_MAX_MEMBERS,
    ProcessStartMarker,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedProcessEvidence<'a> {
    pub(crate) pid: u32,
    pub(crate) start_marker: ProcessStartMarker,
    pub(crate) name: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreshProcessEvidence {
    pub(crate) pid: u32,
    pub(crate) start_marker: ProcessStartMarker,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessEvidenceError {
    PermissionDenied { pid: u32 },
    Missing { pid: u32 },
    NameMissing { pid: u32 },
    NameOversized { pid: u32, bytes: usize },
    IdentityChanged { pid: u32 },
    NameChanged { pid: u32 },
    IncompleteScope { expected: usize, observed: usize },
    MemberLimitExceeded { limit: usize },
    ByteLimitExceeded { limit: usize },
}

pub(crate) struct ProcessEvidenceScope {
    expected_members: usize,
    observed_members: usize,
    retained_name_bytes: usize,
    max_bytes: usize,
}

impl ProcessEvidenceScope {
    pub(crate) fn new(expected_members: usize) -> Result<Self, ProcessEvidenceError> {
        Self::with_limits(
            expected_members,
            PROTECTION_SCOPE_MAX_MEMBERS,
            PROTECTION_SCOPE_MAX_BYTES,
        )
    }

    fn with_limits(
        expected_members: usize,
        max_members: usize,
        max_bytes: usize,
    ) -> Result<Self, ProcessEvidenceError> {
        if expected_members > max_members {
            return Err(ProcessEvidenceError::MemberLimitExceeded { limit: max_members });
        }
        Ok(Self {
            expected_members,
            observed_members: 0,
            retained_name_bytes: 0,
            max_bytes,
        })
    }

    pub(crate) fn observe(
        &mut self,
        expected: &ExpectedProcessEvidence<'_>,
        fresh: Result<FreshProcessEvidence, ProcessEvidenceError>,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        if self.observed_members >= self.expected_members {
            return Err(ProcessEvidenceError::MemberLimitExceeded {
                limit: self.expected_members,
            });
        }
        let fresh = fresh?;
        if fresh.pid != expected.pid || fresh.start_marker != expected.start_marker {
            return Err(ProcessEvidenceError::IdentityChanged { pid: expected.pid });
        }
        if fresh.name.is_empty() {
            return Err(ProcessEvidenceError::NameMissing { pid: expected.pid });
        }
        let name_bytes = fresh.name.len();
        if name_bytes > PROTECTION_NAME_MAX_BYTES {
            return Err(ProcessEvidenceError::NameOversized {
                pid: expected.pid,
                bytes: name_bytes,
            });
        }
        if expected.name.is_some_and(|name| name != fresh.name) {
            return Err(ProcessEvidenceError::NameChanged { pid: expected.pid });
        }
        self.retained_name_bytes = self
            .retained_name_bytes
            .checked_add(name_bytes)
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or(ProcessEvidenceError::ByteLimitExceeded {
                limit: self.max_bytes,
            })?;
        self.observed_members += 1;
        Ok(fresh)
    }

    pub(crate) fn finish(self) -> Result<(), ProcessEvidenceError> {
        if self.observed_members != self.expected_members {
            return Err(ProcessEvidenceError::IncompleteScope {
                expected: self.expected_members,
                observed: self.observed_members,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(pid: u32, name: Option<&str>) -> ExpectedProcessEvidence<'_> {
        ExpectedProcessEvidence {
            pid,
            start_marker: ProcessStartMarker::linux(u64::from(pid) + 10).expect("nonzero marker"),
            name,
        }
    }

    fn fresh(pid: u32, name: String) -> FreshProcessEvidence {
        FreshProcessEvidence {
            pid,
            start_marker: ProcessStartMarker::linux(u64::from(pid) + 10).expect("nonzero marker"),
            name,
        }
    }

    #[test]
    fn typed_missing_and_permission_denial_remain_distinct() {
        let mut missing_scope = ProcessEvidenceScope::new(1).expect("scope");
        let missing = missing_scope.observe(
            &expected(7, Some("worker")),
            Err(ProcessEvidenceError::Missing { pid: 7 }),
        );
        let mut denied_scope = ProcessEvidenceScope::new(1).expect("scope");
        let denied = denied_scope.observe(
            &expected(7, Some("worker")),
            Err(ProcessEvidenceError::PermissionDenied { pid: 7 }),
        );

        assert_eq!(missing, Err(ProcessEvidenceError::Missing { pid: 7 }));
        assert_eq!(
            denied,
            Err(ProcessEvidenceError::PermissionDenied { pid: 7 })
        );
    }

    #[test]
    fn oversized_and_identity_changed_evidence_fail_closed() {
        let mut oversized_scope = ProcessEvidenceScope::new(1).expect("scope");
        let oversized = oversized_scope.observe(
            &expected(7, None),
            Ok(fresh(7, "x".repeat(PROTECTION_NAME_MAX_BYTES + 1))),
        );
        let mut changed_scope = ProcessEvidenceScope::new(1).expect("scope");
        let mut changed = fresh(7, "worker".to_owned());
        changed.start_marker = ProcessStartMarker::linux(18).expect("nonzero marker");
        let changed = changed_scope.observe(&expected(7, Some("worker")), Ok(changed));

        assert!(matches!(
            oversized,
            Err(ProcessEvidenceError::NameOversized { pid: 7, .. })
        ));
        assert_eq!(
            changed,
            Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
        );
    }

    #[test]
    fn wrong_platform_marker_variant_is_identity_change() {
        let mut scope = ProcessEvidenceScope::new(1).expect("scope");
        let mut changed = fresh(7, "worker".to_owned());
        changed.start_marker = ProcessStartMarker::windows(17).expect("nonzero marker");

        assert_eq!(
            scope.observe(&expected(7, Some("worker")), Ok(changed)),
            Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
        );
    }

    #[test]
    fn changed_fresh_name_is_refused() {
        let mut scope = ProcessEvidenceScope::new(1).expect("scope");

        assert_eq!(
            scope.observe(
                &expected(7, Some("worker")),
                Ok(fresh(7, "stranger".to_owned()))
            ),
            Err(ProcessEvidenceError::NameChanged { pid: 7 })
        );
    }

    #[test]
    fn aggregate_member_max_is_accepted_and_max_plus_one_refuses() {
        let mut scope = ProcessEvidenceScope::new(PROTECTION_SCOPE_MAX_MEMBERS).expect("exact max");
        for offset in 0..PROTECTION_SCOPE_MAX_MEMBERS {
            let pid = u32::try_from(offset + 2).expect("test PID");
            scope
                .observe(&expected(pid, None), Ok(fresh(pid, "x".to_owned())))
                .expect("member at exact bound");
        }
        scope.finish().expect("complete exact-max scope");

        assert!(matches!(
            ProcessEvidenceScope::new(PROTECTION_SCOPE_MAX_MEMBERS + 1),
            Err(ProcessEvidenceError::MemberLimitExceeded {
                limit: PROTECTION_SCOPE_MAX_MEMBERS
            })
        ));
    }

    #[test]
    fn aggregate_byte_max_is_accepted_and_max_plus_one_refuses() {
        let mut exact = ProcessEvidenceScope::with_limits(2, 2, 8).expect("scope");
        for offset in 0..2 {
            let pid = u32::try_from(offset + 2).expect("test PID");
            exact
                .observe(&expected(pid, None), Ok(fresh(pid, "xxxx".to_owned())))
                .expect("exact aggregate max");
        }
        exact.finish().expect("complete exact-byte-max scope");

        let mut over = ProcessEvidenceScope::with_limits(2, 2, 8).expect("scope");
        over.observe(&expected(2, None), Ok(fresh(2, "xxxx".to_owned())))
            .expect("first member");
        assert_eq!(
            over.observe(&expected(3, None), Ok(fresh(3, "xxxxx".to_owned()))),
            Err(ProcessEvidenceError::ByteLimitExceeded { limit: 8 })
        );
    }

    #[test]
    fn zero_member_scope_finishes_as_a_noop() {
        ProcessEvidenceScope::new(0)
            .expect("zero-member scope is valid")
            .finish()
            .expect("zero-member scope is complete");
    }

    #[test]
    fn exact_name_max_is_accepted_and_empty_name_is_refused() {
        let mut exact = ProcessEvidenceScope::new(1).expect("scope");
        exact
            .observe(
                &expected(7, None),
                Ok(fresh(7, "x".repeat(PROTECTION_NAME_MAX_BYTES))),
            )
            .expect("exact name maximum is accepted");
        exact.finish().expect("scope is complete");

        let mut empty = ProcessEvidenceScope::new(1).expect("scope");
        assert_eq!(
            empty.observe(&expected(7, None), Ok(fresh(7, String::new()))),
            Err(ProcessEvidenceError::NameMissing { pid: 7 })
        );
    }

    #[test]
    fn finish_reports_incomplete_scope_without_a_pid_sentinel() {
        assert_eq!(
            ProcessEvidenceScope::new(1).expect("scope").finish(),
            Err(ProcessEvidenceError::IncompleteScope {
                expected: 1,
                observed: 0,
            })
        );
    }
}
