//! Plain-language explanations for sockets whose owner is not visible.
//!
//! A socket row without a PID can mean three different things: another user's
//! process holds it and this user cannot read that process, attribution was
//! incomplete for another reason, or no readable process holds it at all (for
//! example a kernel-held socket). The snapshot already records the evidence;
//! this module turns it into wording for human output. It never changes
//! ownership, completeness, or kill authority.

use std::collections::BTreeMap;

use crate::display::sanitize;
use crate::observation::{EvidenceGapCode, NetworkSnapshot, SocketObservation};

/// Snapshot-wide facts needed to explain any owner-less socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerVisibility {
    /// Lower bound on processes whose descriptors could not be read because
    /// permission was denied.
    unreadable_processes: u64,
    /// The effective UID of this process, where the platform has one.
    current_uid: Option<u32>,
}

/// Why one visible socket has no visible owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HiddenOwner {
    /// Another user created the socket, and attribution was incomplete.
    OtherUser { uid: u32 },
    /// Attribution was incomplete, and the socket UID does not point at
    /// another user.
    Unattributed,
    /// Every visible process was read and none holds the socket.
    NoReadableHolder,
}

impl OwnerVisibility {
    pub(crate) fn of(snapshot: &NetworkSnapshot) -> Self {
        // Exact-PID gaps can repeat per endpoint, and an aggregate may cover
        // the same PIDs, so the larger of the two is a safe lower bound.
        let mut exact_pids = std::collections::BTreeSet::new();
        let mut aggregate = 0_u64;
        for gap in &snapshot.evidence_gaps {
            if gap.code != EvidenceGapCode::OwnerPermissionDenied {
                continue;
            }
            if let Some(count) = gap.affected_pid_count() {
                aggregate = aggregate.max(count);
            } else if let Some(pid) = gap.pid {
                exact_pids.insert(pid);
            }
        }
        let exact = u64::try_from(exact_pids.len()).unwrap_or(u64::MAX);
        let unreadable_processes = aggregate.max(exact);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let current_uid = Some(crate::process::current_user_id());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let current_uid = None;
        Self {
            unreadable_processes,
            current_uid,
        }
    }

    pub(crate) fn classify(self, socket: &SocketObservation) -> HiddenOwner {
        let attribution_incomplete =
            self.unreadable_processes > 0 || !socket.owner_completeness.is_complete();
        if !attribution_incomplete {
            return HiddenOwner::NoReadableHolder;
        }
        match (socket.local_uid, self.current_uid) {
            (Some(uid), Some(current)) if uid != current => HiddenOwner::OtherUser { uid },
            _ => HiddenOwner::Unattributed,
        }
    }

    /// How many processes could not be read, as a clause.
    pub(crate) fn unreadable_clause(self) -> String {
        format!(
            "at least {} process(es) could not be read (permission denied)",
            self.unreadable_processes
        )
    }

    /// Why attribution was incomplete, as a clause.
    fn incomplete_clause(self) -> String {
        if self.unreadable_processes > 0 {
            self.unreadable_clause()
        } else {
            "some processes are outside this process's view".to_owned()
        }
    }

    /// The error text for a port selected by `kill` or `inspect` whose
    /// visible socket has no visible owner.
    pub(crate) fn hidden_port_owner_message(self, port: u16, socket: &SocketObservation) -> String {
        match self.classify(socket) {
            HiddenOwner::OtherUser { uid } => format!(
                "port {port} is visible, but its owner is hidden: the socket belongs to {} and {}; rerun with higher privileges, or pass --pid when known",
                user_label(uid),
                self.incomplete_clause(),
            ),
            HiddenOwner::Unattributed => format!(
                "port {port} is visible, but its owner was not attributed: {}; rerun with higher privileges, or pass --pid when known",
                self.incomplete_clause(),
            ),
            HiddenOwner::NoReadableHolder => format!(
                "port {port} is visible, but no readable process holds it; the kernel may hold the socket, or its owner is exiting",
            ),
        }
    }

    /// Explain the owner-less rows of a human table. Each row is
    /// `(has_pid, has_process_name, socket)`. Returns no lines when every row
    /// has an owner and a process name.
    pub(crate) fn table_notes<'a>(
        self,
        rows: impl IntoIterator<Item = (bool, bool, &'a SocketObservation)>,
    ) -> Vec<String> {
        let mut other_users = BTreeMap::<u32, usize>::new();
        let mut unattributed = 0_usize;
        let mut no_holder = 0_usize;
        let mut nameless = 0_usize;
        for (has_pid, has_name, socket) in rows {
            if has_pid {
                nameless += usize::from(!has_name);
                continue;
            }
            match self.classify(socket) {
                HiddenOwner::OtherUser { uid } => *other_users.entry(uid).or_default() += 1,
                HiddenOwner::Unattributed => unattributed += 1,
                HiddenOwner::NoReadableHolder => no_holder += 1,
            }
        }

        let mut lines = Vec::new();
        let hidden = other_users.values().sum::<usize>() + unattributed + no_holder;
        if hidden > 0 {
            lines.push("note: PID \"-\" means the socket's owner is not visible:".to_owned());
        }
        if !other_users.is_empty() {
            let count = other_users.values().sum::<usize>();
            let users = other_users
                .iter()
                .map(|(uid, rows)| format!("{}: {rows}", user_label(*uid)))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "  {count} row(s) belong to other users ({users}); {}. Rerun with sudo to see their owners.",
                self.incomplete_clause(),
            ));
        }
        if unattributed > 0 {
            lines.push(format!(
                "  {unattributed} row(s) have no attributed owner; {}.",
                self.incomplete_clause(),
            ));
        }
        if no_holder > 0 {
            lines.push(format!(
                "  {no_holder} row(s) have no holder among readable processes; the kernel may hold these sockets, or their owner is exiting."
            ));
        }
        if nameless > 0 {
            lines.push(format!(
                "note: {nameless} row(s) show a PID but PROCESS \"-\": that process's name could not be read."
            ));
        }
        lines
    }
}

/// `name (uid N)` when the account name resolves, otherwise `uid N`.
fn user_label(uid: u32) -> String {
    match user_name(uid) {
        Some(name) => format!("{} (uid {uid})", sanitize(&name)),
        None => format!("uid {uid}"),
    }
}

/// Largest `getpwuid_r` scratch buffer tried before giving up on a name.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const USER_NAME_BUFFER_MAX: usize = 64 * 1024;

/// The account name for a UID, or `None` when it does not resolve.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0_u8; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry` and `buffer` are writable for the sizes passed, and
        // `result` is a valid out-pointer. getpwuid_r stores string data only
        // inside `buffer` and retains none of the pointers.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if code == libc::ERANGE && buffer.len() < USER_NAME_BUFFER_MAX {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success with a non-null result, `pw_name` points to a
        // NUL-terminated string inside `buffer`, which is still alive here.
        let name = unsafe { std::ffi::CStr::from_ptr((*result).pw_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn user_name(_uid: u32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests;
