//! Side-effect-free process-tree and process-group planning.
//!
//! This module turns one bounded process-table snapshot into the previews and
//! preflight decisions consumed by the CLI, TUI, and platform executors. It
//! never freezes or signals a process.

use std::collections::{HashMap, HashSet};

use crate::model::{Platform, SystemProcessCheck};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::current_user_id;
use crate::process::{KillMode, unsafe_pid_reason};
use crate::protection::is_protected_by_names;

use super::{TreeKillOutcome, TreeProcessInfo};

pub(crate) const PROCESS_TREE_INDEX_MAX: usize = crate::observation::CANDIDATE_PROCESS_IDS_MAX;

/// One node in the preview tree shown before confirmation.
///
/// Built from one unfrozen snapshot, so concurrent process creation can make the
/// preview undercount. Execution enumerates again after freezing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessTreeNode {
    pub(crate) pid: u32,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) process_name: Option<String>,
    pub(crate) owner_uid: Option<u32>,
    pub(crate) protected: bool,
    system_process: bool,
    pub(crate) depth: usize,
}

/// Preview members and whether collection reached its cap. Tree scope records
/// descendant depth. Group scope records every non-root member at depth 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessTreeTarget {
    nodes: Vec<ProcessTreeNode>,
    truncated: bool,
    /// The member cap this preview was built under, carried so refusal
    /// messages always name the cap that actually applied (the tree and group
    /// caps differ).
    limit: usize,
}

/// Why a tree preview could not be built at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreePlanError {
    /// The root PID is not present in the snapshot because it exited.
    RootMissing,
    SnapshotLimitExceeded {
        limit: usize,
    },
}

pub(crate) fn plan_error_outcome(error: TreePlanError) -> TreeKillOutcome {
    match error {
        TreePlanError::RootMissing => TreeKillOutcome::RootAlreadyExited,
        TreePlanError::SnapshotLimitExceeded { limit } => TreeKillOutcome::Truncated { limit },
    }
}

#[derive(Debug)]
pub(crate) struct ProcessTreeIndex<'a> {
    by_pid: HashMap<u32, &'a TreeProcessInfo>,
    children_by_parent: HashMap<u32, Vec<&'a TreeProcessInfo>>,
}

impl<'a> ProcessTreeIndex<'a> {
    pub(crate) fn new(
        snapshot: &'a [TreeProcessInfo],
        limit: usize,
    ) -> Result<Self, TreePlanError> {
        if snapshot.len() > limit {
            return Err(TreePlanError::SnapshotLimitExceeded { limit });
        }
        let mut by_pid = HashMap::with_capacity(snapshot.len());
        let mut children_by_parent: HashMap<u32, Vec<&TreeProcessInfo>> = HashMap::new();
        for info in snapshot {
            by_pid.entry(info.pid).or_insert(info);
            if let Some(parent_pid) = info.parent_pid {
                children_by_parent.entry(parent_pid).or_default().push(info);
            }
        }
        for children in children_by_parent.values_mut() {
            children.sort_by_key(|info| info.pid);
        }
        Ok(Self {
            by_pid,
            children_by_parent,
        })
    }

    pub(crate) fn process(&self, pid: u32) -> Option<&'a TreeProcessInfo> {
        self.by_pid.get(&pid).copied()
    }

    pub(super) fn children(&self, pid: u32) -> &[&'a TreeProcessInfo] {
        self.children_by_parent.get(&pid).map_or(&[], Vec::as_slice)
    }
}

/// Why a group preview could not be built at all.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupPlanError {
    /// The root PID is not present in the snapshot because it exited.
    RootMissing,
    /// The root has no targetable process group: its group could not be read,
    /// or it lives in the kernel's group `0`.
    GroupUnavailable,
}

impl ProcessTreeTarget {
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn root(&self) -> Option<&ProcessTreeNode> {
        self.nodes.iter().find(|node| node.depth == 0)
    }

    /// Protected descendants (never the root). v1 refuses the whole tree if any
    /// exist, so the caller only needs the first.
    pub(super) fn protected_descendants(&self) -> impl Iterator<Item = &ProcessTreeNode> {
        self.nodes
            .iter()
            .filter(|node| node.depth > 0 && node.protected)
    }

    /// The first node whose PID is an unsafe target (0, 1, or Kickoutchi
    /// itself). The root is already blocked at resolution; this guards
    /// descendants such as Kickoutchi appearing inside its own target's tree.
    fn first_unsafe_node(&self) -> Option<&ProcessTreeNode> {
        self.nodes
            .iter()
            .find(|node| unsafe_pid_reason(node.pid).is_some())
    }

    pub(crate) fn has_system_process(&self) -> bool {
        self.nodes.iter().any(|node| node.system_process)
    }

    fn has_unreadable_name(&self) -> bool {
        self.nodes.iter().any(|node| node.process_name.is_none())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn has_owner_mismatch(&self) -> bool {
        let current_uid = current_user_id();
        self.nodes.iter().any(|node| {
            node.owner_uid
                .is_some_and(|owner_uid| owner_uid != current_uid)
        })
    }

    /// Whether `--yes` must show a prompt because the tree contains a system
    /// process, a different-UID member, or unreadable metadata.
    pub(crate) fn has_warnings(&self) -> bool {
        let base_warnings = self.has_system_process() || self.has_unreadable_name();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            base_warnings || self.has_owner_mismatch()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            base_warnings
        }
    }

    /// Nodes for the banner preview, capped, in display order (depth then PID).
    pub(crate) fn preview_nodes(&self, max: usize) -> &[ProcessTreeNode] {
        let end = max.min(self.nodes.len());
        &self.nodes[..end]
    }
}

/// Required tree confirmation word, shared by the CLI and TUI.
pub(crate) fn tree_scope_word(mode: KillMode) -> &'static str {
    match mode {
        KillMode::Force => "force",
        KillMode::Terminate => "tree",
    }
}

/// Required group confirmation word. Force mode uses `force` in every scope.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn group_scope_word(mode: KillMode) -> &'static str {
    match mode {
        KillMode::Force => "force",
        KillMode::Terminate => "group",
    }
}

/// Whether typed input matches the scope word, ignoring ASCII case.
pub(crate) fn word_confirmation_matches(input: &str, word: &str) -> bool {
    input.trim().eq_ignore_ascii_case(word)
}

/// Comma-separated PID list for denied-delivery reporting, shared by the CLI
/// and TUI outcome text.
pub(crate) fn format_pid_list(pids: &[u32]) -> String {
    pids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check complete enumeration, unsafe PIDs, and protected descendants before
/// signal delivery. This function has no side effects and is shared by the CLI
/// and TUI.
pub(crate) fn preflight_outcome(preview: &ProcessTreeTarget) -> Result<(), TreeKillOutcome> {
    if preview.truncated() {
        return Err(TreeKillOutcome::Truncated {
            limit: preview.limit,
        });
    }
    if let Some(node) = preview.first_unsafe_node() {
        return Err(TreeKillOutcome::UnsafePid {
            pid: node.pid,
            reason: unsafe_pid_reason(node.pid).expect("preview returned an unsafe node"),
        });
    }
    if let Some(node) = preview.protected_descendants().next() {
        return Err(TreeKillOutcome::ProtectedDescendant {
            pid: node.pid,
            name: node.process_name.clone(),
        });
    }
    Ok(())
}

/// The protected-root gate for a tree kill.
///
/// Recheck root protection against the latest preview. The socket row and
/// process-table scan may observe different names, and `exec` can change the
/// name without changing PID or start marker. A protected root proceeds only
/// after protected-root confirmation.
pub(crate) fn root_protection_outcome(
    preview: &ProcessTreeTarget,
    protected_confirmation_completed: bool,
) -> Result<(), TreeKillOutcome> {
    if protected_confirmation_completed {
        return Ok(());
    }
    if let Some(root) = preview.root()
        && root.protected
    {
        return Err(TreeKillOutcome::ProtectedRoot {
            pid: root.pid,
            name: root.process_name.clone(),
        });
    }
    Ok(())
}

/// Build the preview tree from a single snapshot.
///
/// Sends no signals and does not freeze processes. Walks `parent_pid` edges from
/// the root, then sorts nodes by depth and PID and applies protection and
/// system/service policy. At `limit`, stops adding nodes and reports truncation
/// so the caller can refuse the tree.
pub(crate) fn plan_process_tree(
    root_pid: u32,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessTreeTarget, TreePlanError> {
    let index = ProcessTreeIndex::new(snapshot, PROCESS_TREE_INDEX_MAX)?;
    plan_process_tree_with_index(root_pid, &index, protected_names, platform, limit)
}

pub(crate) fn plan_process_tree_with_index(
    root_pid: u32,
    index: &ProcessTreeIndex<'_>,
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessTreeTarget, TreePlanError> {
    let root_info = index.process(root_pid).ok_or(TreePlanError::RootMissing)?;

    let mut nodes = vec![preview_node(root_info, 0, protected_names, platform)];
    let mut seen: HashSet<u32> = HashSet::from([root_pid]);
    let mut frontier = vec![(root_pid, 0_usize)];
    let mut truncated = false;

    while let Some((parent_pid, parent_depth)) = frontier.pop() {
        for &child in index.children(parent_pid) {
            if seen.contains(&child.pid) {
                continue;
            }
            if nodes.len() >= limit {
                truncated = true;
                break;
            }
            seen.insert(child.pid);
            let depth = parent_depth + 1;
            nodes.push(preview_node(child, depth, protected_names, platform));
            frontier.push((child.pid, depth));
        }
        if truncated {
            break;
        }
    }

    nodes.sort_by(|left, right| left.depth.cmp(&right.depth).then(left.pid.cmp(&right.pid)));
    Ok(ProcessTreeTarget {
        nodes,
        truncated,
        limit,
    })
}

/// The previewed process group: its ID plus the member set in the shared
/// preview shape (root at depth 0, every other member at depth 1).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessGroupTarget {
    pgid: u32,
    members: ProcessTreeTarget,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProcessGroupTarget {
    pub(crate) fn pgid(&self) -> u32 {
        self.pgid
    }

    pub(crate) fn members(&self) -> &ProcessTreeTarget {
        &self.members
    }
}

/// Build the group preview from a single snapshot.
///
/// Pure like the tree preview builder: no signals, no freezing. Membership is one
/// flat filter selecting every process whose group ID equals the root's. This
/// group scope can cover reparented survivors a parent-link walk cannot reach.
/// Rows whose group is `None` are provably non-members: the platforms map only
/// the untargetable kernel group `0` to `None` and fail the scan on anything
/// unreadable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn plan_process_group(
    root_pid: u32,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessGroupTarget, GroupPlanError> {
    let root_info = snapshot
        .iter()
        .find(|info| info.pid == root_pid)
        .ok_or(GroupPlanError::RootMissing)?;
    let Some(pgid) = root_info.process_group else {
        return Err(GroupPlanError::GroupUnavailable);
    };

    let mut nodes = vec![preview_node(root_info, 0, protected_names, platform)];
    let mut members: Vec<&TreeProcessInfo> = snapshot
        .iter()
        .filter(|info| info.process_group == Some(pgid) && info.pid != root_pid)
        .collect();
    members.sort_by_key(|info| info.pid);

    let mut truncated = false;
    for member in members {
        if nodes.len() >= limit {
            truncated = true;
            break;
        }
        nodes.push(preview_node(member, 1, protected_names, platform));
    }

    Ok(ProcessGroupTarget {
        pgid,
        members: ProcessTreeTarget {
            nodes,
            truncated,
            limit,
        },
    })
}

fn preview_node(
    info: &TreeProcessInfo,
    depth: usize,
    protected_names: &[String],
    platform: Platform,
) -> ProcessTreeNode {
    ProcessTreeNode {
        pid: info.pid,
        parent_pid: info.parent_pid,
        process_name: info.process_name.clone(),
        owner_uid: info.owner_uid,
        protected: is_protected(info, protected_names, platform),
        system_process: is_system(
            info.pid,
            info.parent_pid,
            info.parent_process_name.as_deref(),
            info.process_name.as_deref(),
            platform,
        ),
        depth,
    }
}

fn is_protected(info: &TreeProcessInfo, protected_names: &[String], platform: Platform) -> bool {
    is_protected_by_names(
        platform,
        info.process_name.as_deref(),
        info.executable_name.as_deref(),
        protected_names,
    )
}

pub(super) fn is_system(
    pid: u32,
    parent_pid: Option<u32>,
    parent_process_name: Option<&str>,
    process_name: Option<&str>,
    platform: Platform,
) -> bool {
    // Parent process name is only consulted on Windows; the Linux/macOS policy
    // reads pid and parent pid, which both the preview snapshot and the frozen
    // set carry.
    SystemProcessCheck {
        platform,
        pid: Some(pid),
        parent_pid,
        process_name,
        parent_process_name,
    }
    .is_system_process()
}
