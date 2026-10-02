//! Shared types for collection, querying, display, and termination.
//!
//! Platform collectors produce an authoritative `NetworkSnapshot`.
//! [`PortEntryView`] borrows rows from it. [`PortEntry`] is the owned projection
//! used when a row must outlive its snapshot. Internal identity evidence is not
//! part of the stable `list --json` shape.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::observation::{Ipv6Scope, ProcessIdentity, ProcessStartMarker};

/// Transport protocol of a socket row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Uppercase label for table output.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Socket states included in open-port views.
///
/// TCP sockets count when listening. UDP sockets count when bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketState {
    Listen,
    Bound,
}

impl SocketState {
    /// Uppercase label for table output.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Listen => "LISTEN",
            Self::Bound => "BOUND",
        }
    }
}

/// Which OS a row came from. Carried per-row so kill-command rendering can show
/// the right command without re-sniffing the OS. All three variants exist now
/// because they're part of the JSON contract.
#[allow(
    dead_code,
    reason = "non-host platform variants are constructed only for their target builds"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Windows,
    Macos,
}

/// Legacy completeness flag retained under its original `permission` name.
///
/// `Partial` means owner verification or optional process metadata was
/// incomplete for any reason, including permission denial, disappearance,
/// races, unsupported native fields, or retention bounds. It is not proof that
/// the operating system denied permission; structured snapshots carry the
/// precise evidence-gap reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionStatus {
    /// Owner verification and optional process metadata were complete.
    Full,
    /// The socket is visible, but owner verification or metadata was incomplete.
    Partial,
}

/// Human-facing bind scope for a local socket address.
///
/// `sort: scope` orders public, local-interface, then loopback-only binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BindScope {
    Public,
    Local,
    Loopback,
}

impl BindScope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Local => "local",
            Self::Loopback => "loopback",
        }
    }
}

/// Owned projection of one socket and its process metadata.
///
/// `Option` fields are `None` when metadata was unavailable. The historical
/// `permission` field records only complete versus partial legacy projection;
/// it does not identify why a value is missing.
///
/// This is an owned *projection* of [`crate::observation::NetworkSnapshot`],
/// not a source of truth. Every field is derived by `project_legacy*`, and the
/// snapshot is authoritative for anything a destructive decision rests on.
///
/// Read-only consumers use [`PortEntryView`] to avoid copying shared metadata.
/// This owned form is used by workers and collection seams that outlive their
/// source snapshot, and by compact test fixtures. Add new
/// source facts to `NetworkSnapshot`, then project them here if required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortEntry {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) state: SocketState,
    pub(crate) pid: Option<u32>,
    pub(crate) process_name: Option<Arc<str>>,
    pub(crate) executable_path: Option<Arc<Path>>,
    pub(crate) command_line: Option<Arc<str>>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<Arc<str>>,
    pub(crate) protected: bool,
    pub(crate) platform: Platform,
    pub(crate) permission: PermissionStatus,
    pub(crate) process_identity: Option<ProcessIdentity>,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
}

/// Borrowed TUI/query row backed by one socket and its shared process metadata.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PortEntryView<'a> {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) state: SocketState,
    pub(crate) pid: Option<u32>,
    pub(crate) process_name: Option<&'a str>,
    pub(crate) executable_path: Option<&'a Path>,
    pub(crate) command_line: Option<&'a str>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<&'a str>,
    pub(crate) protected: bool,
    pub(crate) platform: Platform,
    pub(crate) permission: PermissionStatus,
    pub(crate) process_identity: Option<ProcessIdentity>,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
    pub(crate) label: Option<&'a str>,
}

impl<'a> From<&'a PortEntry> for PortEntryView<'a> {
    fn from(entry: &'a PortEntry) -> Self {
        Self {
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
            state: entry.state,
            pid: entry.pid,
            process_name: entry.process_name.as_deref(),
            executable_path: entry.executable_path.as_deref(),
            command_line: entry.command_line.as_deref(),
            parent_pid: entry.parent_pid,
            parent_process_name: entry.parent_process_name.as_deref(),
            protected: entry.protected,
            platform: entry.platform,
            permission: entry.permission,
            process_identity: entry.process_identity,
            ipv6_scope: entry.ipv6_scope,
            label: None,
        }
    }
}

impl PortEntryView<'_> {
    pub(crate) fn scope(self) -> BindScope {
        bind_scope(self.local_addr)
    }

    pub(crate) fn scope_label(self) -> &'static str {
        self.scope().label()
    }

    /// Best-effort "is this a system/service process?" check, used for optional
    /// hiding.
    ///
    /// Classifies PID 0/1, direct children of PID 1, and known OS process names.
    /// Owner UID is resolved only for selected rows, so it is unavailable here.
    /// Protected-process policy is independent of this classification.
    pub(crate) fn is_system_process(self) -> bool {
        SystemProcessCheck {
            platform: self.platform,
            pid: self.pid,
            parent_pid: self.parent_pid,
            process_name: self.process_name,
            parent_process_name: self.parent_process_name,
        }
        .is_system_process()
    }
}

impl<'a> PortEntryView<'a> {
    pub(crate) fn with_label(mut self, label: Option<&'a str>) -> Self {
        self.label = label;
        self
    }
}

/// Borrow a slice of owned fixture rows as the views production code speaks.
///
/// Production builds views from snapshots. Tests may use small owned fixtures
/// and convert them through this helper.
#[cfg(test)]
pub(crate) fn entry_views(rows: &[PortEntry]) -> Vec<PortEntryView<'_>> {
    rows.iter().map(PortEntryView::from).collect()
}

/// Extra context we gather lazily for the selected process.
///
/// This stays outside [`PortEntry`] because table and JSON rows contain only
/// OS-confirmed socket facts. Process-tree data belongs to selected-row details.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ProcessContext {
    pub(crate) owner_uid: Option<u32>,
    /// Start marker of the process generation this context was read from.
    ///
    /// Selected-row details attach the owner UID and children only when this
    /// matches the row's snapshot identity, so a reused PID cannot pair one
    /// process's socket with another's metadata. Termination identity comes
    /// from the snapshot, not from this field. It is never rendered or
    /// serialized.
    pub(crate) process_start_time_marker: Option<ProcessStartMarker>,
    pub(crate) children: ChildProcessSnapshot,
    pub(crate) docker: Option<DockerPortContext>,
}

/// A capped list of children for one selected PID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ChildProcessSnapshot {
    pub(crate) children: Vec<ChildProcess>,
    pub(crate) truncated: bool,
}

/// A single direct child of the selected PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChildProcess {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
}

/// An evidence-only hint for the "no socket confirmed" diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelatedProcessHint {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
    pub(crate) command_line: String,
}

/// Optional Docker ownership context for one selected local port.
///
/// This stays outside [`PortEntry`] because Docker is enrichment, not the
/// OS-confirmed socket source of truth or the `list --json` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerPortContext {
    pub(crate) containers: Vec<DockerContainerPort>,
    pub(crate) truncated: bool,
}

impl DockerPortContext {
    pub(crate) fn single_container(&self) -> Option<&DockerContainerPort> {
        if self.containers.len() == 1 {
            self.containers.first()
        } else {
            None
        }
    }
}

/// One Docker container whose published host port matches the selected row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerContainerPort {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) compose_project: Option<String>,
    pub(crate) compose_service: Option<String>,
    pub(crate) host_port: u16,
    pub(crate) container_port: u16,
    pub(crate) protocol: Protocol,
}

impl DockerContainerPort {
    fn stop_target(&self) -> &str {
        if self.name.is_empty() {
            &self.id
        } else {
            &self.name
        }
    }

    pub(crate) fn stop_command(&self) -> String {
        format!("docker stop {}", self.stop_target())
    }
}

/// Classify a local bind address, treating IPv4-mapped IPv6 as IPv4.
pub(crate) fn bind_scope(local_addr: IpAddr) -> BindScope {
    let addr = match local_addr {
        // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1) down to real V4 so the
        // loopback/unspecified checks below see the actual address family. The
        // V4 arm is just the passthrough that keeps the match exhaustive.
        IpAddr::V4(addr) => IpAddr::V4(addr),
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
    };

    if addr.is_loopback() {
        BindScope::Loopback
    } else if addr.is_unspecified() {
        BindScope::Public
    } else {
        BindScope::Local
    }
}

/// The raw process fields the shared system/service policy reads.
///
/// This lives outside `PortEntry` because the policy must cover more than
/// table rows: kill-time process-tree nodes carry the same fields without
/// being socket entries, and two copies of the policy would drift apart.
///
/// Named fields prevent callers from swapping the same-typed PID and name
/// values. Such a swap can change the system-process policy without a type
/// error.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemProcessCheck<'a> {
    pub(crate) platform: Platform,
    pub(crate) pid: Option<u32>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) process_name: Option<&'a str>,
    pub(crate) parent_process_name: Option<&'a str>,
}

impl SystemProcessCheck<'_> {
    /// Best-effort system/service classification; see
    /// [`PortEntryView::is_system_process`] for the policy rationale.
    pub(crate) fn is_system_process(&self) -> bool {
        match self.platform {
            Platform::Windows => self.is_windows_system_process(),
            Platform::Linux | Platform::Macos => self.is_unix_system_process(),
        }
    }

    fn is_unix_system_process(&self) -> bool {
        if self.pid.is_some_and(|pid| pid <= 1) || self.parent_pid == Some(1) {
            return true;
        }

        self.process_name
            .is_some_and(|name| matches!(name, "systemd" | "launchd" | "init" | "WindowServer"))
    }

    fn is_windows_system_process(&self) -> bool {
        if self.pid.is_some_and(|pid| pid <= 4) {
            return true;
        }
        if self
            .parent_process_name
            .is_some_and(|name| name.eq_ignore_ascii_case("services.exe"))
        {
            return true;
        }

        self.process_name.is_some_and(|name| {
            WINDOWS_SYSTEM_PROCESS_NAMES
                .iter()
                .any(|system_name| system_name.eq_ignore_ascii_case(name))
        })
    }
}

const WINDOWS_SYSTEM_PROCESS_NAMES: [&str; 13] = [
    "System",
    "Registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "explorer.exe",
];

/// The table sort orders, shared by the CLI and the TUI.
/// Read straight from the config file (`default_sort = "port"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SortMode {
    Port,
    Pid,
    Protocol,
    Process,
    Parent,
    Scope,
}

impl SortMode {
    /// Lowercase label used in status output and config-facing text.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Pid => "pid",
            Self::Protocol => "protocol",
            Self::Process => "process",
            Self::Parent => "parent",
            Self::Scope => "scope",
        }
    }

    pub(crate) fn from_label(label: &str) -> Option<Self> {
        match label {
            "port" => Some(Self::Port),
            "pid" => Some(Self::Pid),
            "protocol" => Some(Self::Protocol),
            "process" => Some(Self::Process),
            "parent" => Some(Self::Parent),
            "scope" => Some(Self::Scope),
            _ => None,
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Port => Self::Pid,
            Self::Pid => Self::Protocol,
            Self::Protocol => Self::Process,
            Self::Process => Self::Parent,
            Self::Parent => Self::Scope,
            Self::Scope => Self::Port,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::{
        PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState, SortMode,
    };

    /// A tiny entry builder so each test only spells out the fields it cares
    /// about.
    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: name.map(Arc::from),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    #[test]
    fn sort_mode_labels_match_config_values() {
        assert_eq!(SortMode::Port.label(), "port");
        assert_eq!(SortMode::Pid.label(), "pid");
        assert_eq!(SortMode::Protocol.label(), "protocol");
        assert_eq!(SortMode::Process.label(), "process");
        assert_eq!(SortMode::Parent.label(), "parent");
        assert_eq!(SortMode::Scope.label(), "scope");
        assert_eq!(SortMode::from_label("parent"), Some(SortMode::Parent));
        assert_eq!(SortMode::from_label("unknown"), None);
        assert_eq!(SortMode::Scope.next(), SortMode::Port);
    }

    #[test]
    fn system_process_classification_is_conservative() {
        let mut row = entry(5432, Some(1201), Some("postgres"));
        assert!(!PortEntryView::from(&row).is_system_process());

        row.parent_pid = Some(1);
        assert!(PortEntryView::from(&row).is_system_process());

        row.parent_pid = None;
        row.process_name = Some(Arc::from("systemd"));
        assert!(PortEntryView::from(&row).is_system_process());
    }

    #[test]
    fn windows_system_process_classification_covers_core_services() {
        let mut row = entry(445, Some(4), Some("System"));
        row.platform = Platform::Windows;
        assert!(PortEntryView::from(&row).is_system_process());

        row.pid = Some(20_000);
        row.process_name = Some(Arc::from("SVCHOST.EXE"));
        assert!(PortEntryView::from(&row).is_system_process());

        row.process_name = Some(Arc::from("vendor-service.exe"));
        row.parent_process_name = Some(Arc::from("services.exe"));
        assert!(PortEntryView::from(&row).is_system_process());

        row.parent_process_name = Some(Arc::from("explorer.exe"));
        assert!(!PortEntryView::from(&row).is_system_process());
    }

    #[test]
    fn json_shape_is_stable() {
        // Pin field names, enum casing, and null handling in the public JSON
        // contract.
        let mut row = entry(3000, Some(18422), Some("node"));
        row.executable_path = Some(PathBuf::from("/usr/bin/node").into());
        row.command_line = Some(Arc::from("node server.js"));
        row.parent_pid = Some(18001);
        row.parent_process_name = Some(Arc::from("cursor-agent"));

        let view = PortEntryView::from(&row).with_label(Some("web dev"));
        let value = serde_json::to_value(crate::public_output::LegacyListRecord::from(&view))
            .expect("production list view must serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "protocol": "tcp",
                "local_addr": "127.0.0.1",
                "local_port": 3000,
                "state": "listen",
                "pid": 18422,
                "process_name": "node",
                "executable_path": "/usr/bin/node",
                "command_line": "node server.js",
                "parent_pid": 18001,
                "parent_process_name": "cursor-agent",
                // `child_pids` is a frozen 1.x compatibility field with no
                // backing data: the serializer emits an empty array for every
                // row. Scripts still parse the key, so it must keep appearing.
                "child_pids": [],
                "protected": false,
                "platform": "linux",
                "permission": "full",
                "label": "web dev",
            })
        );
    }

    #[test]
    fn json_renders_missing_metadata_as_null() {
        let row = entry(53, None, None);
        let view = PortEntryView::from(&row);
        let value = serde_json::to_value(crate::public_output::LegacyListRecord::from(&view))
            .expect("must serialize");
        assert_eq!(value["pid"], serde_json::Value::Null);
        assert_eq!(value["process_name"], serde_json::Value::Null);
        assert_eq!(value["executable_path"], serde_json::Value::Null);
        assert_eq!(value["label"], serde_json::Value::Null);
    }
}
