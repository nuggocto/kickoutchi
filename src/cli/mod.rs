//! CLI arguments, commands, and exit-code mapping.
//!
//! CLI commands print to standard output or error and do not open the TUI. They
//! use the same collector and model as the TUI.

mod kill;
mod list;
mod scoped;
mod settle;
mod watch;
mod why;

use std::io::{self, ErrorKind, Write};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};

use crate::collector;
use crate::config::{Config, REFRESH_INTERVAL_SECONDS_MAX, REFRESH_INTERVAL_SECONDS_MIN};
use crate::diagnostic;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::display::sanitize;
use crate::inspect;
use crate::model::Platform;
use crate::model::{PortEntryView, SortMode};
use crate::owner_visibility::OwnerVisibility;
use crate::platform;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree;

use self::kill::run_kill;
use self::kill::{KillTargetError, print_target_error, resolve_single_port_owner};
use self::list::run_list_snapshot;
pub(crate) use self::watch::WatchSignalGuard;
use self::watch::{WatchArgs, run_watch};
use self::why::{WhyArgs, run_why};

/// Stable script-facing exit codes.
///
/// Every variant is used by the CLI. Clap produces `InvalidArguments` in
/// practice, but it remains part of this mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ExitReason {
    Success = 0,
    Failure = 1,
    InvalidArguments = 2,
    NoMatch = 3,
    PermissionDenied = 4,
    KillCancelled = 5,
    ProtectedNeedsConfirmation = 6,
}

impl From<ExitReason> for ExitCode {
    fn from(reason: ExitReason) -> Self {
        Self::from(reason as u8)
    }
}

/// Top-level argument shape. No subcommand opens the TUI; `list` and `kill`
/// run headless and exit.
///
/// `about` uses the Cargo package description. `long_about = None` keeps this
/// developer documentation out of `--help`.
///
/// The fixed `name` keeps `--version` reporting the canonical `kickoutchi` under
/// both binary names, while clap takes the usage line from argv(0), so
/// `kick --help` shows `Usage: kick ...`, preserving the short binary alias.
#[derive(Debug, Parser)]
#[command(name = "kickoutchi", version, about, long_about = None)]
pub(crate) struct Cli {
    /// Path to an alternate config file (default: the platform config dir).
    #[arg(long, value_name = "FILE", global = true)]
    pub(crate) config: Option<PathBuf>,

    /// Override the configured refresh interval (1..=3600 seconds).
    #[arg(
        long,
        value_name = "SECONDS",
        global = true,
        value_parser = clap::value_parser!(u64).range(REFRESH_INTERVAL_SECONDS_MIN..=REFRESH_INTERVAL_SECONDS_MAX)
    )]
    pub(crate) refresh_interval: Option<u64>,

    /// Emit internal diagnostics to stderr without changing command stdout.
    #[arg(short, long, global = true)]
    pub(crate) verbose: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Print open ports and exit.
    ///
    /// Filters use AND semantics. Structured fields are `pid:`, `port:`,
    /// `proto:`, `scope:`, `protected:`, `parent:`, `label:`, `address:`,
    /// `scope_id:`, and `family:`. For example:
    /// `--filter 'proto:tcp family:ipv6 parent:node'`. `state:` is reserved for
    /// `watch` and is rejected here. See the filter syntax documentation for
    /// matching and normalization rules.
    ///
    /// `--json` preserves the legacy visible-row `kickoutchi.list/1` array for
    /// existing scripts and may include full command lines. `--snapshot-json`
    /// emits the complete, unfiltered within-scope `kickoutchi.snapshot/1`
    /// observation, including completeness and evidence gaps but not full command
    /// lines. See the structured output documentation for schemas and privacy
    /// guidance.
    List(ListArgs),
    /// Terminate a verified port owner, process tree, or process group.
    ///
    /// After delivery, kill waits up to two seconds and reports, on separate
    /// stderr lines, whether each signalled process exited and whether its
    /// confirmed ports are still visible. Exit code 0 means the signal was
    /// accepted, not that the process exited: a process can close its ports
    /// and keep running, which kill reports as a warning.
    ///
    /// Several `--pid` or `--port` values kill several processes behind one
    /// confirmation and one summary. Nothing is sent if any target is refused.
    /// The exit code is then the most serious outcome across targets: 1, then
    /// 4, then 6, then 3.
    Kill(KillCommandArgs),
    /// Show a process's family, group, and ports without sending signals.
    Inspect(InspectArgs),
    /// Stream bounded socket changes until interrupted or the duration expires.
    ///
    /// Watch compares full-state native snapshots. Polling can miss sockets that
    /// appear and disappear between snapshots; observation times bracket a
    /// collection attempt, not the exact event time. Neither protocol flag means
    /// both TCP and UDP, and `--tcp --udp` also selects both. Docker and other
    /// external network tools are never run by the polling loop.
    ///
    /// Filters use AND semantics and support plain text plus `pid:`, `port:`,
    /// `proto:`, `scope:`, `protected:`, `parent:`, `label:`, `address:`,
    /// `scope_id:`, `family:`, and watch-only `state:`. Missing owner or process
    /// metadata can produce an emitted `indeterminate` match when those facts are
    /// needed to decide an otherwise possible event; definite nonmatches remain
    /// suppressed. `--matched-only` suppresses `indeterminate` events too. See
    /// the filter documentation for accepted values.
    ///
    /// An initial collection failure emits no records and exits 1. After a valid
    /// baseline, an unusable poll emits and flushes `collection_gap`, retains the
    /// last valid snapshot, and retries; the third consecutive failure flushes
    /// its gap and exits 1. Collection gaps bypass endpoint filters.
    ///
    /// JSON mode writes one `kickoutchi.watch_event/1` object per stdout line;
    /// diagnostics go only to stderr. Records omit full command lines but can
    /// contain sensitive owner, process, endpoint, label, and evidence data. See
    /// the structured output documentation for the schema and failure contract.
    Watch(WatchArgs),
    /// Explain whether exact local endpoints are bindable now.
    ///
    /// The default query probes TCP on `127.0.0.1`, then `::1`. Protocol order is
    /// TCP then UDP; `--all-addresses` order is `127.0.0.1`, `0.0.0.0`, `::1`,
    /// then `::`. Results preserve that protocol-major matrix order, capped at
    /// eight endpoints.
    ///
    /// `--scope-id` requires one explicit IPv6 address. `--ipv6-only` and
    /// `--dual-stack` are mutually exclusive and require only IPv6 addresses;
    /// without either flag, the operating system's IPv6 behavior is used.
    ///
    /// Each exact endpoint is temporarily bound and immediately closed in
    /// sequence. A successful bind proves availability only at probe completion:
    /// it does not reserve the endpoint, and another process may bind afterward.
    /// Why does not run Docker and never includes full process command lines.
    ///
    /// `--json` emits one `kickoutchi.why/1` document. Exit codes are 0 for all
    /// bindable, 1 for operational or indeterminate results, 2 for invalid
    /// arguments, 3 for occupied, unavailable, unsupported, or otherwise
    /// non-bindable endpoints, and 4 for permission denial. See the structured
    /// output documentation for verdicts and the schema.
    Why(WhyArgs),
}

/// `inspect` accepts either a PID or a port whose owner becomes the starting
/// PID. The command is read-only, and the starting PID need not own a port.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "port"])))]
pub(crate) struct InspectArgs {
    /// PID whose family to show.
    #[arg(long)]
    pid: Option<u32>,

    /// Show the family of the process that owns this port.
    #[arg(long, value_parser = parse_port)]
    port: Option<u16>,
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    /// Only show rows bound to this exact port.
    #[arg(long, value_parser = parse_port)]
    port: Option<u16>,

    /// Only show rows whose process name contains this text.
    #[arg(long, value_parser = parse_process)]
    process: Option<String>,

    /// Apply plain search or structured filters (all terms must match).
    ///
    /// Examples: `3000`, `pid:4242`, `proto:udp`, `protected:false`,
    /// `parent:node`, `label:web`, `address:127.0.0.1`, `scope_id:3`,
    /// `family:ipv6`. `state:` is watch-only and rejected by list.
    #[arg(long, value_name = "TEXT")]
    filter: Option<String>,

    /// Sort rows by port, pid, protocol, process, parent, or scope.
    #[arg(long, value_name = "MODE", value_parser = parse_sort_mode)]
    sort: Option<SortMode>,

    /// Print the legacy visible-row `kickoutchi.list/1` JSON array.
    #[arg(long, conflicts_with = "snapshot_json")]
    json: bool,

    /// Print the complete, unfiltered `kickoutchi.snapshot/1` JSON observation.
    #[arg(
        long,
        conflicts_with_all = ["json", "port", "process", "filter", "sort"]
    )]
    snapshot_json: bool,
}

/// `kill` takes PIDs or ports, never both. Several targets kill several
/// single processes behind one confirmation and one summary.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent CLI flag; clap's derive requires bools, and `--tree --group` is already rejected at parse time. `allow`, not `expect`: only Linux and macOS have `--group`, so Windows stays under the threshold"
)]
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "port"])))]
pub(crate) struct KillCommandArgs {
    /// PID to target; repeat it or separate PIDs with commas to kill several
    /// processes. A plain PID kill requires a visible owned port; a scoped
    /// kill may start from a live portless root. Unsafe PIDs are refused.
    #[arg(long, value_delimiter = ',', action = ArgAction::Append)]
    pid: Vec<u32>,

    /// Terminate the process that owns this port; repeat it or separate
    /// ports with commas to kill several owners.
    #[arg(long, value_delimiter = ',', action = ArgAction::Append, value_parser = parse_port)]
    port: Vec<u16>,

    /// Force kill instead of normal termination where the platform supports a distinction.
    #[arg(long)]
    force: bool,

    /// Skip the confirmation prompt. Never bypasses protected-process
    /// confirmation.
    #[arg(long)]
    yes: bool,

    /// Terminate the whole process tree rooted at the target, not just the one
    /// process. Opt-in; typed confirmation unless --yes passes all-clear gates.
    /// May start from a live root with no visible port. Takes one target.
    /// Linux, macOS, and Windows CLI only.
    #[arg(long)]
    tree: bool,

    /// Terminate every process sharing the target's group ID, including members
    /// that reparented away from the tree. Opt-in; typed confirmation unless
    /// --yes passes all-clear gates. May start from a live root with no visible
    /// port. Takes one target. Linux and macOS only.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long, conflicts_with = "tree")]
    group: bool,
}

impl KillCommandArgs {
    /// One single-target request per distinct selector, in command-line order.
    fn targets(&self) -> Result<Vec<KillArgs>, String> {
        let mut pids = self.pid.clone();
        dedup_in_order(&mut pids);
        let mut ports = self.port.clone();
        dedup_in_order(&mut ports);
        let targets = pids
            .into_iter()
            .map(|pid| self.target(Some(pid), None))
            .chain(ports.into_iter().map(|port| self.target(None, Some(port))))
            .collect::<Vec<_>>();
        if targets.len() > kill::batch::BATCH_TARGETS_MAX {
            return Err(format!(
                "at most {} targets can be killed at once",
                kill::batch::BATCH_TARGETS_MAX
            ));
        }
        if targets.len() > 1 && self.scoped() {
            return Err(
                "--tree and --group take one target; run one scoped kill per root".to_owned(),
            );
        }
        Ok(targets)
    }

    fn target(&self, pid: Option<u32>, port: Option<u16>) -> KillArgs {
        KillArgs {
            pid,
            port,
            force: self.force,
            yes: self.yes,
            tree: self.tree,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: self.group,
        }
    }

    fn scoped(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let group = self.group;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let group = false;
        self.tree || group
    }
}

fn dedup_in_order<T: Copy + Ord>(values: &mut Vec<T>) {
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| seen.insert(*value));
}

/// One kill request: exactly one of `pid` and `port` is set.
#[allow(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent CLI flags; `allow`, not `expect`, because Windows has no `group`"
)]
#[derive(Debug, Clone)]
pub(crate) struct KillArgs {
    pid: Option<u32>,
    port: Option<u16>,
    force: bool,
    yes: bool,
    tree: bool,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    group: bool,
}

/// Run a CLI command to completion and report how the process should exit.
///
/// Print command errors to stderr and map them to CLI exit codes.
pub(crate) fn run(
    command: &Command,
    config: &Config,
    watch_signal_guard: Option<WatchSignalGuard>,
) -> ExitReason {
    if let Command::Watch(args) = command {
        return run_watch(
            args,
            config,
            watch_signal_guard.expect("watch installs its signal guard before config loading"),
        );
    }
    if let Command::Why(args) = command {
        return run_why(args, config);
    }
    debug_assert!(watch_signal_guard.is_none());
    if let Command::List(args) = command
        && let Err(error) = crate::query::validate_filter_text(
            args.filter.as_deref().unwrap_or_default(),
            crate::query::QueryCapabilities::LIST,
        )
    {
        eprintln!("error: invalid filter: {error}");
        return ExitReason::InvalidArguments;
    }
    let profile = match command {
        Command::List(args) if args.snapshot_json => crate::observation::MetadataProfile::Display,
        Command::List(_) => crate::observation::MetadataProfile::LegacyList,
        Command::Kill(_) | Command::Inspect(_) => crate::observation::MetadataProfile::Display,
        Command::Watch(_) => unreachable!("watch owns its repeated collection loop"),
        Command::Why(_) => unreachable!("why owns collection and exact probing"),
    };
    let snapshot = match collector::collect_snapshot(profile) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("error: collecting ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    match command {
        Command::List(args) => run_list_snapshot(args, config, &snapshot),
        Command::Kill(command) => {
            let targets = match command.targets() {
                Ok(targets) => targets,
                Err(message) => {
                    eprintln!("error: {message}");
                    return ExitReason::InvalidArguments;
                }
            };
            let [args] = targets.as_slice() else {
                return kill::batch::run_batch_kill(&targets, config, &snapshot);
            };
            // Descriptors resolve protection during construction, so this is the
            // whole projection: no owned legacy rows, no second marking pass.
            let descriptors = match snapshot.port_entry_descriptors_matching(
                args.pid,
                args.port,
                &config.protected_processes,
            ) {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    eprintln!("error: projecting collected ports failed: {error}");
                    return ExitReason::Failure;
                }
            };
            let entries = descriptors
                .iter()
                .map(|descriptor| snapshot.port_entry_view(descriptor))
                .collect::<Vec<_>>();
            if let Some(port) = args.port
                && let Some(reason) = refuse_unprovable_port_kill(args, port, &snapshot, &entries)
            {
                return reason;
            }
            run_kill(args, config, &entries)
        }
        Command::Inspect(args) => {
            if let Some(port) = args.port
                && let Some(message) = hidden_port_owner_message(&snapshot, port)
            {
                eprintln!("error: {message}");
                return ExitReason::PermissionDenied;
            }
            run_inspect(args, config, &snapshot)
        }
        Command::Watch(_) => unreachable!("watch is dispatched before one-shot collection"),
        Command::Why(_) => unreachable!("why is dispatched before one-shot collection"),
    }
}

/// Explain a selected port whose visible socket has no visible owner.
///
/// Port resolution would refuse the same port as `MissingPid`; this gives the
/// refusal its cause (another user's socket, incomplete attribution, or no
/// readable holder) without changing the exit code.
fn hidden_port_owner_message(
    snapshot: &crate::observation::NetworkSnapshot,
    port: u16,
) -> Option<String> {
    let socket = snapshot.sockets.iter().find(|socket| {
        socket.local_endpoint.port.get() == port
            && matches!(
                socket.state,
                crate::observation::SocketState::Listen | crate::observation::SocketState::Bound
            )
            && socket.owners.is_empty()
    })?;
    Some(OwnerVisibility::of(snapshot).hidden_port_owner_message(port, socket))
}

/// Refuse a port-selected kill before any prompt when the snapshot cannot
/// prove the visible owner is the port's only holder.
///
/// The same authority check runs again before delivery; refusing here only
/// avoids asking for a confirmation that cannot succeed, and says why. An
/// unreadable process anywhere on the host could share the socket, so the
/// refusal names the verified owner and suggests targeting it by PID.
fn refuse_unprovable_port_kill(
    args: &KillArgs,
    port: u16,
    snapshot: &crate::observation::NetworkSnapshot,
    entries: &[PortEntryView<'_>],
) -> Option<ExitReason> {
    let message = unprovable_port_kill_message(args, port, snapshot, entries)?;
    eprintln!("error: {message}");
    Some(ExitReason::PermissionDenied)
}

/// Why a port-selected kill must be refused before any prompt, if it must.
/// Every such refusal exits with `PermissionDenied`.
fn unprovable_port_kill_message(
    args: &KillArgs,
    port: u16,
    snapshot: &crate::observation::NetworkSnapshot,
    entries: &[PortEntryView<'_>],
) -> Option<String> {
    if let Some(message) = hidden_port_owner_message(snapshot, port) {
        return Some(message);
    }
    // Other resolution failures keep their existing messages.
    let (pid, rows) = resolve_single_port_owner(port, entries).ok()?;
    // These refusals come first in the normal flow and keep their own
    // wording and exit codes: an unsafe PID has no `--pid` alternative, and
    // `--yes` on a protected owner exits 6.
    if crate::process::unsafe_pid_reason(pid).is_some()
        || (args.yes && rows.iter().any(|row| row.protected))
    {
        return None;
    }
    match collector::kill_ports_from_snapshot(snapshot, None, Some(port)) {
        Err(error) if error.is_ownership_permission_denied() => {}
        _ => return None,
    }
    let name = rows
        .iter()
        .find_map(|row| row.process_name)
        .map_or_else(|| "<unknown>".to_owned(), crate::display::sanitize);
    Some(format!(
        "kick cannot prove that PID {pid} ({name}) is the only holder of port {port}: {}; an unreadable process could share the socket, so kick will not signal by port. Run `{}` to target the verified owner, or rerun with higher privileges",
        OwnerVisibility::of(snapshot).unreadable_clause(),
        pid_kill_suggestion(args, pid),
    ))
}

/// The `--pid` form of a port-selected kill, keeping its scope and mode.
fn pid_kill_suggestion(args: &KillArgs, pid: u32) -> String {
    let mut command = format!("kick kill --pid {pid}");
    if args.tree {
        command.push_str(" --tree");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if args.group {
        command.push_str(" --group");
    }
    if args.force {
        command.push_str(" --force");
    }
    command
}

fn write_stdout(text: &str) -> Option<ExitReason> {
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => None,
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Some(ExitReason::Success),
        Err(error) => {
            eprintln!("error: writing stdout failed: {error}");
            Some(ExitReason::Failure)
        }
    }
}

pub(super) fn maybe_print_no_match_diagnostic<'a>(
    diagnostic_port: Option<u16>,
    entries: impl Iterator<Item = PortEntryView<'a>>,
) {
    let Some(port) = diagnostic_port_without_confirmed_socket(diagnostic_port, entries) else {
        return;
    };
    let hints = platform::collect_related_process_hints(port);
    if let Some(message) = diagnostic::diagnostic_message(port, &hints) {
        eprint!("{message}");
    }
}

fn diagnostic_port_without_confirmed_socket<'a>(
    diagnostic_port: Option<u16>,
    mut entries: impl Iterator<Item = PortEntryView<'a>>,
) -> Option<u16> {
    let port = diagnostic_port?;
    if entries.any(|entry| entry.local_port == port) {
        None
    } else {
        Some(port)
    }
}

fn parse_sort_mode(value: &str) -> Result<SortMode, String> {
    SortMode::from_label(value)
        .ok_or_else(|| "expected one of: port, pid, protocol, process, parent, scope".to_owned())
}

/// Reject an empty `--process` selector.
///
/// An empty needle would select every readable process name instead of every
/// row. Whitespace is preserved because a space is a legitimate substring of a
/// process title.
fn parse_process(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("expected a nonempty process name substring".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .map(NonZeroU16::get)
        .ok_or_else(|| "expected a TCP/UDP port in 1..=65535".to_owned())
}

/// Run the read-only family inspection and print the report to stdout.
///
/// This command sends no signals. It may print a suggested tree-kill command.
fn run_inspect(
    args: &InspectArgs,
    config: &Config,
    network_snapshot: &crate::observation::NetworkSnapshot,
) -> ExitReason {
    let initial_descriptors = match network_snapshot.port_entry_descriptors_matching(
        args.pid,
        args.port,
        &config.protected_processes,
    ) {
        Ok(descriptors) => descriptors,
        Err(error) => {
            eprintln!("error: projecting inspect target failed: {error}");
            return ExitReason::Failure;
        }
    };
    let initial_entries = initial_descriptors
        .iter()
        .map(|descriptor| network_snapshot.port_entry_view(descriptor))
        .collect::<Vec<_>>();
    let target_pid = match resolve_inspect_target(args, &initial_entries) {
        Ok(pid) => pid,
        Err(KillTargetError::NoMatch) => {
            eprintln!("error: no open port matches the requested target");
            // Same evidence-only hint `list` prints: a command line naming the
            // port often identifies the process the user was looking for.
            maybe_print_no_match_diagnostic(args.port, initial_entries.iter().copied());
            return ExitReason::NoMatch;
        }
        Err(error) => return print_target_error(error),
    };

    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    #[cfg(windows)]
    let snapshot = match crate::platform::windows::collect_tree_process_infos() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process table failed: {}",
                crate::display::sanitize(&error.to_string())
            );
            return ExitReason::Failure;
        }
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let snapshot_result = tree::TreeProcessOps::snapshot(&mut ops);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let snapshot = match snapshot_result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process table failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    if !inspect_port_owner_matches_snapshot(args, target_pid, &initial_entries, &snapshot) {
        eprintln!(
            "error: the port owner changed or could not be identity-verified before inspection"
        );
        return ExitReason::NoMatch;
    }

    let report_scope = inspect::build_scope(
        target_pid,
        &snapshot,
        TREE_HOST_PLATFORM,
        &config.protected_processes,
    );
    let report_rows = match crate::observation::project_legacy_identities(
        network_snapshot,
        report_scope.port_identities(),
    ) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: projecting inspect report ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    let entries = report_rows
        .iter()
        .map(PortEntryView::from)
        .collect::<Vec<_>>();
    let deleted_executables = deleted_executables_in(&report_scope);
    let command_line_identities = inspect::command_line_scope_identities(target_pid, &snapshot);
    let command_line = platform::inspect_command_line_reader(&command_line_identities);
    match inspect::render_family_report_with_scope(
        target_pid,
        &snapshot,
        &entries,
        &config.protected_processes,
        TREE_HOST_PLATFORM,
        &report_scope,
        &deleted_executables,
        command_line,
    ) {
        Ok(report) => write_stdout(&report).unwrap_or(ExitReason::Success),
        Err(inspect::InspectError::TargetMissing) => {
            eprintln!("error: PID {target_pid} is not running");
            ExitReason::NoMatch
        }
    }
}

/// Processes in an inspect report whose executable was deleted or replaced.
fn deleted_executables_in(
    scope: &inspect::InspectScope,
) -> std::collections::HashMap<u32, std::path::PathBuf> {
    scope
        .port_identities()
        .iter()
        .filter_map(|identity| {
            platform::deleted_executable(*identity).map(|path| (identity.pid, path))
        })
        .collect()
}

/// Pick the PID to inspect. Unlike kill resolution there is no unsafe-PID
/// guard: reading PID 1's family is legitimate, and nothing here signals.
fn resolve_inspect_target(
    args: &InspectArgs,
    entries: &[PortEntryView<'_>],
) -> Result<u32, KillTargetError> {
    match (args.pid, args.port) {
        (Some(pid), None) => Ok(pid),
        (None, Some(port)) => {
            let (pid, _rows) = resolve_single_port_owner(port, entries)?;
            Ok(pid)
        }
        (None, None) | (Some(_), Some(_)) => {
            unreachable!("clap requires exactly one inspect target")
        }
    }
}

fn inspect_port_owner_matches_snapshot(
    args: &InspectArgs,
    target_pid: u32,
    entries: &[PortEntryView<'_>],
    snapshot: &[crate::tree::TreeProcessInfo],
) -> bool {
    if args.port.is_none() {
        return true;
    }

    let mut expected = None;
    for entry in entries.iter().filter(|entry| entry.pid == Some(target_pid)) {
        let Some(identity) = entry.process_identity else {
            return false;
        };
        if expected.is_some_and(|prior| prior != identity) {
            return false;
        }
        expected = Some(identity);
    }
    let Some(expected) = expected else {
        return false;
    };
    snapshot
        .iter()
        .find(|info| info.pid == target_pid)
        .and_then(|info| info.start_time_marker)
        == Some(expected.start_marker)
}

/// The platform a tree target built from the local process table lives on.
/// Snapshot rows come from the host OS, so this is a compile-time fact. Legacy
/// `PortEntry` rows carry their platform per row.
#[cfg(target_os = "linux")]
const TREE_HOST_PLATFORM: Platform = Platform::Linux;
#[cfg(target_os = "macos")]
const TREE_HOST_PLATFORM: Platform = Platform::Macos;
#[cfg(windows)]
const TREE_HOST_PLATFORM: Platform = Platform::Windows;

/// CLI-local wrappers around the shared port fixture plus process contexts.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::model::{PortEntry, ProcessContext, Protocol};

    pub(crate) fn entry(port: u16) -> PortEntry {
        entry_with_pid(port, Some(18_422), Protocol::Tcp, "node")
    }

    pub(crate) fn entry_with_pid(
        port: u16,
        pid: Option<u32>,
        protocol: Protocol,
        name: &str,
    ) -> PortEntry {
        crate::test_support::port_entry(port, pid, protocol, name)
    }

    pub(crate) fn no_context(_: u32) -> ProcessContext {
        ProcessContext {
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            ..ProcessContext::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::entry_views;
    use clap::Parser;

    use super::kill::KillTargetError;
    use super::test_support::entry;
    use super::test_support::entry_with_pid;
    use super::{Cli, Command, ExitReason, diagnostic_port_without_confirmed_socket};
    use crate::model::Protocol;
    use crate::model::SortMode;

    #[test]
    fn exit_codes_match_the_documented_contract() {
        // Pin the script-facing exit-code values.
        assert_eq!(ExitReason::Success as u8, 0);
        assert_eq!(ExitReason::Failure as u8, 1);
        assert_eq!(ExitReason::InvalidArguments as u8, 2);
        assert_eq!(ExitReason::NoMatch as u8, 3);
        assert_eq!(ExitReason::PermissionDenied as u8, 4);
        assert_eq!(ExitReason::KillCancelled as u8, 5);
        assert_eq!(ExitReason::ProtectedNeedsConfirmation as u8, 6);
    }

    #[test]
    fn bare_invocation_has_no_command_and_opens_the_tui() {
        let cli = Cli::try_parse_from(["kickoutchi"]).expect("bare invocation parses");
        assert!(cli.command.is_none());
    }

    #[test]
    fn list_flags_parse() {
        let cli = Cli::try_parse_from([
            "kickoutchi",
            "list",
            "--port",
            "3000",
            "--process",
            "node",
            "--filter",
            "scope:public",
            "--sort",
            "scope",
            "--json",
        ])
        .expect("valid list invocation");
        let Some(Command::List(args)) = cli.command else {
            panic!("expected a list command");
        };
        assert_eq!(args.port, Some(3000));
        assert_eq!(args.process.as_deref(), Some("node"));
        assert_eq!(args.filter.as_deref(), Some("scope:public"));
        assert_eq!(args.sort, Some(SortMode::Scope));
        assert!(args.json);
        assert!(!args.snapshot_json);
    }

    #[test]
    fn snapshot_json_parses_alone_and_rejects_legacy_selectors() {
        let cli = Cli::try_parse_from(["kickoutchi", "list", "--snapshot-json"])
            .expect("valid snapshot invocation");
        let Some(Command::List(args)) = cli.command else {
            panic!("expected a list command");
        };
        assert!(args.snapshot_json);
        assert!(!args.json);

        for conflict in [
            vec!["--json"],
            vec!["--port", "3000"],
            vec!["--process", "node"],
            vec!["--filter", "proto:tcp"],
            vec!["--sort", "port"],
        ] {
            let mut invocation = vec!["kickoutchi", "list", "--snapshot-json"];
            invocation.extend(conflict);
            assert!(Cli::try_parse_from(invocation).is_err());
        }
    }

    #[test]
    fn list_sort_rejects_unknown_modes_at_parse_time() {
        assert!(Cli::try_parse_from(["kickoutchi", "list", "--sort", "alphabetical"]).is_err());
    }

    #[test]
    fn why_flags_parse_and_conflicting_selectors_are_rejected() {
        let cli = Cli::try_parse_from([
            "kick",
            "why",
            "3000",
            "--all-protocols",
            "--all-addresses",
            "--reuse-address",
            "--json",
        ])
        .expect("valid why invocation");
        let Some(Command::Why(args)) = cli.command else {
            panic!("expected a why command");
        };
        assert_eq!(args.port, 3000);
        assert!(args.all_protocols);
        assert!(args.all_addresses);
        assert!(args.reuse_address);
        assert!(args.json);

        assert!(Cli::try_parse_from(["kick", "why", "3000", "--tcp", "--udp"]).is_err());
        assert!(
            Cli::try_parse_from([
                "kick",
                "why",
                "3000",
                "--address",
                "127.0.0.1",
                "--all-addresses",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["kick", "why", "3000", "--ipv6-only", "--dual-stack"]).is_err()
        );
    }

    #[test]
    fn kill_requires_exactly_one_target() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "1", "--port", "80"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422"]).is_ok());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--port", "3000", "--force"]).is_ok());
    }

    fn kill_command(arguments: &[&str]) -> super::KillCommandArgs {
        let mut invocation = vec!["kick", "kill"];
        invocation.extend(arguments);
        let Some(Command::Kill(command)) = Cli::try_parse_from(invocation)
            .expect("valid kill invocation")
            .command
        else {
            panic!("expected a kill command");
        };
        command
    }

    #[test]
    fn kill_accepts_repeated_and_comma_separated_targets_in_order() {
        let targets = kill_command(&["--pid", "30,10", "--pid", "20", "--pid", "10", "--yes"])
            .targets()
            .expect("three distinct PIDs");

        let pids = targets.iter().map(|target| target.pid).collect::<Vec<_>>();
        assert_eq!(
            pids,
            [Some(30), Some(10), Some(20)],
            "first occurrence wins"
        );
        assert!(
            targets
                .iter()
                .all(|target| target.port.is_none() && target.yes)
        );

        let ports = kill_command(&["--port", "3000,3001"])
            .targets()
            .expect("two ports");
        assert_eq!(
            ports.iter().map(|target| target.port).collect::<Vec<_>>(),
            [Some(3000), Some(3001)]
        );
        // PIDs and ports still cannot be mixed.
        assert!(Cli::try_parse_from(["kick", "kill", "--pid", "1", "--port", "2"]).is_err());
    }

    #[test]
    fn scoped_kills_and_oversized_batches_are_usage_errors() {
        assert!(kill_command(&["--pid", "1,2", "--tree"]).targets().is_err());
        assert!(kill_command(&["--pid", "7", "--tree"]).targets().is_ok());

        let too_many = (1..=super::kill::batch::BATCH_TARGETS_MAX + 1)
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(kill_command(&["--pid", &too_many]).targets().is_err());
        let at_limit = (1..=super::kill::batch::BATCH_TARGETS_MAX)
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(kill_command(&["--pid", &at_limit]).targets().is_ok());
    }

    #[test]
    fn every_cli_port_selector_rejects_zero() {
        let invocations: &[&[&str]] = &[
            &["kickoutchi", "list", "--port", "0"],
            &["kickoutchi", "kill", "--port", "0"],
            &["kickoutchi", "inspect", "--port", "0"],
            &["kickoutchi", "watch", "--port", "0"],
            &["kickoutchi", "why", "0"],
        ];
        for invocation in invocations {
            assert!(Cli::try_parse_from(*invocation).is_err(), "{invocation:?}");
        }
    }

    /// An empty needle is a substring of every name, so `--process ""` used to
    /// select "every row whose process name was readable" and exit 0 on that
    /// silently narrowed answer. Every structured filter already rejects an
    /// empty value; this selector now agrees, and a script that passes an
    /// unset variable gets a usage error instead of a wrong list.
    #[test]
    fn empty_process_selector_is_a_usage_error() {
        assert!(Cli::try_parse_from(["kickoutchi", "list", "--process", ""]).is_err());

        // Only the empty string: whitespace is a real substring of a process
        // title, and a nonempty needle is the ordinary case.
        for accepted in [" ", "node"] {
            assert!(
                Cli::try_parse_from(["kickoutchi", "list", "--process", accepted]).is_ok(),
                "{accepted:?}",
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn tree_flag_parses_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--tree"]).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn inspect_subcommand_parses_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "18422"]).is_ok());
    }

    /// Same per-platform contract for `--group`: no field on Windows builds,
    /// so the flag is a parse-time usage error there.
    #[cfg(windows)]
    #[test]
    fn group_flag_is_rejected_at_parse_time_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--group"]).is_err());
    }

    /// `--tree` and `--group` are two different blast radii; asking for both
    /// is a contradiction clap must reject before any process is looked at.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_flag_parses_and_conflicts_with_tree() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--group"]).is_ok());
        assert!(
            Cli::try_parse_from(["kickoutchi", "kill", "--port", "3000", "--group", "--force"])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--tree", "--group",])
                .is_err()
        );
    }

    #[test]
    fn inspect_requires_exactly_one_target() {
        assert!(Cli::try_parse_from(["kickoutchi", "inspect"]).is_err());
        assert!(
            Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "1", "--port", "80"]).is_err()
        );
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "18422"]).is_ok());
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--port", "3000"]).is_ok());
    }

    #[test]
    fn inspect_resolution_mirrors_kill_port_rules_but_allows_any_pid() {
        use super::{InspectArgs, resolve_inspect_target};

        let by_pid = |pid| InspectArgs {
            pid: Some(pid),
            port: None,
        };
        let by_port = |port| InspectArgs {
            pid: None,
            port: Some(port),
        };

        // Inspect may read PID 1 because it does not signal the process.
        assert_eq!(resolve_inspect_target(&by_pid(1), &[]), Ok(1));

        let rows = vec![entry(3000)];
        assert_eq!(
            resolve_inspect_target(&by_port(3000), &entry_views(&rows)),
            Ok(18_422)
        );
        assert_eq!(
            resolve_inspect_target(&by_port(4000), &entry_views(&rows)),
            Err(KillTargetError::NoMatch),
        );

        let hidden = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
        assert_eq!(
            resolve_inspect_target(&by_port(3000), &entry_views(&hidden)),
            Err(KillTargetError::MissingPid { port: 3000 }),
        );

        let shared = vec![
            entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
            entry_with_pid(3000, Some(200), Protocol::Udp, "worker"),
        ];
        assert!(matches!(
            resolve_inspect_target(&by_port(3000), &entry_views(&shared)),
            Err(KillTargetError::AmbiguousPort { port: 3000, .. }),
        ));
    }

    #[test]
    fn inspect_port_owner_must_match_the_later_process_identity() {
        use super::{InspectArgs, inspect_port_owner_matches_snapshot};

        let by_port = InspectArgs {
            pid: None,
            port: Some(3000),
        };
        let by_pid = InspectArgs {
            pid: Some(18_422),
            port: None,
        };
        let rows = vec![entry(3000)];
        let process = |marker| crate::tree::TreeProcessInfo {
            pid: 18_422,
            parent_pid: None,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: marker,
            owner_uid: None,
            process_group: None,
            executable_name: None,
        };
        let matching = crate::observation::ProcessStartMarker::linux(55).ok();
        let recycled = crate::observation::ProcessStartMarker::linux(56).ok();

        assert!(inspect_port_owner_matches_snapshot(
            &by_port,
            18_422,
            &entry_views(&rows),
            &[process(matching)]
        ));
        assert!(!inspect_port_owner_matches_snapshot(
            &by_port,
            18_422,
            &entry_views(&rows),
            &[process(recycled)]
        ));
        assert!(!inspect_port_owner_matches_snapshot(
            &by_port,
            18_422,
            &entry_views(&rows),
            &[process(None)]
        ));
        assert!(inspect_port_owner_matches_snapshot(
            &by_pid,
            18_422,
            &entry_views(&rows),
            &[process(recycled)]
        ));

        let mut unverified = rows;
        unverified[0].process_identity = None;
        assert!(!inspect_port_owner_matches_snapshot(
            &by_port,
            18_422,
            &entry_views(&unverified),
            &[process(matching)]
        ));
    }

    #[test]
    fn global_flags_parse_with_and_without_subcommands() {
        let cli = Cli::try_parse_from(["kickoutchi", "--refresh-interval", "9", "--verbose"])
            .expect("global flag without subcommand");
        assert_eq!(cli.refresh_interval, Some(9));
        assert!(cli.verbose);

        let cli = Cli::try_parse_from([
            "kickoutchi",
            "list",
            "--config",
            "/tmp/alt.toml",
            "--verbose",
        ])
        .expect("global flag after subcommand");
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/alt.toml"))
        );
        assert!(cli.verbose);
    }

    #[test]
    fn out_of_range_refresh_interval_is_a_usage_error() {
        // clap is the one that hands out exit code 2; this pins that the bound is
        // caught at parse time instead of leaking into config validation.
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "0"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "3601"]).is_err());
    }

    #[test]
    fn refresh_interval_accepts_both_inclusive_boundaries() {
        let minimum = Cli::try_parse_from(["kickoutchi", "--refresh-interval", "1"])
            .expect("minimum refresh interval parses");
        let maximum = Cli::try_parse_from(["kickoutchi", "--refresh-interval", "3600"])
            .expect("maximum refresh interval parses");

        assert_eq!(minimum.refresh_interval, Some(1));
        assert_eq!(maximum.refresh_interval, Some(3600));
    }

    #[test]
    fn port_kill_is_refused_before_the_prompt_without_complete_authority() {
        use super::{KillArgs, pid_kill_suggestion, refuse_unprovable_port_kill};

        let snapshot = crate::test_support::permission_denied_owner_snapshot();
        let descriptors = snapshot
            .port_entry_descriptors(&[])
            .expect("fixture projects");
        let entries = descriptors
            .iter()
            .map(|descriptor| snapshot.port_entry_view(descriptor))
            .collect::<Vec<_>>();
        let args = KillArgs {
            pid: None,
            port: Some(3000),
            force: true,
            yes: true,
            tree: true,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        };

        assert_eq!(
            refuse_unprovable_port_kill(&args, 3000, &snapshot, &entries),
            Some(ExitReason::PermissionDenied)
        );
        // The suggestion keeps scope and mode but never adds --yes.
        assert_eq!(
            pid_kill_suggestion(&args, 18_422),
            "kick kill --pid 18422 --tree --force"
        );
    }

    #[test]
    fn earlier_port_kill_refusals_keep_their_own_exit_codes() {
        use super::{KillArgs, refuse_unprovable_port_kill};

        let mut snapshot = crate::test_support::permission_denied_owner_snapshot();
        let descriptors = snapshot
            .port_entry_descriptors(&[])
            .expect("fixture projects");
        // The unverified owner has no readable name, so mark its row the way
        // a matching protection rule would.
        let protected_entries = descriptors
            .iter()
            .map(|descriptor| {
                let mut entry = snapshot.port_entry_view(descriptor);
                entry.protected = entry.local_port == 3000;
                entry
            })
            .collect::<Vec<_>>();
        let args = KillArgs {
            pid: None,
            port: Some(3000),
            force: false,
            yes: true,
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        };

        // `--yes` on a protected owner is left to the exit-6 refusal.
        assert_eq!(
            refuse_unprovable_port_kill(&args, 3000, &snapshot, &protected_entries),
            None
        );

        // An unsafe owner PID is left to the unsafe-PID refusal.
        for socket in &mut snapshot.sockets {
            for owner in &mut socket.owners {
                if let crate::observation::OwnerObservation::UnverifiedPid { pid, .. } = owner {
                    *pid = 1;
                }
            }
        }
        let descriptors = snapshot
            .port_entry_descriptors(&[])
            .expect("fixture projects");
        let entries = descriptors
            .iter()
            .map(|descriptor| snapshot.port_entry_view(descriptor))
            .collect::<Vec<_>>();
        assert_eq!(
            refuse_unprovable_port_kill(&args, 3000, &snapshot, &entries),
            None
        );
    }

    #[test]
    fn port_kill_with_complete_authority_reaches_the_normal_flow() {
        use super::{KillArgs, refuse_unprovable_port_kill};

        let rows = vec![entry(3000)];
        let snapshot = crate::observation::snapshot_from_test_rows(rows);
        let descriptors = snapshot
            .port_entry_descriptors(&[])
            .expect("fixture projects");
        let entries = descriptors
            .iter()
            .map(|descriptor| snapshot.port_entry_view(descriptor))
            .collect::<Vec<_>>();
        let args = KillArgs {
            pid: None,
            port: Some(3000),
            force: false,
            yes: true,
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        };

        assert_eq!(
            refuse_unprovable_port_kill(&args, 3000, &snapshot, &entries),
            None
        );
    }

    #[test]
    fn hidden_port_owner_message_only_names_ownerless_sockets() {
        let rows = vec![
            entry_with_pid(3000, None, Protocol::Tcp, "hidden"),
            entry(4000),
        ];
        let snapshot = crate::observation::snapshot_from_test_rows(rows);

        let message = super::hidden_port_owner_message(&snapshot, 3000)
            .expect("an ownerless socket is explained");
        assert!(
            message.starts_with("port 3000 is visible, but its owner"),
            "{message}"
        );
        assert_eq!(super::hidden_port_owner_message(&snapshot, 4000), None);
        assert_eq!(super::hidden_port_owner_message(&snapshot, 5000), None);
    }

    #[test]
    fn no_match_diagnostic_requires_absent_confirmed_socket() {
        assert_eq!(
            diagnostic_port_without_confirmed_socket(Some(3000), std::iter::empty()),
            Some(3000)
        );
        assert_eq!(
            diagnostic_port_without_confirmed_socket(
                Some(3000),
                entry_views(&[entry(3000)]).into_iter()
            ),
            None
        );
        assert_eq!(
            diagnostic_port_without_confirmed_socket(None, std::iter::empty()),
            None
        );
    }
}
