//! Post-termination verification for CLI kills.
//!
//! A delivered signal is not an exit. After delivery the CLI polls two separate
//! facts for a bounded window: whether each signalled process identity exited,
//! and whether the confirmed ports stopped being visible. A closed listener
//! does not prove an exit, and an exit does not prove the port is free, so the
//! report keeps them apart.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::collector;
use crate::display::sanitize;
use crate::model::{PortEntry, PortEntryView};
use crate::observation::ProcessIdentity;
use crate::process::{self, ExitObservation, KillMode, KillTarget, KillTargetPort};

/// How many times the settle loop polls, and the pause between polls.
/// Termination is asynchronous: a `SIGTERM`'d process may run shutdown
/// handlers before it exits and closes its sockets. Twenty 100ms polls give it
/// about two seconds; the loop stops early once every fact is settled.
pub(super) const SETTLE_ATTEMPTS_MAX: usize = 20;
pub(super) const SETTLE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// What the confirmed ports looked like once the settle window closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PortsStatus {
    /// No confirmed ports were given, so nothing was polled.
    NotChecked,
    Cleared,
    StillVisible,
    RefreshFailed(String),
}

/// The exit and port facts observed after termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SettleReport {
    pub(super) exited: Vec<u32>,
    pub(super) running: Vec<u32>,
    /// PIDs whose exit check kept failing, with the last unsanitized error.
    pub(super) unknown: Vec<(u32, String)>,
    pub(super) ports: PortsStatus,
    /// The confirmed ports seen on the last poll when `ports` is
    /// `StillVisible`; empty otherwise.
    pub(super) visible_ports: Vec<KillTargetPort>,
}

/// The reads the settle loop performs. Tests inject all three.
pub(super) struct SettleProbe<'a> {
    pub(super) collect_ports:
        &'a mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    pub(super) observe_exit: &'a mut dyn FnMut(ProcessIdentity) -> ExitObservation,
    pub(super) sleep: &'a mut dyn FnMut(Duration),
}

/// Poll until every identity exited and the ports cleared, or the window ends.
///
/// A port refresh error stops port polling with a warning instead of claiming
/// the ports cleared without evidence. Exit polling continues.
pub(super) fn settle(
    identities: &[ProcessIdentity],
    ports: &[KillTargetPort],
    probe: &mut SettleProbe<'_>,
) -> SettleReport {
    let mut pending = identities.to_vec();
    let mut exited = Vec::new();
    let mut last_errors = BTreeMap::new();
    let mut ports_status = if ports.is_empty() {
        PortsStatus::NotChecked
    } else {
        PortsStatus::StillVisible
    };
    let mut visible_ports = Vec::new();

    for attempt in 0..SETTLE_ATTEMPTS_MAX {
        pending.retain(|identity| match (probe.observe_exit)(*identity) {
            ExitObservation::Exited => {
                exited.push(identity.pid);
                last_errors.remove(&identity.pid);
                false
            }
            ExitObservation::Running => {
                last_errors.remove(&identity.pid);
                true
            }
            ExitObservation::Unknown(error) => {
                last_errors.insert(identity.pid, error);
                true
            }
        });

        if ports_status == PortsStatus::StillVisible {
            visible_ports.clear();
            ports_status = match (probe.collect_ports)() {
                Err(error) => PortsStatus::RefreshFailed(error.to_string()),
                Ok(entries) => {
                    visible_ports = confirmed_ports_visible(ports, &entries);
                    if visible_ports.is_empty() {
                        PortsStatus::Cleared
                    } else {
                        PortsStatus::StillVisible
                    }
                }
            };
        }

        if pending.is_empty() && ports_status != PortsStatus::StillVisible {
            break;
        }
        if attempt + 1 < SETTLE_ATTEMPTS_MAX {
            (probe.sleep)(SETTLE_RETRY_DELAY);
        }
    }

    let mut running = Vec::new();
    let mut unknown = Vec::new();
    for identity in pending {
        match last_errors.remove(&identity.pid) {
            Some(error) => unknown.push((identity.pid, error)),
            None => running.push(identity.pid),
        }
    }
    exited.sort_unstable();
    running.sort_unstable();
    SettleReport {
        exited,
        running,
        unknown,
        ports: ports_status,
        visible_ports,
    }
}

/// The confirmed ports present in `entries`, sorted. `ports` must be sorted.
fn confirmed_ports_visible(ports: &[KillTargetPort], entries: &[PortEntry]) -> Vec<KillTargetPort> {
    let mut visible = entries
        .iter()
        .map(|entry| KillTargetPort::from(PortEntryView::from(entry)))
        .filter(|port| process::kill_target_has_port(ports, port))
        .collect::<Vec<_>>();
    visible.sort_unstable();
    visible.dedup();
    visible
}

/// The settle window as shown to users, for example `2.0s`.
pub(super) fn settle_window_text() -> String {
    let window = SETTLE_RETRY_DELAY.saturating_mul(
        u32::try_from(SETTLE_ATTEMPTS_MAX).expect("the settle attempt bound fits u32"),
    );
    format!("{:.1}s", window.as_secs_f64())
}

/// Advice for a process that outlived its terminating signal.
fn force_hint(target: &KillTarget, mode: KillMode) -> &'static str {
    if mode == KillMode::Terminate && target.platform != crate::model::Platform::Windows {
        "; rerun with --force to send SIGKILL"
    } else {
        ""
    }
}

/// Report lines for one signalled process.
pub(super) fn single_report_lines(
    target: &KillTarget,
    mode: KillMode,
    verified: bool,
    report: &SettleReport,
) -> Vec<String> {
    let mut lines = Vec::new();
    let identity = target.identity();
    if !verified {
        lines.push(format!(
            "warning: could not confirm that {identity} exited: its start identity is unknown"
        ));
    } else if !report.exited.is_empty() {
        lines.push(format!("{identity} exited"));
    } else if let Some((_, error)) = report.unknown.first() {
        lines.push(format!(
            "warning: could not confirm that {identity} exited: {}",
            sanitize(error)
        ));
    } else {
        lines.push(format!(
            "warning: {identity} is still running {} after {}; it may still be shutting down{}",
            settle_window_text(),
            mode.delivery_label(target.platform),
            force_hint(target, mode),
        ));
    }
    lines.extend(ports_line(&report.ports));
    lines
}

/// Report lines for the members of a Unix tree or group kill. Windows tree
/// kills confirm member exits inside Job Object termination.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn scoped_report_lines(
    root: &KillTarget,
    mode: KillMode,
    delivered: usize,
    report: &SettleReport,
) -> Vec<String> {
    let mut lines = Vec::new();
    let verified = report.exited.len() + report.running.len() + report.unknown.len();
    if delivered > 0 && report.exited.len() == delivered {
        lines.push(format!("all {delivered} signalled process(es) exited"));
    } else if !report.exited.is_empty() {
        lines.push(format!(
            "{} of {delivered} signalled process(es) exited",
            report.exited.len()
        ));
    }
    if !report.running.is_empty() {
        lines.push(format!(
            "warning: PID(s) {} still running {} after {}; they may still be shutting down{}",
            crate::tree::format_pid_list(&report.running),
            settle_window_text(),
            mode.delivery_label(root.platform),
            force_hint(root, mode),
        ));
    }
    if !report.unknown.is_empty() {
        let details = report
            .unknown
            .iter()
            .map(|(pid, error)| format!("PID {pid}: {}", sanitize(error)))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("warning: could not confirm exit for {details}"));
    }
    if let Some(missing) = delivered
        .checked_sub(verified)
        .filter(|missing| *missing > 0)
    {
        lines.push(format!(
            "warning: could not confirm exit for {missing} signalled process(es) without a start identity"
        ));
    }
    lines.extend(ports_line(&report.ports));
    lines
}

/// The port line, or nothing when no confirmed port was polled.
pub(super) fn ports_line(status: &PortsStatus) -> Option<String> {
    match status {
        PortsStatus::NotChecked => None,
        PortsStatus::Cleared => Some("confirmed target ports are no longer visible".to_owned()),
        PortsStatus::StillVisible => Some(
            "warning: one or more confirmed ports are still visible after termination; another process may own them or shutdown may still be completing".to_owned(),
        ),
        PortsStatus::RefreshFailed(error) => Some(format!(
            "warning: collecting ports after termination failed; refresh manually to verify the port disappeared: {error}",
        )),
    }
}

/// Poll the root's confirmed ports with no exit checks, and return the line.
pub(super) fn ports_only_status_message(
    target: &KillTarget,
    collect_ports: &mut dyn FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
) -> Option<String> {
    let report = settle(
        &[],
        &target.ports,
        &mut SettleProbe {
            collect_ports,
            observe_exit: &mut |_| ExitObservation::Running,
            sleep: &mut std::thread::sleep,
        },
    );
    ports_line(&report.ports)
}

#[cfg(test)]
mod tests;
