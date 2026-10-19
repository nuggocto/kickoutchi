//! Projection from authoritative snapshots into the legacy `PortEntry` view.

use crate::model::{Platform, PortEntry};

use super::{
    DERIVED_PORT_ENTRIES_MAX, NetworkSnapshot, ObservationError, OwnerObservation, PortRowSource,
    ProcessIdentity, snapshot_platform,
};

pub(crate) fn project_legacy(
    snapshot: &NetworkSnapshot,
) -> Result<Vec<PortEntry>, ObservationError> {
    project_legacy_with_limit(snapshot, DERIVED_PORT_ENTRIES_MAX, None, None)
}

pub(crate) fn project_legacy_target(
    snapshot: &NetworkSnapshot,
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, ObservationError> {
    project_legacy_with_limit(snapshot, DERIVED_PORT_ENTRIES_MAX, pid, port)
}

pub(crate) fn project_legacy_identities(
    snapshot: &NetworkSnapshot,
    identities: &std::collections::BTreeSet<ProcessIdentity>,
) -> Result<Vec<PortEntry>, ObservationError> {
    let platform = snapshot_platform(snapshot);
    let mut entries = Vec::new();
    for socket in &snapshot.sockets {
        for owner in &socket.owners {
            let OwnerObservation::Verified(identity) = owner else {
                continue;
            };
            if !identities.contains(identity) {
                continue;
            }
            // State belongs to the socket, so none of its owners can become a row.
            let Some(row) = snapshot.port_row_source(socket, Some(owner)) else {
                break;
            };
            if entries.len() == DERIVED_PORT_ENTRIES_MAX {
                return Err(ObservationError::LegacyProjectionLimitExceeded);
            }
            entries.push(legacy_entry(&row, platform));
        }
    }
    Ok(entries)
}

pub(super) fn project_legacy_with_limit(
    snapshot: &NetworkSnapshot,
    max_entries: usize,
    target_pid: Option<u32>,
    target_port: Option<u16>,
) -> Result<Vec<PortEntry>, ObservationError> {
    let descriptors = snapshot.port_entry_descriptors_matching_with_limit(
        target_pid,
        target_port,
        &[],
        max_entries,
    )?;
    let platform = snapshot_platform(snapshot);
    Ok(descriptors
        .iter()
        .map(|descriptor| legacy_entry(&snapshot.descriptor_row_source(descriptor), platform))
        .collect())
}

pub(super) const fn owner_pid(owner: &OwnerObservation) -> u32 {
    match owner {
        OwnerObservation::Verified(identity) => identity.pid,
        OwnerObservation::UnverifiedPid { pid, .. } => *pid,
    }
}

fn legacy_entry(row: &PortRowSource<'_>, platform: Platform) -> PortEntry {
    let process = row.process;
    PortEntry {
        protocol: row.socket.local_endpoint.protocol,
        local_addr: row.socket.local_endpoint.address,
        local_port: row.socket.local_endpoint.port.get(),
        state: row.state,
        pid: row.pid,
        process_name: process.and_then(|process| process.name.clone()),
        executable_path: process.and_then(|process| process.executable_path.clone()),
        command_line: process.and_then(|process| process.command_line.clone()),
        parent_pid: process.and_then(|process| process.parent_pid),
        parent_process_name: process.and_then(|process| process.parent_process_name.clone()),
        protected: false,
        platform,
        permission: row.permission(),
        process_identity: row.process_identity,
        ipv6_scope: row.socket.local_endpoint.ipv6_scope,
    }
}
