//! Protected-process matching and confirmation policy.
//!
//! The collector reports process facts. Configuration marks operationally
//! critical processes that require an additional warning before termination.

use std::borrow::Cow;
use std::path::Path;

use crate::model::{Platform, PortEntry};

const LINUX_COMM_MAX_BYTES: usize = 15;

const DEFAULT_PROTECTED_PROCESS_NAMES: [&str; 23] = [
    "docker",
    "docker.exe",
    "dockerd",
    "dockerd.exe",
    "docker-proxy",
    "docker-proxy.exe",
    "Docker Desktop.exe",
    "com.docker.backend",
    "com.docker.backend.exe",
    "postgres",
    "postgres.exe",
    "systemd",
    "System",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "WindowServer",
];

pub(crate) fn default_protected_processes() -> Vec<String> {
    DEFAULT_PROTECTED_PROCESS_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

/// Tag entries whose process identity matches the protected list.
pub(crate) fn mark_protected(entries: &mut [PortEntry], protected_names: &[String]) {
    for entry in entries {
        entry.protected |= is_protected_process(
            entry.platform,
            entry.process_name.as_deref(),
            entry.executable_path.as_deref(),
            protected_names,
        );
    }
}

/// One policy for owned rows, borrowed views, and watch filtering.
pub(crate) fn is_protected_process(
    platform: Platform,
    name: Option<&str>,
    executable_path: Option<&Path>,
    protected_names: &[String],
) -> bool {
    name.is_some_and(|name| is_protected_process_name(platform, name, protected_names))
        || (platform == Platform::Macos
            && executable_path
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .is_some_and(|name| protected_names.iter().any(|protected| protected == name)))
}

/// Platform-aware protected-name match.
///
/// Unix names are exact and case-sensitive. Linux also accepts the `/proc/comm`
/// 15-byte truncation of a longer configured protected name, because that is all
/// the collector can read from the kernel. macOS also accepts a configured name
/// followed by a process-title delimiter (`:` or ASCII whitespace). Windows names
/// match case-insensitively, following the platform convention. Arbitrary
/// substrings do not match, so `postgres-backup-helper` does not inherit
/// `postgres` protection.
pub(crate) fn is_protected_process_name(
    platform: Platform,
    process_name: &str,
    protected_names: &[String],
) -> bool {
    protected_names.iter().any(|protected| match platform {
        Platform::Windows => windows_process_name_eq(protected, process_name),
        Platform::Linux => {
            protected == process_name
                || (protected.len() > LINUX_COMM_MAX_BYTES
                    && linux_comm_prefix(protected).as_ref() == process_name)
        }
        Platform::Macos => macos_process_name_matches(protected, process_name),
    })
}

fn macos_process_name_matches(protected: &str, process_name: &str) -> bool {
    protected == process_name
        || (!protected.is_empty()
            && process_name.strip_prefix(protected).is_some_and(|suffix| {
                suffix
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == ':' || ch.is_ascii_whitespace())
            }))
}

pub(crate) fn windows_process_name_eq(left: &str, right: &str) -> bool {
    if left.is_ascii() && right.is_ascii() {
        return left.eq_ignore_ascii_case(right);
    }

    #[cfg(any(windows, test))]
    {
        left.chars()
            .flat_map(char::to_uppercase)
            .eq(right.chars().flat_map(char::to_uppercase))
    }

    // A Windows row cannot exist in a non-Windows production collector. Keep
    // the synthetic branch small while native Windows uses Unicode casing.
    #[cfg(all(not(windows), not(test)))]
    left.eq_ignore_ascii_case(right)
}

fn linux_comm_prefix(name: &str) -> Cow<'_, str> {
    if name.len() <= LINUX_COMM_MAX_BYTES {
        return Cow::Borrowed(name);
    }
    String::from_utf8_lossy(&name.as_bytes()[..LINUX_COMM_MAX_BYTES])
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{default_protected_processes, is_protected_process_name, mark_protected};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    fn entry(port: u16, name: Option<&str>, platform: Platform) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: name.map(Into::into),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    #[test]
    fn defaults_cover_documented_safety_names() {
        let defaults = default_protected_processes();
        assert!(defaults.contains(&"docker".to_owned()));
        assert!(defaults.contains(&"dockerd".to_owned()));
        assert!(defaults.contains(&"dockerd.exe".to_owned()));
        assert!(defaults.contains(&"docker-proxy".to_owned()));
        assert!(defaults.contains(&"com.docker.backend".to_owned()));
        assert!(defaults.contains(&"postgres".to_owned()));
        assert!(defaults.contains(&"postgres.exe".to_owned()));
        assert!(defaults.contains(&"systemd".to_owned()));
        assert!(defaults.contains(&"svchost.exe".to_owned()));
        assert!(defaults.contains(&"lsass.exe".to_owned()));
        assert!(defaults.contains(&"explorer.exe".to_owned()));
        assert!(defaults.contains(&"WindowServer".to_owned()));
    }

    #[test]
    fn unix_matching_is_exact_and_case_sensitive() {
        let protected = vec!["postgres".to_owned()];

        assert!(is_protected_process_name(
            Platform::Linux,
            "postgres",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            "Postgres",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            "postgres-backup-helper",
            &protected
        ));
    }

    #[test]
    fn linux_matching_accepts_kernel_comm_truncation_for_long_configured_names() {
        let protected = vec!["postgres-backup-helper".to_owned()];

        assert!(is_protected_process_name(
            Platform::Linux,
            "postgres-backup",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Macos,
            "postgres-backup",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            "postgres",
            &protected
        ));
    }

    #[test]
    fn linux_matching_reproduces_lossy_kernel_comm_truncation_mid_utf8() {
        let protected = vec![format!("{}é-helper", "a".repeat(14))];
        let kernel_comm = format!("{}�", "a".repeat(14));
        let boundary_protected = vec![format!("{}é-helper", "a".repeat(13))];
        let boundary_comm = format!("{}é", "a".repeat(13));

        assert!(is_protected_process_name(
            Platform::Linux,
            &kernel_comm,
            &protected,
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            &"a".repeat(14),
            &protected,
        ));
        assert!(is_protected_process_name(
            Platform::Linux,
            &boundary_comm,
            &boundary_protected,
        ));
    }

    #[test]
    fn macos_matching_accepts_only_strict_process_title_boundaries() {
        let protected = vec!["postgres".to_owned()];

        for name in ["postgres", "postgres: checkpointer", "postgres worker"] {
            assert!(is_protected_process_name(Platform::Macos, name, &protected));
        }
        for name in [
            "Postgres",
            "postgres-backup-helper",
            "postgres.helper",
            "postgres/worker",
        ] {
            assert!(!is_protected_process_name(
                Platform::Macos,
                name,
                &protected
            ));
        }
    }

    #[test]
    fn windows_matching_is_exact_but_case_insensitive() {
        let protected = vec!["explorer.exe".to_owned(), "äpp.exe".to_owned()];

        assert!(is_protected_process_name(
            Platform::Windows,
            "EXPLORER.EXE",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Windows,
            "explorer.exe.old",
            &protected
        ));
        assert!(is_protected_process_name(
            Platform::Windows,
            "ÄPP.EXE",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Windows,
            "ÄPP.EXE.OLD",
            &protected
        ));
    }

    #[test]
    fn marking_skips_unknown_names_and_preserves_exactness() {
        let protected = vec!["postgres".to_owned()];
        let mut rows = vec![
            entry(5432, Some("postgres"), Platform::Linux),
            entry(5433, Some("postgres-backup-helper"), Platform::Linux),
            entry(53, None, Platform::Linux),
        ];

        mark_protected(&mut rows, &protected);

        assert!(rows[0].protected);
        assert!(!rows[1].protected);
        assert!(!rows[2].protected);
    }

    #[test]
    fn macos_marking_uses_exact_executable_basename_when_available() {
        let protected = vec!["postgres".to_owned()];
        let mut exact = entry(5432, Some("renamed process"), Platform::Macos);
        exact.executable_path = Some(std::path::PathBuf::from("/opt/postgres").into());
        let mut prefixed = entry(5433, None, Platform::Macos);
        prefixed.executable_path =
            Some(std::path::PathBuf::from("/opt/postgres-backup-helper").into());
        let mut rows = [exact, prefixed];

        mark_protected(&mut rows, &protected);

        assert!(rows[0].protected);
        assert!(!rows[1].protected);
    }
}
