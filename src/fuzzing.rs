//! Pure, bounded parser entry points for cargo-fuzz.
//!
//! This module exists only under `--cfg fuzzing`; it is absent from ordinary
//! library and release builds.

/// Exercise config decoding, TOML parsing, and semantic validation.
pub fn config(bytes: &[u8]) {
    crate::config::exercise_config_parser(bytes);
}

/// Exercise bounded Linux `/proc` stat, status, and socket-table parsing.
#[cfg(target_os = "linux")]
pub fn linux_proc(bytes: &[u8]) {
    crate::platform::linux::exercise_proc_parser(bytes);
}
