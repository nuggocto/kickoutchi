//! Kickoutchi: a cross-platform TUI and CLI port janitor.
//!
//! This crate is internal application plumbing shared by the `kickoutchi` and
//! `kick` binaries. It is not a supported embedding API. Its bootstrap reads
//! process-global arguments and owns terminal, standard-I/O, tracing, and signal
//! lifecycle while it runs.

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Kickoutchi supports only Linux, macOS, and Windows");

mod app;
mod cli;
mod collector;
mod command;
mod config;
mod diagnostic;
mod display;
mod docker;
mod error;
mod input;
mod inspect;
mod labels;
mod model;
mod observation;
mod output;
mod platform;
mod probe;
mod process;
mod process_evidence;
mod protection;
mod public_output;
mod query;
#[cfg(fuzzing)]
mod release_archive_path;
#[cfg(test)]
mod test_support;
mod tree;
mod ui;
mod watch;

#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind as ClapErrorKind;

use crate::cli::{Cli, Command, ExitReason, WatchSignalGuard};
use crate::config::Config;
use crate::display::sanitize_multiline;

/// Binary bootstrap entry point shared by `kickoutchi` and `kick`.
///
/// This remains public only because Cargo builds each binary as a separate crate.
/// Argument errors are rendered here rather than by clap's process-exiting helper
/// so untrusted argv text passes through the terminal sanitizer.
#[doc(hidden)]
#[must_use]
pub fn run() -> ExitCode {
    #[cfg(windows)]
    if tree::windows::freeze_probe_requested() {
        return tree::windows::run_freeze_probe_child();
    }

    // Install tracing before clap renders errors, without replacing an existing
    // subscriber or interpreting other argv content.
    init_tracing(verbose_requested());
    let args = match Cli::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) {
                let rendered = sanitize_multiline(&error.to_string());
                return match write_cli_stdout(io::stdout().lock(), &rendered) {
                    Ok(()) => ExitReason::Success.into(),
                    Err(error) => {
                        eprintln!("error: writing stdout failed: {error}");
                        ExitReason::Failure.into()
                    }
                };
            }
            let rendered = sanitize_multiline(&error.to_string());
            eprintln!("{}", rendered.trim_end());
            return ExitReason::InvalidArguments.into();
        }
    };
    if args.verbose {
        tracing::debug!("verbose diagnostics enabled");
    }

    let watch_signal_guard = if matches!(args.command.as_ref(), Some(Command::Watch(_))) {
        match WatchSignalGuard::install() {
            Ok(guard) => Some(guard),
            Err(error) => {
                eprintln!(
                    "error: installing Ctrl-C handler failed: {}",
                    sanitize_multiline(&error.to_string())
                );
                return ExitReason::Failure.into();
            }
        }
    } else {
        None
    };

    let mut config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            if watch_signal_guard.is_some() && WatchSignalGuard::cancelled() {
                return ExitReason::Success.into();
            }
            eprintln!("error: {}", error.render_terminal());
            return ExitReason::Failure.into();
        }
    };
    config.apply_cli_overrides(args.refresh_interval);

    match args.command {
        Some(command) => cli::run(&command, &config, watch_signal_guard).into(),
        None => run_tui(&config),
    }
}

/// Run the TUI path. [`ui::run_owned`] scopes terminal restoration and the panic
/// hook to this path. The headless CLI path never enters the alternate screen
/// and keeps the existing hook.
///
/// Order matters for safety: install the panic hook *before* entering the
/// alternate screen, so a panic during setup or rendering still restores the
/// terminal before anything prints. Normal exits and `?`-errors are already
/// covered by the `Drop` guard inside [`ui::run`].
fn run_tui(config: &Config) -> ExitCode {
    let result = match ui::run_owned(|| ui::run(config)) {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(()) => ExitReason::Success.into(),
        Err(error) => {
            // The terminal is restored before this branch. Print the fatal error
            // once because tracing also writes to stderr.
            eprintln!("error: {}", sanitize_multiline(&error.to_string()));
            ExitReason::Failure.into()
        }
    }
}

fn write_cli_stdout(mut writer: impl Write, text: &str) -> io::Result<()> {
    match writer
        .write_all(text.as_bytes())
        .and_then(|()| writer.flush())
    {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

/// Set up tracing for diagnostics written outside rendered TUI frames.
///
/// Logs go to stderr during startup, shutdown, panic handling, and fatal-error
/// reporting. The alternate screen owns stdout.
fn init_tracing(verbose: bool) {
    // Embedders own the process-global subscriber; an existing one is valid.
    let max_level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_max_level(max_level)
        .try_init();
}

fn verbose_requested() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|argument| argument == "--verbose" || argument == "-v")
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::write_cli_stdout;

    struct FailingWriter(io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn help_output_treats_a_closed_pipe_as_success() {
        assert!(write_cli_stdout(FailingWriter(io::ErrorKind::BrokenPipe), "help").is_ok());
    }

    #[test]
    fn help_output_preserves_non_pipe_write_failures() {
        let error = write_cli_stdout(FailingWriter(io::ErrorKind::PermissionDenied), "help")
            .expect_err("permission errors must remain failures");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
