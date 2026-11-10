//! Kickoutchi: a cross-platform TUI and CLI port janitor.
//!
//! This crate is internal application plumbing shared by the `kickoutchi` and
//! `kick` binaries. It is not a supported embedding API. Its bootstrap reads
//! process-global arguments and owns terminal, standard-I/O, and signal
//! lifecycle while it runs.

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Kickoutchi supports only Linux, macOS, and Windows");

/// Print a best-effort warning to stderr.
///
/// Used where a cleanup or restore step fails but the command can continue.
/// Write errors are ignored because callers include `Drop` and panic paths.
macro_rules! warn_stderr {
    ($($argument:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "warning: {}", format_args!($($argument)*));
    }};
}

mod app;
mod cli;
mod collector;
mod command;
mod config;
mod diagnostic;
mod display;
mod error;
mod input;
mod inspect;
mod labels;
mod model;
mod observation;
mod output;
mod owner_visibility;
mod platform;
mod probe;
mod process;
mod process_evidence;
mod protection;
mod public_output;
mod query;
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
        Some(mut command) => {
            if let Command::Why(why) = &mut command {
                why.detailed = args.verbose;
            }
            cli::run(&command, &config, watch_signal_guard).into()
        }
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
            // The terminal is restored before this branch.
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
