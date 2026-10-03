//! The `list` command: filter and sort the collected port table, then print
//! it as the human-facing table or the stable JSON contract.

use std::io::{self, BufWriter, ErrorKind, Write};

use crate::config::Config;
use crate::diagnostic::requested_diagnostic_port;
use crate::observation::NetworkSnapshot;
use crate::output;
use crate::owner_visibility::OwnerVisibility;
use crate::query::{self, QueryCapabilities, QueryOptions};

use super::{ExitReason, ListArgs, maybe_print_no_match_diagnostic};

pub(super) fn run_list_snapshot(
    args: &ListArgs,
    config: &Config,
    snapshot: &NetworkSnapshot,
) -> ExitReason {
    run_list_snapshot_with_writer(args, config, snapshot, &mut io::stdout().lock())
}

fn run_list_snapshot_with_writer(
    args: &ListArgs,
    config: &Config,
    snapshot: &NetworkSnapshot,
    writer: &mut impl Write,
) -> ExitReason {
    // Bound bulk output memory while amortizing line-buffered stdout writes.
    let mut buffered = BufWriter::with_capacity(output::OUTPUT_BUFFER_BYTES, writer);
    let result = run_list_snapshot_buffered(args, config, snapshot, &mut buffered);
    // Success explicitly flushes. Discard pending bytes after failure so Drop
    // cannot retry a write after the command has already selected its exit code.
    let _ = buffered.into_parts();
    result
}

fn run_list_snapshot_buffered(
    args: &ListArgs,
    config: &Config,
    snapshot: &NetworkSnapshot,
    writer: &mut impl Write,
) -> ExitReason {
    if args.snapshot_json {
        return match crate::public_output::write_snapshot_json(writer, snapshot, &config.labels)
            .and_then(|()| {
                writer
                    .flush()
                    .map_err(crate::public_output::PublicOutputError::from)
            }) {
            Ok(()) => ExitReason::Success,
            Err(error) if error.io_error_kind() == Some(ErrorKind::BrokenPipe) => {
                ExitReason::Success
            }
            Err(error) => {
                eprintln!("error: rendering snapshot JSON failed: {error}");
                ExitReason::Failure
            }
        };
    }

    let descriptors = match snapshot.port_entry_descriptors(&config.protected_processes) {
        Ok(descriptors) => descriptors,
        Err(error) => {
            eprintln!("error: projecting collected ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    let view_at = |index: usize| {
        let view = snapshot.port_entry_view(&descriptors[index]);
        let label = config.labels.resolve_parts(
            view.protocol,
            view.local_addr,
            view.local_port,
            view.ipv6_scope,
        );
        view.with_label(label)
    };
    let sort_mode = args.sort.unwrap_or(config.default_sort);
    let diagnostic_port =
        requested_diagnostic_port(args.port, args.filter.as_deref().unwrap_or_default());
    let result = match query::query_view_indices_by(
        descriptors.len(),
        view_at,
        QueryOptions {
            port: args.port,
            process: args.process.as_deref(),
            filter_text: args.filter.as_deref().unwrap_or_default(),
            sort_mode,
            hide_system_processes: config.hide_system_processes,
            capabilities: QueryCapabilities::LIST,
        },
    ) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("error: invalid filter: {error}");
            return ExitReason::InvalidArguments;
        }
    };
    let visible_indices = result.indices;

    if args.json {
        match output::write_view_json(writer, view_at, &visible_indices) {
            Ok(()) => {}
            Err(error) if error.io_error_kind() == Some(ErrorKind::BrokenPipe) => {
                return ExitReason::Success;
            }
            Err(error) => {
                eprintln!("error: rendering JSON failed: {error}");
                return ExitReason::Failure;
            }
        }
    } else if visible_indices.is_empty() {
        let suffix = if result.explicit_filter_active {
            " match the filter"
        } else if result.hidden_system_process_count > 0 {
            " visible"
        } else {
            ""
        };
        if let Err(error) = writeln!(writer, "no open ports{suffix}") {
            return output_error_reason(&error);
        }
        maybe_print_no_match_diagnostic(diagnostic_port, (0..descriptors.len()).map(view_at));
    } else if let Err(error) =
        output::write_view_table(writer, view_at, &visible_indices, !config.labels.is_empty())
    {
        return output_error_reason(&error);
    }

    if let Err(error) = writer.flush() {
        return output_error_reason(&error);
    }

    // Explain `-` cells on stderr so stdout stays a plain table.
    if !args.json {
        print_owner_notes(snapshot, &descriptors, &visible_indices);
    }

    // An empty *filtered* result exits 3, so scripts can probe occupancy
    // (`kickoutchi list --port 3000 && echo busy`). An empty *unfiltered* list
    // means a quiet machine and is successful.
    if result.explicit_filter_active && visible_indices.is_empty() {
        return ExitReason::NoMatch;
    }
    ExitReason::Success
}

fn print_owner_notes(
    snapshot: &NetworkSnapshot,
    descriptors: &[crate::observation::PortEntryDescriptor],
    visible_indices: &[usize],
) {
    let rows = visible_indices.iter().map(|&index| {
        let descriptor = &descriptors[index];
        let view = snapshot.port_entry_view(descriptor);
        (
            view.pid.is_some(),
            view.process_name.is_some(),
            snapshot.descriptor_socket(descriptor),
        )
    });
    for note in OwnerVisibility::of(snapshot).table_notes(rows) {
        eprintln!("{note}");
    }
}

fn output_error_reason(error: &io::Error) -> ExitReason {
    if error.kind() == ErrorKind::BrokenPipe {
        ExitReason::Success
    } else {
        eprintln!("error: writing output failed: {error}");
        ExitReason::Failure
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::run_list_snapshot_with_writer;
    use crate::cli::{ExitReason, ListArgs};
    use crate::config::Config;
    use crate::labels::{LabelInput, LabelRegistry};
    use crate::model::SortMode;

    fn args(json: bool) -> ListArgs {
        ListArgs {
            port: None,
            process: None,
            filter: None,
            sort: Some(SortMode::Port),
            json,
            snapshot_json: false,
        }
    }

    fn snapshot_args() -> ListArgs {
        ListArgs {
            snapshot_json: true,
            ..args(false)
        }
    }

    fn run_list_with_writer(
        args: &ListArgs,
        config: &Config,
        rows: &[crate::model::PortEntry],
        writer: &mut impl Write,
    ) -> ExitReason {
        let snapshot = crate::observation::snapshot_from_test_rows(rows.to_vec());
        run_list_snapshot_with_writer(args, config, &snapshot, writer)
    }

    #[test]
    fn list_streams_sorted_source_indexes_in_legacy_json_shape() {
        let rows = [
            crate::cli::test_support::entry(5000),
            crate::cli::test_support::entry(3000),
        ];
        let mut output = Vec::new();

        let reason = run_list_with_writer(&args(true), &Config::default(), &rows, &mut output);
        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
        let ports = value
            .as_array()
            .expect("top-level array")
            .iter()
            .map(|row| row["local_port"].as_u64().expect("numeric port"))
            .collect::<Vec<_>>();

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(ports, [3000, 5000]);
        assert!(output.ends_with(b"\n"));
    }

    #[test]
    fn snapshot_mode_bypasses_legacy_projection_and_visibility_filters() {
        let mut row = crate::cli::test_support::entry(3000);
        row.process_name = Some(std::sync::Arc::from("systemd"));
        let rows = [row];
        let config = Config {
            hide_system_processes: true,
            ..Config::default()
        };
        let mut legacy_output = Vec::new();
        assert_eq!(
            run_list_with_writer(&args(false), &config, &rows, &mut legacy_output),
            ExitReason::Success,
        );
        assert_eq!(
            String::from_utf8(legacy_output).expect("legacy output is UTF-8"),
            "no open ports visible\n",
        );

        let mut snapshot = crate::observation::snapshot_from_test_rows(rows.to_vec());
        snapshot.sockets[0].state = crate::observation::SocketState::Established;
        let mut output = Vec::new();

        let reason =
            run_list_snapshot_with_writer(&snapshot_args(), &config, &snapshot, &mut output);
        let value: serde_json::Value = serde_json::from_slice(&output).expect("snapshot JSON");

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(value["schema"], "kickoutchi.snapshot");
        assert_eq!(value["version"], 1);
        assert_eq!(value["sockets"][0]["state"]["kind"], "established");
        assert_eq!(value["sockets"].as_array().map(Vec::len), Some(1));
        assert!(value.is_object());
    }

    #[test]
    fn configured_labels_annotate_table_json_and_filters() {
        let rows = [
            crate::cli::test_support::entry(3000),
            crate::cli::test_support::entry(5000),
        ];
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "127.0.0.1".to_owned(),
                port: 3000,
                scope_id: None,
                label: "web dev".to_owned(),
            }])
            .unwrap(),
            ..Config::default()
        };

        let mut table = Vec::new();
        assert_eq!(
            run_list_with_writer(&args(false), &config, &rows, &mut table),
            ExitReason::Success
        );
        let table = String::from_utf8(table).unwrap();
        assert!(table.lines().next().unwrap().ends_with("LABEL"), "{table}");
        assert!(table.contains("web dev"), "{table}");

        let mut json = Vec::new();
        assert_eq!(
            run_list_with_writer(&args(true), &config, &rows, &mut json),
            ExitReason::Success
        );
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value[0]["label"], "web dev");
        assert!(value[1]["label"].is_null());

        let mut filtered_args = args(false);
        filtered_args.filter = Some("label:web".to_owned());
        let mut filtered = Vec::new();
        assert_eq!(
            run_list_with_writer(&filtered_args, &config, &rows, &mut filtered),
            ExitReason::Success
        );
        let filtered = String::from_utf8(filtered).unwrap();
        assert!(filtered.contains("3000"), "{filtered}");
        assert!(!filtered.contains("5000"), "{filtered}");
    }

    #[test]
    fn unmatched_configured_selector_still_enables_label_column() {
        let rows = [crate::cli::test_support::entry(3000)];
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "*".to_owned(),
                port: 5000,
                scope_id: None,
                label: "unused".to_owned(),
            }])
            .unwrap(),
            ..Config::default()
        };
        let mut output = Vec::new();

        assert_eq!(
            run_list_with_writer(&args(false), &config, &rows, &mut output),
            ExitReason::Success
        );
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.lines().next().unwrap().ends_with("LABEL"),
            "{output}"
        );
        assert!(!output.contains("unused"), "{output}");
    }

    struct FailingWriter {
        bytes_before_failure: usize,
        write_error: Option<io::ErrorKind>,
        flush_error: Option<io::ErrorKind>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes_before_failure == 0 {
                return self.write_error.map_or(Ok(bytes.len()), |kind| {
                    Err(io::Error::new(kind, "injected write failure"))
                });
            }
            let written = bytes.len().min(self.bytes_before_failure);
            self.bytes_before_failure -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_error.map_or(Ok(()), |kind| {
                Err(io::Error::new(kind, "injected flush failure"))
            })
        }
    }

    #[test]
    fn writer_error_matrix_covers_formats_stages_and_empty_outputs() {
        let populated = [crate::cli::test_support::entry(3000)];
        for json in [false, true] {
            for rows in [&[][..], &populated[..]] {
                for flush_only in [false, true] {
                    for (kind, expected) in [
                        (io::ErrorKind::BrokenPipe, ExitReason::Success),
                        (io::ErrorKind::Other, ExitReason::Failure),
                    ] {
                        let mut writer = FailingWriter {
                            bytes_before_failure: if flush_only { 4_096 } else { 1 },
                            write_error: (!flush_only).then_some(kind),
                            flush_error: flush_only.then_some(kind),
                        };

                        assert_eq!(
                            run_list_with_writer(
                                &args(json),
                                &Config::default(),
                                rows,
                                &mut writer,
                            ),
                            expected,
                            "json={json} empty={} flush_only={flush_only} kind={kind:?}",
                            rows.is_empty(),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bulk_output_stops_at_the_first_write_failure_without_retrying_on_drop() {
        struct FailOnce {
            calls: usize,
            kind: io::ErrorKind,
        }

        impl Write for FailOnce {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                assert_eq!(self.calls, 1, "failed output must not be retried");
                Err(io::Error::new(self.kind, "injected bulk write failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("a failed write must stop before flushing");
            }
        }

        let rows = (1000..3000)
            .map(crate::cli::test_support::entry)
            .collect::<Vec<_>>();
        for options in [args(false), args(true), snapshot_args()] {
            for (kind, expected) in [
                (io::ErrorKind::BrokenPipe, ExitReason::Success),
                (io::ErrorKind::Other, ExitReason::Failure),
            ] {
                let mut writer = FailOnce { calls: 0, kind };
                assert_eq!(
                    run_list_with_writer(&options, &Config::default(), &rows, &mut writer),
                    expected,
                );
                assert_eq!(writer.calls, 1);
            }
        }
    }

    #[test]
    fn snapshot_writer_errors_treat_only_broken_pipe_as_success() {
        let snapshot =
            crate::observation::snapshot_from_test_rows(vec![crate::cli::test_support::entry(
                3000,
            )]);
        for flush_only in [false, true] {
            for (kind, expected) in [
                (io::ErrorKind::BrokenPipe, ExitReason::Success),
                (io::ErrorKind::Other, ExitReason::Failure),
            ] {
                let mut writer = FailingWriter {
                    bytes_before_failure: if flush_only { 1_000_000 } else { 1 },
                    write_error: (!flush_only).then_some(kind),
                    flush_error: flush_only.then_some(kind),
                };
                assert_eq!(
                    run_list_snapshot_with_writer(
                        &snapshot_args(),
                        &Config::default(),
                        &snapshot,
                        &mut writer,
                    ),
                    expected,
                    "flush_only={flush_only} kind={kind:?}",
                );
            }
        }
    }
}
