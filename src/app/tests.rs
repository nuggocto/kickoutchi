use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{
    App, ContextWorker, ModalKind, RefreshWorker, RowKey, preserved_selection,
    termination_status_line,
};
use crate::config::Config;
use crate::input::Action;
use crate::model::{
    DockerContainerPort, DockerPortContext, PermissionStatus, Platform, PortEntry, PortEntryView,
    ProcessContext, Protocol, SocketState, SortMode,
};
use crate::observation::Ipv6Scope;
use crate::process::{ConfirmationRequirement, KillMode, KillTarget, TerminationOutcome};
use crate::test_support::port_entry;

// Complete the same worker channel consumed by production, without a thread or host I/O.
fn start_test_refresh(app: &mut App, rows: Vec<PortEntry>) {
    app.refresh_with(|| {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Ok(Ok(crate::observation::snapshot_from_test_rows(rows))))
            .expect("refresh receiver is retained");
        Ok(receiver)
    });
}

fn entry(port: u16, name: Option<&str>) -> PortEntry {
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
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        process_identity: Some(crate::observation::ProcessIdentity {
            pid: u32::from(port),
            start_marker: crate::observation::ProcessStartMarker::linux(55)
                .expect("test marker is nonzero"),
        }),
        ipv6_scope: None,
    }
}

fn entry_without_pid(port: u16) -> PortEntry {
    let mut row = entry(port, Some("hidden"));
    row.pid = None;
    row.permission = PermissionStatus::Partial;
    row
}

fn app_with_rows(rows: Vec<PortEntry>) -> App {
    let config = Config {
        default_sort: SortMode::Port,
        protected_processes: vec!["postgres".to_owned()],
        ..Config::default()
    };
    App::from_rows(rows, &config)
}

fn context(start_time_ticks: u64) -> ProcessContext {
    ProcessContext {
        process_start_time_marker: crate::observation::ProcessStartMarker::linux(start_time_ticks)
            .ok(),
        ..ProcessContext::default()
    }
}

fn docker_context() -> DockerPortContext {
    DockerPortContext {
        containers: vec![DockerContainerPort {
            id: "abc123".to_owned(),
            name: "postgres-dev".to_owned(),
            compose_project: None,
            compose_service: None,
            host_port: 5432,
            container_port: 5432,
            protocol: Protocol::Tcp,
        }],
        truncated: false,
    }
}

fn finish_selected_context(app: &mut App, context: ProcessContext) {
    let key = RowKey::from(app.selected_row().expect("test app has selected row"));
    let (sender, receiver) = mpsc::channel();
    sender
        .send(Ok(context))
        .expect("test context result must send before polling");
    app.context_worker = Some(ContextWorker {
        key,
        receiver,
        stale: false,
    });
    app.poll_process_context();
}

fn set_confirmation_start_time(app: &mut App, start_time_ticks: u64) {
    finish_selected_context(app, context(start_time_ticks));
}

#[test]
fn preserved_selection_distinguishes_ipv6_interface_scopes() {
    let mut first = port_entry(8080, Some(42), Protocol::Tcp, "service");
    first.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
    first.ipv6_scope = Some(Ipv6Scope::interface_index(1).unwrap());
    let mut second = first.clone();
    second.ipv6_scope = Some(Ipv6Scope::interface_index(2).unwrap());
    let rows = [first, second];
    let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
    let selected_key = RowKey::from(views[1]);
    let selected_source_rows = views
        .iter()
        .copied()
        .map(|view| RowKey::from(view) == selected_key)
        .collect::<Vec<_>>();

    assert_ne!(RowKey::from(views[0]), selected_key);
    assert_eq!(
        preserved_selection(&[0, 1], Some(&selected_source_rows), 0),
        Some(1)
    );
}

#[test]
fn selected_context_can_attach_docker_metadata_without_a_pid() {
    let row = entry_without_pid(5432);

    let context =
        super::collect_selected_process_context_with(PortEntryView::from(&row), true, |_| {
            Some(docker_context())
        });

    assert_eq!(context.children.children.len(), 0);
    assert!(context.process_start_time_marker.is_none());
    assert_eq!(
        context
            .docker
            .as_ref()
            .and_then(DockerPortContext::single_container)
            .map(|container| container.name.as_str()),
        Some("postgres-dev"),
    );
}

#[test]
fn selected_context_requests_docker_enrichment_without_a_rendering_gate() {
    let mut row = entry(5432, Some("docker-proxy"));
    row.executable_path = Some(std::path::PathBuf::from("/usr/bin/docker-proxy").into());
    let enrichment_requested = Cell::new(false);

    let _context =
        super::collect_selected_process_context_with(PortEntryView::from(&row), true, |_| {
            enrichment_requested.set(true);
            None
        });

    assert!(enrichment_requested.get());
}

#[test]
fn disabled_docker_enrichment_never_invokes_the_enricher() {
    let row = entry(5432, Some("docker-proxy"));
    let enrichment_requested = Cell::new(false);

    let context =
        super::collect_selected_process_context_with(PortEntryView::from(&row), false, |_| {
            enrichment_requested.set(true);
            Some(docker_context())
        });

    assert!(!enrichment_requested.get());
    assert!(context.docker.is_none());
}

#[test]
fn starts_sorted_and_selects_first_row() {
    let app = app_with_rows(vec![entry(5173, Some("vite")), entry(3000, Some("node"))]);

    assert_eq!(app.rows().next().map(|row| row.local_port), Some(3000));
    assert_eq!(app.selected_index(), Some(0));
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
}

#[test]
fn table_selection_never_requests_details_or_docker_context() {
    let mut app = app_with_rows(vec![entry(1, Some("one")), entry(2, Some("two"))]);

    app.apply_action(Action::MoveUp);
    assert_eq!(app.selected_index(), Some(0));
    assert_eq!(app.selected_process_context(), None);

    app.apply_action(Action::MoveDown);
    assert_eq!(app.selected_index(), Some(1));
    assert_eq!(app.selected_process_context(), None);
    assert!(app.context_worker.is_none());

    app.apply_action(Action::MoveDown);
    assert_eq!(app.selected_index(), Some(1));
    assert_eq!(app.selected_process_context(), None);
}

#[test]
fn empty_rows_have_no_selection_and_no_details_modal() {
    let mut app = app_with_rows(Vec::new());

    assert_eq!(app.selected_index(), None);
    assert_eq!(app.selected_process_context(), None);
    app.apply_action(Action::MoveDown);
    app.apply_action(Action::OpenDetails);
    assert_eq!(app.modal(), ModalKind::None);
}

#[test]
fn modal_and_quit_actions_update_state() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    assert_eq!(app.selected_process_context(), None);
    app.apply_action(Action::OpenDetails);
    assert_eq!(app.modal(), ModalKind::Details);
    assert!(app.selected_process_context_loading());
    assert_eq!(app.selected_process_context(), None);

    finish_selected_context(&mut app, context(55));
    assert!(app.selected_process_context().is_some());

    app.apply_action(Action::CloseModal);
    assert_eq!(app.modal(), ModalKind::None);

    app.apply_action(Action::OpenHelp);
    assert_eq!(app.modal(), ModalKind::Help);

    app.apply_action(Action::Quit);
    assert!(app.should_quit());
}

#[test]
fn details_context_is_single_flight_and_latest_selection_wins() {
    let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);
    let first_key = RowKey::from(app.selected_row().expect("first row is selected"));
    let (first_sender, first_receiver) = mpsc::channel();
    app.context_worker = Some(ContextWorker {
        key: first_key,
        receiver: first_receiver,
        stale: false,
    });

    app.apply_action(Action::OpenDetails);
    app.apply_action(Action::CloseModal);
    app.apply_action(Action::MoveDown);
    let latest_key = RowKey::from(app.selected_row().expect("second row is selected"));
    app.apply_action(Action::OpenDetails);

    assert_eq!(
        app.context_worker.as_ref().map(|worker| worker.key),
        Some(first_key),
        "the in-flight worker must not be replaced",
    );
    assert!(app.context_requested);

    first_sender
        .send(Ok(context(55)))
        .expect("the first worker result must be delivered");
    app.poll_process_context();

    assert_eq!(app.selected_process_context(), None);
    assert!(!app.context_requested);
    assert_eq!(
        app.context_worker.as_ref().map(|worker| worker.key),
        Some(latest_key),
        "the newest selection starts only after the first worker drains",
    );
}

#[test]
fn terminate_key_opens_normal_confirmation_for_selected_pid() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::RequestTerminate);

    let confirmation = app
        .kill_confirmation()
        .expect("termination request opens confirmation");
    assert_eq!(app.modal(), ModalKind::ConfirmKill);
    assert_eq!(confirmation.target.pid, 3000);
    assert_eq!(confirmation.mode, KillMode::Terminate);
    assert_eq!(confirmation.requirement, ConfirmationRequirement::Yes);
}

#[test]
fn terminate_confirmation_keeps_snapshot_identity_while_context_loads() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::RequestTerminate);

    assert!(app.selected_process_context_loading());
    assert_eq!(
        app.kill_confirmation()
            .and_then(|confirmation| confirmation.target.process_start_time_marker),
        crate::observation::ProcessStartMarker::linux(55).ok(),
    );

    finish_selected_context(&mut app, context(55));

    assert_eq!(
        app.kill_confirmation()
            .and_then(|confirmation| confirmation.target.process_start_time_marker),
        crate::observation::ProcessStartMarker::linux(55).ok(),
    );
}

#[test]
fn yes_confirmation_waits_for_process_metadata_before_executing() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::RequestTerminate);
    app.apply_action(Action::KillInputAppend('y'));

    let confirmation = app
        .kill_confirmation()
        .expect("confirmation remains open while metadata loads");
    assert_eq!(app.modal(), ModalKind::ConfirmKill);
    assert!(
        confirmation
            .error
            .as_deref()
            .is_some_and(|error| error.contains("still reading process metadata")),
    );
}

#[test]
fn unknown_failure_status_is_sanitized_for_tui() {
    let row = entry(3000, Some("node"));
    let target = KillTarget::from_entries(3000, [PortEntryView::from(&row)], None);

    let status = termination_status_line(
        &target,
        KillMode::Terminate,
        &TerminationOutcome::UnknownFailure("\x1b[31mboom\nnext".to_owned()),
    );

    assert!(status.contains("boom next"), "{status}");
    assert!(!status.contains('\x1b'), "{status}");
    assert!(!status.contains('\n'), "{status}");
}

#[test]
fn confirmation_lists_all_ports_owned_by_selected_pid_from_full_snapshot() {
    let mut app = app_with_rows(vec![
        port_entry(3000, Some(18422), Protocol::Tcp, "node"),
        port_entry(5173, Some(18422), Protocol::Udp, "node"),
        port_entry(8000, Some(18001), Protocol::Tcp, "cursor-agent"),
    ]);
    app.apply_action(Action::StartSearch);
    app.apply_action(Action::SearchAppend('3'));
    app.apply_action(Action::SearchAppend('0'));
    assert_eq!(app.rows().len(), 1);

    app.apply_action(Action::RequestTerminate);

    let confirmation = app
        .kill_confirmation()
        .expect("termination request opens confirmation");
    assert_eq!(confirmation.target.pid, 18422);
    assert_eq!(confirmation.target.ports.len(), 2);
    assert!(
        confirmation
            .target
            .ports_text()
            .contains("TCP 127.0.0.1:3000")
    );
    assert!(
        confirmation
            .target
            .ports_text()
            .contains("UDP 127.0.0.1:5173")
    );
}

#[test]
fn force_key_uses_force_word_confirmation() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::RequestForceKill);

    let confirmation = app
        .kill_confirmation()
        .expect("force request opens confirmation");
    assert_eq!(app.modal(), ModalKind::ConfirmKill);
    assert_eq!(confirmation.mode, KillMode::Force);
    assert_eq!(confirmation.requirement, ConfirmationRequirement::ForceWord);
}

#[test]
fn wrong_confirmation_word_rejects_and_keeps_the_modal_open() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestForceKill);
    for ch in "yes".chars() {
        app.apply_action(Action::KillInputAppend(ch));
    }

    app.apply_action(Action::SubmitKillConfirmation);

    assert_eq!(app.modal(), ModalKind::ConfirmKill);
    let confirmation = app
        .kill_confirmation()
        .expect("rejected submit must keep the confirmation pending");
    assert_eq!(confirmation.input, "yes");
    let error = confirmation
        .error
        .as_deref()
        .expect("rejected submit sets the inline error");
    assert!(error.contains("type force"), "{error}");
    assert!(app.kill_status().is_none(), "{:?}", app.kill_status());
}

#[test]
fn windows_terminate_key_uses_yes_confirmation() {
    let mut row = entry(3000, Some("node.exe"));
    row.platform = Platform::Windows;
    let mut app = app_with_rows(vec![row]);

    app.apply_action(Action::RequestTerminate);

    let confirmation = app
        .kill_confirmation()
        .expect("windows termination request opens confirmation");
    assert_eq!(confirmation.mode, KillMode::Terminate);
    assert_eq!(confirmation.requirement, ConfirmationRequirement::Yes);
}

#[test]
fn protected_process_uses_stronger_confirmation() {
    // A port-derived PID can equal the test runner's own PID on CI. That
    // correctly trips the self-kill guard instead of reaching confirmation.
    let pid = std::process::id()
        .checked_add(1)
        .expect("fixture PID fits u32");
    let mut app = app_with_rows(vec![port_entry(5432, Some(pid), Protocol::Tcp, "postgres")]);
    finish_selected_context(&mut app, context(55));

    app.apply_action(Action::RequestTerminate);

    let confirmation = app.kill_confirmation().unwrap_or_else(|| {
        panic!(
            "protected target must open confirmation: {:?}",
            app.kill_status()
        )
    });
    assert!(confirmation.target.protected);
    assert_eq!(
        confirmation.requirement,
        ConfirmationRequirement::ProtectedProcess,
    );
}

#[test]
fn missing_pid_selection_reports_status_without_confirmation() {
    let mut app = app_with_rows(vec![entry_without_pid(8080)]);

    app.apply_action(Action::RequestTerminate);

    assert_eq!(app.modal(), ModalKind::None);
    assert!(app.kill_confirmation().is_none());
    assert_eq!(
        app.kill_status(),
        Some("selected row has no PID; cannot terminate"),
    );
}

#[test]
fn kill_confirmation_can_be_cancelled() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestTerminate);

    app.apply_action(Action::CancelKill);

    assert_eq!(app.modal(), ModalKind::None);
    assert!(app.kill_confirmation().is_none());
    assert_eq!(app.kill_status(), Some("kill cancelled"));
}

#[test]
fn force_confirmation_input_is_bounded_and_editable() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestForceKill);

    app.apply_action(Action::KillInputAppend('f'));
    app.apply_action(Action::KillInputAppend('o'));
    app.apply_action(Action::KillInputBackspace);

    let confirmation = app
        .kill_confirmation()
        .expect("confirmation remains open while editing");
    assert_eq!(confirmation.input, "f");
    assert_eq!(confirmation.error, None);
}

#[test]
fn auto_refresh_pauses_while_kill_confirmation_is_open() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestTerminate);

    assert!(!app.refresh_due_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(1),
    ));
    assert_eq!(
        app.time_until_refresh_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        ),
        Duration::from_secs(1),
    );
}

#[test]
fn confirmed_kill_revalidates_signals_and_refreshes_rows() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestTerminate);
    set_confirmation_start_time(&mut app, 55);
    let fresh_before_signal = vec![entry(3000, Some("node"))];
    let fresh_after_signal = Vec::new();
    let mut kill_collect_calls = 0;
    let mut visibility_collect_calls = 0;
    let mut terminated = None;

    app.execute_kill_confirmation_with(
        || {
            kill_collect_calls += 1;
            Ok(fresh_before_signal.clone())
        },
        |app| {
            visibility_collect_calls += 1;
            start_test_refresh(app, fresh_after_signal.clone());
        },
        |_| context(55),
        Ok::<u32, TerminationOutcome>,
        |pid, _target, _protected, mode| {
            terminated = Some((*pid, mode));
            TerminationOutcome::Success
        },
    );

    assert_eq!(
        app.rows().len(),
        1,
        "rows remain until worker completion is polled"
    );
    app.poll_refresh();
    assert_eq!(terminated, Some((3000, KillMode::Terminate)));
    assert_eq!(kill_collect_calls, 1);
    assert_eq!(visibility_collect_calls, 1);
    assert_eq!(app.rows().len(), 0);
    assert_eq!(app.modal(), ModalKind::None);
    assert!(
        app.kill_status()
            .is_some_and(|status| status.contains("sent SIGTERM")),
    );
}

#[test]
fn confirmed_kill_refuses_stale_process_identity_without_signalling() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestTerminate);
    set_confirmation_start_time(&mut app, 55);
    let mut stale = entry(3000, Some("node"));
    stale.process_identity = Some(crate::observation::ProcessIdentity {
        pid: 3000,
        start_marker: crate::observation::ProcessStartMarker::linux(99)
            .expect("test marker is nonzero"),
    });
    let fresh_rows = vec![stale];
    let mut terminated = false;

    app.execute_kill_confirmation_with(
        || Ok(fresh_rows.clone()),
        |app| start_test_refresh(app, fresh_rows.clone()),
        |_| context(99),
        Ok::<u32, TerminationOutcome>,
        |_pid, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert!(!terminated);
    assert_eq!(app.rows().len(), 1);
    assert!(
        app.kill_status()
            .is_some_and(|status| status.contains("no longer owns")),
    );
}

#[test]
fn prepare_already_exited_refreshes_snapshot_so_freed_port_drops() {
    // The target exits between confirmation and pidfd_open, so prepare reports
    // AlreadyExited before any signal is attempted. The status only says the
    // target already exited; the best-effort re-collect is what drops the freed
    // row, so verify that re-collect actually runs.
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.apply_action(Action::RequestTerminate);
    set_confirmation_start_time(&mut app, 55);
    let fresh_after_exit: Vec<PortEntry> = Vec::new();
    let mut collect_calls = 0;
    let mut terminated = false;

    app.execute_kill_confirmation_with(
        || panic!("prepare failure must not run authoritative collection"),
        |app| {
            collect_calls += 1;
            start_test_refresh(app, fresh_after_exit.clone());
        },
        |_| context(55),
        |_pid| -> Result<u32, TerminationOutcome> { Err(TerminationOutcome::AlreadyExited) },
        |_handle: &u32, _target, _protected, _mode| {
            terminated = true;
            TerminationOutcome::Success
        },
    );

    assert!(!terminated);
    assert_eq!(collect_calls, 1);
    assert_eq!(app.rows().len(), 1);
    app.poll_refresh();
    assert_eq!(app.rows().len(), 0);
    assert_eq!(app.modal(), ModalKind::None);
    assert!(
        app.kill_status()
            .is_some_and(|status| status.contains("already exited")),
    );
}

#[test]
fn confirmed_kill_discards_stale_in_flight_refresh_so_freed_port_cannot_reappear() {
    // A background refresh spawned before the kill carries a pre-kill snapshot
    // (port 3000 still listening). The kill must invalidate it and queue one
    // replacement rather than applying the stale result later.
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    let (stale_sender, stale_receiver) = mpsc::channel();
    app.refresh_worker = Some(RefreshWorker {
        receiver: stale_receiver,
        stale: false,
    });

    app.apply_action(Action::RequestTerminate);
    set_confirmation_start_time(&mut app, 55);
    let fresh_before_signal = vec![entry(3000, Some("node"))];
    let fresh_after_signal: Vec<PortEntry> = Vec::new();
    let mut kill_collect_calls = 0;
    let mut visibility_collect_calls = 0;

    app.execute_kill_confirmation_with(
        || {
            kill_collect_calls += 1;
            Ok(fresh_before_signal.clone())
        },
        |app| {
            visibility_collect_calls += 1;
            start_test_refresh(app, fresh_after_signal.clone());
        },
        |_| context(55),
        Ok::<u32, TerminationOutcome>,
        |_pid, _target, _protected, _mode| TerminationOutcome::Success,
    );

    assert_eq!(kill_collect_calls, 1);
    assert_eq!(visibility_collect_calls, 0);
    assert!(
        app.refresh_worker
            .as_ref()
            .is_some_and(|worker| worker.stale)
    );
    assert!(app.refresh_after_kill);
    assert!(app.refresh_in_progress());
    app.apply_action(Action::Refresh);
    stale_sender
        .send(Ok(crate::collector::Collector::collect(
            &crate::collector::FakeCollector,
            crate::observation::MetadataProfile::LegacyList,
        )))
        .expect("stale worker receiver must stay installed");

    let mut fresh_collections = 0;
    app.poll_refresh_with(|app| {
        fresh_collections += 1;
        start_test_refresh(app, Vec::new());
    });
    assert_eq!(fresh_collections, 1);
    assert!(!app.refresh_after_kill);
    assert!(app.refresh_in_progress());
    assert_eq!(app.rows().len(), 1);
    app.poll_refresh();
    assert!(!app.refresh_in_progress());
    assert_eq!(app.rows().len(), 0);
}

#[test]
fn search_actions_filter_and_clear_rows() {
    let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);
    let sorted = app
        .sorted_row_indices
        .as_ref()
        .expect("initial rows are cached")
        .indices
        .clone();

    app.apply_action(Action::StartSearch);
    app.apply_action(Action::SearchAppend('v'));
    app.apply_action(Action::SearchAppend('i'));

    assert!(app.search_mode());
    assert_eq!(app.filter_text(), "vi");
    assert_eq!(app.rows().len(), 1);
    assert_eq!(app.rows().next().map(|row| row.local_port), Some(5173));
    assert_eq!(
        app.sorted_row_indices
            .as_ref()
            .expect("search retains the sort cache")
            .indices,
        sorted
    );

    app.apply_action(Action::CancelSearch);

    assert!(!app.search_mode());
    assert_eq!(app.filter_text(), "");
    assert_eq!(app.rows().len(), 2);
}

#[test]
fn same_length_refresh_invalidates_the_sorted_row_cache() {
    let mut app = app_with_rows(vec![entry(3000, Some("zulu")), entry(5173, Some("alpha"))]);
    app.sort_mode = SortMode::Process;
    app.rebuild_visible_rows();
    assert_eq!(app.visible_row_indices, [1, 0]);

    app.apply_test_rows(
        vec![entry(3000, Some("alpha")), entry(5173, Some("zulu"))],
        Instant::now(),
    );

    assert_eq!(app.visible_row_indices, [0, 1]);
    assert_eq!(
        app.sorted_row_indices
            .as_ref()
            .expect("refresh rebuilds the cache")
            .indices,
        [0, 1]
    );
}

#[test]
fn search_edit_rebuilds_a_cache_missing_after_filtered_refresh() {
    let mut app = app_with_rows(vec![entry(3000, Some("alpha")), entry(5173, Some("beta"))]);
    app.apply_action(Action::StartSearch);
    app.apply_action(Action::SearchAppend('a'));

    app.apply_test_rows(
        vec![entry(5173, Some("beta")), entry(3000, Some("alpha"))],
        Instant::now(),
    );
    assert!(app.sorted_row_indices.is_none());

    app.apply_action(Action::SearchAppend('l'));

    assert_eq!(app.filter_text(), "al");
    assert_eq!(
        app.rows().map(|row| row.local_port).collect::<Vec<_>>(),
        [3000]
    );
    assert!(app.sorted_row_indices.is_some());
}

#[test]
fn details_and_actions_use_filtered_rows_with_nonzero_backing_indices() {
    let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);
    app.apply_action(Action::StartSearch);
    for ch in "vite".chars() {
        app.apply_action(Action::SearchAppend(ch));
    }
    assert_eq!(app.visible_row_indices, [1]);
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(5173));

    app.apply_action(Action::OpenDetails);
    assert_eq!(app.modal(), ModalKind::Details);
    app.apply_action(Action::CloseModal);
    app.apply_action(Action::RequestTerminate);

    assert_eq!(
        app.kill_confirmation()
            .map(|confirmation| confirmation.target.ports[0].local_port),
        Some(5173),
    );
}

#[test]
fn sort_cycle_preserves_selected_row_when_possible() {
    let mut app = app_with_rows(vec![entry(3000, Some("zed")), entry(5173, Some("alpha"))]);
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));

    app.apply_action(Action::CycleSort);
    app.apply_action(Action::CycleSort);
    app.apply_action(Action::CycleSort);

    assert_eq!(app.sort_mode(), SortMode::Process);
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
    assert_eq!(app.selected_index, Some(1));
}

#[test]
fn filtering_duplicate_row_keys_preserves_the_visible_match() {
    let mut zulu = entry(3000, Some("zulu"));
    let mut alpha = entry(3000, Some("alpha"));
    alpha.process_identity = Some(crate::observation::ProcessIdentity {
        pid: 3000,
        start_marker: crate::observation::ProcessStartMarker::linux(56)
            .expect("test marker is nonzero"),
    });
    zulu.parent_pid = Some(1);
    alpha.parent_pid = Some(2);
    let unrelated = entry(4000, Some("alpha-worker"));
    let mut app = app_with_rows(vec![zulu, alpha, unrelated]);
    app.apply_action(Action::MoveDown);
    assert_eq!(
        app.selected_row().and_then(|row| row.process_name),
        Some("alpha")
    );

    app.apply_action(Action::StartSearch);
    for ch in "alpha".chars() {
        app.apply_action(Action::SearchAppend(ch));
    }

    assert_eq!(app.rows().len(), 2);
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
    assert_eq!(
        app.selected_row().and_then(|row| row.process_name),
        Some("alpha")
    );
    assert_eq!(app.selected_index(), Some(0));
}

#[test]
fn successful_refresh_preserves_selection_by_row_identity() {
    let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);
    app.apply_action(Action::MoveDown);
    let refreshed = vec![entry(5173, Some("vite")), entry(3000, Some("node"))];

    app.apply_test_rows(refreshed, Instant::now());

    assert_eq!(app.selected_row().map(|row| row.local_port), Some(5173));
}

#[test]
fn refresh_reloads_details_context_when_modal_stays_open() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::OpenDetails);
    assert!(app.selected_process_context_loading());
    finish_selected_context(&mut app, context(55));
    assert!(app.selected_process_context().is_some());

    app.apply_test_rows(vec![entry(3000, Some("node"))], Instant::now());

    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
    assert_eq!(app.modal(), ModalKind::Details);
    assert!(app.selected_process_context_loading());
    assert_eq!(app.selected_process_context(), None);

    finish_selected_context(&mut app, context(56));
    assert!(app.selected_process_context().is_some());
}

#[test]
fn refresh_invalidates_details_context_when_modal_is_closed() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

    app.apply_action(Action::OpenDetails);
    finish_selected_context(&mut app, context(55));
    assert!(app.selected_process_context().is_some());
    app.apply_action(Action::CloseModal);

    app.apply_test_rows(vec![entry(3000, Some("node"))], Instant::now());

    assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
    assert_eq!(app.modal(), ModalKind::None);
    assert_eq!(app.selected_process_context(), None);
}

#[test]
fn refresh_moves_selection_to_nearest_row_when_selected_row_disappears() {
    let mut app = app_with_rows(vec![
        entry(3000, Some("node")),
        entry(5173, Some("vite")),
        entry(8000, Some("python")),
    ]);
    app.apply_action(Action::MoveDown);
    let refreshed = vec![entry(3000, Some("node")), entry(8000, Some("python"))];

    app.apply_test_rows(refreshed, Instant::now());

    assert_eq!(app.selected_index(), Some(1));
    assert_eq!(app.selected_row().map(|row| row.local_port), Some(8000));
}

#[test]
fn collection_error_keeps_last_successful_rows_visible() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.latest_error = Some("cannot read /proc/net/tcp".to_owned());
    app.rebuild_visible_rows();

    assert_eq!(app.rows().len(), 1);
    assert_eq!(app.latest_error(), Some("cannot read /proc/net/tcp"));
}

#[test]
fn refresh_deadline_uses_completed_attempt_time() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    let completed_at = Instant::now();
    app.last_refresh_attempt = completed_at
        .checked_sub(Duration::from_secs(3))
        .expect("test timestamp remains representable");

    assert!(app.refresh_due_at(completed_at, Duration::from_secs(3)));
    assert_eq!(
        app.time_until_refresh_at(completed_at, Duration::from_secs(3)),
        Duration::ZERO
    );

    app.finish_refresh_attempt(Ok(vec![entry(3000, Some("node"))]), completed_at);

    assert!(!app.refresh_due_at(completed_at, Duration::from_secs(3)));
    assert_eq!(
        app.time_until_refresh_at(completed_at, Duration::from_secs(3)),
        Duration::from_secs(3)
    );
}

#[test]
fn refresh_due_waits_for_in_flight_background_refresh() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    let (_sender, receiver) = mpsc::channel();
    app.refresh_worker = Some(RefreshWorker {
        receiver,
        stale: false,
    });

    assert!(app.refresh_in_progress());
    assert!(!app.refresh_due_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(1),
    ));
    assert_eq!(
        app.time_until_refresh_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        ),
        Duration::from_secs(1),
    );
}

#[test]
fn polling_finished_background_refresh_applies_snapshot() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    let (sender, receiver) = mpsc::channel();
    app.refresh_worker = Some(RefreshWorker {
        receiver,
        stale: false,
    });
    sender
        .send(Ok(crate::collector::Collector::collect(
            &crate::collector::FakeCollector,
            crate::observation::MetadataProfile::LegacyList,
        )))
        .expect("test refresh result must send");

    app.poll_refresh();

    assert!(!app.refresh_in_progress());
    assert!(app.rows().any(|row| row.local_port == 5173));
    assert_eq!(app.latest_error(), None);
}

#[test]
fn refresh_worker_panic_is_reserved_for_owner_control_flow() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    let (sender, receiver) = mpsc::channel();
    app.refresh_worker = Some(RefreshWorker {
        receiver,
        stale: false,
    });
    sender
        .send(Err(crate::ui::WorkerFailure::for_test(
            "kickoutchi-refresh",
            "collector invariant failed",
        )))
        .expect("test worker failure must send");

    app.poll_refresh();

    assert!(!app.refresh_in_progress());
    let failure = app
        .take_worker_failure()
        .expect("owner must receive the worker failure");
    assert_eq!(
        failure.to_string(),
        "TUI worker kickoutchi-refresh panicked: collector invariant failed"
    );
    assert_eq!(app.latest_error(), None);
}

#[test]
fn protected_names_are_marked_from_config() {
    let app = app_with_rows(vec![entry(5432, Some("postgres"))]);

    assert!(app.rows().next().is_some_and(|row| row.protected));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tree_kill {
    use super::{App, ModalKind, app_with_rows, context, entry, mpsc, start_test_refresh};
    use crate::app::{TreeConfirmStage, TreePreviewWorker};
    use crate::collector::{Collector, FakeCollector};
    use crate::input::Action;
    use crate::model::Platform;
    use crate::observation::{
        EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot, OwnerCompleteness,
        SnapshotCompleteness,
    };
    use crate::process::KillMode;
    use crate::tree::{
        ProcessTreeTarget, TreeProcessInfo, TreeProcessOps, TreeSignalResult, plan_process_tree,
    };
    use std::time::{Duration, Instant};

    fn tree_info(pid: u32, parent: Option<u32>, name: &str, marker: u64) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid: parent,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(name.to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(marker).ok(),
            owner_uid: None,
            process_group: None,
        }
    }

    fn preview_of(infos: &[TreeProcessInfo], root_pid: u32) -> ProcessTreeTarget {
        plan_process_tree(
            root_pid,
            infos,
            &["postgres".to_owned()],
            Platform::Linux,
            256,
        )
        .expect("test preview root must exist")
    }

    /// Scripted process table plus recorded signal calls, standing in for
    /// the real platform ops during execution tests.
    struct FakeTreeOps {
        snapshot: Vec<TreeProcessInfo>,
        stops: Vec<u32>,
        delivered: Vec<u32>,
    }

    impl FakeTreeOps {
        fn new(snapshot: Vec<TreeProcessInfo>) -> Self {
            Self {
                snapshot,
                stops: Vec::new(),
                delivered: Vec::new(),
            }
        }
    }

    impl TreeProcessOps for FakeTreeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            Ok(self.snapshot.clone())
        }

        fn stop(&mut self, pid: u32, _deadline: Instant) -> crate::tree::TreeStopResult {
            self.stops.push(pid);
            crate::tree::TreeStopResult::Stopped { transitioned: true }
        }

        fn cont(&mut self, _pid: u32) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
        ) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn deliver(&mut self, pid: u32, _mode: KillMode) -> TreeSignalResult {
            self.delivered.push(pid);
            TreeSignalResult::Delivered
        }
    }

    fn set_tree_confirmation_start_time(app: &mut App, start_time_ticks: u64) {
        app.tree_confirmation_mut()
            .expect("tree confirmation must be open")
            .target
            .process_start_time_marker =
            crate::observation::ProcessStartMarker::linux(start_time_ticks).ok();
    }

    fn authoritative_snapshot() -> NetworkSnapshot {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake snapshot collects");
        snapshot.completeness = SnapshotCompleteness::Complete;
        snapshot.owner_completeness = OwnerCompleteness::Complete;
        snapshot
            .evidence_gaps
            .retain(|gap| gap.impact != EvidenceImpact::SocketSet);
        for socket in &mut snapshot.sockets {
            socket.owner_completeness = OwnerCompleteness::Complete;
        }
        snapshot
    }

    fn assert_authoritative_snapshot_refuses_before_tree_signals(snapshot: &NetworkSnapshot) {
        let mut row = entry(3000, Some("node"));
        row.pid = Some(18_422);
        row.process_identity.as_mut().expect("fixture identity").pid = 18_422;
        let mut app = app_with_rows(vec![row]);
        app.apply_action(Action::RequestTreeTerminate);
        set_tree_confirmation_start_time(&mut app, 55);
        let infos = vec![tree_info(18_422, Some(1), "node", 55)];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 18_422)));
        let mut ops = FakeTreeOps::new(infos);

        app.execute_tree_kill_confirmation_with(
            || crate::collector::kill_ports_from_snapshot(snapshot, Some(18_422), None),
            |_| panic!("authoritative refusal must not visibility-poll ports"),
            |_| context(55),
            &mut ops,
        );

        assert!(ops.stops.is_empty(), "refusal must precede every stop");
        assert!(
            ops.delivered.is_empty(),
            "refusal must precede every delivery"
        );
        assert!(
            app.kill_status().is_some_and(|status| status
                .contains("collecting ports before tree kill failed; no termination was sent")),
            "{:?}",
            app.kill_status(),
        );
    }

    #[test]
    fn authority_refusal_precedes_tui_tree_signals() {
        let mut snapshot = authoritative_snapshot();
        snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has port 3000")
            .owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits");

        assert_authoritative_snapshot_refuses_before_tree_signals(&snapshot);
    }

    #[test]
    fn tree_request_opens_loading_modal_then_preview_populates_it() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::RequestTreeTerminate);

        assert_eq!(app.modal(), ModalKind::ConfirmTreeKill);
        let confirmation = app
            .tree_confirmation()
            .expect("tree request opens a confirmation");
        assert_eq!(confirmation.target.pid, 3000);
        assert_eq!(confirmation.mode, KillMode::Terminate);
        assert_eq!(confirmation.stage, TreeConfirmStage::Word);
        assert!(confirmation.preview.is_none(), "preview starts loading");

        let infos = vec![
            tree_info(3000, Some(1), "node", 55),
            tree_info(3001, Some(3000), "worker", 56),
        ];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));

        let confirmation = app.tree_confirmation().expect("confirmation stays open");
        assert_eq!(
            confirmation.preview.as_ref().map(ProcessTreeTarget::len),
            Some(2),
        );
    }

    #[test]
    fn submit_while_preview_is_loading_rejects_without_executing() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);
        for ch in "tree".chars() {
            app.apply_action(Action::KillInputAppend(ch));
        }

        app.apply_action(Action::SubmitKillConfirmation);

        let confirmation = app.tree_confirmation().expect("confirmation stays open");
        assert!(
            confirmation.input.is_empty(),
            "typing while the preview loads must not pre-arm execution",
        );
        assert!(
            confirmation
                .error
                .as_deref()
                .is_some_and(|error| error.contains("still enumerating")),
            "{:?}",
            confirmation.error,
        );
        assert_eq!(app.modal(), ModalKind::ConfirmTreeKill);

        let infos = vec![tree_info(3000, Some(1), "node", 55)];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));
        let confirmation = app.tree_confirmation().expect("confirmation stays open");
        assert!(confirmation.input.is_empty());
        assert!(confirmation.error.is_none());
    }

    #[test]
    fn execute_waits_for_process_metadata_before_tree_signals() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);
        app.tree_confirmation_mut()
            .expect("tree confirmation opens")
            .target
            .process_start_time_marker = None;
        let infos = vec![tree_info(3000, Some(1), "node", 55)];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));
        let mut ops = FakeTreeOps::new(infos);

        app.execute_tree_kill_confirmation_with(
            || panic!("metadata wait must precede port collection"),
            |_| panic!("metadata wait must precede visibility polling"),
            |_| panic!("metadata wait must precede synchronous context collection"),
            &mut ops,
        );

        let confirmation = app
            .tree_confirmation()
            .expect("confirmation remains open while metadata loads");
        assert_eq!(app.modal(), ModalKind::ConfirmTreeKill);
        assert!(ops.stops.is_empty());
        assert!(ops.delivered.is_empty());
        assert!(
            confirmation
                .error
                .as_deref()
                .is_some_and(|error| error.contains("still reading process metadata")),
            "{:?}",
            confirmation.error,
        );
    }

    #[test]
    fn preflight_refusal_from_preview_closes_modal_with_status() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);

        // The enumerated tree carries a protected descendant, so the gate
        // fires before any confirmation input is possible.
        let infos = vec![
            tree_info(3000, Some(1), "node", 55),
            tree_info(3001, Some(3000), "postgres", 56),
        ];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));

        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("protected process PID 3001")),
            "{:?}",
            app.kill_status(),
        );
    }

    #[test]
    fn preview_failure_closes_modal_with_status() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);

        app.finish_tree_preview_for_test(Err("scan failed".to_owned()));

        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("scan failed")),
            "{:?}",
            app.kill_status(),
        );
    }

    #[test]
    fn preview_discovering_a_protected_root_forces_the_protected_stage() {
        // The selected socket row has no readable process name, so the
        // port-row policy cannot mark the root protected, but the tree
        // snapshot reads the name and it is on the protected list. The
        // confirmation must upgrade to the protected stage instead of
        // accepting the bare scope word.
        let mut app = app_with_rows(vec![entry(3000, None)]);
        app.apply_action(Action::RequestTreeTerminate);
        let confirmation = app.tree_confirmation().expect("confirmation opens");
        assert_eq!(confirmation.stage, TreeConfirmStage::Word);

        let infos = vec![tree_info(3000, Some(500), "postgres", 55)];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));

        let confirmation = app.tree_confirmation().expect("confirmation stays open");
        assert_eq!(
            confirmation.stage,
            TreeConfirmStage::ProtectedRoot,
            "a root the tree scan classifies as protected must require the protected confirmation",
        );
        assert!(confirmation.target.protected);
        assert!(confirmation.input.is_empty());
    }

    #[test]
    fn execute_refuses_root_that_fresh_scan_classifies_as_protected() {
        // Between confirmation and execution the root execs into a
        // protected name: exec changes the name but not the PID, parent, or
        // start marker, so identity revalidation passes when the confirmed
        // name was unreadable. The fresh-scan root protection guard must
        // refuse, without a single signal.
        let mut app = app_with_rows(vec![entry(3000, None)]);
        app.apply_action(Action::RequestTreeTerminate);
        set_tree_confirmation_start_time(&mut app, 55);
        let clean = vec![tree_info(3000, Some(500), "node", 55)];
        app.finish_tree_preview_for_test(Ok(preview_of(&clean, 3000)));

        let execed = vec![tree_info(3000, Some(500), "postgres", 55)];
        let fresh_rows = vec![entry(3000, None)];
        let mut ops = FakeTreeOps::new(execed);

        app.execute_tree_kill_confirmation_with(
            || Ok(fresh_rows.clone()),
            |_| panic!("protected-root refusal must not visibility-poll ports"),
            |_| context(55),
            &mut ops,
        );

        assert!(ops.stops.is_empty(), "refusal must precede any stop");
        assert!(ops.delivered.is_empty(), "no signal may be sent");
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("protected root")),
            "{:?}",
            app.kill_status(),
        );
    }

    #[test]
    fn cancel_discards_confirmation_and_late_preview_results() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);
        let (sender, receiver) = mpsc::channel();
        app.tree_preview_worker = Some(TreePreviewWorker {
            root_pid: 3000,
            receiver,
        });

        app.apply_action(Action::CancelKill);

        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert_eq!(app.kill_status(), Some("tree kill cancelled"));
        assert!(
            app.tree_preview_worker.is_some(),
            "cancel keeps the one worker so it can be drained instead of replaced",
        );

        let infos = vec![tree_info(3000, Some(1), "node", 55)];
        sender
            .send(Ok(Ok(preview_of(&infos, 3000))))
            .expect("test preview result must send");
        app.poll_tree_preview();
        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert!(app.tree_preview_worker.is_none());
    }

    #[test]
    fn tree_request_waits_for_cancelled_preview_worker_to_finish() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        let (_sender, receiver) = mpsc::channel();
        app.tree_preview_worker = Some(TreePreviewWorker {
            root_pid: 3000,
            receiver,
        });

        app.apply_action(Action::RequestTreeTerminate);

        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("still finishing")),
            "{:?}",
            app.kill_status(),
        );
    }

    #[test]
    fn auto_refresh_pauses_while_tree_confirmation_is_open() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);

        assert!(!app.refresh_due_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        assert_eq!(
            app.time_until_refresh_at(
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(1),
            ),
            Duration::from_secs(1),
        );
    }

    #[test]
    fn execute_happy_path_kills_leaves_first_and_refreshes_rows() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTreeTerminate);
        set_tree_confirmation_start_time(&mut app, 55);
        let infos = vec![
            tree_info(3000, Some(1), "node", 55),
            tree_info(3001, Some(3000), "worker", 56),
        ];
        app.finish_tree_preview_for_test(Ok(preview_of(&infos, 3000)));
        let fresh_rows = vec![entry(3000, Some("node"))];
        let mut collect_calls = 0;
        let mut ops = FakeTreeOps::new(infos);

        app.execute_tree_kill_confirmation_with(
            || Ok(fresh_rows.clone()),
            |app| {
                collect_calls += 1;
                start_test_refresh(app, Vec::new());
            },
            |_| context(55),
            &mut ops,
        );

        assert_eq!(app.modal(), ModalKind::None);
        assert!(app.tree_confirmation().is_none());
        assert_eq!(ops.delivered, vec![3001, 3000]);
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("sent SIGTERM to 2 process(es)")),
            "{:?}",
            app.kill_status(),
        );
        assert_eq!(collect_calls, 1);
        assert_eq!(app.rows().len(), 1);
        app.poll_refresh();
        assert_eq!(app.rows().len(), 0);
    }
}

#[test]
fn redraw_requests_follow_input_and_worker_completion_without_poll_churn() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    assert!(app.take_redraw_request());
    app.apply_action(Action::Noop);
    app.poll_refresh();
    app.poll_process_context();
    assert!(!app.take_redraw_request());

    app.apply_action(Action::StartSearch);
    assert!(app.take_redraw_request());
    app.set_modal_scroll(2);
    assert!(app.take_redraw_request());

    let (sender, receiver) = mpsc::channel();
    app.refresh_with(|| Ok(receiver));
    assert!(app.take_redraw_request());
    app.poll_refresh();
    assert!(!app.take_redraw_request());
    sender
        .send(Ok(Ok(crate::observation::snapshot_from_test_rows(
            Vec::new(),
        ))))
        .expect("worker receiver remains installed");
    app.poll_refresh();
    assert!(app.take_redraw_request());
    assert_eq!(app.rows().len(), 0);
    app.poll_refresh();
    assert!(!app.take_redraw_request());
}

#[test]
fn failed_refresh_start_preserves_rows_and_allows_a_later_refresh() {
    let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
    app.refresh_with(|| Err(std::io::Error::other("worker capacity exhausted")));
    assert!(!app.refresh_in_progress());
    assert_eq!(app.rows().len(), 1);
    assert!(
        app.latest_error()
            .is_some_and(|error| error.contains("worker capacity exhausted"))
    );
    start_test_refresh(&mut app, Vec::new());
    app.poll_refresh();
    assert_eq!(app.rows().len(), 0);
    assert!(app.latest_error().is_none());
}
