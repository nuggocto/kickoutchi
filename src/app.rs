//! TUI state and transitions.
//!
//! `App` holds the latest good snapshot, the filtered table view, the selection,
//! search and sort state, the active modal, and status text.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use crate::collector;
#[cfg(test)]
use crate::collector::{Collector, FakeCollector};
use crate::config::Config;
use crate::display::sanitize;
use crate::input::Action;
use crate::model::{PortEntry, PortEntryView, ProcessContext, Protocol, SortMode};
use crate::observation::Ipv6Scope;
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome,
};
use crate::protection::mark_protected;
use crate::query::{self, FILTER_TEXT_MAX_BYTES, QueryOptions};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree;

mod helpers;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tree_action;

#[cfg(test)]
use helpers::collect_selected_process_context_with;
pub(crate) use helpers::kill_command_text;
use helpers::{collect_selected_process_context, preserved_selection, termination_status_line};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tree_action::{
    TreeSubmitVerdict, collect_tree_preview, fresh_tree_gates, host_tree_ops, tree_kill_status_line,
};

type RefreshResult = Result<crate::observation::NetworkSnapshot, collector::CollectorError>;
#[cfg(any(target_os = "linux", target_os = "macos"))]
type TreePreviewResult = Result<tree::ProcessTreeTarget, String>;

#[derive(Debug)]
struct RefreshWorker {
    receiver: Receiver<Result<RefreshResult, crate::ui::WorkerFailure>>,
    stale: bool,
}

#[derive(Debug)]
struct ContextWorker {
    key: RowKey,
    receiver: Receiver<Result<ProcessContext, crate::ui::WorkerFailure>>,
    stale: bool,
}

/// In-flight enumeration of the selected root's process tree, so the full
/// process-table scan never runs on the render/input loop.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct TreePreviewWorker {
    root_pid: u32,
    receiver: Receiver<Result<TreePreviewResult, crate::ui::WorkerFailure>>,
}

/// Whichever modal is currently sitting over the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModalKind {
    None,
    Details,
    Help,
    ConfirmKill,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ConfirmTreeKill,
}

#[derive(Debug, Default)]
enum Modal {
    #[default]
    None,
    Details,
    Help,
    ConfirmKill(KillConfirmation),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ConfirmTreeKill(TreeKillConfirmation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowKey {
    pid: Option<u32>,
    protocol: Protocol,
    local_addr: std::net::IpAddr,
    local_port: u16,
    ipv6_scope: Option<Ipv6Scope>,
}

impl From<&PortEntry> for RowKey {
    fn from(entry: &PortEntry) -> Self {
        Self {
            pid: entry.pid,
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
            ipv6_scope: entry.ipv6_scope,
        }
    }
}

impl From<PortEntryView<'_>> for RowKey {
    fn from(entry: PortEntryView<'_>) -> Self {
        Self {
            pid: entry.pid,
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
            ipv6_scope: entry.ipv6_scope,
        }
    }
}

#[derive(Debug)]
struct SortedRowIndices {
    sort_mode: SortMode,
    indices: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KillConfirmation {
    pub(crate) target: KillTarget,
    pub(crate) mode: KillMode,
    pub(crate) requirement: ConfirmationRequirement,
    pub(crate) input: String,
    pub(crate) error: Option<String>,
}

impl KillConfirmation {
    fn new(target: KillTarget, mode: KillMode, requirement: ConfirmationRequirement) -> Self {
        Self {
            target,
            mode,
            requirement,
            input: String::new(),
            error: None,
        }
    }
}

/// Which fact the tree confirmation is currently asking the user to type.
///
/// A protected root completes two stages: its PID or name, then the scope word.
/// This matches the CLI prompt so the TUI cannot authorize a protected tree on
/// less evidence than the CLI would.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeConfirmStage {
    ProtectedRoot,
    Word,
}

/// State of the tree-kill confirmation modal.
///
/// `preview` starts `None` while the background worker enumerates the process
/// table; the modal renders a loading line until it lands. The preview is
/// informational only. Execution collects again after freezing, so the preview
/// does not select signal targets.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeKillConfirmation {
    pub(crate) target: KillTarget,
    pub(crate) mode: KillMode,
    pub(crate) preview: Option<tree::ProcessTreeTarget>,
    pub(crate) stage: TreeConfirmStage,
    pub(crate) input: String,
    pub(crate) error: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TreeKillConfirmation {
    fn new(target: KillTarget, mode: KillMode) -> Self {
        let stage = if target.protected {
            TreeConfirmStage::ProtectedRoot
        } else {
            TreeConfirmStage::Word
        };
        Self {
            target,
            mode,
            preview: None,
            stage,
            input: String::new(),
            error: None,
        }
    }

    pub(crate) fn scope_word(&self) -> &'static str {
        tree::tree_scope_word(self.mode)
    }
}

/// Mutable TUI state.
#[expect(
    clippy::struct_excessive_bools,
    reason = "redraw invalidation is independent of search, visibility, and quit state"
)]
#[derive(Debug)]
pub(crate) struct App {
    row_descriptors: Vec<crate::observation::PortEntryDescriptor>,
    visible_row_indices: Vec<usize>,
    sorted_row_indices: Option<SortedRowIndices>,
    selected_index: Option<usize>,

    filter_text: String,
    search_mode: bool,
    sort_mode: SortMode,
    hide_system_processes: bool,
    confirm_force_kill: bool,
    docker_enrichment: bool,
    protected_processes: Vec<String>,
    labels: crate::labels::LabelRegistry,
    network_snapshot: Option<crate::observation::NetworkSnapshot>,

    selected_context_key: Option<RowKey>,
    selected_process_context: Option<ProcessContext>,
    context_worker: Option<ContextWorker>,
    context_requested: bool,

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    tree_preview_worker: Option<TreePreviewWorker>,
    kill_status: Option<String>,

    refresh_worker: Option<RefreshWorker>,
    refresh_after_kill: bool,
    last_successful_refresh: Option<Instant>,
    last_refresh_attempt: Instant,

    modal: Modal,
    modal_scroll: u16,
    latest_error: Option<String>,
    worker_failure: Option<crate::ui::WorkerFailure>,
    filter_error: Option<String>,
    should_quit: bool,
    redraw_needed: bool,
}

impl App {
    /// Build the app with its first snapshot already populated.
    ///
    /// The initial collect runs on this thread because worker completion does
    /// not wake `event::poll`. Otherwise the table could remain blank for one
    /// tick. Later refreshes run through the background worker.
    pub(crate) fn new(config: &Config) -> Self {
        let mut app = Self::empty(config, Instant::now());
        app.refresh_blocking();
        app
    }

    #[cfg(test)]
    pub(crate) fn new_fake(config: &Config) -> Self {
        let snapshot = FakeCollector
            .collect(crate::observation::MetadataProfile::LegacyList)
            .expect("fake collection cannot fail");
        Self::from_snapshot(snapshot, config)
    }

    #[cfg(test)]
    fn from_rows(rows: Vec<PortEntry>, config: &Config) -> Self {
        Self::from_snapshot(crate::observation::snapshot_from_test_rows(rows), config)
    }

    #[cfg(test)]
    fn from_snapshot(snapshot: crate::observation::NetworkSnapshot, config: &Config) -> Self {
        let mut app = Self::empty(config, Instant::now());
        app.apply_network_snapshot(snapshot, Instant::now());
        app
    }

    fn empty(config: &Config, now: Instant) -> Self {
        Self {
            row_descriptors: Vec::new(),
            visible_row_indices: Vec::new(),
            sorted_row_indices: None,
            selected_index: None,
            filter_text: String::new(),
            search_mode: false,
            sort_mode: config.default_sort,
            hide_system_processes: config.hide_system_processes,
            confirm_force_kill: config.confirm_force_kill,
            docker_enrichment: config.docker_enrichment,
            protected_processes: config.protected_processes.clone(),
            labels: config.labels.clone(),
            network_snapshot: None,
            selected_context_key: None,
            selected_process_context: None,
            context_worker: None,
            context_requested: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            tree_preview_worker: None,
            kill_status: None,
            refresh_worker: None,
            refresh_after_kill: false,
            last_successful_refresh: None,
            last_refresh_attempt: now,
            modal: Modal::None,
            modal_scroll: 0,
            latest_error: None,
            worker_failure: None,
            filter_error: None,
            should_quit: false,
            redraw_needed: true,
        }
    }

    /// Collect one snapshot on the calling thread. Used only for the initial
    /// load in [`App::new`]; every refresh after that runs through the worker.
    fn refresh_blocking(&mut self) {
        self.finish_snapshot_refresh_attempt(
            collector::collect_snapshot(crate::observation::MetadataProfile::LegacyList),
            Instant::now(),
        );
    }

    pub(crate) fn refresh(&mut self) {
        self.refresh_with(|| {
            crate::ui::spawn_worker(
                thread::Builder::new().name("kickoutchi-refresh".to_owned()),
                || collector::collect_snapshot(crate::observation::MetadataProfile::LegacyList),
            )
            .map(crate::ui::Worker::detach)
        });
    }

    fn refresh_with(
        &mut self,
        start: impl FnOnce()
            -> std::io::Result<Receiver<Result<RefreshResult, crate::ui::WorkerFailure>>>,
    ) {
        if self.refresh_worker.is_some() {
            return;
        }

        // Keep collection off the render loop and allow only one worker. The
        // Linux collector may scan every process descriptor directory.
        self.redraw_needed = true;
        match start() {
            Ok(receiver) => {
                self.refresh_worker = Some(RefreshWorker {
                    receiver,
                    stale: false,
                });
            }
            Err(error) => {
                self.last_refresh_attempt = Instant::now();
                self.latest_error = Some(format!("starting refresh worker failed: {error}"));
            }
        }
    }

    pub(crate) fn poll_refresh(&mut self) {
        self.poll_refresh_with(Self::refresh);
    }

    fn poll_refresh_with(&mut self, start_refresh: impl FnOnce(&mut Self)) {
        let Some(worker) = self.refresh_worker.as_ref() else {
            return;
        };

        let result = match worker.receiver.try_recv() {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                self.refresh_worker = None;
                self.worker_failure = Some(error);
                return;
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(collector::CollectorError::WorkerExited),
        };
        let stale = worker.stale;

        self.refresh_worker = None;
        if !stale {
            self.finish_snapshot_refresh_attempt(result, Instant::now());
        }
        if std::mem::take(&mut self.refresh_after_kill) {
            start_refresh(self);
        }
    }

    pub(crate) fn poll_process_context(&mut self) {
        let Some(worker) = self.context_worker.as_ref() else {
            return;
        };

        let result = match worker.receiver.try_recv() {
            Ok(Ok(context)) => context,
            Ok(Err(error)) => {
                self.context_worker = None;
                self.worker_failure = Some(error);
                return;
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.context_worker = None;
                self.redraw_needed = true;
                self.latest_error =
                    Some("details worker exited before returning context".to_owned());
                self.start_pending_process_context_request();
                return;
            }
        };
        self.redraw_needed = true;
        let worker_key = worker.key;
        let stale = worker.stale;
        self.context_worker = None;
        if !stale {
            let updated_target = worker_key
                .pid
                .and_then(|pid| self.kill_target_with_optional_context(pid, Some(&result)));

            if self.selected_row().map(RowKey::from) == Some(worker_key) {
                self.selected_context_key = Some(worker_key);
                self.selected_process_context = Some(result.clone());
            }
            if let Some(target) = updated_target {
                self.apply_context_target_to_confirmations(target);
            }
        }
        self.start_pending_process_context_request();
    }

    #[cfg(test)]
    fn finish_refresh_attempt(
        &mut self,
        result: Result<Vec<PortEntry>, collector::CollectorError>,
        completed_at: Instant,
    ) {
        self.finish_snapshot_refresh_attempt(
            result.map(crate::observation::snapshot_from_test_rows),
            completed_at,
        );
    }

    fn finish_snapshot_refresh_attempt(&mut self, result: RefreshResult, completed_at: Instant) {
        self.redraw_needed = true;
        self.last_refresh_attempt = completed_at;
        match result {
            Ok(snapshot) => self.apply_network_snapshot(snapshot, completed_at),
            Err(error) => self.latest_error = Some(error.to_string()),
        }
    }

    fn apply_network_snapshot(
        &mut self,
        snapshot: crate::observation::NetworkSnapshot,
        now: Instant,
    ) {
        self.redraw_needed = true;
        let descriptors = match snapshot.port_entry_descriptors(&self.protected_processes) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                self.latest_error = Some(error.to_string());
                return;
            }
        };
        let selected_key = self.selected_row().map(RowKey::from);
        let fallback_index = self.selected_index.unwrap_or(0);
        if let Some(worker) = self.refresh_worker.as_mut() {
            worker.stale = true;
        }
        self.network_snapshot = Some(snapshot);
        self.row_descriptors = descriptors;
        self.sorted_row_indices = None;
        self.last_successful_refresh = Some(now);
        self.latest_error = None;
        if let Some(worker) = self.context_worker.as_mut() {
            worker.stale = true;
        }
        self.context_requested = false;
        self.selected_context_key = None;
        self.selected_process_context = None;
        self.rebuild_visible_rows_preserving(selected_key, fallback_index);
        if self.modal() == ModalKind::Details {
            self.load_selected_process_context();
        }
    }

    pub(crate) fn refresh_due(&self, refresh_interval: Duration) -> bool {
        self.refresh_due_at(Instant::now(), refresh_interval)
    }

    pub(crate) fn time_until_refresh(&self, refresh_interval: Duration) -> Duration {
        self.time_until_refresh_at(Instant::now(), refresh_interval)
    }

    /// Whether a termination confirmation (single or tree) is on screen. Both
    /// pause auto-refresh: the user is reading target facts, and a refresh
    /// changing them mid-decision would be worse than a slightly stale table.
    fn confirmation_modal_open(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            matches!(
                self.modal(),
                ModalKind::ConfirmKill | ModalKind::ConfirmTreeKill
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            self.modal() == ModalKind::ConfirmKill
        }
    }

    fn refresh_due_at(&self, now: Instant, refresh_interval: Duration) -> bool {
        if self.confirmation_modal_open() {
            return false;
        }
        if self.refresh_worker.is_some() {
            return false;
        }
        now.saturating_duration_since(self.last_refresh_attempt) >= refresh_interval
    }

    fn time_until_refresh_at(&self, now: Instant, refresh_interval: Duration) -> Duration {
        if self.confirmation_modal_open() {
            return refresh_interval;
        }
        if self.refresh_worker.is_some() {
            return refresh_interval;
        }
        refresh_interval.saturating_sub(now.saturating_duration_since(self.last_refresh_attempt))
    }

    pub(crate) fn rows(&self) -> impl ExactSizeIterator<Item = PortEntryView<'_>> {
        self.visible_row_indices
            .iter()
            .map(|&index| self.row_view(index).expect("visible row index is valid"))
    }

    pub(crate) fn rows_range(
        &self,
        range: std::ops::Range<usize>,
    ) -> impl ExactSizeIterator<Item = PortEntryView<'_>> {
        self.visible_row_indices[range]
            .iter()
            .map(|&index| self.row_view(index).expect("visible row index is valid"))
    }

    pub(crate) fn total_row_count(&self) -> usize {
        self.row_count()
    }

    pub(crate) fn labels_configured(&self) -> bool {
        !self.labels.is_empty()
    }

    pub(crate) fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub(crate) fn selected_row(&self) -> Option<PortEntryView<'_>> {
        self.selected_index
            .and_then(|index| self.visible_row_indices.get(index))
            .and_then(|&index| self.row_view(index))
    }

    fn row_count(&self) -> usize {
        self.row_descriptors.len()
    }

    fn row_view(&self, index: usize) -> Option<PortEntryView<'_>> {
        let view = self.row_view_without_label(index)?;
        let label = self.labels.resolve_parts(
            view.protocol,
            view.local_addr,
            view.local_port,
            view.ipv6_scope,
        );
        Some(view.with_label(label))
    }

    fn row_view_without_label(&self, index: usize) -> Option<PortEntryView<'_>> {
        let snapshot = self.network_snapshot.as_ref()?;
        self.row_descriptors
            .get(index)
            .map(|descriptor| snapshot.port_entry_view(descriptor))
    }

    fn all_views(&self) -> impl ExactSizeIterator<Item = PortEntryView<'_>> {
        (0..self.row_count()).map(|index| self.row_view(index).expect("row index is valid"))
    }

    pub(crate) fn selected_process_metadata(
        &self,
    ) -> Option<&crate::observation::ProcessObservation> {
        let identity = self.selected_row()?.process_identity?;
        self.network_snapshot.as_ref()?.processes.get(&identity)
    }

    pub(crate) fn request_redraw(&mut self) {
        self.redraw_needed = true;
    }

    pub(crate) fn take_redraw_request(&mut self) -> bool {
        std::mem::take(&mut self.redraw_needed)
    }

    pub(crate) fn selected_process_context(&self) -> Option<&ProcessContext> {
        let selected_key = self.selected_row().map(RowKey::from)?;
        if self.selected_context_key == Some(selected_key) {
            self.selected_process_context.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn selected_process_context_loading(&self) -> bool {
        let selected_key = self.selected_row().map(RowKey::from);
        self.context_requested
            || self
                .context_worker
                .as_ref()
                .is_some_and(|worker| Some(worker.key) == selected_key)
    }

    pub(crate) fn kill_confirmation(&self) -> Option<&KillConfirmation> {
        match &self.modal {
            Modal::ConfirmKill(confirmation) => Some(confirmation),
            _ => None,
        }
    }

    fn kill_confirmation_mut(&mut self) -> Option<&mut KillConfirmation> {
        match &mut self.modal {
            Modal::ConfirmKill(confirmation) => Some(confirmation),
            _ => None,
        }
    }

    fn take_kill_confirmation(&mut self) -> Option<KillConfirmation> {
        self.kill_confirmation()?;
        match std::mem::take(&mut self.modal) {
            Modal::ConfirmKill(confirmation) => Some(confirmation),
            _ => unreachable!("confirmation was checked before taking the modal"),
        }
    }

    pub(crate) fn kill_status(&self) -> Option<&str> {
        self.kill_status.as_deref()
    }

    pub(crate) fn modal_scroll(&self) -> u16 {
        self.modal_scroll
    }

    pub(crate) fn scroll_modal_by(&mut self, rows: i32) {
        self.redraw_needed = true;
        self.modal_scroll = if rows.is_negative() {
            self.modal_scroll
                .saturating_sub(u16::try_from(rows.unsigned_abs()).unwrap_or(u16::MAX))
        } else {
            self.modal_scroll
                .saturating_add(u16::try_from(rows).unwrap_or(u16::MAX))
        };
    }

    pub(crate) fn set_modal_scroll(&mut self, rows: u16) {
        self.redraw_needed |= self.modal_scroll != rows;
        self.modal_scroll = rows;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn cancel_confirmation_for_layout(&mut self) {
        self.cancel_confirmation();
        self.kill_status = Some(
            "confirmation cancelled: terminal cannot show all mandatory safety text".to_owned(),
        );
    }

    /// Whether a background refresh worker is still in flight. Test-only: the
    /// status bar does not show refresh progress.
    #[cfg(test)]
    fn refresh_in_progress(&self) -> bool {
        self.refresh_worker.is_some()
    }

    pub(crate) fn take_worker_failure(&mut self) -> Option<crate::ui::WorkerFailure> {
        self.worker_failure.take()
    }

    pub(crate) fn filter_text(&self) -> &str {
        &self.filter_text
    }

    pub(crate) fn search_mode(&self) -> bool {
        self.search_mode
    }

    pub(crate) fn sort_mode(&self) -> SortMode {
        self.sort_mode
    }

    pub(crate) fn refresh_age(&self) -> Option<Duration> {
        self.last_successful_refresh
            .map(|instant| instant.elapsed())
    }

    pub(crate) fn modal(&self) -> ModalKind {
        match self.modal {
            Modal::None => ModalKind::None,
            Modal::Details => ModalKind::Details,
            Modal::Help => ModalKind::Help,
            Modal::ConfirmKill(_) => ModalKind::ConfirmKill,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Modal::ConfirmTreeKill(_) => ModalKind::ConfirmTreeKill,
        }
    }

    pub(crate) fn latest_error(&self) -> Option<&str> {
        self.latest_error.as_deref()
    }

    pub(crate) fn filter_error(&self) -> Option<&str> {
        self.filter_error.as_deref()
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn apply_action(&mut self, action: Action) {
        self.redraw_needed |= action != Action::Noop;
        match action {
            Action::MoveDown => self.select_next(),
            Action::MoveUp => self.select_previous(),
            Action::OpenDetails => self.open_details(),
            Action::OpenHelp => {
                self.modal_scroll = 0;
                self.modal = Modal::Help;
            }
            Action::CloseModal => {
                self.modal = Modal::None;
                self.modal_scroll = 0;
                self.context_requested = false;
            }
            Action::RequestTerminate => self.request_kill(KillMode::Terminate),
            Action::RequestForceKill => self.request_kill(KillMode::Force),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::RequestTreeTerminate => self.request_tree_kill(KillMode::Terminate),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Action::RequestTreeForceKill => self.request_tree_kill(KillMode::Force),
            Action::SubmitKillConfirmation => self.submit_confirmation(),
            Action::KillInputAppend(ch) => self.append_confirmation_input(ch),
            Action::KillInputBackspace => self.backspace_confirmation_input(),
            Action::CancelKill => self.cancel_confirmation(),
            Action::Refresh => self.refresh(),
            Action::StartSearch => self.search_mode = true,
            Action::SearchAppend(ch) => self.append_search_char(ch),
            Action::SearchBackspace => self.backspace_search(),
            Action::FinishSearch => self.search_mode = false,
            Action::CancelSearch => self.cancel_search(),
            Action::CycleSort => self.cycle_sort(),
            Action::Quit => self.should_quit = true,
            Action::Noop => {}
        }
    }

    fn select_next(&mut self) {
        let Some(index) = self.selected_index else {
            return;
        };
        let max_index = self.visible_row_indices.len().saturating_sub(1);
        self.selected_index = Some((index + 1).min(max_index));
    }

    fn select_previous(&mut self) {
        let Some(index) = self.selected_index else {
            return;
        };
        self.selected_index = Some(index.saturating_sub(1));
    }

    fn open_details(&mut self) {
        if self.selected_row().is_some() {
            self.search_mode = false;
            self.modal_scroll = 0;
            self.load_selected_process_context();
            self.modal = Modal::Details;
        }
    }

    /// Resolve the selected row into a kill target, or set `kill_status` with
    /// the refusal and return `None`. Shared by the single-process and
    /// tree-kill request paths so their refusal messages stay identical.
    fn resolve_selected_kill_target(&mut self) -> Option<KillTarget> {
        let Some(entry) = self.selected_row() else {
            self.kill_status = Some("no selected process to terminate".to_owned());
            return None;
        };
        let Some(pid) = entry.pid else {
            self.kill_status = Some("selected row has no PID; cannot terminate".to_owned());
            return None;
        };
        if let Some(reason) = process::unsafe_pid_reason(pid) {
            self.kill_status = Some(format!("unsafe PID blocked: {}", reason.message()));
            return None;
        }
        let context = self.selected_process_context().cloned();
        if context.is_none() {
            self.load_selected_process_context();
        }

        let target = self
            .kill_target_with_optional_context(pid, context.as_ref())
            .expect("the selected PID has at least one row");
        Some(target)
    }

    fn request_kill(&mut self, mode: KillMode) {
        self.search_mode = false;
        self.kill_status = None;

        let Some(target) = self.resolve_selected_kill_target() else {
            return;
        };
        // The TUI has no `--yes`, so this path should always require
        // confirmation. Treat an unexpected skip as a `y` prompt.
        let requirement = match process::confirmation_requirement(
            target.protected,
            mode,
            false,
            self.confirm_force_kill,
        ) {
            Ok(Some(requirement)) => requirement,
            Ok(None) => ConfirmationRequirement::Yes,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(&target, mode, &outcome));
                return;
            }
        };

        self.modal = Modal::ConfirmKill(KillConfirmation::new(target, mode, requirement));
    }

    fn append_kill_input(&mut self, ch: char) {
        let Some(requirement) = self
            .kill_confirmation()
            .map(|confirmation| confirmation.requirement)
        else {
            return;
        };

        if requirement == ConfirmationRequirement::Yes {
            if ch == 'y' || ch == 'Y' {
                self.execute_kill_confirmation();
            } else if ch == 'n' || ch == 'N' {
                self.cancel_kill_confirmation();
            } else if let Some(confirmation) = self.kill_confirmation_mut() {
                confirmation.error = Some("press y to confirm or Esc to cancel".to_owned());
            }
            return;
        }

        let Some(confirmation) = self.kill_confirmation_mut() else {
            return;
        };
        if confirmation.input.len() + ch.len_utf8() > CONFIRMATION_INPUT_MAX_BYTES {
            confirmation.error = Some(format!(
                "confirmation input is capped at {CONFIRMATION_INPUT_MAX_BYTES} bytes",
            ));
            return;
        }
        confirmation.input.push(ch);
        confirmation.error = None;
    }

    fn backspace_kill_input(&mut self) {
        let Some(confirmation) = self.kill_confirmation_mut() else {
            return;
        };
        confirmation.input.pop();
        confirmation.error = None;
    }

    /// Route confirmation keystrokes to whichever confirmation modal is open.
    /// The key contract is shared (Enter submits, Esc cancels, text appends),
    /// so the split happens here rather than in the input layer.
    fn submit_confirmation(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.modal() == ModalKind::ConfirmTreeKill {
            self.submit_tree_confirmation();
            return;
        }
        self.submit_kill_confirmation();
    }

    fn append_confirmation_input(&mut self, ch: char) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.modal() == ModalKind::ConfirmTreeKill {
            self.append_tree_input(ch);
            return;
        }
        self.append_kill_input(ch);
    }

    fn backspace_confirmation_input(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.modal() == ModalKind::ConfirmTreeKill {
            self.backspace_tree_input();
            return;
        }
        self.backspace_kill_input();
    }

    fn cancel_confirmation(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.modal() == ModalKind::ConfirmTreeKill {
            self.cancel_tree_confirmation();
            return;
        }
        self.cancel_kill_confirmation();
    }

    fn submit_kill_confirmation(&mut self) {
        let Some(confirmation) = self.kill_confirmation() else {
            return;
        };
        if process::confirmation_input_matches(
            &confirmation.input,
            &confirmation.target,
            confirmation.requirement,
        ) {
            self.execute_kill_confirmation();
            return;
        }

        if let Some(confirmation) = self.kill_confirmation_mut() {
            confirmation.error = Some(match confirmation.requirement {
                ConfirmationRequirement::Yes => "press y to confirm or Esc to cancel".to_owned(),
                ConfirmationRequirement::ForceWord => format!(
                    "type force and press Enter to confirm {}",
                    confirmation
                        .mode
                        .delivery_label(confirmation.target.platform),
                ),
                ConfirmationRequirement::ProtectedProcess => format!(
                    "type PID {} or process name {} to confirm",
                    confirmation.target.pid,
                    sanitize(confirmation.target.process_name_or_unknown()),
                ),
            });
        }
    }

    fn cancel_kill_confirmation(&mut self) {
        self.context_requested = false;
        self.modal = Modal::None;
        self.kill_status = Some("kill cancelled".to_owned());
    }

    /// Open the tree-kill confirmation for the selected row's PID and start the
    /// background preview enumeration.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn request_tree_kill(&mut self, mode: KillMode) {
        self.search_mode = false;
        self.kill_status = None;

        // Drain a completed cancelled worker before deciding whether a new one
        // can start. If it is still running, apply backpressure instead of
        // spawning another full process-table scan.
        self.poll_tree_preview();
        if self.tree_preview_worker.is_some() {
            self.kill_status = Some("tree preview is still finishing; retry shortly".to_owned());
            return;
        }

        let Some(target) = self.resolve_selected_kill_target() else {
            return;
        };
        let pid = target.pid;
        let platform = target.platform;

        self.modal = Modal::ConfirmTreeKill(TreeKillConfirmation::new(target, mode));
        self.spawn_tree_preview_worker(pid, platform);
    }

    /// Enumerate the tree off-thread because the process-table scan must not
    /// run on the render/input loop. The result is informational only; execution
    /// collects a fresh snapshot. A worker that loses a race with cancellation
    /// is drained later, and new preview requests wait for that worker instead
    /// of queuing more process-table scans.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn spawn_tree_preview_worker(&mut self, root_pid: u32, platform: crate::model::Platform) {
        let protected_names = self.protected_processes.clone();
        match crate::ui::spawn_worker(
            thread::Builder::new().name("kickoutchi-tree-preview".to_owned()),
            move || collect_tree_preview(root_pid, &protected_names, platform),
        ) {
            Ok(worker) => {
                self.tree_preview_worker = Some(TreePreviewWorker {
                    root_pid,
                    receiver: worker.detach(),
                });
            }
            Err(error) => {
                self.tree_preview_worker = None;

                self.modal = Modal::None;
                self.kill_status = Some(format!("starting tree preview worker failed: {error}"));
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn poll_tree_preview(&mut self) {
        let Some(worker) = self.tree_preview_worker.as_ref() else {
            return;
        };
        let result = match worker.receiver.try_recv() {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                self.tree_preview_worker = None;
                self.worker_failure = Some(error);
                return;
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                Err("tree preview worker exited before returning".to_owned())
            }
        };
        self.redraw_needed = true;
        let worker_pid = worker.root_pid;
        self.tree_preview_worker = None;
        self.apply_tree_preview(worker_pid, result);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn apply_tree_preview(&mut self, worker_pid: u32, result: TreePreviewResult) {
        let Some(mut confirmation) = self.take_tree_confirmation() else {
            // Cancelled while the worker was scanning; nothing to update.
            return;
        };
        if confirmation.target.pid != worker_pid {
            // The worker slot and confirmation are replaced together, so this
            // state is unreachable. Fail closed if that invariant breaks.
            debug_assert!(
                false,
                "tree preview worker PID does not match the open confirmation"
            );
            self.modal = Modal::None;
            self.kill_status = Some(
                "tree preview no longer matches the requested process; press t or T to retry"
                    .to_owned(),
            );
            return;
        }

        match result {
            Ok(preview) => match tree::preflight_outcome(&preview) {
                Ok(()) => {
                    // The port row and the tree scan are different readers: a
                    // root whose socket row had no readable name can still be
                    // identified as protected here. Protection can only become
                    // stricter, and input typed while loading is discarded.
                    confirmation.input.clear();
                    confirmation.error = None;
                    if preview.root().is_some_and(|node| node.protected)
                        && !confirmation.target.protected
                    {
                        confirmation.target.protected = true;
                        confirmation.stage = TreeConfirmStage::ProtectedRoot;
                    }
                    confirmation.preview = Some(preview);
                    self.modal = Modal::ConfirmTreeKill(confirmation);
                }
                // A gate failed on data we just read: close the modal and put
                // the refusal where kill outcomes go. Nothing was signalled.
                Err(outcome) => {
                    self.modal = Modal::None;
                    self.kill_status = Some(tree_kill_status_line(
                        &confirmation.target,
                        confirmation.mode,
                        &outcome,
                    ));
                }
            },
            Err(error) => {
                self.modal = Modal::None;
                self.kill_status = Some(format!("enumerating the process tree failed: {error}"));
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn append_tree_input(&mut self, ch: char) {
        let Some(confirmation) = self.tree_confirmation_mut() else {
            return;
        };
        if confirmation.preview.is_none() {
            confirmation.error = Some(
                "still enumerating the process tree; wait for the count before typing".to_owned(),
            );
            return;
        }
        if confirmation.input.len() + ch.len_utf8() > CONFIRMATION_INPUT_MAX_BYTES {
            confirmation.error = Some(format!(
                "confirmation input is capped at {CONFIRMATION_INPUT_MAX_BYTES} bytes",
            ));
            return;
        }
        confirmation.input.push(ch);
        confirmation.error = None;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn backspace_tree_input(&mut self) {
        let Some(confirmation) = self.tree_confirmation_mut() else {
            return;
        };
        if confirmation.preview.is_none() {
            return;
        }
        confirmation.input.pop();
        confirmation.error = None;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn cancel_tree_confirmation(&mut self) {
        self.context_requested = false;
        self.modal = Modal::None;
        self.kill_status = Some("tree kill cancelled".to_owned());
    }

    /// Decide what one Enter press on the tree confirmation means from an
    /// immutable view. Keeping the decision typed makes the stage transition
    /// explicit and lets the follow-up mutation happen after the shared borrow.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_submit_verdict(&self) -> Option<TreeSubmitVerdict> {
        let confirmation = self.tree_confirmation()?;
        if confirmation.preview.is_none() {
            return Some(TreeSubmitVerdict::Reject(
                "still enumerating the process tree; wait for the count".to_owned(),
            ));
        }
        Some(match confirmation.stage {
            TreeConfirmStage::ProtectedRoot => {
                if process::confirmation_input_matches(
                    &confirmation.input,
                    &confirmation.target,
                    ConfirmationRequirement::ProtectedProcess,
                ) {
                    TreeSubmitVerdict::AdvanceToWord
                } else {
                    TreeSubmitVerdict::Reject(format!(
                        "type PID {} or process name {} to confirm",
                        confirmation.target.pid,
                        sanitize(confirmation.target.process_name_or_unknown()),
                    ))
                }
            }
            TreeConfirmStage::Word => {
                let word = confirmation.scope_word();
                if tree::word_confirmation_matches(&confirmation.input, word) {
                    TreeSubmitVerdict::Execute
                } else {
                    TreeSubmitVerdict::Reject(format!(
                        "type {word} and press Enter to send {} to the tree",
                        confirmation
                            .mode
                            .delivery_label(confirmation.target.platform),
                    ))
                }
            }
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn submit_tree_confirmation(&mut self) {
        let Some(verdict) = self.tree_submit_verdict() else {
            return;
        };
        match verdict {
            TreeSubmitVerdict::Execute => self.execute_tree_kill_confirmation(),
            TreeSubmitVerdict::AdvanceToWord => {
                if let Some(confirmation) = self.tree_confirmation_mut() {
                    confirmation.stage = TreeConfirmStage::Word;
                    confirmation.input.clear();
                    confirmation.error = None;
                }
            }
            TreeSubmitVerdict::Reject(message) => {
                if let Some(confirmation) = self.tree_confirmation_mut() {
                    confirmation.error = Some(message);
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn execute_tree_kill_confirmation(&mut self) {
        let Some(pid) = self
            .tree_confirmation()
            .map(|confirmation| confirmation.target.pid)
        else {
            return;
        };
        let mut ops = host_tree_ops();
        self.execute_tree_kill_confirmation_with(
            || collector::collect_kill_ports(Some(pid), None),
            Self::refresh,
            platform::collect_process_context,
            &mut ops,
        );
    }

    /// Run the confirmed tree kill: fresh root revalidation, fresh bounded
    /// preflight, then the freeze-first pipeline. The preview the user saw is
    /// not trusted for execution. Membership may change between confirmation
    /// and now, but every gate must re-pass against reality, and the root must
    /// still be exactly the confirmed process.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn execute_tree_kill_confirmation_with<CollectKillPorts, StartRefresh, CollectContext, Ops>(
        &mut self,
        mut collect_kill_ports: CollectKillPorts,
        mut start_refresh: StartRefresh,
        mut collect_context: CollectContext,
        ops: &mut Ops,
    ) where
        CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
        StartRefresh: FnMut(&mut Self),
        CollectContext: FnMut(u32) -> ProcessContext,
        Ops: tree::TreeProcessOps,
    {
        let Some(confirmation) = self.take_tree_confirmation() else {
            return;
        };
        if confirmation.target.process_start_time_marker.is_none()
            && self.process_context_loading_for_pid(confirmation.target.pid)
        {
            self.modal = Modal::ConfirmTreeKill(TreeKillConfirmation {
                error: Some("still reading process metadata; retry once it finishes".to_owned()),
                ..confirmation
            });
            return;
        }
        self.tree_preview_worker = None;
        self.modal = Modal::None;

        if let Err(outcome) = tree::pin_root_before_revalidation(confirmation.target.pid, ops) {
            self.apply_tree_pin_refusal(
                &confirmation.target,
                confirmation.mode,
                &outcome,
                &mut start_refresh,
            );
            return;
        }

        let mut fresh_rows = match collect_kill_ports() {
            Ok(rows) => rows,
            Err(error) => {
                self.latest_error = Some(error.to_string());
                self.kill_status = Some(format!(
                    "collecting ports before tree kill failed; no termination was sent: {error}",
                ));
                return;
            }
        };
        mark_protected(&mut fresh_rows, &self.protected_processes);
        let fresh_context = collect_context(confirmation.target.pid);
        // Revalidation borrows the freshly collected rows until the gate completes.
        let fresh_views = fresh_rows
            .iter()
            .map(PortEntryView::from)
            .collect::<Vec<_>>();
        let fresh_root = match process::revalidate_confirmed_target(
            &confirmation.target,
            &fresh_views,
            Some(&fresh_context),
        ) {
            Ok(root) => root,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(
                    &confirmation.target,
                    confirmation.mode,
                    &outcome,
                ));
                self.refresh_after_kill(&mut start_refresh);
                return;
            }
        };

        if let Err(outcome) =
            fresh_tree_gates(&fresh_root, &self.protected_processes, &confirmation, ops)
        {
            self.kill_status = Some(tree_kill_status_line(
                &fresh_root,
                confirmation.mode,
                &outcome,
            ));
            if matches!(outcome, tree::TreeKillOutcome::RootAlreadyExited) {
                self.refresh_after_kill(&mut start_refresh);
            }
            return;
        }

        // The TUI never skips the typed-word modal.
        let authorization = if confirmation.target.protected {
            tree::ScopeAuthorization::ProtectedRootAndWordConfirmed
        } else {
            tree::ScopeAuthorization::TypedWordConfirmed
        };
        let outcome = tree::execute_tree_kill(
            &fresh_root,
            confirmation.mode,
            &self.protected_processes,
            fresh_root.platform,
            authorization,
            ops,
        );
        self.kill_status = Some(tree_kill_status_line(
            &fresh_root,
            confirmation.mode,
            &outcome,
        ));
        // Best-effort post-kill refresh so freed ports drop from the table; a
        // failed re-collect shows as the standard error line rather than the
        // status overclaiming a refresh that did not run.
        self.refresh_after_kill(&mut start_refresh);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn apply_tree_pin_refusal<StartRefresh>(
        &mut self,
        target: &KillTarget,
        mode: KillMode,
        outcome: &tree::TreeKillOutcome,
        start_refresh: &mut StartRefresh,
    ) where
        StartRefresh: FnMut(&mut Self),
    {
        self.kill_status = Some(tree_kill_status_line(target, mode, outcome));
        if matches!(outcome, tree::TreeKillOutcome::RootAlreadyExited) {
            self.refresh_after_kill(start_refresh);
        }
    }

    fn execute_kill_confirmation(&mut self) {
        let Some(pid) = self
            .kill_confirmation()
            .map(|confirmation| confirmation.target.pid)
        else {
            return;
        };
        self.execute_kill_confirmation_with(
            || collector::collect_kill_ports(Some(pid), None),
            Self::refresh,
            platform::collect_process_context,
            process::prepare_termination,
            process::terminate_handle_checked,
        );
    }

    fn execute_kill_confirmation_with<
        CollectKillPorts,
        StartRefresh,
        CollectContext,
        Prepare,
        Terminate,
        Handle,
    >(
        &mut self,
        mut collect_kill_ports: CollectKillPorts,
        mut start_refresh: StartRefresh,
        mut collect_context: CollectContext,
        mut prepare: Prepare,
        mut terminate: Terminate,
    ) where
        CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
        StartRefresh: FnMut(&mut Self),
        CollectContext: FnMut(u32) -> ProcessContext,
        Prepare: FnMut(u32) -> Result<Handle, TerminationOutcome>,
        Terminate: FnMut(&Handle, &KillTarget, &[String], KillMode) -> TerminationOutcome,
    {
        let Some(confirmation) = self.take_kill_confirmation() else {
            return;
        };
        if self.process_context_loading_for_pid(confirmation.target.pid) {
            self.modal = Modal::ConfirmKill(KillConfirmation {
                error: Some("still reading process metadata; retry once it finishes".to_owned()),
                ..confirmation
            });
            return;
        }
        self.modal = Modal::None;

        let handle = match prepare(confirmation.target.pid) {
            Ok(handle) => handle,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(
                    &confirmation.target,
                    confirmation.mode,
                    &outcome,
                ));
                // Re-collect after an already-exited target so its freed row can
                // leave the table. Other preparation failures leave the process
                // running and need no refresh.
                if matches!(outcome, TerminationOutcome::AlreadyExited) {
                    self.refresh_after_kill(&mut start_refresh);
                }
                return;
            }
        };

        let mut fresh_rows = match collect_kill_ports() {
            Ok(rows) => rows,
            Err(error) => {
                self.latest_error = Some(error.to_string());
                self.kill_status = Some(format!(
                    "collecting ports before kill failed; no termination was sent: {error}",
                ));
                return;
            }
        };
        mark_protected(&mut fresh_rows, &self.protected_processes);
        let fresh_context = collect_context(confirmation.target.pid);
        // Revalidation borrows the freshly collected rows until the gate completes.
        let fresh_views = fresh_rows
            .iter()
            .map(PortEntryView::from)
            .collect::<Vec<_>>();
        let target = match process::revalidate_confirmed_target(
            &confirmation.target,
            &fresh_views,
            Some(&fresh_context),
        ) {
            Ok(target) => target,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(
                    &confirmation.target,
                    confirmation.mode,
                    &outcome,
                ));
                self.refresh_after_kill(&mut start_refresh);
                return;
            }
        };
        if let Err(outcome) =
            process::validate_single_delivery_evidence(&confirmation.target, &target)
        {
            self.kill_status = Some(termination_status_line(
                &confirmation.target,
                confirmation.mode,
                &outcome,
            ));
            self.refresh_after_kill(&mut start_refresh);
            return;
        }
        let outcome = terminate(
            &handle,
            &target,
            &self.protected_processes,
            confirmation.mode,
        );
        self.kill_status = Some(termination_status_line(
            &target,
            confirmation.mode,
            &outcome,
        ));
        // Best-effort post-kill refresh so the freed port drops from the table.
        // The status reports only the signal result; a failed re-collect shows up
        // as the standard error line rather than letting the status overclaim a
        // refresh that did not run.
        self.refresh_after_kill(&mut start_refresh);
    }

    fn refresh_after_kill(&mut self, start_refresh: &mut impl FnMut(&mut Self)) {
        if let Some(worker) = self.refresh_worker.as_mut() {
            worker.stale = true;
            self.refresh_after_kill = true;
        } else {
            start_refresh(self);
        }
    }

    #[cfg(test)]
    pub(crate) fn apply_test_rows(&mut self, rows: Vec<PortEntry>, now: Instant) {
        self.apply_network_snapshot(crate::observation::snapshot_from_test_rows(rows), now);
    }

    fn rebuild_visible_rows(&mut self) {
        let selected_key = self.selected_row().map(RowKey::from);
        let fallback_index = self.selected_index.unwrap_or(0);
        self.rebuild_visible_rows_preserving(selected_key, fallback_index);
    }

    fn ensure_sorted_row_indices(&mut self) {
        let row_count = self.row_count();
        if self.sorted_row_indices.as_ref().is_some_and(|cached| {
            cached.sort_mode == self.sort_mode && cached.indices.len() == row_count
        }) {
            return;
        }

        let result = query::query_view_indices_by(
            row_count,
            |index| {
                self.row_view(index)
                    .expect("snapshot and row descriptors must remain synchronized")
            },
            QueryOptions {
                port: None,
                process: None,
                filter_text: "",
                sort_mode: self.sort_mode,
                hide_system_processes: false,
                capabilities: crate::query::QueryCapabilities::LIST,
            },
        )
        .expect("an empty list query is always valid");
        debug_assert_eq!(result.indices.len(), row_count);
        self.sorted_row_indices = Some(SortedRowIndices {
            sort_mode: self.sort_mode,
            indices: result.indices,
        });
    }

    fn rebuild_visible_rows_preserving(
        &mut self,
        selected_key: Option<RowKey>,
        fallback_index: usize,
    ) {
        // The selection mask stores one bool per source row. Recording key matches during
        // the query's sole projection avoids rebuilding views while preserving
        // the existing first-visible-match behavior for duplicate row keys.
        let mut selected_source_rows = selected_key.map(|_| vec![false; self.row_count()]);
        // The bound and callback share the same descriptor table. A missing
        // view therefore means the snapshot and its descriptors diverged.
        let options = QueryOptions {
            port: None,
            process: None,
            filter_text: &self.filter_text,
            sort_mode: self.sort_mode,
            hide_system_processes: self.hide_system_processes,
            capabilities: crate::query::QueryCapabilities::LIST,
        };
        let query_result = {
            let mut view_at = |index| {
                let view = self
                    .row_view(index)
                    .expect("snapshot and row descriptors must remain synchronized");
                if selected_key.is_some_and(|key| RowKey::from(view) == key) {
                    selected_source_rows
                        .as_mut()
                        .expect("a selected key allocates its source-row mask")[index] = true;
                }
                view
            };
            match self.sorted_row_indices.as_ref() {
                Some(cached)
                    if cached.sort_mode == self.sort_mode
                        && cached.indices.len() == self.row_count() =>
                {
                    query::filter_preordered_view_indices_by(&cached.indices, &mut view_at, options)
                }
                Some(_) | None => {
                    query::query_view_indices_by(self.row_count(), &mut view_at, options)
                }
            }
        };
        let (visible_row_indices, filter_error) = match query_result {
            Ok(result) => {
                if !result.explicit_filter_active && !self.hide_system_processes {
                    self.sorted_row_indices = Some(SortedRowIndices {
                        sort_mode: self.sort_mode,
                        indices: result.indices.clone(),
                    });
                }
                (result.indices, None)
            }
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let selected_index = preserved_selection(
            &visible_row_indices,
            selected_source_rows.as_deref(),
            fallback_index,
        );
        self.visible_row_indices = visible_row_indices;
        self.filter_error = filter_error;
        self.selected_index = selected_index;
    }

    fn load_selected_process_context(&mut self) {
        let selected_key = self.selected_row().map(RowKey::from);
        if self.selected_context_key == selected_key && self.selected_process_context.is_some() {
            self.context_requested = false;
            return;
        }
        if let Some(worker) = self.context_worker.as_ref() {
            if Some(worker.key) == selected_key && !worker.stale {
                return;
            }
            // One worker owns the process/Docker scan until its channel drains.
            // A single boolean is the bounded latest-request queue: the current
            // selection is read only when the worker finishes, so repeated row
            // changes cannot accumulate entries or background threads.
            self.context_requested = true;
            self.selected_context_key = None;
            self.selected_process_context = None;
            return;
        }

        self.selected_context_key = None;
        self.selected_process_context = None;

        let Some(view) = self.selected_row() else {
            self.context_requested = false;
            return;
        };
        let entry = PortEntry {
            protocol: view.protocol,
            local_addr: view.local_addr,
            local_port: view.local_port,
            state: view.state,
            pid: view.pid,
            process_name: view.process_name.map(Into::into),
            executable_path: view.executable_path.map(Into::into),
            command_line: view.command_line.map(Into::into),
            parent_pid: view.parent_pid,
            parent_process_name: view.parent_process_name.map(Into::into),
            protected: view.protected,
            platform: view.platform,
            permission: view.permission,
            process_identity: view.process_identity,
            ipv6_scope: view.ipv6_scope,
        };
        let key = RowKey::from(&entry);
        let docker_enrichment = self.docker_enrichment;
        match crate::ui::spawn_worker(
            thread::Builder::new().name("kickoutchi-details".to_owned()),
            move || {
                // The worker outlives the snapshot the view borrowed, so the row
                // is owned across the thread boundary and re-borrowed here.
                collect_selected_process_context(PortEntryView::from(&entry), docker_enrichment)
            },
        ) {
            Ok(worker) => {
                self.context_requested = false;
                self.context_worker = Some(ContextWorker {
                    key,
                    receiver: worker.detach(),
                    stale: false,
                });
            }
            Err(error) => {
                self.context_requested = false;
                self.context_worker = None;
                self.latest_error = Some(format!("starting details worker failed: {error}"));
            }
        }
    }

    fn process_context_loading_for_pid(&self, pid: u32) -> bool {
        self.context_worker
            .as_ref()
            .is_some_and(|worker| worker.key.pid == Some(pid))
            || (self.context_requested
                && self.selected_row().is_some_and(|row| row.pid == Some(pid)))
    }

    fn start_pending_process_context_request(&mut self) {
        if !self.context_requested {
            return;
        }
        self.context_requested = false;
        self.load_selected_process_context();
    }

    fn kill_target_with_optional_context(
        &self,
        pid: u32,
        context: Option<&ProcessContext>,
    ) -> Option<KillTarget> {
        let mut rows = self
            .all_views()
            .filter(|row| row.pid == Some(pid))
            .peekable();
        rows.peek()?;
        Some(KillTarget::from_entries(pid, rows, context))
    }

    fn apply_context_target_to_confirmations(&mut self, mut target: KillTarget) {
        if let Some(confirmation) = self.kill_confirmation_mut()
            && confirmation.target.pid == target.pid
        {
            target.protected |= confirmation.target.protected;
            confirmation.target = target.clone();
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(confirmation) = self.tree_confirmation_mut()
            && confirmation.target.pid == target.pid
        {
            target.protected |= confirmation.target.protected;
            confirmation.target = target;
        }
    }

    fn append_search_char(&mut self, ch: char) {
        if !self.search_mode {
            return;
        }
        if self.filter_text.len() + ch.len_utf8() > FILTER_TEXT_MAX_BYTES {
            return;
        }
        self.ensure_sorted_row_indices();
        self.filter_text.push(ch);
        self.rebuild_visible_rows();
    }

    fn backspace_search(&mut self) {
        if !self.search_mode {
            return;
        }
        self.ensure_sorted_row_indices();
        self.filter_text.pop();
        self.rebuild_visible_rows();
    }

    fn cancel_search(&mut self) {
        self.search_mode = false;
        if !self.filter_text.is_empty() {
            self.ensure_sorted_row_indices();
            self.filter_text.clear();
            self.rebuild_visible_rows();
        }
    }

    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.rebuild_visible_rows();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn tree_confirmation(&self) -> Option<&TreeKillConfirmation> {
        match &self.modal {
            Modal::ConfirmTreeKill(confirmation) => Some(confirmation),
            _ => None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_confirmation_mut(&mut self) -> Option<&mut TreeKillConfirmation> {
        match &mut self.modal {
            Modal::ConfirmTreeKill(confirmation) => Some(confirmation),
            _ => None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn take_tree_confirmation(&mut self) -> Option<TreeKillConfirmation> {
        self.tree_confirmation()?;
        match std::mem::take(&mut self.modal) {
            Modal::ConfirmTreeKill(confirmation) => Some(confirmation),
            _ => unreachable!("confirmation was checked before taking the modal"),
        }
    }

    /// Deliver a tree preview result as if the background worker had returned
    /// it, so render and state tests never wait on a real process-table scan.
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn finish_tree_preview_for_test(&mut self, result: TreePreviewResult) {
        let pid = self
            .tree_confirmation()
            .map(|confirmation| confirmation.target.pid)
            .expect("a tree confirmation must be open");
        self.tree_preview_worker = None;
        self.apply_tree_preview(pid, result);
    }
}

#[cfg(test)]
mod tests;
