//! Selected-row details panel and modal.

use std::path::Path;
use std::sync::Arc;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::App;
use crate::display::{human_address_text, human_endpoint_text, sanitize};
use crate::model::{ChildProcessSnapshot, PermissionStatus, PortEntryView, ProcessContext};

use super::{field, rendered_rows, theme::Theme, wrapped_rows};

const MISSING: &str = "-";
const CHILDREN_DISPLAY_MAX: usize = 8;

/// At most one selected command and path. Sources share the snapshot's immutable
/// Arcs; sanitized text is bounded by three times the native metadata byte caps.
/// Retaining the source Arc prevents pointer reuse from hiding a metadata change.
#[derive(Default)]
pub(super) struct TextCache {
    command: Option<Arc<str>>,
    command_text: String,
    path: Option<Arc<Path>>,
    path_text: String,
}

impl TextCache {
    pub(super) fn update(&mut self, metadata: Option<&crate::observation::ProcessObservation>) {
        update_text(
            &mut self.command,
            &mut self.command_text,
            metadata.and_then(|process| process.command_line.as_ref()),
            sanitize,
        );
        update_text(
            &mut self.path,
            &mut self.path_text,
            metadata.and_then(|process| process.executable_path.as_ref()),
            |path| sanitize(&path.display().to_string()),
        );
    }

    fn command(&self) -> &str {
        if self.command.is_some() {
            &self.command_text
        } else {
            MISSING
        }
    }

    fn path(&self) -> &str {
        if self.path.is_some() {
            &self.path_text
        } else {
            MISSING
        }
    }
}

fn update_text<T: ?Sized>(
    source: &mut Option<Arc<T>>,
    text: &mut String,
    current: Option<&Arc<T>>,
    render: impl FnOnce(&T) -> String,
) {
    match current {
        Some(current) if source.as_ref().is_some_and(|old| Arc::ptr_eq(old, current)) => {}
        Some(current) => {
            *text = render(current);
            *source = Some(Arc::clone(current));
        }
        None => {
            *source = None;
            *text = String::new();
        }
    }
}

pub(super) fn render_panel(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: Theme,
    text: &TextCache,
) {
    let block = Block::bordered()
        .title("Details")
        .title_style(theme.title())
        .border_style(theme.border());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if let Some(entry) = app.selected_row().filter(|entry| entry.protected) {
        let warning = Line::styled(
            "Warning: protected process; stronger confirmation required.",
            theme.protected(),
        );
        let warning_rows = wrapped_rows(&warning.to_string(), usize::from(inner.width));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(u16::try_from(warning_rows).unwrap_or(u16::MAX)),
            ])
            .split(inner);
        let lines = panel_lines(
            entry,
            app.selected_process_context(),
            app.selected_process_context_loading(),
            theme,
            usize::from(chunks[0].height),
            text,
        );
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
        frame.render_widget(
            Paragraph::new(warning).wrap(Wrap { trim: false }),
            chunks[1],
        );
    } else {
        let lines = app.selected_row().map_or_else(
            || empty_lines(theme),
            |entry| {
                panel_lines(
                    entry,
                    app.selected_process_context(),
                    app.selected_process_context_loading(),
                    theme,
                    usize::from(inner.height),
                    text,
                )
            },
        );
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

pub(super) fn render_modal(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: Theme,
    text: &TextCache,
) {
    let lines = app.selected_row().map_or_else(
        || empty_lines(theme),
        |entry| {
            modal_lines(
                entry,
                app.selected_process_context(),
                app.selected_process_context_loading(),
                theme,
                text,
            )
        },
    );
    let warning = app.selected_row().filter(|entry| entry.protected).map(|_| {
        Line::styled(
            "Protected process: stronger confirmation will be required before termination.",
            theme.protected(),
        )
    });
    let block = Block::bordered()
        .title("Port Details")
        .title_style(theme.title())
        .border_style(theme.border());
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let warning_rows = warning.as_ref().map_or(0, |warning| {
        wrapped_rows(&warning.to_string(), usize::from(inner.width))
    });
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(u16::try_from(warning_rows).unwrap_or(u16::MAX)),
            Constraint::Length(1),
        ])
        .split(inner);
    let total_rows = rendered_rows(&lines, usize::from(chunks[0].width));
    let max_scroll = total_rows.saturating_sub(usize::from(chunks[0].height));
    let scroll = usize::from(app.modal_scroll()).min(max_scroll);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    if let Some(warning) = warning {
        frame.render_widget(
            Paragraph::new(warning).wrap(Wrap { trim: false }),
            chunks[1],
        );
    }
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Up/Down", theme.key()),
            Span::raw(" scroll  "),
            Span::styled("Esc", theme.key()),
            Span::raw(" closes"),
        ])),
        chunks[2],
    );
}

fn panel_lines<'a>(
    entry: PortEntryView<'_>,
    context: Option<&ProcessContext>,
    context_loading: bool,
    theme: Theme,
    max_rows: usize,
    text: &'a TextCache,
) -> Vec<Line<'a>> {
    // Evaluate only visible fields. A hidden command can be a full MiB.
    (0..max_rows.min(7))
        .map(|index| match index {
            0 => field(
                "PID",
                format!(
                    "{} | Process: {}",
                    optional_u32(entry.pid),
                    sanitize_optional_str(entry.process_name)
                ),
                theme,
            ),
            1 => field(
                "Bind",
                format!(
                    "{} {} {} | {}",
                    entry.protocol.label(),
                    human_endpoint_text(entry.local_addr, entry.local_port, entry.ipv6_scope),
                    entry.state.label(),
                    entry.scope_label()
                ),
                theme,
            ),
            2 => field("Permission", permission_text(entry), theme),
            3 => field("Parent", parent_text(entry), theme),
            4 => field(
                "Children",
                children_text(entry, context, context_loading),
                theme,
            ),
            5 => field("Path", text.path(), theme),
            6 => field("Command", text.command(), theme),
            _ => unreachable!("the panel has seven fields"),
        })
        .collect()
}

fn modal_lines<'a>(
    entry: PortEntryView<'_>,
    context: Option<&ProcessContext>,
    context_loading: bool,
    theme: Theme,
    text: &'a TextCache,
) -> Vec<Line<'a>> {
    let mut lines = vec![
        field("Protocol", entry.protocol.label().to_owned(), theme),
        field(
            "Address",
            human_address_text(entry.local_addr, entry.ipv6_scope),
            theme,
        ),
        field("Port", entry.local_port.to_string(), theme),
        field("Scope", entry.scope_label().to_owned(), theme),
        field("State", entry.state.label().to_owned(), theme),
        field("PID", optional_u32(entry.pid), theme),
        field("Process", sanitize_optional_str(entry.process_name), theme),
    ];

    lines.extend([
        field("Parent", parent_text(entry), theme),
        field(
            "Children",
            children_text(entry, context, context_loading),
            theme,
        ),
        field("User", user_text(context), theme),
        field("Permission", permission_text(entry), theme),
    ]);

    lines.push(field("Path", text.path(), theme));
    lines.push(field("Command", text.command(), theme));
    lines
}

fn empty_lines(theme: Theme) -> Vec<Line<'static>> {
    vec![Line::styled("No open ports to show.", theme.muted())]
}

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| MISSING.to_owned(), |value| value.to_string())
}

fn sanitize_optional_str(value: Option<&str>) -> String {
    value.map_or_else(|| MISSING.to_owned(), sanitize)
}

fn parent_text(entry: PortEntryView<'_>) -> String {
    match (entry.parent_process_name, entry.parent_pid) {
        (Some(name), Some(pid)) => format!("{} (PID {pid})", sanitize(name)),
        (Some(name), None) => sanitize(name),
        (None, Some(pid)) => format!("PID {pid}"),
        (None, None) => MISSING.to_owned(),
    }
}

fn children_text(
    entry: PortEntryView<'_>,
    context: Option<&ProcessContext>,
    context_loading: bool,
) -> String {
    if entry.pid.is_none() {
        return MISSING.to_owned();
    }

    if context_loading {
        return "loading".to_owned();
    }

    let Some(context) = context else {
        return "open details to load".to_owned();
    };
    // Children are attached only after the row's process generation was
    // re-verified; without that proof the PID may now name another process.
    if context.process_start_time_marker.is_none() {
        return "not shown (the process may have exited or been replaced)".to_owned();
    }
    children_snapshot_text(&context.children)
}

fn children_snapshot_text(snapshot: &ChildProcessSnapshot) -> String {
    if snapshot.children.is_empty() {
        return "none".to_owned();
    }

    let visible = snapshot
        .children
        .iter()
        .take(CHILDREN_DISPLAY_MAX)
        .map(|child| {
            let name = child
                .process_name
                .as_deref()
                .map_or_else(|| "<unknown>".to_owned(), sanitize);
            format!("PID {} ({name})", child.pid)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let hidden = snapshot.children.len().saturating_sub(CHILDREN_DISPLAY_MAX);
    let suffix = if snapshot.truncated {
        " (truncated)".to_owned()
    } else if hidden > 0 {
        format!(" (+{hidden} more)")
    } else {
        String::new()
    };
    format!("{} ({visible}){suffix}", snapshot.children.len())
}

fn user_text(context: Option<&ProcessContext>) -> String {
    context
        .and_then(|context| context.owner_uid)
        .map_or_else(|| MISSING.to_owned(), |uid| format!("uid {uid}"))
}

fn permission_text(entry: PortEntryView<'_>) -> &'static str {
    match (entry.permission, entry.pid) {
        (PermissionStatus::Full, _) => "full",
        (PermissionStatus::Partial, None) => {
            "owner hidden: the owning process could not be read (usually another user's; try sudo)"
        }
        (PermissionStatus::Partial, Some(_)) => "partial: some process details could not be read",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use super::{MISSING, children_text, panel_lines, parent_text, permission_text, user_text};
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, PortEntryView,
        ProcessContext, Protocol, SocketState,
    };
    use crate::ui::theme::Theme;

    fn entry() -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(18_422),
            process_name: Some("node".into()),
            executable_path: Some(PathBuf::from("/usr/bin/node").into()),
            command_line: Some("node server.js".into()),
            parent_pid: Some(18_001),
            parent_process_name: Some("cursor-agent".into()),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    #[test]
    fn protected_panel_keeps_permission_and_leaves_warning_to_the_reserved_row() {
        let mut row = entry();
        let text = super::TextCache::default();
        row.protected = true;
        let lines = panel_lines(
            PortEntryView::from(&row),
            Some(&ProcessContext::default()),
            false,
            Theme::from_environment(),
            6,
            &text,
        );
        let text = lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Permission: full"), "{text}");
        assert!(!text.contains("Warning: protected process"), "{text}");
    }

    #[test]
    fn panel_bind_text_preserves_ipv6_interface_scope() {
        let mut row = entry();
        let text = super::TextCache::default();
        row.local_addr = IpAddr::V6("fe80::1".parse().expect("test address is valid"));
        row.ipv6_scope =
            Some(crate::observation::Ipv6Scope::interface_index(3).expect("test scope is valid"));
        let lines = panel_lines(
            PortEntryView::from(&row),
            None,
            false,
            Theme::from_environment(),
            7,
            &text,
        );

        assert!(
            lines
                .iter()
                .any(|line| line.to_string().contains("TCP [fe80::1%3]:3000"))
        );
    }

    #[test]
    fn parent_text_covers_partial_metadata() {
        let mut row = entry();
        assert_eq!(
            parent_text(PortEntryView::from(&row)),
            "cursor-agent (PID 18001)"
        );

        row.parent_process_name = None;
        assert_eq!(parent_text(PortEntryView::from(&row)), "PID 18001");

        row.parent_pid = None;
        assert_eq!(parent_text(PortEntryView::from(&row)), MISSING);
    }

    #[test]
    fn children_text_distinguishes_missing_none_and_named_children() {
        let mut row = entry();
        let context = ProcessContext {
            owner_uid: Some(1000),
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            children: ChildProcessSnapshot {
                children: vec![
                    ChildProcess {
                        pid: 18_430,
                        process_name: Some("worker".to_owned()),
                    },
                    ChildProcess {
                        pid: 18_431,
                        process_name: None,
                    },
                ],
                truncated: false,
            },
        };

        assert_eq!(
            children_text(PortEntryView::from(&row), Some(&context), false),
            "2 (PID 18430 (worker), PID 18431 (<unknown>))"
        );
        assert_eq!(user_text(Some(&context)), "uid 1000");

        row.pid = None;
        assert_eq!(
            children_text(PortEntryView::from(&row), Some(&context), false),
            MISSING
        );

        row.pid = Some(18_422);
        let verified_without_children = ProcessContext {
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            ..ProcessContext::default()
        };
        assert_eq!(
            children_text(
                PortEntryView::from(&row),
                Some(&verified_without_children),
                false
            ),
            "none"
        );
        assert_eq!(
            children_text(
                PortEntryView::from(&row),
                Some(&ProcessContext::default()),
                false
            ),
            "not shown (the process may have exited or been replaced)"
        );
        assert_eq!(
            children_text(PortEntryView::from(&row), None, true),
            "loading"
        );
        assert_eq!(
            children_text(PortEntryView::from(&row), None, false),
            "open details to load"
        );
    }

    #[test]
    fn permission_text_explains_hidden_owners_and_partial_metadata() {
        let mut row = entry();
        row.permission = PermissionStatus::Full;
        assert_eq!(permission_text(PortEntryView::from(&row)), "full");
        row.permission = PermissionStatus::Partial;
        assert_eq!(
            permission_text(PortEntryView::from(&row)),
            "partial: some process details could not be read"
        );
        row.pid = None;
        assert!(permission_text(PortEntryView::from(&row)).starts_with("owner hidden:"));
    }
}
