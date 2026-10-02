//! Termination confirmation modal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::{self, App, KillConfirmation};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::app::{TreeConfirmStage, TreeKillConfirmation};
use crate::display::sanitize;
use crate::process::{ConfirmationRequirement, KillTarget, WarningScope};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::wrapped_rows;
use super::{field, rendered_rows, theme::Theme};

/// Ceiling on the node preview inside the tree confirmation modal. The actual
/// number of preview rows is budgeted per render from the modal height, so the
/// typed-word instruction, input echo, and Escape hint remain visible.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TREE_MODAL_PREVIEW_MAX: usize = 8;

/// Render the single-process confirmation modal.
///
/// Returns `false` when the modal cannot show every warning and the prompt in
/// full; the caller must then cancel instead of leaving a clipped prompt open.
pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) -> bool {
    let content_rows = usize::from(area.height.saturating_sub(2));
    let content_cols = usize::from(area.width.saturating_sub(2));
    let lines = app.kill_confirmation().map_or_else(
        || {
            Some(vec![Line::styled(
                "No termination target selected.",
                theme.muted(),
            )])
        },
        |confirmation| confirmation_lines(confirmation, theme, content_rows, content_cols),
    );
    let (lines, actionable) = lines.map_or_else(
        || (confirmation_unavailable_lines("operation", theme), false),
        |lines| (lines, true),
    );

    let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Confirm Termination")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(modal, area);
    actionable
}

fn confirmation_unavailable_lines(operation: &str, theme: Theme) -> Vec<Line<'static>> {
    vec![
        Line::styled("Confirmation unavailable", theme.warning()),
        Line::raw("The terminal cannot show every warning and confirmation field."),
        Line::raw(format!(
            "Enlarge the terminal and request the {operation} again."
        )),
    ]
}

/// Render the tree-kill confirmation modal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn render_tree(frame: &mut Frame, area: Rect, app: &App, theme: Theme) -> bool {
    // Rows available inside the borders drive the preview budget, so the
    // prompt block stays visible at every supported terminal size.
    let content_rows = usize::from(area.height.saturating_sub(2));
    let content_cols = usize::from(area.width.saturating_sub(2));
    let lines = app.tree_confirmation().map_or_else(
        || {
            Some(vec![Line::styled(
                "No tree termination target selected.",
                theme.muted(),
            )])
        },
        |confirmation| tree_confirmation_lines(confirmation, theme, content_rows, content_cols),
    );
    let (lines, actionable) = lines.map_or_else(
        || {
            (
                confirmation_unavailable_lines("tree operation", theme),
                false,
            )
        },
        |lines| (lines, true),
    );

    let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Confirm Tree Termination")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(modal, area);
    actionable
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_confirmation_lines(
    confirmation: &TreeKillConfirmation,
    theme: Theme,
    content_rows: usize,
    content_cols: usize,
) -> Option<Vec<Line<'static>>> {
    // Measure the rendered mandatory lines before allocating preview rows. This
    // keeps the instruction, input, and Escape hint visible.
    let mut head = vec![
        Line::styled(tree_header_text(confirmation), theme.title()),
        field(
            "Ports",
            clipped_field_value(
                &sanitize(&confirmation.target.ports_text()),
                "Ports",
                content_cols,
            ),
            theme,
        ),
    ];
    let preview_ready = confirmation.preview.is_some();
    match &confirmation.preview {
        // The background worker is still walking the process table; the modal
        // must say so instead of showing a count it does not have or accepting
        // a word before the user can review that count.
        None => head.push(Line::styled(
            "Enumerating the process tree...",
            theme.muted(),
        )),
        Some(preview) => head.push(field(
            "Scope",
            format!("tree ({} processes)", preview.len()),
            theme,
        )),
    }

    // Append warnings and the prompt after the budgeted preview nodes.
    let mut tail: Vec<Line<'static>> = Vec::new();
    if let Some(preview) = &confirmation.preview {
        if preview.has_system_process() {
            tail.push(Line::styled(
                "Warning: tree includes system/service processes; verify this is safe to terminate.",
                theme.warning(),
            ));
        }
        if preview.has_owner_mismatch() {
            tail.push(Line::styled(
                "Warning: tree includes processes owned by another uid; verify this is safe to terminate.",
                theme.warning(),
            ));
        }
    }
    if let Some(warning) = confirmation
        .mode
        .force_warning(confirmation.target.platform)
    {
        tail.push(Line::styled(format!("Warning: {warning}"), theme.warning()));
    }
    for warning in confirmation.target.warnings() {
        tail.push(Line::styled(
            format!("Warning: {}.", sanitize(&warning.text(WarningScope::Tree))),
            theme.warning(),
        ));
    }
    tail.push(Line::raw(""));
    tail.push(tree_instruction_line(confirmation, theme));
    if preview_ready {
        tail.push(field("Input", confirmation.input.clone(), theme));
    }
    if let Some(error) = &confirmation.error {
        tail.push(Line::styled(format!("Error: {error}"), theme.warning()));
    }
    tail.push(Line::raw(""));
    tail.push(Line::from(vec![
        Span::styled("Esc", theme.key()),
        Span::raw(" cancels."),
    ]));

    let fixed_rows =
        rendered_rows(&head, content_cols).saturating_add(rendered_rows(&tail, content_cols));
    // A modal too small for the mandatory rows must refuse to be actionable
    // instead of rendering a prompt the user cannot fully review.
    let preview_rows = content_rows.checked_sub(fixed_rows)?;

    let mut lines = head;
    if let Some(preview) = &confirmation.preview {
        let node_lines = preview
            .preview_nodes(preview.len().min(TREE_MODAL_PREVIEW_MAX))
            .iter()
            .map(|node| Line::raw(tree_node_text(node)))
            .collect::<Vec<_>>();
        let fitting_nodes =
            fitting_preview_nodes(&node_lines, preview.len(), preview_rows, content_cols);
        lines.extend(node_lines.into_iter().take(fitting_nodes));
        if fitting_nodes > 0 && preview.len() > fitting_nodes {
            lines.push(Line::raw(omitted_count_text(preview.len() - fitting_nodes)));
        }
    }
    lines.extend(tail);
    Some(lines)
}

/// How many preview node lines fit in `preview_rows`. Node names are charged
/// by wrapped terminal height rather than logical line count, so a long name
/// cannot push the actionable prompt below the modal. Each candidate count
/// also reserves room for the omitted-count line it would leave behind.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fitting_preview_nodes(
    node_lines: &[Line<'_>],
    preview_len: usize,
    preview_rows: usize,
    content_cols: usize,
) -> usize {
    let mut node_rows = 0;
    let mut fitting_nodes = 0;
    for (index, line) in node_lines.iter().enumerate() {
        node_rows += wrapped_rows(&line.to_string(), content_cols);
        let count = index + 1;
        let omitted_rows = if preview_len > count {
            wrapped_rows(&omitted_count_text(preview_len - count), content_cols)
        } else {
            0
        };
        if node_rows + omitted_rows > preview_rows {
            break;
        }
        fitting_nodes = count;
    }
    fitting_nodes
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn omitted_count_text(omitted: usize) -> String {
    format!("  ... and {omitted} more")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_node_text(node: &crate::tree::ProcessTreeNode) -> String {
    let indent = "  ".repeat(node.depth + 1);
    let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
    format!("{indent}PID {} ({name})", node.pid)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_header_text(confirmation: &TreeKillConfirmation) -> String {
    format!(
        "{} process tree from {}",
        confirmation.mode.action_label(),
        confirmation.target.identity(),
    )
}

fn clipped_field_value(value: &str, label: &str, content_cols: usize) -> String {
    let available = content_cols
        .saturating_sub(label.chars().count() + 2)
        .max(1);
    clipped_chars(value, available)
}

fn clipped_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let mut clipped = value.chars().take(max_chars - 3).collect::<String>();
    clipped.push_str("...");
    clipped
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_instruction_line(confirmation: &TreeKillConfirmation, theme: Theme) -> Line<'static> {
    if confirmation.preview.is_none() {
        return Line::from(vec![Span::raw(
            "Wait for the process count before typing confirmation.",
        )]);
    }
    match confirmation.stage {
        TreeConfirmStage::ProtectedRoot => {
            let mut spans = vec![Span::raw("Protected root: type ")];
            spans.extend(protected_identity_spans(&confirmation.target, theme));
            spans.extend([
                Span::raw(", press "),
                Span::styled("Enter", theme.key()),
                Span::raw(", then confirm the tree word."),
            ]);
            Line::from(spans)
        }
        TreeConfirmStage::Word => Line::from(vec![
            Span::raw("Type "),
            Span::styled(confirmation.scope_word(), theme.key()),
            Span::raw(" and press "),
            Span::styled("Enter", theme.key()),
            Span::raw(format!(
                " to send {} to all processes above.",
                confirmation
                    .mode
                    .delivery_label(confirmation.target.platform),
            )),
        ]),
    }
}

/// Lines for the single-process modal, or `None` when the wrapped warnings and
/// prompt cannot all fit. Only the identity header and port list are clipped to
/// one row; the instruction repeats the confirmable identity in full.
fn confirmation_lines(
    confirmation: &KillConfirmation,
    theme: Theme,
    content_rows: usize,
    content_cols: usize,
) -> Option<Vec<Line<'static>>> {
    let mut lines = vec![
        Line::styled(
            clipped_chars(
                &format!(
                    "{} {}",
                    confirmation.mode.action_label(),
                    confirmation.target.identity(),
                ),
                content_cols.max(1),
            ),
            theme.title(),
        ),
        field(
            "Ports",
            clipped_field_value(
                &sanitize(&confirmation.target.ports_text()),
                "Ports",
                content_cols,
            ),
            theme,
        ),
        field(
            "Command",
            sanitize(&app::kill_command_text(
                &confirmation.target,
                confirmation.mode,
            )),
            theme,
        ),
    ];

    if let Some(warning) = confirmation
        .mode
        .force_warning(confirmation.target.platform)
    {
        lines.push(Line::styled(format!("Warning: {warning}"), theme.warning()));
    }
    for warning in confirmation.target.warnings() {
        lines.push(Line::styled(
            format!(
                "Warning: {}.",
                sanitize(&warning.text(WarningScope::Process))
            ),
            theme.warning(),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(instruction_line(confirmation, theme));
    if confirmation.requirement != ConfirmationRequirement::Yes {
        lines.push(field("Input", confirmation.input.clone(), theme));
    }
    if let Some(error) = &confirmation.error {
        lines.push(Line::styled(format!("Error: {error}"), theme.warning()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", theme.key()),
        Span::raw(" cancels."),
    ]));

    if rendered_rows(&lines, content_cols) > content_rows {
        lines.retain(|line| line.width() != 0);
    }
    (rendered_rows(&lines, content_cols) <= content_rows).then_some(lines)
}

fn instruction_line(confirmation: &KillConfirmation, theme: Theme) -> Line<'static> {
    match confirmation.requirement {
        ConfirmationRequirement::Yes => Line::from(vec![
            Span::styled("y", theme.key()),
            Span::raw(format!(
                " confirms {}. ",
                confirmation.mode.action_label().to_ascii_lowercase(),
            )),
            Span::styled("n", theme.key()),
            Span::raw(" cancels."),
        ]),
        ConfirmationRequirement::ForceWord => Line::from(vec![
            Span::raw("Type "),
            Span::styled("force", theme.key()),
            Span::raw(" and press "),
            Span::styled("Enter", theme.key()),
            Span::raw(format!(
                " to send {}.",
                confirmation
                    .mode
                    .delivery_label(confirmation.target.platform),
            )),
        ]),
        ConfirmationRequirement::ProtectedProcess => {
            let mut spans = vec![Span::raw("Protected process: type ")];
            spans.extend(protected_identity_spans(&confirmation.target, theme));
            spans.extend([
                Span::raw(" and press "),
                Span::styled("Enter", theme.key()),
                Span::raw("."),
            ]);
            Line::from(spans)
        }
    }
}

/// The PID, and the name when it can be typed, that confirm a protected target.
fn protected_identity_spans(target: &KillTarget, theme: Theme) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(target.pid.to_string(), theme.key())];
    if let Some(name) = target.protected_confirmation_name() {
        spans.extend([Span::raw(" or "), Span::styled(name, theme.key())]);
    }
    spans
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::confirmation_lines;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::wrapped_rows;
    use crate::app::KillConfirmation;
    use crate::model::{
        PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState,
    };
    use crate::process::{ConfirmationRequirement, KillMode, KillTarget};
    use crate::ui::theme::Theme;

    fn target(protected: bool) -> KillTarget {
        let row = PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(18422),
            process_name: Some("node".into()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: Some(crate::observation::ProcessIdentity {
                pid: 18422,
                start_marker: crate::observation::ProcessStartMarker::linux(55)
                    .expect("test marker is nonzero"),
            }),
            ipv6_scope: None,
        };
        KillTarget::from_entries(18422, [PortEntryView::from(&row)], None)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn target_with_port_count(count: u16) -> KillTarget {
        let rows = (0..count)
            .map(|offset| PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 3000 + offset,
                state: SocketState::Listen,
                pid: Some(18422),
                process_name: Some("node".into()),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                protected: false,
                platform: Platform::Linux,
                permission: PermissionStatus::Full,
                process_identity: Some(crate::observation::ProcessIdentity {
                    pid: 18422,
                    start_marker: crate::observation::ProcessStartMarker::linux(55)
                        .expect("test marker is nonzero"),
                }),
                ipv6_scope: None,
            })
            .collect::<Vec<_>>();
        KillTarget::from_entries(18422, rows.iter().map(PortEntryView::from), None)
    }

    #[test]
    fn confirmation_lines_show_command_and_required_input() {
        let confirmation = KillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::ForceWord,
            input: "for".to_owned(),
            error: Some("keep typing".to_owned()),
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40, 100)
            .expect("uncrowded confirmation fits")
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("kill -9 18422"), "{text}");
        assert!(text.contains("force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("keep typing"), "{text}");
    }

    #[test]
    fn protected_confirmation_requires_pid_or_name() {
        let confirmation = KillConfirmation {
            target: target(true),
            mode: KillMode::Terminate,
            requirement: ConfirmationRequirement::ProtectedProcess,
            input: String::new(),
            error: None,
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40, 100)
            .expect("uncrowded confirmation fits")
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Protected process"), "{text}");
        assert!(text.contains("18422"), "{text}");
        assert!(text.contains("node"), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_lines_cover_loading_word_and_protected_stages() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let render = |confirmation: &TreeKillConfirmation| {
            tree_confirmation_lines(confirmation, Theme::from_environment(), 40, 100)
                .expect("mandatory confirmation rows fit")
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        let mut confirmation = TreeKillConfirmation {
            target: target(false),
            mode: KillMode::Terminate,
            preview: None,
            stage: TreeConfirmStage::Word,
            input: String::new(),
            error: None,
        };
        let text = render(&confirmation);
        assert!(text.contains("Enumerating the process tree"), "{text}");
        assert!(text.contains("Wait for the process count"), "{text}");
        assert!(!text.contains("Type tree"), "{text}");
        assert!(!text.contains("Input:"), "{text}");

        let infos = vec![
            crate::tree::TreeProcessInfo {
                pid: 18422,
                parent_pid: Some(1),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("node".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
                owner_uid: None,
                process_group: None,
                executable_name: None,
            },
            crate::tree::TreeProcessInfo {
                pid: 18430,
                parent_pid: Some(18422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(56).ok(),
                owner_uid: None,
                process_group: None,
                executable_name: None,
            },
        ];
        confirmation.preview = Some(
            crate::tree::plan_process_tree(18422, &infos, &[], crate::model::Platform::Linux, 256)
                .expect("preview must build"),
        );
        let text = render(&confirmation);
        assert!(text.contains("tree (2 processes)"), "{text}");
        assert!(text.contains("PID 18430 (worker)"), "{text}");
        assert!(text.contains("Type tree"), "{text}");
        assert!(text.contains("SIGTERM"), "{text}");

        confirmation.target = target(true);
        confirmation.stage = TreeConfirmStage::ProtectedRoot;
        let text = render(&confirmation);
        assert!(text.contains("Protected root"), "{text}");
        assert!(text.contains("18422"), "{text}");
        assert!(text.contains("then confirm the tree word"), "{text}");
    }

    /// At the smallest supported modal (80x20 terminal -> 13 content rows),
    /// a large tree must shrink its preview to keep the instruction, input, and
    /// Escape hint visible.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_prompt_stays_visible_at_minimum_modal_height() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let mut infos = vec![crate::tree::TreeProcessInfo {
            pid: 18422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: None,
            process_group: None,
            executable_name: None,
        }];
        for pid in 18430..18450 {
            infos.push(crate::tree::TreeProcessInfo {
                pid,
                parent_pid: Some(18422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid))
                    .ok(),
                owner_uid: None,
                process_group: None,
                executable_name: None,
            });
        }
        let confirmation = TreeKillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            preview: Some(
                crate::tree::plan_process_tree(
                    18422,
                    &infos,
                    &[],
                    crate::model::Platform::Linux,
                    256,
                )
                .expect("preview must build"),
            ),
            stage: TreeConfirmStage::Word,
            input: "for".to_owned(),
            error: Some("keep typing".to_owned()),
        };

        // 80x20 terminal, 76% modal height = 15 rows, minus borders = 13.
        let content_rows = 13;
        let lines =
            tree_confirmation_lines(&confirmation, Theme::from_environment(), content_rows, 78)
                .expect("mandatory confirmation rows fit");
        let rendered_rows = lines
            .iter()
            .map(|line| wrapped_rows(&line.to_string(), 78))
            .sum::<usize>();
        assert!(
            rendered_rows <= content_rows,
            "modal emits {rendered_rows} rendered rows for {content_rows} rows",
        );
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Type force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("keep typing"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
        assert!(text.contains("tree (21 processes)"), "{text}");
        assert!(text.contains("more"), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn wrapped_rows_counts_word_wrap_waste_not_just_character_mass() {
        use super::wrapped_rows;

        // Three 11-column words at 20 columns: greedy word wrap fits one word
        // per row (11 + space + 11 overflows), so the widget spends 3 rows
        // where a plain character count claims ceil(35/20) = 2. Undercounting
        // here is what lets the preview push the prompt below the fold.
        assert_eq!(wrapped_rows("aaaaaaaaaaa bbbbbbbbbbb ccccccccccc", 20), 3);
        // Double-width names occupy two columns per char.
        assert_eq!(wrapped_rows("数据库数据库", 6), 2);
        // Unicode em spaces are word boundaries and consume a terminal column;
        // treating only ASCII space as a separator undercounts this as two rows.
        assert_eq!(wrapped_rows("aaaa\u{2003}aaaa\u{2003}aaaa", 8), 3);
        // A single word wider than the modal hard-breaks across rows.
        assert_eq!(wrapped_rows(&"x".repeat(45), 20), 3);
        // Boundary cases keep the one-row floor.
        assert_eq!(wrapped_rows("", 20), 1);
        assert_eq!(wrapped_rows("short", 20), 1);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_refuses_when_all_mandatory_warnings_cannot_fit() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let mut crowded_target = target(true);
        crowded_target.process_name =
            Some("service\u{2003}with\u{2003}unicode\u{2003}spaces".to_owned());
        crowded_target.system_process = true;
        crowded_target.permission = PermissionStatus::Partial;
        // SAFETY: geteuid has no preconditions and only reads credentials.
        crowded_target.owner_uid = Some(unsafe { libc::geteuid() }.wrapping_add(1));
        crowded_target.child_count = 12;
        crowded_target.children_truncated = true;
        let infos = [crate::tree::TreeProcessInfo {
            pid: 18422,
            parent_pid: Some(1),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: crowded_target.process_name.clone(),
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: crowded_target.owner_uid,
            process_group: None,
            executable_name: None,
        }];
        let confirmation = TreeKillConfirmation {
            target: crowded_target,
            mode: KillMode::Force,
            preview: Some(
                crate::tree::plan_process_tree(
                    18422,
                    &infos,
                    &[],
                    crate::model::Platform::Linux,
                    256,
                )
                .expect("preview must build"),
            ),
            stage: TreeConfirmStage::ProtectedRoot,
            input: "184".to_owned(),
            error: Some("type the complete protected process identity".to_owned()),
        };

        assert!(
            tree_confirmation_lines(&confirmation, Theme::from_environment(), 13, 58,).is_none(),
            "an overfull mandatory block must not remain actionable",
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_preview_budgets_wrapped_node_names_by_rendered_height() {
        use super::{tree_confirmation_lines, wrapped_rows};
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let mut infos = vec![crate::tree::TreeProcessInfo {
            pid: 18422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("root with a name that wraps over several rows".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: None,
            process_group: None,
            executable_name: None,
        }];
        for pid in 18430..18440 {
            infos.push(crate::tree::TreeProcessInfo {
                pid,
                parent_pid: Some(18422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker with a name that also wraps repeatedly".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid))
                    .ok(),
                owner_uid: None,
                process_group: None,
                executable_name: None,
            });
        }
        let confirmation = TreeKillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            preview: Some(
                crate::tree::plan_process_tree(
                    18422,
                    &infos,
                    &[],
                    crate::model::Platform::Linux,
                    256,
                )
                .expect("preview must build"),
            ),
            stage: TreeConfirmStage::Word,
            input: "for".to_owned(),
            error: None,
        };

        let content_rows = 18;
        let lines =
            tree_confirmation_lines(&confirmation, Theme::from_environment(), content_rows, 32)
                .expect("mandatory confirmation rows fit");
        let rendered_rows = lines
            .iter()
            .map(|line| wrapped_rows(&line.to_string(), 32))
            .sum::<usize>();
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            rendered_rows <= content_rows,
            "{rendered_rows} rows:\n{text}"
        );
        assert!(text.contains("Type force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_clips_long_ports_line_to_modal_width() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let confirmation = TreeKillConfirmation {
            target: target_with_port_count(20),
            mode: KillMode::Terminate,
            preview: None,
            stage: TreeConfirmStage::Word,
            input: String::new(),
            error: None,
        };

        let lines = tree_confirmation_lines(&confirmation, Theme::from_environment(), 10, 32)
            .expect("mandatory loading rows fit");
        let ports = lines
            .iter()
            .map(ToString::to_string)
            .find(|line| line.starts_with("Ports: "))
            .expect("ports line is rendered");
        assert!(ports.ends_with("..."), "{ports}");
        assert!(ports.chars().count() <= 32, "{ports}");
    }

    #[test]
    fn single_confirmation_refuses_when_mandatory_rows_cannot_fit() {
        let mut crowded_target = target(true);
        crowded_target.system_process = true;
        crowded_target.permission = PermissionStatus::Partial;
        crowded_target.child_count = 4;
        let confirmation = KillConfirmation {
            target: crowded_target,
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::ProtectedProcess,
            input: "18".to_owned(),
            error: Some("keep typing".to_owned()),
        };

        let fitted = confirmation_lines(&confirmation, Theme::from_environment(), 16, 70)
            .expect("the minimum terminal fits every mandatory row");
        assert!(super::rendered_rows(&fitted, 70) <= 16);
        assert!(
            confirmation_lines(&confirmation, Theme::from_environment(), 9, 70).is_none(),
            "an overfull mandatory block must not remain actionable",
        );
    }

    #[test]
    fn yes_confirmation_names_force_kill_when_force_is_selected() {
        let confirmation = KillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::Yes,
            input: String::new(),
            error: None,
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40, 100)
            .expect("uncrowded confirmation fits")
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("confirms force-kill"), "{text}");
        assert!(!text.contains("confirms normal termination"), "{text}");
    }
}
