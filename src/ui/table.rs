//! Main open-ports table rendering.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Block, Row, Table, TableState};

use crate::app::App;
use crate::display::{human_address_text, sanitize};
use crate::labels::label_display_text;
use crate::model::{PermissionStatus, PortEntryView};

use super::theme::Theme;

const MISSING: &str = "-";
// Borders, selected-row marker, and seven inter-column spaces sit outside the
// declared constraints, so 106 is the first width that preserves every legacy
// column while adding the 32-column label.
const LABEL_COLUMN_MIN_TABLE_WIDTH: u16 = 106;

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let show_labels = app.labels_configured() && area.width >= LABEL_COLUMN_MIN_TABLE_WIDTH;
    let headers = if show_labels {
        vec![
            "PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE", "SCOPE", "LABEL",
        ]
    } else {
        vec![
            "PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE", "SCOPE",
        ]
    };
    let header = Row::new(headers)
        .style(theme.table_header())
        .bottom_margin(1);
    // Borders, the header, and its bottom margin consume four rows.
    let viewport_len = usize::from(area.height.saturating_sub(4));
    let (viewport_start, viewport_end) =
        visible_range(app.rows().len(), app.selected_index(), viewport_len);
    let rows = app
        .rows_range(viewport_start..viewport_end)
        .map(|entry| row(entry, theme, show_labels));
    let mut widths = vec![
        Constraint::Length(6),
        Constraint::Min(13),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Min(12),
        Constraint::Length(8),
        Constraint::Length(9),
    ];
    if show_labels {
        widths.push(Constraint::Length(32));
    }
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::bordered()
                .title("Open Ports")
                .title_style(theme.title()),
        )
        .row_highlight_style(theme.selected())
        .highlight_symbol(">> ");
    let mut state = TableState::default();
    state.select(app.selected_index().and_then(|index| {
        (viewport_start..viewport_end)
            .contains(&index)
            .then_some(index - viewport_start)
    }));
    frame.render_stateful_widget(table, area, &mut state);
}

fn visible_range(total: usize, selected: Option<usize>, capacity: usize) -> (usize, usize) {
    if capacity == 0 || total == 0 {
        return (0, 0);
    }
    let selected = selected.unwrap_or(0).min(total - 1);
    let start = selected
        .saturating_add(1)
        .saturating_sub(capacity)
        .min(total.saturating_sub(capacity));
    (start, start.saturating_add(capacity).min(total))
}

fn row(entry: PortEntryView<'_>, theme: Theme, show_labels: bool) -> Row<'static> {
    let mut cells = vec![
        entry.protocol.label().to_owned(),
        human_address_text(entry.local_addr, entry.ipv6_scope),
        entry.local_port.to_string(),
        pid_text(entry),
        process_text(entry),
        entry.state.label().to_owned(),
        entry.scope_label().to_owned(),
    ];
    if show_labels {
        cells.push(
            entry
                .label
                .map_or_else(|| MISSING.to_owned(), label_display_text),
        );
    }
    let mut row = Row::new(cells);

    if let Some(style) = row_style(entry, theme) {
        row = row.style(style);
    }

    row
}

/// The row color. The help modal's "Rows:" line describes these cases.
///
/// A hidden owner is the normal state for other users' sockets, so those rows
/// stay in the plain default foreground: readable in every terminal theme and
/// not flagged. Rows whose owner was read are bold, because those are the ones
/// the user can act on. Yellow marks a known PID whose details are incomplete.
fn row_style(entry: PortEntryView<'_>, theme: Theme) -> Option<Style> {
    if entry.protected {
        Some(theme.protected())
    } else if entry.permission == PermissionStatus::Full {
        Some(theme.readable_owner())
    } else if entry.pid.is_none() {
        None
    } else {
        Some(theme.warning())
    }
}

fn pid_text(entry: PortEntryView<'_>) -> String {
    entry
        .pid
        .map_or_else(|| MISSING.to_owned(), |pid| pid.to_string())
}

fn process_text(entry: PortEntryView<'_>) -> String {
    entry
        .process_name
        .map_or_else(|| MISSING.to_owned(), sanitize)
}

#[cfg(test)]
mod tests {
    use ratatui::style::{Color, Modifier};

    use super::{row_style, visible_range};
    use crate::model::{PermissionStatus, PortEntryView, Protocol};
    use crate::test_support::port_entry;
    use crate::ui::theme::Theme;

    #[test]
    fn row_style_separates_hidden_partial_and_protected_rows() {
        let theme = Theme::from_no_color(false);
        let mut entry = port_entry(3000, Some(42), Protocol::Tcp, "node");
        let readable =
            row_style(PortEntryView::from(&entry), theme).expect("readable rows are styled");
        assert_eq!(readable.fg, None);
        assert!(readable.add_modifier.contains(Modifier::BOLD));

        entry.permission = PermissionStatus::Partial;
        let partial =
            row_style(PortEntryView::from(&entry), theme).expect("partial rows are styled");
        assert_eq!(partial.fg, Some(Color::Yellow));

        entry.pid = None;
        assert_eq!(row_style(PortEntryView::from(&entry), theme), None);

        entry.protected = true;
        let protected =
            row_style(PortEntryView::from(&entry), theme).expect("protected rows are styled");
        assert_eq!(protected.fg, Some(Color::Red));
    }

    #[test]
    fn viewport_bounds_rendering_around_nonzero_selection() {
        assert_eq!(visible_range(10_000, Some(5_000), 20), (4_981, 5_001));
        assert_eq!(visible_range(10_000, Some(9_999), 20), (9_980, 10_000));
        assert_eq!(visible_range(10_000, Some(5_000), 0), (0, 0));
    }
}
