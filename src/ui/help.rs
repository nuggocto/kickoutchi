//! Drawing the help modal.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::App;

use super::{rendered_rows, theme::Theme};

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let mut lines = vec![
        Line::styled("Kickoutchi", theme.title()),
        Line::raw("Native ports with refresh, search filters, sortable rows, and process context."),
        Line::raw(""),
        key_line("r", "refresh ports now", theme),
        key_line("/", "edit search/filter text", theme),
        key_line("s", "cycle sort mode", theme),
        key_line("j / Down", "move selection down", theme),
        key_line("k / Up", "move selection up", theme),
        key_line("Enter", "open selected-row details", theme),
        key_line("x", "terminate selected process", theme),
        key_line("X", "force-kill selected process", theme),
    ];
    // Tree kill exists only on Linux/macOS builds; the help modal must not
    // advertise keys the running binary does not have.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    lines.extend([
        key_line("t", "terminate selected process tree", theme),
        key_line("T", "force-kill selected process tree", theme),
    ]);
    lines.extend([
        key_line("m", "show full kill results and errors", theme),
        key_line("?", "open this help", theme),
        key_line("Esc", "clear search, close a modal, or quit", theme),
        key_line("q", "quit", theme),
        key_line("Ctrl+C", "quit", theme),
        Line::raw(""),
        Line::raw("Search mode: type to filter, Enter keeps the filter, Esc clears it."),
        Line::raw("Filters: pid:18422 port:3000 proto:udp scope:public protected:true parent:node"),
        Line::raw("         label:web address:127.0.0.1 scope_id:3 family:ipv6"),
        Line::raw("Press Enter to load selected-row children, owner UID, and protected warnings."),
    ]);
    let block = Block::bordered()
        .title("Help")
        .title_style(theme.title())
        .border_style(theme.border());
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
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
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Up/Down", theme.key()),
            Span::raw(" scroll  "),
            Span::styled("Esc", theme.key()),
            Span::raw(" closes"),
        ])),
        chunks[1],
    );
}

fn key_line(key: &'static str, description: &'static str, theme: Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<10}"), theme.key()),
        Span::raw(description),
    ])
}
