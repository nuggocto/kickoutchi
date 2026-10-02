//! Scrollable view of the complete kill results and errors.
//!
//! The status area shows a bounded preview. A long report, such as a tree
//! cleanup failure that lists every PID left stopped, stays readable here.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::App;

use super::{rendered_rows, status_messages, theme::Theme};

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let messages = status_messages(app);
    let lines = if messages.is_empty() {
        vec![Line::styled(
            "No kill results or errors to show.",
            theme.muted(),
        )]
    } else {
        let mut lines = Vec::with_capacity(messages.len() * 2);
        for message in messages {
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }
            lines.push(Line::raw(message));
        }
        lines
    };
    let block = Block::bordered()
        .title("Kill Results and Errors")
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
            Span::styled("End", theme.key()),
            Span::raw(" last line  "),
            Span::styled("Esc", theme.key()),
            Span::raw(" closes"),
        ])),
        chunks[1],
    );
}
