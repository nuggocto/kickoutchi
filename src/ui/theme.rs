//! Colors and styles for the TUI.
//!
//! The UI has to stay usable with no color at all. `NO_COLOR` drops foreground
//! and background colors but keeps color-free emphasis through bold and reverse
//! video for the selected row.

use ratatui::style::{Color, Modifier, Style};
use std::ffi::OsStr;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Theme {
    no_color: bool,
}

impl Theme {
    pub(crate) fn from_environment() -> Self {
        Self {
            no_color: no_color_requested(std::env::var_os("NO_COLOR").as_deref()),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_no_color(no_color: bool) -> Self {
        Self { no_color }
    }

    pub(crate) fn title(self) -> Style {
        self.fg(Color::Cyan).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn table_header(self) -> Style {
        self.fg(Color::Blue).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn selected(self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        }
    }

    pub(crate) fn protected(self) -> Style {
        self.fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn warning(self) -> Style {
        self.fg(Color::Yellow).add_modifier(Modifier::BOLD)
    }

    /// A row whose owner could be read: the default foreground in bold. It
    /// uses no palette color, so it is legible in any terminal theme and stays
    /// on under `NO_COLOR`.
    #[expect(
        clippy::unused_self,
        reason = "every Theme accessor takes self so callers stay uniform when a style becomes palette-dependent"
    )]
    pub(crate) fn readable_owner(self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }

    pub(crate) fn label(self) -> Style {
        self.fg(Color::Blue).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn key(self) -> Style {
        self.fg(Color::Green).add_modifier(Modifier::BOLD)
    }

    #[expect(
        clippy::unused_self,
        reason = "every Theme accessor takes self so callers stay uniform when a style becomes palette-dependent"
    )]
    pub(crate) fn status(self) -> Style {
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .add_modifier(Modifier::BOLD)
    }

    fn fg(self, color: Color) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }
}

fn no_color_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::no_color_requested;

    #[test]
    fn no_color_requires_a_nonempty_value() {
        assert!(!no_color_requested(None));
        assert!(!no_color_requested(Some(OsStr::new(""))));
        assert!(no_color_requested(Some(OsStr::new("1"))));
    }
}
