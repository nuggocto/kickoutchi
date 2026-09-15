//! Turning key presses into actions for the TUI.
//!
//! This module returns small `Action` values instead of mutating `App`. The state
//! machine therefore has no crossterm dependency and can be tested without a
//! terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::ModalKind;

/// One state transition requested by a key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    MoveDown,
    MoveUp,
    OpenDetails,
    OpenHelp,
    CloseModal,
    RequestTerminate,
    RequestForceKill,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    RequestTreeTerminate,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    RequestTreeForceKill,
    SubmitKillConfirmation,
    KillInputAppend(char),
    KillInputBackspace,
    CancelKill,
    Refresh,
    StartSearch,
    SearchAppend(char),
    SearchBackspace,
    FinishSearch,
    CancelSearch,
    CycleSort,
    Quit,
    Noop,
}

/// Turn a key event into an app action.
///
/// `filter_active` lets a single `Esc` outside search mode clear an applied
/// filter instead of quitting. Escape closes a modal first, then clears a
/// filter, then quits.
pub(crate) fn action_for_key(
    key: KeyEvent,
    modal: ModalKind,
    search_mode: bool,
    filter_active: bool,
) -> Action {
    if key.kind != KeyEventKind::Press {
        return Action::Noop;
    }

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Action::Quit;
    }

    if modal == ModalKind::ConfirmKill {
        return kill_confirmation_action_for_key(key);
    }
    // The tree confirmation modal captures text exactly like the single-kill
    // one; the app routes the shared actions to whichever confirmation is open.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if modal == ModalKind::ConfirmTreeKill {
        return kill_confirmation_action_for_key(key);
    }

    if search_mode {
        return search_action_for_key(key);
    }

    match key.code {
        KeyCode::Esc if modal != ModalKind::None => Action::CloseModal,
        KeyCode::Esc if filter_active => Action::CancelSearch,
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('?') => Action::OpenHelp,
        _ if modal != ModalKind::None => Action::Noop,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('/') => Action::StartSearch,
        KeyCode::Char('s') => Action::CycleSort,
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'x')
                && key.modifiers.contains(KeyModifiers::SHIFT)
                && !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::RequestForceKill
        }
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'x')
                && !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::RequestTerminate
        }
        // t/T mirror x/X exactly, Caps Lock handling included: only an explicit
        // Shift makes it force, so a Caps Lock uppercase T stays on the normal
        // tree termination path.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'t')
                && key.modifiers.contains(KeyModifiers::SHIFT)
                && !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::RequestTreeForceKill
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'t')
                && !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::RequestTreeTerminate
        }
        KeyCode::Char('j') | KeyCode::Down => Action::MoveDown,
        KeyCode::Char('k') | KeyCode::Up => Action::MoveUp,
        KeyCode::Enter => Action::OpenDetails,
        _ => Action::Noop,
    }
}

fn kill_confirmation_action_for_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::CancelKill,
        KeyCode::Enter => Action::SubmitKillConfirmation,
        KeyCode::Backspace => Action::KillInputBackspace,
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::KillInputAppend(ch)
        }
        _ => Action::Noop,
    }
}

fn search_action_for_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::CancelSearch,
        KeyCode::Enter => Action::FinishSearch,
        KeyCode::Backspace => Action::SearchBackspace,
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::SearchAppend(ch)
        }
        _ => Action::Noop,
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, action_for_key};
    use crate::app::ModalKind;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn modified_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    /// Default helper for cases without an active filter.
    fn act(code: KeyCode, modal: ModalKind, search_mode: bool) -> Action {
        action_for_key(key(code), modal, search_mode, false)
    }

    #[test]
    fn quit_keys_quit() {
        assert_eq!(
            act(KeyCode::Char('q'), ModalKind::None, false),
            Action::Quit
        );
        assert_eq!(act(KeyCode::Esc, ModalKind::None, false), Action::Quit);
        assert_eq!(
            action_for_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                ModalKind::None,
                false,
                false,
            ),
            Action::Quit
        );
    }

    #[test]
    fn navigation_keys_move_when_no_modal_is_open() {
        assert_eq!(
            act(KeyCode::Char('j'), ModalKind::None, false),
            Action::MoveDown
        );
        assert_eq!(act(KeyCode::Down, ModalKind::None, false), Action::MoveDown);
        assert_eq!(
            act(KeyCode::Char('k'), ModalKind::None, false),
            Action::MoveUp
        );
        assert_eq!(act(KeyCode::Up, ModalKind::None, false), Action::MoveUp);
    }

    #[test]
    fn modal_keys_are_contextual() {
        assert_eq!(
            act(KeyCode::Enter, ModalKind::None, false),
            Action::OpenDetails
        );
        assert_eq!(
            act(KeyCode::Char('?'), ModalKind::None, false),
            Action::OpenHelp
        );
        assert_eq!(
            act(KeyCode::Esc, ModalKind::Help, false),
            Action::CloseModal
        );
        assert_eq!(act(KeyCode::Down, ModalKind::Help, false), Action::Noop);
        assert_eq!(
            act(KeyCode::Char('q'), ModalKind::Help, false),
            Action::Quit
        );
    }

    #[test]
    fn refresh_search_and_sort_keys_work_without_modal() {
        assert_eq!(
            act(KeyCode::Char('r'), ModalKind::None, false),
            Action::Refresh
        );
        assert_eq!(
            act(KeyCode::Char('/'), ModalKind::None, false),
            Action::StartSearch
        );
        assert_eq!(
            act(KeyCode::Char('s'), ModalKind::None, false),
            Action::CycleSort
        );
    }

    #[test]
    fn kill_keys_request_termination_without_modal() {
        assert_eq!(
            act(KeyCode::Char('x'), ModalKind::None, false),
            Action::RequestTerminate,
        );
        assert_eq!(
            action_for_key(
                modified_key(KeyCode::Char('X'), KeyModifiers::SHIFT),
                ModalKind::None,
                false,
                false,
            ),
            Action::RequestForceKill,
        );
    }

    #[test]
    fn caps_lock_x_stays_on_the_normal_termination_path() {
        assert_eq!(
            act(KeyCode::Char('X'), ModalKind::None, false),
            Action::RequestTerminate,
        );
        assert_eq!(
            action_for_key(
                modified_key(KeyCode::Char('x'), KeyModifiers::CONTROL),
                ModalKind::None,
                false,
                false,
            ),
            Action::Noop,
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_keys_mirror_the_kill_keys_including_caps_lock() {
        assert_eq!(
            act(KeyCode::Char('t'), ModalKind::None, false),
            Action::RequestTreeTerminate,
        );
        assert_eq!(
            action_for_key(
                modified_key(KeyCode::Char('T'), KeyModifiers::SHIFT),
                ModalKind::None,
                false,
                false,
            ),
            Action::RequestTreeForceKill,
        );
        // Caps Lock uppercase T without Shift must stay on the normal tree
        // path, exactly like x/X.
        assert_eq!(
            act(KeyCode::Char('T'), ModalKind::None, false),
            Action::RequestTreeTerminate,
        );
        assert_eq!(
            action_for_key(
                modified_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
                ModalKind::None,
                false,
                false,
            ),
            Action::Noop,
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_modal_captures_text_until_submit_or_cancel() {
        assert_eq!(
            act(KeyCode::Char('q'), ModalKind::ConfirmTreeKill, false),
            Action::KillInputAppend('q'),
        );
        assert_eq!(
            act(KeyCode::Backspace, ModalKind::ConfirmTreeKill, false),
            Action::KillInputBackspace,
        );
        assert_eq!(
            act(KeyCode::Enter, ModalKind::ConfirmTreeKill, false),
            Action::SubmitKillConfirmation,
        );
        assert_eq!(
            act(KeyCode::Esc, ModalKind::ConfirmTreeKill, false),
            Action::CancelKill,
        );
    }

    #[test]
    fn kill_confirmation_modal_captures_text_until_submit_or_cancel() {
        assert_eq!(
            act(KeyCode::Char('q'), ModalKind::ConfirmKill, false),
            Action::KillInputAppend('q'),
        );
        assert_eq!(
            act(KeyCode::Backspace, ModalKind::ConfirmKill, false),
            Action::KillInputBackspace,
        );
        assert_eq!(
            act(KeyCode::Enter, ModalKind::ConfirmKill, false),
            Action::SubmitKillConfirmation,
        );
        assert_eq!(
            act(KeyCode::Esc, ModalKind::ConfirmKill, false),
            Action::CancelKill,
        );
    }

    #[test]
    fn search_mode_treats_plain_keys_as_query_text() {
        assert_eq!(
            act(KeyCode::Char('q'), ModalKind::None, true),
            Action::SearchAppend('q')
        );
        assert_eq!(
            act(KeyCode::Backspace, ModalKind::None, true),
            Action::SearchBackspace
        );
        assert_eq!(
            act(KeyCode::Enter, ModalKind::None, true),
            Action::FinishSearch
        );
        assert_eq!(
            act(KeyCode::Esc, ModalKind::None, true),
            Action::CancelSearch
        );
    }

    #[test]
    fn esc_clears_an_applied_filter_before_quitting() {
        // Search editing is done (search_mode false) but a filter is still on:
        // Esc has to clear the filter, not quit. A second Esc, nothing left to
        // clear, quits. An open modal still beats both.
        assert_eq!(
            action_for_key(key(KeyCode::Esc), ModalKind::None, false, true),
            Action::CancelSearch
        );
        assert_eq!(
            action_for_key(key(KeyCode::Esc), ModalKind::None, false, false),
            Action::Quit
        );
        assert_eq!(
            action_for_key(key(KeyCode::Esc), ModalKind::Help, false, true),
            Action::CloseModal
        );
    }

    #[test]
    fn only_key_press_events_act() {
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(
            action_for_key(release, ModalKind::None, false, false),
            Action::Noop
        );
    }
}
