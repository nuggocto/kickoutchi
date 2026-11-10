//! Human-facing display sanitizer.
//!
//! Process names, paths, and command lines are read straight from the OS and can
//! contain control characters, newlines, or ANSI escape sequences. The JSON path
//! keeps that data raw because scripts need the real values, but anything a human
//! sees must pass through this module so untrusted process text cannot move the
//! cursor, hide text, or imitate a prompt.

use std::net::IpAddr;

use crate::observation::Ipv6Scope;

pub(crate) const REPLACEMENT: char = '�';

/// Render an address for a human.
///
/// A known IPv6 interface index is kept as `%index`. When the platform cannot
/// report the scope (Linux procfs and macOS descriptor rows never do), the plain
/// address is shown; structured output still records the scope as unavailable.
pub(crate) fn human_address_text(address: IpAddr, ipv6_scope: Option<Ipv6Scope>) -> String {
    debug_assert!(
        address.is_ipv6() || ipv6_scope.is_none(),
        "IPv4 endpoints never carry IPv6 scope state"
    );
    match (address, ipv6_scope) {
        (IpAddr::V4(address), _) => address.to_string(),
        (IpAddr::V6(address), Some(Ipv6Scope::InterfaceIndex(index))) => {
            format!("{address}%{index}")
        }
        (IpAddr::V6(address), Some(Ipv6Scope::Unscoped | Ipv6Scope::Unavailable) | None) => {
            address.to_string()
        }
    }
}

/// Render an address and port using brackets where IPv6 requires them.
pub(crate) fn human_endpoint_text(
    address: IpAddr,
    port: u16,
    ipv6_scope: Option<Ipv6Scope>,
) -> String {
    let address_text = human_address_text(address, ipv6_scope);
    if address.is_ipv6() {
        format!("[{address_text}]:{port}")
    } else {
        format!("{address_text}:{port}")
    }
}

/// Make an untrusted string safe to print where humans read it.
///
/// - Tabs become spaces so columns don't drift.
/// - Carriage returns and line feeds become spaces so a single row can't break
///   into multiple lines.
/// - Other ASCII control characters and the C0/C1 control ranges become the
///   replacement character.
/// - ANSI escape sequences are stripped so a process name can't redraw the
///   terminal or fake a confirmation prompt.
/// - Bidi and zero-width formatting characters become the replacement character,
///   so names cannot hide or reorder text in a terminal prompt.
/// - Everything else is preserved, including visible Unicode.
pub(crate) fn sanitize(text: &str) -> String {
    sanitize_with_layout(text, false)
}

/// Sanitize untrusted terminal output while retaining intentional line breaks.
/// This is for whole diagnostics and help text, not table cells or prompts.
pub(crate) fn sanitize_multiline(text: &str) -> String {
    sanitize_with_layout(text, true)
}

pub(crate) fn sanitize_bounded(text: &str, max_bytes: usize) -> String {
    let mut sanitized = sanitize(text);
    if sanitized.len() <= max_bytes {
        return sanitized;
    }
    let mut end = max_bytes;
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    sanitized.truncate(end);
    sanitized
}

fn sanitize_with_layout(text: &str, preserve_newlines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\n' && preserve_newlines {
            out.push('\n');
            continue;
        }
        if ch == '\t' || ch == '\n' || ch == '\r' {
            out.push(' ');
            continue;
        }

        // ANSI escape: ESC followed by '[' or '(' or ')' or '#' or any other
        // standard introducer, then parameter bytes and a final letter.
        if ch == '\x1b' {
            strip_ansi_sequence(&mut chars);
            continue;
        }

        if is_control(ch) || is_default_ignorable(ch) {
            out.push(REPLACEMENT);
            continue;
        }

        out.push(ch);
    }

    out
}

/// Drop the rest of a single ANSI escape sequence from the iterator.
///
/// This handles CSI (`ESC [` ... final byte), short escape sequences such as
/// `ESC 7` and `ESC ( B`, and control strings that end with BEL or ST. It is
/// intentionally conservative: it stops at the first byte that does not belong
/// to the sequence, so a malformed escape does not eat the whole string.
fn strip_ansi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(introducer) = chars.peek().copied() else {
        return;
    };

    // DCS, SOS, OSC, PM, and APC: consume until BEL or ST.
    if matches!(introducer, 'P' | 'X' | ']' | '^' | '_') {
        chars.next();
        loop {
            match chars.next() {
                Some('\x07') | None => break,
                Some('\x1b') => {
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                    }
                    break;
                }
                _ => {}
            }
        }
        return;
    }

    if introducer == '[' {
        chars.next();
        while chars.peek().is_some_and(|c| ('\x30'..='\x3f').contains(c)) {
            chars.next();
        }
        while chars.peek().is_some_and(|c| ('\x20'..='\x2f').contains(c)) {
            chars.next();
        }
        if chars.peek().is_some_and(|c| ('\x40'..='\x7e').contains(c)) {
            chars.next();
        }
        return;
    }

    // A non-CSI escape has zero or more intermediate bytes followed by one
    // final byte. If the first byte is already final, consume only that byte.
    while chars.peek().is_some_and(|c| ('\x20'..='\x2f').contains(c)) {
        chars.next();
    }
    if chars.peek().is_some_and(|c| ('\x30'..='\x7e').contains(c)) {
        chars.next();
    }
}

fn is_control(ch: char) -> bool {
    matches!(ch, '\x00'..='\x1f' | '\x7f' | '\u{0080}'..='\u{009f}')
}

/// Unicode 17.0 `Default_Ignorable_Code_Point`, which includes bidi controls.
/// Keeping one pinned table prevents validation and terminal sinks from drifting.
pub(crate) const fn is_default_ignorable(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{human_address_text, human_endpoint_text, sanitize, sanitize_multiline};
    use crate::observation::Ipv6Scope;

    #[test]
    fn human_endpoint_text_preserves_every_ipv6_scope_state() {
        let link_local = IpAddr::V6("fe80::1".parse().expect("test address is valid"));
        let interface = Ipv6Scope::interface_index(3).expect("test scope is valid");

        assert_eq!(
            human_address_text(IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            "127.0.0.1"
        );
        assert_eq!(
            human_endpoint_text(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000, None),
            "127.0.0.1:3000"
        );
        assert_eq!(
            human_address_text(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(Ipv6Scope::Unscoped)),
            "::1"
        );
        assert_eq!(
            human_endpoint_text(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                3000,
                Some(Ipv6Scope::Unscoped)
            ),
            "[::1]:3000"
        );
        assert_eq!(human_address_text(link_local, Some(interface)), "fe80::1%3");
        assert_eq!(
            human_endpoint_text(link_local, 3000, Some(interface)),
            "[fe80::1%3]:3000"
        );
        assert_eq!(
            human_address_text(link_local, Some(Ipv6Scope::Unavailable)),
            "fe80::1"
        );
    }

    #[test]
    fn leaves_clean_text_unchanged() {
        assert_eq!(sanitize("node server.js"), "node server.js");
        assert_eq!(sanitize("/usr/bin/node"), "/usr/bin/node");
    }

    #[test]
    fn replaces_newlines_and_tabs_with_space() {
        assert_eq!(sanitize("node\nserver\tjs"), "node server js");
        assert_eq!(sanitize("line1\r\nline2"), "line1  line2");
    }

    #[test]
    fn replaces_control_characters() {
        assert_eq!(sanitize("no\x00null"), "no�null");
        assert_eq!(sanitize("beep\x07"), "beep�");
    }

    #[test]
    fn strips_ansi_escape_sequences() {
        assert_eq!(sanitize("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(sanitize("\x1b[1;31mbold red\x1b[m"), "bold red");
        assert_eq!(sanitize("\x1b]0;title\x07after"), "after");
    }

    #[test]
    fn strips_complete_csi_sequences_with_intermediate_bytes() {
        assert_eq!(sanitize("before\x1b[1;2 $~after"), "beforeafter");
        assert_eq!(sanitize("before\x1b[ qafter"), "beforeafter");
    }

    #[test]
    fn two_byte_escapes_do_not_consume_following_text() {
        assert_eq!(sanitize("before\x1b7after"), "beforeafter");
        assert_eq!(sanitize("before\x1bcafter"), "beforeafter");
        assert_eq!(sanitize("before\x1b(Bafter"), "beforeafter");
    }

    #[test]
    fn multiline_diagnostics_keep_layout_but_remove_terminal_controls() {
        assert_eq!(
            sanitize_multiline("error: bad\u{202e}value\n  help\x1b]0;title\x07 here\n"),
            "error: bad�value\n  help here\n"
        );
    }

    #[test]
    fn preserves_unicode() {
        assert_eq!(sanitize("héllo 世界 🌍"), "héllo 世界 🌍");
    }

    #[test]
    fn replaces_bidi_and_zero_width_formatting() {
        assert_eq!(sanitize("safe\u{202e}txt"), "safe�txt");
        assert_eq!(sanitize("zero\u{200b}width"), "zero�width");
    }
}
