//! Table and JSON rendering for CLI mode.
//!
//! This layer only knows how to format borrowed `PortEntryView` rows by index.
//! It writes rows incrementally so large shared process metadata is never
//! duplicated into cell vectors or a complete output string. Total output bytes
//! are externally driven by the selected row count and writer; this module
//! retains no complete rendered output.

use std::io::Write;

use serde::ser::{SerializeSeq, Serializer};
use unicode_width::UnicodeWidthStr;

use crate::display::{human_address_text, sanitize};
use crate::labels::label_display_text;
use crate::model::PortEntryView;

// 64 KiB bounds retained CLI output without buffering an entire document.
pub(crate) const OUTPUT_BUFFER_BYTES: usize = 64 * 1024;

const COLUMN_COUNT: usize = 6;
const HEADERS: [&str; COLUMN_COUNT] = ["PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE"];
const LABELED_COLUMN_COUNT: usize = 7;
const LABELED_HEADERS: [&str; LABELED_COLUMN_COUNT] = [
    "PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE", "LABEL",
];

/// Visible placeholder for unavailable metadata.
const MISSING: &str = "-";

/// Spaces used to pad every column, sized to the widest cell any column can
/// hold. `write_cells` clamps against this length rather than relying on the
/// argument, so an unforeseen column can never index past the end.
///
/// The widest cell is a process name: addresses, ports, PIDs, states and
/// protocols are short, and labels are clipped to
/// [`crate::labels::LABEL_DISPLAY_MAX_COLUMNS`]. Process names are capped at
/// [`crate::observation::PROCESS_NAME_MAX_BYTES`] by the metadata budget, and a
/// sanitized string's terminal width never exceeds its byte length. Every
/// width-2 scalar starts at U+1100 and needs three UTF-8 bytes, so this
/// length is an upper bound on any padding request.
const PADDING: [u8; crate::observation::PROCESS_NAME_MAX_BYTES] =
    [b' '; crate::observation::PROCESS_NAME_MAX_BYTES];

/// Render entries as a plain-text table, columns padded to fit their content.
///
/// Uses plain spaces instead of box-drawing characters so shell tools can split
/// each line on whitespace.
pub(crate) fn write_view_table<'a>(
    writer: &mut impl Write,
    view_at: impl Fn(usize) -> PortEntryView<'a>,
    indices: &[usize],
    show_labels: bool,
) -> std::io::Result<()> {
    if show_labels {
        return write_labeled_view_table(writer, view_at, indices);
    }

    // Each column grows to its widest cell. The model's own types keep content
    // in check (addresses, ports, PIDs, short comm-style names), so there's no
    // need for a width cap. Command lines are not table columns.
    // Widths are terminal columns, not bytes: `sanitize` keeps visible Unicode,
    // and an accented or CJK process name occupies fewer/more columns than its
    // byte length suggests.
    let mut widths: [usize; COLUMN_COUNT] = HEADERS.map(UnicodeWidthStr::width);
    for &index in indices {
        update_widths(&view_at(index), &mut widths);
    }

    write_cells(writer, HEADERS, &widths)?;
    writer.write_all(b"\n")?;
    for &index in indices {
        write_entry(writer, &view_at(index), &widths)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write_labeled_view_table<'a>(
    writer: &mut impl Write,
    view_at: impl Fn(usize) -> PortEntryView<'a>,
    indices: &[usize],
) -> std::io::Result<()> {
    let mut widths: [usize; LABELED_COLUMN_COUNT] = LABELED_HEADERS.map(UnicodeWidthStr::width);
    for &index in indices {
        let entry = &view_at(index);
        update_widths(entry, &mut widths);
        widths[6] = widths[6].max(
            entry
                .label
                .map_or(1, |label| label_display_text(label).width()),
        );
    }

    write_cells(writer, LABELED_HEADERS, &widths)?;
    writer.write_all(b"\n")?;
    for &index in indices {
        write_labeled_entry(writer, &view_at(index), &widths)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Render entries as pretty-printed JSON using the `PortEntry` serialization
/// contract pinned by model tests.
pub(crate) fn write_view_json<'a>(
    writer: &mut impl Write,
    view_at: impl Fn(usize) -> PortEntryView<'a>,
    indices: &[usize],
) -> Result<(), serde_json::Error> {
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut *writer, formatter);
    let mut sequence = serializer.serialize_seq(Some(indices.len()))?;
    for &index in indices {
        sequence.serialize_element(&crate::public_output::LegacyListRecord::from(&view_at(
            index,
        )))?;
    }
    sequence.end()?;
    writer.write_all(b"\n").map_err(serde_json::Error::io)
}

fn update_widths(entry: &PortEntryView<'_>, widths: &mut [usize]) {
    widths[0] = widths[0].max(entry.protocol.label().width());
    widths[1] = widths[1].max(human_address_text(entry.local_addr, entry.ipv6_scope).width());
    widths[2] = widths[2].max(entry.local_port.to_string().width());
    widths[3] = widths[3].max(entry.pid.map_or(1, |pid| pid.to_string().width()));
    widths[4] = widths[4].max(entry.process_name.map_or(1, |name| sanitize(name).width()));
    widths[5] = widths[5].max(entry.state.label().width());
}

fn write_entry(
    writer: &mut impl Write,
    entry: &PortEntryView<'_>,
    widths: &[usize; COLUMN_COUNT],
) -> std::io::Result<()> {
    let address = human_address_text(entry.local_addr, entry.ipv6_scope);
    let port = entry.local_port.to_string();
    let pid = entry.pid.map(|pid| pid.to_string());
    let process = entry.process_name.map(sanitize);
    write_cells(
        writer,
        [
            entry.protocol.label(),
            &address,
            &port,
            pid.as_deref().unwrap_or(MISSING),
            process.as_deref().unwrap_or(MISSING),
            entry.state.label(),
        ],
        widths,
    )
}

fn write_labeled_entry(
    writer: &mut impl Write,
    entry: &PortEntryView<'_>,
    widths: &[usize; LABELED_COLUMN_COUNT],
) -> std::io::Result<()> {
    let address = human_address_text(entry.local_addr, entry.ipv6_scope);
    let port = entry.local_port.to_string();
    let pid = entry.pid.map(|pid| pid.to_string());
    let process = entry.process_name.map(sanitize);
    let label = entry.label.map(label_display_text);
    write_cells(
        writer,
        [
            entry.protocol.label(),
            &address,
            &port,
            pid.as_deref().unwrap_or(MISSING),
            process.as_deref().unwrap_or(MISSING),
            entry.state.label(),
            label.as_deref().unwrap_or(MISSING),
        ],
        widths,
    )
}

fn write_cells<const N: usize>(
    writer: &mut impl Write,
    cells: [&str; N],
    widths: &[usize; N],
) -> std::io::Result<()> {
    for (index, (cell, width)) in cells.into_iter().zip(widths.iter()).enumerate() {
        if index > 0 {
            writer.write_all(b"  ")?;
        }
        writer.write_all(cell.as_bytes())?;
        // Do not add trailing spaces after the last column.
        if index < N - 1 {
            // Clamped, not asserted: the bound documented on PADDING holds, but
            // a misaligned column is a cosmetic bug while an out-of-range slice
            // is a panic in the middle of writing a row.
            let remaining = width.saturating_sub(cell.width()).min(PADDING.len());
            writer.write_all(&PADDING[..remaining])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use unicode_width::UnicodeWidthStr;

    use super::{write_view_json, write_view_table};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState, entry_views};

    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: name.map(Into::into),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    fn table(entries: &[PortEntry]) -> String {
        let indices = (0..entries.len()).collect::<Vec<_>>();
        let views = entry_views(entries);
        let mut bytes = Vec::new();
        write_view_table(&mut bytes, |index| views[index], &indices, false).expect("table writes");
        String::from_utf8(bytes).expect("table is UTF-8")
    }

    fn json(entries: &[PortEntry]) -> String {
        let indices = (0..entries.len()).collect::<Vec<_>>();
        let views = entry_views(entries);
        let mut bytes = Vec::new();
        write_view_json(&mut bytes, |index| views[index], &indices).expect("JSON writes");
        String::from_utf8(bytes).expect("JSON is UTF-8")
    }

    fn labeled_table(entries: &[PortEntry], labels: &[Option<&str>]) -> String {
        let mut views = entry_views(entries);
        for (view, label) in views.iter_mut().zip(labels.iter().copied()) {
            view.label = label;
        }
        let indices = (0..views.len()).collect::<Vec<_>>();
        let mut bytes = Vec::new();
        write_view_table(&mut bytes, |index| views[index], &indices, true)
            .expect("labeled table writes");
        String::from_utf8(bytes).expect("table is UTF-8")
    }

    #[test]
    fn table_renders_header_rows_and_missing_placeholders() {
        let mut hidden = entry(8080, None, None);
        hidden.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let table = table(&[entry(3000, Some(18422), Some("node")), hidden]);

        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("PROTO"));
        assert!(lines[1].contains("node"));
        assert!(lines[1].contains("18422"));
        // Withheld metadata renders as "-" and the row still appears.
        assert!(lines[2].contains("::%unavailable"));
        assert!(lines[2].contains('-'));
    }

    #[test]
    fn table_distinguishes_scoped_ipv6_without_changing_legacy_json() {
        let mut scoped = entry(3000, Some(1), Some("node"));
        scoped.local_addr = IpAddr::V6("fe80::1".parse().expect("test address is valid"));
        scoped.ipv6_scope =
            Some(crate::observation::Ipv6Scope::interface_index(3).expect("test scope is valid"));

        assert!(table(&[scoped.clone()]).contains("fe80::1%3"));
        let value: serde_json::Value = serde_json::from_str(&json(&[scoped])).unwrap();
        assert_eq!(value[0]["local_addr"], "fe80::1");
        assert!(value[0].get("ipv6_scope").is_none());
    }

    #[test]
    fn table_columns_stay_aligned() {
        let table = table(&[
            entry(80, Some(1), Some("nginx")),
            entry(65000, Some(4_000_000), Some("a-much-longer-name")),
        ]);
        // Every row must put the STATE column at the same offset; comparing the
        // header's position against the cells pins the padding logic without
        // snapshotting the whole table.
        let lines: Vec<&str> = table.lines().collect();
        let state_offset = lines[0].find("STATE").expect("header has STATE");
        assert_eq!(lines[1].find("LISTEN"), Some(state_offset));
        assert_eq!(lines[2].find("LISTEN"), Some(state_offset));
    }

    #[test]
    fn table_sanitizes_hostile_process_names() {
        // `list` output lands on real terminals, and a process names itself:
        // the escape must be stripped by `render_table`'s own wiring, not
        // just be strippable by `sanitize` in isolation. Deleting the
        // `sanitize` call in `row_cells` must fail this test.
        let table = table(&[entry(3000, Some(1), Some("evil\x1b[2J\nname"))]);

        assert!(!table.contains('\x1b'), "{table}");
        let lines: Vec<&str> = table.lines().collect();
        // Header plus exactly one row: the embedded newline must not split
        // the entry across lines and break `awk`-style consumers.
        assert_eq!(lines.len(), 2, "{table}");
        assert!(lines[1].contains("evil"), "{table}");
    }

    #[test]
    fn table_columns_stay_aligned_for_wide_unicode_names() {
        // `sanitize` keeps visible Unicode, so widths must be terminal
        // columns, not bytes: "数据库" is 9 bytes but 6 columns, and
        // byte-based padding would shift every later column in that row.
        let table = table(&[
            entry(80, Some(1), Some("nginx")),
            entry(5432, Some(2), Some("数据库")),
            entry(3000, Some(3), Some("héllo")),
        ]);

        let lines: Vec<&str> = table.lines().collect();
        // The header is pure ASCII, so its byte offset is its column offset.
        let header_state_columns = lines[0].find("STATE").expect("header has STATE");
        for line in &lines[1..] {
            let listen_start = line.find("LISTEN").expect("row has LISTEN");
            assert_eq!(
                line[..listen_start].width(),
                header_state_columns,
                "STATE column drifted: {table}",
            );
        }
    }

    #[test]
    fn table_lines_have_no_trailing_whitespace() {
        let table = table(&[entry(80, Some(1), Some("x"))]);
        for line in table.lines() {
            assert_eq!(line, line.trim_end());
        }
    }

    #[test]
    fn label_column_is_conditional_aligned_and_unicode_bounded() {
        let entries = [
            entry(3000, Some(1), Some("node")),
            entry(5353, Some(2), Some("mdns")),
        ];
        let legacy = table(&entries);
        assert!(!legacy.lines().next().unwrap().contains("LABEL"));

        let labeled = labeled_table(&entries, &[Some(&"界".repeat(17)), None]);
        let lines = labeled.lines().collect::<Vec<_>>();
        assert!(lines[0].ends_with("LABEL"), "{labeled}");
        assert!(lines[1].ends_with('…'), "{labeled}");
        assert!(lines[2].ends_with('-'), "{labeled}");
        let label_offset = lines[0].find("LABEL").unwrap();
        assert_eq!(
            lines[1][..lines[1].find('界').unwrap()].width(),
            label_offset
        );

        let hostile = labeled_table(&entries[..1], &[Some("safe\u{1b}[2J\u{202e}text")]);
        assert!(!hostile.contains('\u{1b}'), "{hostile}");
        assert!(!hostile.contains('\u{202e}'), "{hostile}");
    }

    #[test]
    fn legacy_json_serializes_present_and_missing_labels() {
        let entries = [
            entry(3000, Some(1), Some("node")),
            entry(5353, Some(2), Some("mdns")),
        ];
        let mut views = entry_views(&entries);
        views[0].label = Some("web dev");
        let mut bytes = Vec::new();
        write_view_json(&mut bytes, |index| views[index], &[0, 1]).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value[0]["label"], "web dev");
        assert_eq!(value[1]["label"], serde_json::Value::Null);
    }

    #[test]
    fn json_is_an_array_even_when_empty() {
        assert_eq!(json(&[]), "[]\n");
        let rows = [entry(3000, Some(1), Some("node"))];
        let json = json(&rows);
        let value: serde_json::Value = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["label"], serde_json::Value::Null);
    }
}
