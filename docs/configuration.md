# Configuration and Filters

Kickoutchi uses a TOML configuration file for persistent policy, display, and
label settings. The `list` command, TUI search, and `watch` command also expose
command-local filters. This document is the complete reference for both.

Both executable names, `kickoutchi` and `kick`, have identical behavior.

## Configuration file

### Path selection and loading

Without `--config`, Kickoutchi reads `kickoutchi/config.toml` below the
platform configuration directory returned by the operating system. Typical
locations are:

| Platform | Default path |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/kickoutchi/config.toml`, or `~/.config/kickoutchi/config.toml` when `XDG_CONFIG_HOME` is unset |
| macOS | `~/Library/Application Support/kickoutchi/config.toml` |
| Windows | `%APPDATA%\kickoutchi\config.toml` |

If the OS does not provide a configuration directory, Kickoutchi uses built-in
defaults. A missing file at the default path is also normal and uses built-in
defaults. Other failures at the default path, including permission and I/O
errors, are fatal.

Use the global option `--config FILE` to select an exact path. It may appear
before or after a subcommand:

```sh
kick --config ./kickoutchi.toml list
kick watch --config ./kickoutchi.toml
```

An explicitly selected file must exist and be readable. A missing explicit
file is an error; Kickoutchi does not fall back to the default path or built-in
defaults.

Configuration input must be valid UTF-8 and no larger than 65,536 bytes (64
KiB). Exactly 65,536 bytes is accepted; byte 65,537 is rejected. Reads stop
after the first excess byte, although the host OS may still block while opening
or reading a regular or special file. Invalid TOML, wrong value types, unknown
top-level keys, and unknown keys inside `[[ports]]` are fatal and identify the
configuration path.

### Precedence

Resolved settings use this order, from lowest to highest precedence:

1. Built-in defaults.
2. Values present in the selected configuration file.
3. Applicable CLI overrides.

Omitted TOML keys leave the lower-precedence value unchanged. An empty file is
valid and therefore selects all built-in defaults.

`--refresh-interval SECONDS` is the global CLI override for
`refresh_interval_seconds`; it accepts `1..=3600`. For `list`, `--sort MODE`
overrides `default_sort` for that invocation. There are no CLI overrides for
`hide_system_processes`, `confirm_force_kill`, `docker_enrichment`,
`protected_processes`, or `ports`.

Global `--verbose`/`-v` is a diagnostic-output switch rather than a
configuration override. It enables internal debug diagnostics on stderr and
never changes command stdout.

The watch polling interval is separate: `watch --interval` does not use
`refresh_interval_seconds`.

### Keys

| Key | TOML type | Default | Valid values and effect |
| --- | --- | --- | --- |
| `refresh_interval_seconds` | integer | `3` | `1..=3600`. Controls TUI automatic recollection. The global `--refresh-interval` overrides it. |
| `default_sort` | string | `"port"` | Exactly `"port"`, `"pid"`, `"protocol"`, `"process"`, `"parent"`, or `"scope"`. Sets the initial TUI sort and the `list` sort when `--sort` is absent. |
| `hide_system_processes` | boolean | `false` | When `true`, conservatively classified system/service rows are hidden from normal `list` and TUI views. It does not affect `watch` or `list --snapshot-json`. |
| `confirm_force_kill` | boolean | `true` | When `true`, force kill uses stronger typed confirmation unless `--yes` applies. It does not weaken protected-process confirmation. |
| `docker_enrichment` | boolean | `false` | When `true`, qualifying TUI details and termination-context requests may run a bounded, PATH-resolved Docker CLI query for optional container metadata. When `false`, Kickoutchi never resolves or executes the Docker CLI. Native socket evidence and termination policy are unaffected. |
| `check_for_updates` | boolean | N/A | Deprecated compatibility key. Both `true` and `false` are accepted and ignored so older configuration files still load. Kickoutchi performs no automatic update check. Non-boolean values remain invalid. |
| `protected_processes` | array of strings | `[]` as a configured extension | Adds names to the built-in protected set; it never replaces that set. Empty names are invalid. The merged, exactly deduplicated set may contain at most 256 names. |
| `ports` | array of tables | empty | Defines up to 256 validated endpoint label selectors. See [Endpoint labels](#endpoint-labels). |

`default_sort` ordering is deterministic. In particular, `scope` orders public,
then local-interface, then loopback endpoints. The TUI can cycle away from its
configured initial sort interactively.

No other top-level keys are accepted. Internal event-loop timing is not a
configuration option.

### Protected process extension

The built-in protected names are:

```text
docker
docker.exe
dockerd
dockerd.exe
docker-proxy
docker-proxy.exe
Docker Desktop.exe
com.docker.backend
com.docker.backend.exe
postgres
postgres.exe
systemd
System
smss.exe
csrss.exe
wininit.exe
services.exe
lsass.exe
svchost.exe
winlogon.exe
explorer.exe
dwm.exe
WindowServer
```

Configured values extend this list. Exact duplicates of an existing built-in or
earlier configured string are removed before enforcing the 256-name merged
limit. An empty configured array is valid; an empty string is not. Other strings,
including strings containing whitespace, pass configuration validation, although
matching is always against the exact process name rather than a substring.

Matching follows platform process-name conventions:

- Linux and macOS compare names exactly and case-sensitively.
- Linux also recognizes the first 15 bytes of a longer configured name, because
  `/proc/<pid>/comm` exposes only that prefix. When the cut splits a UTF-8
  character, the partial character becomes U+FFFD on both sides, as Kickoutchi
  reads `comm`.
- macOS also accepts a configured name followed by `:` or ASCII whitespace in
  the process name, as in a `postgres: checkpointer` title. A configured name
  also matches the executable's file name exactly, because the kernel process
  name is truncated. Rows, filters, tree and group kills, `inspect`, and the
  final check before a signal all apply this rule. An unreadable executable
  path adds no protection.
- Windows compares process names case-insensitively, including Unicode casing
  on a native Windows build.
- No platform uses arbitrary substring matching for protection.

A protected process is confirmed by typing its PID, or its process name as the
prompt shows it. When the displayed name is empty or starts or ends with
whitespace, the prompt offers only the PID, and an empty answer never confirms.

Adding a name changes protection policy everywhere it is evaluated, including
kill confirmation and `protected:` filtering. It cannot remove protection from
a built-in name.

## Endpoint labels

Each `[[ports]]` table associates a label with either one exact endpoint or all
addresses for one protocol and port.

```toml
[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "any-address fallback"

[[ports]]
protocol = "udp"
address = "fe80::1"
scope_id = 7
port = 5353
label = "scoped discovery"
```

### Selector fields

| Field | Required | Validation |
| --- | --- | --- |
| `protocol` | Yes | String, exactly lowercase `"tcp"` or `"udp"`. |
| `address` | Yes | `"*"` or a literal IPv4/IPv6 address. Exact address text is limited to 64 UTF-8 bytes. Hostnames, DNS names, CIDR ranges, interface names, and `%zone` syntax are invalid. |
| `port` | Yes | Integer in `1..=65535`. |
| `scope_id` | No | Integer in `1..=4294967295`; valid only with an exact IPv6 address. |
| `label` | Yes | Nonempty safe visible Unicode, at most 128 UTF-8 bytes, with no leading or trailing Unicode whitespace. |

Unknown selector fields and missing required fields are errors naming the zero-based
selector index, such as `ports[0]`. At most 256 selectors are accepted.

A label consisting only of whitespace is invalid. Control characters and
default-ignorable Unicode scalars, including terminal escapes, bidi controls,
zero-width characters, and soft hyphens, are rejected. Stored and structured
labels retain their validated text. Human table/TUI labels are sanitized again
and clipped to at most 32 terminal columns with an ellipsis when necessary.

### Address and scope normalization

IPv4-mapped IPv6 addresses are normalized to IPv4. Consequently,
`::ffff:127.0.0.1` and `127.0.0.1` identify the same selector, and a
`scope_id` is invalid for either spelling. An exact IPv4 selector has no scope.
An exact IPv6 selector without `scope_id` matches only an observed unscoped IPv6
endpoint; one with `scope_id` matches only that interface index.

IPv6 interface scope is currently available from the Windows collector. Linux
and macOS report it as unavailable, so exact IPv6 selectors, including unscoped
ones, do not match those unavailable-scope observations. A wildcard selector
does not inspect address or scope and is the portable choice when protocol and
port alone identify the service.

### Duplicate and resolution rules

Selectors are duplicate-checked after address normalization:

- Two wildcard selectors with the same protocol and port are duplicates.
- Two exact selectors with the same normalized protocol, address, port, and IPv6
  scope are duplicates.
- IPv4 and its IPv4-mapped IPv6 spelling are therefore duplicates.
- TCP and UDP selectors, different ports, different exact addresses, and
  different IPv6 scope IDs remain distinct.

Duplicate selectors are rejected; declaration order is not a tie-breaker.

Resolution first looks for an exact normalized endpoint selector. If none
matches, it looks for the wildcard selector with the same protocol and port.
Thus an exact selector always takes precedence over its wildcard fallback,
regardless of their order in the file.

Configuring at least one selector enables the `LABEL` column in CLI tables and
sufficiently wide TUI tables even when no current row has a matching label.
Labels also appear in legacy list JSON, snapshot JSON, watch output, plain
search, and `label:` filters.

## Filter syntax

`list --filter TEXT`, TUI search, and `watch --filter TEXT` share one parser.
The filter expression is at most 256 UTF-8 bytes. Exactly 256 bytes is accepted;
257 bytes is rejected. The TUI simply stops accepting characters that would
cross the limit, while CLI commands report invalid arguments.

The parser splits on Unicode whitespace. There is no quoting or escaping layer:

```sh
kick list --filter 'proto:tcp scope:loopback node'
```

This expression has three terms. Every term must match: terms use **AND**
semantics. Repeating a field also means AND, so contradictory exact terms match
nothing. `list --port`, `list --process`, configuration-driven system hiding,
and all `--filter` terms are likewise combined.

A token whose text before the first colon is a recognized field is parsed and
validated as structured syntax. A token without a colon is plain search. For
backward compatibility, an unrecognized `name:value` token is also plain search
using the entire token; it is not rejected merely because it contains a colon.
For example, `future:value` searches for the literal case-normalized text
`future:value`.

Recognized fields are reserved. If a recognized field is unsupported by a
command, the command reports an invalid-arguments error rather than treating it
as plain text. CLI filter syntax and command capability are validated before
socket collection begins, so an unsupported `state:` on `list` cannot trigger a
collection first.

### Capability matrix

| Selector or field | `list` | TUI | `watch` | Meaning |
| --- | :---: | :---: | :---: | --- |
| Plain term | Yes | Yes | Yes | Case-insensitive substring search across the command's searchable facts. |
| `pid:` | Yes | Yes | Yes | Exact owner PID. |
| `port:` | Yes | Yes | Yes | Exact endpoint port. |
| `proto:` | Yes | Yes | Yes | Exact TCP or UDP protocol. |
| `scope:` | Yes | Yes | Yes | Exact derived bind scope. |
| `protected:` | Yes | Yes | Yes | Exact protection classification. |
| `parent:` | Yes | Yes | Yes | Parent PID substring or parent process-name substring. |
| `label:` | Yes | Yes | Yes | Label substring. |
| `address:` | Yes | Yes | Yes | Exact normalized literal IP address across IPv6 scopes. |
| `scope_id:` | Yes | Yes | Yes | Exact nonzero IPv6 interface index. |
| `family:` | Yes | Yes | Yes | Normalized IPv4 or IPv6 family. |
| `state:` | Error | Error | Yes | Exact full socket state. Reserved but unsupported by list/TUI. |
| `list --port` | Yes | No | No | Separate exact-port CLI selector; `u16`, including `0`. |
| `list --process` | Yes | No | No | Separate case-insensitive process-name substring selector. |
| `watch --tcp`, `--udp` | No | No | Yes | Protocol selectors; neither means both, and both may be supplied. |
| `watch --address`, `--scope-id`, `--port` | No | No | Yes | Endpoint selectors applied before filter terms. |

The TUI uses list capabilities because it displays only listening TCP and bound
UDP legacy rows. `watch` filters the complete native socket-state snapshot.
`why` uses exact endpoint arguments and has no general filter expression.

### Structured fields and values

| Field | Accepted value | Match behavior |
| --- | --- | --- |
| `pid:` | Decimal `u32`, `0..=4294967295` | Exact owner PID. |
| `port:` | Decimal `u16`, `1..=65535` | Exact nonzero port. Port zero is rejected rather than treated as an always-empty query. |
| `proto:` | `tcp` or `udp`, ASCII case-insensitive | Exact protocol. |
| `scope:` | `public`, `local`, or `loopback`, ASCII case-insensitive | Exact derived bind scope. Unspecified addresses are `public`, loopback addresses are `loopback`, and other concrete local addresses are `local`. |
| `protected:` | `true` or `false`, ASCII case-insensitive | Exact policy classification using the merged protected-name list. |
| `parent:` | Any nonempty text | Case-normalized substring of the decimal parent PID or parent process name. |
| `label:` | Any nonempty text | Case-normalized substring of the resolved endpoint label. |
| `address:` | Literal IPv4/IPv6 address, at most 64 bytes | Exact normalized address. IPv4-mapped IPv6 input and observations normalize to IPv4. `%zone` text is invalid. |
| `scope_id:` | Decimal integer `1..=4294967295` | Exact IPv6 interface index. It cannot be combined with `family:ipv4` or an IPv4 `address:` term. |
| `family:` | `ipv4` or `ipv6`, ASCII case-insensitive | Exact family after IPv4-mapped IPv6 normalization. |
| `state:` | One exact lowercase state name listed below | Exact state; watch only. |

Empty structured values are invalid where text is required. Invalid values are
errors rather than no-match results. `scope_id:` plus `family:ipv4` or an IPv4
`address:` is a contradictory request and is rejected explicitly. Other
contradictions, such as `proto:tcp proto:udp`, are valid AND expressions that
match nothing.

The complete `state:` vocabulary is:

```text
listen
bound
closed
syn_sent
syn_received
established
fin_wait1
fin_wait2
close_wait
closing
last_ack
time_wait
delete_tcb
new_syn_received
unknown
```

These names are case-sensitive and must be lowercase. `bound` is the portable
UDP state. `unknown` matches any retained unknown native TCP state regardless of
its numeric native code.

### Normalization and case behavior

Plain terms, `parent:` values, `label:` values, process names, parent names,
paths, command lines where available, and labels are normalized with Unicode
lowercasing before substring comparison. Numeric, protocol, state, scope, and
address display facts use their canonical text; plain matching against those
facts is ASCII case-insensitive or against already lowercase text. Structured
`proto:`, `scope:`, `protected:`, and `family:` values accept ASCII case
variants. Structured `state:` values do not.

IP comparisons are exact after parsing and IPv4-mapped normalization, not text
substrings. Structured numeric fields are exact, except `parent:`, which is
intentionally a substring search over both parent PID text and parent name.

### Plain-search fields

For list and TUI rows, each plain term can match any of:

- local port or owner PID;
- local address, `address:port`, `[address]:port`, or scoped
  `[address%scope]:port` text (`%unavailable` when the interface is unknown);
- protocol, visible legacy state (`listen` or `bound`), or bind scope;
- resolved label;
- process name, executable path, or complete bounded command line;
- parent PID or parent process name.

The separate `list --process TEXT` option searches only process names, using a
case-insensitive substring, and excludes rows with no process name. `TEXT` must
be nonempty. An empty substring matches every name, so it would reduce the
result to "rows whose process name was readable" rather than filter it; that is
rejected as an invalid argument (exit `2`). Whitespace is accepted, because a
space is a legitimate substring of a process title.

Watch deliberately collects the `Display` metadata profile rather than the
legacy list/TUI profile. Watch plain search includes:

- endpoint port, address, unscoped and scoped endpoint text forms, protocol, full
  state, scope, and label;
- verified or unverified owner PID;
- available process name and executable path;
- parent PID and parent process name;
- the derived words `protected` or `unprotected` when protection can be
  determined.

Watch does **not** collect or search complete process command lines. List and TUI
do. Conversely, watch plain search can match full socket states and the
protection-classification words; list/TUI plain search is limited to their
legacy rows and does not add those protection words as synthetic searchable
metadata.

Missing metadata is a simple non-match for a list/TUI row. Watch preserves
uncertainty: unavailable owner or process metadata can make an otherwise
possible owner-dependent expression `indeterminate` rather than false.

### Watch selectors and event semantics

Watch has endpoint selectors in addition to `--filter`:

| Option | Default | Validation and behavior |
| --- | --- | --- |
| `--tcp` | Both protocols when neither protocol flag is present | Include TCP. May be combined with `--udp`. |
| `--udp` | Both protocols when neither protocol flag is present | Include UDP. May be combined with `--tcp`. |
| `--address ADDRESS` | Any address | Literal normalized IP address, at most 64 bytes, matched across IPv6 scopes. No hostname or `%zone`. |
| `--scope-id ID` | Any scope | `1..=4294967295`; requires one explicit IPv6 `--address` and narrows it to that interface index. |
| `--port PORT` | Any port | Exact nonzero port in `1..=65535`. |
| `--filter TEXT` | No terms | Shared expression, with watch capabilities. |

All active watch selectors and filter terms use AND semantics. Endpoint-only
terms must match the socket. Owner-dependent terms (`pid:`, `parent:`,
`protected:`, and owner metadata portions of plain search) must all be
satisfied by the same conceptual owner row; separate owners cannot each satisfy
half of one expression. If at least one owner satisfies the whole expression,
the event matches. Incomplete ownership or metadata may instead produce an
indeterminate result.

Baseline and bind events evaluate the current observation. Release events
evaluate the previous observation. A replacement event is retained when the
complete expression matches either its previous side or its current side. A
definite false result suppresses the endpoint event. A true result is emitted as
`matched`; an uncertainty-preserving result is emitted as `indeterminate` with
applicable evidence gaps. `kick watch --matched-only` suppresses
`indeterminate` events like definite non-matches, at the cost of hiding possible
matches behind unreadable facts. With no selector or filter, emitted endpoint
events use `not_applied`.

`collection_gap` records describe polling failure rather than an endpoint and
bypass endpoint/filter selection. Filters therefore cannot hide the fact that
collection failed.

Watch timing is command-local. `--interval` defaults to `1s` and accepts
`100ms..=60s`; `--duration`, when present, accepts `100ms..=7d`. A time token is
one unsigned integer immediately followed by `ms`, `s`, `m`, `h`, or `d`.

## Snapshot JSON mode

`kick list --snapshot-json` emits the complete versioned network snapshot rather
than the legacy list projection. Clap rejects any invocation that combines it
with:

- `--json`;
- `--port`;
- `--process`;
- `--filter`;
- `--sort`.

These conflicts are argument errors before collection. Global options such as
`--config` and `--refresh-interval` do not conflict, although the refresh value
does not alter a one-shot snapshot.

Snapshot mode intentionally ignores `hide_system_processes` and does not apply
the configured/default list sort. It bypasses list/TUI visibility filtering and
the listening-TCP/bound-UDP legacy projection, so it can include system-owned
sockets and non-listening full-state sockets. Configured endpoint labels are
still resolved into snapshot output. This behavior prevents a display preference
from silently removing evidence from the complete snapshot contract.

## Complete example

```toml
# TUI refresh and initial list/TUI presentation.
refresh_interval_seconds = 5
default_sort = "scope"
hide_system_processes = true

# Keep stronger force confirmation and add project-specific protected names.
confirm_force_kill = true
protected_processes = ["redis-server", "project-supervisor"]

# Exact development endpoint, preferred over the fallback below.
[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "web service"

[[ports]]
protocol = "udp"
address = "*"
port = 5353
label = "mDNS"
```

Example queries:

```sh
# File sort is scope; this invocation overrides it with process.
kick list --sort process

# TCP loopback rows whose label contains "web" and whose owner metadata
# contains "node" somewhere in the plain-search fields.
kick list --filter 'proto:tcp scope:loopback label:web node'

# Exact normalized IPv6 address and interface scope.
kick list --filter 'family:ipv6 address:fe80::1 scope_id:7'

# Full-state watch expression; all terms must hold.
kick watch --tcp --address 127.0.0.1 \
  --filter 'state:established parent:supervisor' --interval 500ms

# Complete evidence output: no list filters, sort, or system-row hiding apply.
kick list --snapshot-json
```

## Related documentation

- [Documentation index](README.md)
- [Security policy](../SECURITY.md), including sensitive labels and output
- [Structured output](structured-output.md)
- [Platform support and observation limits](platform-support.md)
