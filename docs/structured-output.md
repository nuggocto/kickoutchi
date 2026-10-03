# Structured Output Reference

Kickoutchi exposes four machine-readable contracts:

| Command | Contract | Top-level form |
| --- | --- | --- |
| `kick list --json` | `kickoutchi.list/1` | JSON array |
| `kick list --snapshot-json` | `kickoutchi.snapshot/1` | One JSON object |
| `kick watch --json` | `kickoutchi.watch_event/1` | NDJSON, one JSON object per line |
| `kick why PORT --json` | `kickoutchi.why/1` | One JSON object |

The `schema`/`version` pairs carried in-band are:

| Contract | `schema` | `version` |
| --- | --- | ---: |
| `kickoutchi.snapshot/1` | `kickoutchi.snapshot` | `1` |
| `kickoutchi.watch_event/1` | `kickoutchi.watch_event` | `1` |
| `kickoutchi.why/1` | `kickoutchi.why` | `1` |

`kickoutchi.list/1` is the compatibility exception: it remains a top-level array and has no in-band `schema` or `version` fields.

All field names and stable enum values use lowercase `snake_case`. JSON whitespace is not part of any contract. JSON documents end with a newline; each watch line is independently valid compact JSON and includes its newline in the record-size bound.

## Common Rules

### Integer domains

Unless a narrower range is stated on a field:

| Meaning | JSON integer domain |
| --- | --- |
| PID, socket multiplicity | `u32`, `0..=4294967295` |
| Port | nonzero `u16`, `1..=65535` |
| Schema version | `u32`, `0..=4294967295` |
| Sequence, Unix timestamps, counts, timer ticks, socket tokens | `u64`, `0..=18446744073709551615` |
| IPv6 interface index and query scope ID | nonzero `u32`, `1..=4294967295` |
| Native socket-state code | `u32`, `0..=4294967295` |
| Raw OS error | `i32`, `-2147483648..=2147483647` |

Values outside a public domain are operational errors. They are never wrapped, clamped, or emitted through a lossy cast. Consumers whose JSON implementation cannot exactly represent all 64-bit integers should use an integer-preserving parser.

Structured timestamps are unsigned Unix milliseconds. Capture and probe completion never precede the corresponding start. Watch observation times identify capture windows, not exact kernel event times.

### Resource bounds

These limits bound collection, retention, and serialization. A lower native-platform limit applies when an OS API cannot safely represent the shared maximum.

| Resource | Limit and over-limit behavior |
| --- | --- |
| Config file | 64 KiB; larger files are rejected. |
| Label selectors | 256; a 257th selector is rejected. |
| Label text | 128 UTF-8 bytes; larger labels are rejected. JSON retains the complete validated label. |
| Filter expression | 256 bytes; larger filters are rejected before term parsing. |
| CLI literal address token | 64 bytes; a 65th byte is rejected before IP parsing. |
| Native socket table buffer | 16 MiB per table; oversized source data fails collection. |
| Socket observations per snapshot | 262,144; a larger socket set fails collection. |
| Candidate or uniquely referenced PIDs | 131,072; excess identity work fails collection. |
| Aggregate Linux or macOS file-descriptor entries | 1,048,576 per applicable collection scope; excess entries fail collection. |
| Owner edges per association pass | 262,144; excess edges fail collection. |
| Process identity reads | 262,144 per consistency attempt and 524,288 across both attempts. |
| Derived legacy list rows | 262,144; excess projection rows fail with `legacy_projection_limit_exceeded`. |
| Serialized owners per owner set | 64 plus `omitted_owner_count`. |
| Owner-completeness reasons per set | Eight; a ninth distinct reason fails with `owner_reason_limit_exceeded`. |
| Process or parent-process name | 4 KiB; a larger value becomes `null` with partial metadata and a gap. |
| Executable path | 128 KiB; a larger or invalid-UTF-8 value becomes `null` with partial metadata and a gap. |
| Legacy command line | 1 MiB; a larger value becomes `null` with partial metadata and a gap, never a prefix. |
| Aggregate optional process metadata per snapshot | 64 MiB; subsequent values are omitted before allocation while identities and sockets remain. |
| Consistency collection | Two attempts total; collection does not retry until success. |
| Retained snapshot evidence gaps | 4,096 plus `omitted_evidence_gap_count`; omission forces partial completeness. |
| Scope identifier | 256 UTF-8 bytes after sanitization; excess produces `null`, a scope gap, and partial completeness without retaining a prefix. |
| Scope limitations | Eight distinct codes; a ninth is an operational error. |
| Retained watch snapshots | Previous valid snapshot plus current snapshot. |
| Watch events per poll | 524,288; excess or overflow fails with `event_limit_exceeded`. |
| Retained watch event batch | 4,096; later events start another streamed batch. |
| Evidence and gaps per watch event | Eight of each, with separate omitted counts. |
| Consecutive watch collection failures | Three; the third gap is flushed before exit `1`. |
| Watch interval | `100ms..=60s`, default `1s`. |
| Explicit watch duration | `100ms..=7d`. |
| Watch NDJSON record | 64 KiB including newline; an oversized record is refused without a partial line. |
| Why endpoint matrix | Eight endpoints; a larger matrix is rejected before collection and probing. |
| Evidence and gaps per Why result | 16 of each, with separate omitted counts. |
| Evidence, gap, probe, and operational message | 512 UTF-8 bytes after sanitization. |

Counts use checked arithmetic. Limits that preserve data through an omitted count do not change the underlying completeness classification unless stated; limits that make identity-critical or socket-set data unreliable fail rather than emit a misleading result.

### Null, empty, and omitted values

Fields shown in this document are always present unless a union selects a different data shape. Nullable fields are serialized as JSON `null`; they are not omitted.

- `null` means the value is unavailable or not applicable according to that field's rules.
- `[]` means a known empty collection.
- An empty complete owner set is an affirmative observation that no owner was observed after complete attribution.
- An empty partial owner set does not claim that no owner exists.
- An omitted-count field reports items not retained after the corresponding array cap. It is `0` when nothing was omitted.

### Reusable shapes

The following shapes are shared by the versioned contracts.

#### `Endpoint`

```text
{
  protocol: "tcp" | "udp",
  address: string,
  port: integer 1..65535,
  ipv6_scope:
    null |
    { kind: "unscoped", interface_index: null } |
    { kind: "interface_index", interface_index: integer 1..4294967295 } |
    { kind: "unavailable", interface_index: null }
}
```

`address` is canonical Rust `IpAddr` text without a zone suffix. IPv4-mapped IPv6 addresses are normalized to IPv4. `ipv6_scope` is `null` if and only if `address` is IPv4. Every IPv6 endpoint has exactly one non-null scope object. `interface_index` is non-null only for `kind: "interface_index"`.

`unscoped` means scope ID zero is part of the endpoint identity. `unavailable` means the native source could not report scope; it is not equivalent to unscoped.

#### `ProcessIdentity`

```text
{
  pid: integer 0..4294967295,
  start_marker:
    { kind: "linux_start_ticks", ticks: integer 1..18446744073709551615 } |
    {
      kind: "macos_start_time",
      seconds: integer 0..18446744073709551615,
      microseconds: integer 0..999999
    } |
    {
      kind: "windows_creation_time",
      filetime_ticks: integer 1..18446744073709551615
    }
}
```

The macOS `seconds` and `microseconds` pair cannot both be zero. A process identity is the complete PID-and-marker pair; PID alone is not stable across process reuse.

#### `SocketState`

```text
{
  kind: "closed" | "listen" | "syn_sent" | "syn_received" |
        "established" | "fin_wait1" | "fin_wait2" | "close_wait" |
        "closing" | "last_ack" | "time_wait" | "delete_tcb" |
        "new_syn_received" | "bound" | "unknown",
  native_code: integer 0..4294967295 | null
}
```

`native_code` is non-null if and only if `kind` is `unknown`. `bound` is the UDP state. The other known values are TCP states.

#### `OwnerObservation`

```text
{ kind: "verified", identity: ProcessIdentity }
```

or:

```text
{
  kind: "unverified_pid",
  pid: integer 0..4294967295,
  reason: EvidenceGapCode
}
```

An unverified PID was observed but could not be paired with a reliable process-start marker. Its `reason` uses the stable evidence-gap vocabulary.

#### `OwnerSet`

```text
{
  owners: [OwnerObservation],
  omitted_owner_count: integer 0..18446744073709551615,
  completeness: "complete" | "partial" | "raced",
  reasons: [EvidenceGapCode]
}
```

At most 64 owners are serialized. Additional owners increment `omitted_owner_count` without changing `completeness`. `reasons` is socket-local, deduplicated, lexicographically sorted, and capped at eight distinct codes. A ninth reason is an `owner_reason_limit_exceeded` operational failure, not silent truncation.

- `complete` normally has an empty `reasons` array.
- `partial` contains the actual local reason codes.
- `raced` has exactly `reasons: ["observation_raced"]`.

Snapshot-global ownership gaps remain in the snapshot's evidence-gap fields and are not copied into arbitrary owner sets.

#### `EvidenceGap`

```text
{
  code: EvidenceGapCode,
  impact: "metadata" | "ownership" | "socket_set" | "scope",
  endpoint: Endpoint | null,
  pid: integer 0..4294967295 | null,
  affected_pid_count: integer 1..131072 | null,
  message: string
}
```

`endpoint: null` means the gap may affect the whole observation scope rather than
one endpoint. `affected_pid_count` is non-null only for an aggregated PID-scoped
loss: the positive count is bounded by the 131,072 candidate-PID scan limit, and
`pid` is always `null`. A gap tied to one exact PID instead uses `pid` and has
`affected_pid_count: null`. When consistency passes repeat the same aggregate
observation, Kickoutchi keeps the maximum count; it does not sum counts that may
describe overlapping PID sets. `omitted_evidence_gap_count` is separate: it
counts gap records not retained after an array cap, never PIDs represented by
`affected_pid_count`. When both PID fields are `null`, the gap is not confined to
a known PID and is not a PID-count aggregate. `message` is sanitized and limited
to 512 UTF-8 bytes. It is explanatory text, not a stable programmatic value; use
`code`, `impact`, `endpoint`, `pid`, and `affected_pid_count` for logic.

#### `Scope`

```text
{
  kind: "current_network_namespace" |
        "current_host_process_visible_sockets" |
        "current_host_network_stack",
  identifier: string | null,
  limitations: [ScopeLimitation]
}
```

Scope kinds currently map to Linux, macOS, and Windows respectively. On Linux, `identifier` is a bounded, sanitized `/proc/self/ns/net` link in `net:[decimal]` form when available. It is `null` on macOS and Windows and when the Linux identifier is unavailable. An identifier over 256 UTF-8 bytes is not truncated: collection retains `null`, records a scope gap, and makes the snapshot partial.

`limitations` is deduplicated and ordered by the stable vocabulary order below, with at most eight values.

#### `Evidence`

```text
{
  code: EvidenceCode,
  source: EvidenceSource,
  certainty: "proven" | "estimated" | "heuristic" | "unknown",
  message: string
}
```

`message` is sanitized and limited to 512 UTF-8 bytes. It is explanatory, not stable. The stable fields are `code`, `source`, and `certainty`.

### Stable vocabularies

#### Completeness and certainty

- Snapshot and owner completeness: `complete`, `partial`, `raced`.
- Process metadata completeness: `complete`, `partial`.
- Certainty: `proven`, `estimated`, `heuristic`, `unknown`.

Certainty meanings:

| Value | Meaning |
| --- | --- |
| `proven` | The specific claim is directly established by an authoritative native fact or exact probe. |
| `estimated` | The value or interval is derived, for example from a native timer or polling interval. |
| `heuristic` | The interpretation is plausible but not established by authoritative data. |
| `unknown` | Permission, scope, race, platform, or other evidence limits prevent the claim. |

Certainty applies to the specific claim carrying it. It does not make every fact in the same record equally certain.

#### Evidence-gap codes

The stable `EvidenceGapCode` values are:

- `owner_permission_denied`
- `owner_attribution_incomplete`
- `owner_disappeared`
- `process_identity_unavailable`
- `process_metadata_unavailable`
- `native_field_unavailable`
- `scope_excluded`
- `noncritical_evidence_truncated`
- `observation_raced`

#### Scope limitations

The stable values, in serialization order, are:

- `other_network_namespaces_excluded`
- `process_first_socket_visibility_limited`
- `wsl_network_stack_excluded`
- `process_metadata_permission_limited`
- `ipv6_scope_unavailable`
- `scoped_ipv6_exact_matching_unavailable`
- `native_field_unavailable`
- `polling_interval_blind_spot`

#### Evidence sources

The stable values, in canonical source order, are:

- `linux_procfs`
- `macos_libproc`
- `macos_sysctl`
- `windows_ip_helper`
- `windows_process_api`
- `bind_probe`
- `docker`
- `analysis`

The presence of `docker` in the vocabulary does not mean current watch or Why commands run Docker. They do not.

#### Evidence codes

The stable `EvidenceCode` values are:

- `visible_verified_owner`
- `visible_unreadable_owner`
- `non_listening_kernel_state`
- `process_identity_changed`
- `exact_bind_succeeded`
- `exact_bind_address_in_use`
- `exact_bind_permission_denied`
- `exact_bind_address_unavailable`
- `exact_bind_unsupported`
- `exact_bind_other_error`
- `linux_timer_estimate`
- `docker_context`
- `scope_limitation`
- `potential_scope_overlap`
- `observation_probe_conflict`

Some codes are reserved by the public vocabulary but are not emitted by every command or host.

#### Operational codes

The stable public operational codes are:

- `socket_table_unavailable`
- `socket_table_permission_denied`
- `native_data_malformed`
- `native_data_oversized`
- `socket_observation_limit_exceeded`
- `process_identity_limit_exceeded`
- `owner_attribution_limit_exceeded`
- `legacy_projection_limit_exceeded`
- `platform_api_failed`
- `clock_unavailable`
- `partial_socket_set`
- `observation_raced`
- `owner_reason_limit_exceeded`
- `event_limit_exceeded`
- `writer_failed`

Watch `collection_gap` records contain collection-related codes only. A failed writer cannot reliably describe itself through that writer, so writer failures use stderr prose when possible rather than emitting a partial NDJSON record. `writer_failed` and `event_limit_exceeded` are stable classifications reserved for consumers of public operational errors; the current CLI does not promise those code strings in stderr text.

`native_data_oversized` is for oversized source buffers or malformed native counts. Socket-row, process-identity, owner-edge, and legacy-projection limits use their more specific codes.

### Canonical ordering

Reusable values use these ordering rules wherever a contract calls for canonical sorting:

- Protocol: `tcp`, then `udp`.
- Address: IPv4 before IPv6, then numeric address bytes.
- Endpoint scope: IPv4/no scope, IPv6 `unscoped`, IPv6 `interface_index` numerically, then IPv6 `unavailable`.
- State: `closed`, `listen`, `syn_sent`, `syn_received`, `established`, `fin_wait1`, `fin_wait2`, `close_wait`, `closing`, `last_ack`, `time_wait`, `delete_tcb`, `new_syn_received`, `bound`, then `unknown` by `native_code`.
- Process marker kind: Linux, macOS, then Windows, followed by each variant's numeric fields.
- Owner: verified before unverified, then PID, marker kind/value with an absent marker last, then reason bytes.
- Owner set: completeness `complete`, `partial`, `raced`; reasons lexicographically; omitted count; then owner array lexicographically.
- Socket token: `linux_inode`, then `macos_socket_id`, each by value; `null` after present tokens.
- Filter result: `not_applied`, `matched`, `indeterminate`.
- Certainty: `proven`, `estimated`, `heuristic`, `unknown`.

No public array relies on hash-map iteration order.

## `kickoutchi.list/1`

Run `kick list --json`. The result is the stable legacy top-level array used by existing scripts. It deliberately has no envelope.

Each array element has exactly these fields:

| Field | Type | Meaning and null rule |
| --- | --- | --- |
| `protocol` | `"tcp" \| "udp"` | Transport protocol. |
| `local_addr` | string | Canonical local IP address text. |
| `local_port` | integer `1..65535` | Local port. |
| `state` | `"listen" \| "bound"` | TCP listening or UDP bound. |
| `pid` | `u32 \| null` | Attributed PID, or `null` when unavailable. |
| `process_name` | `string \| null` | Process name, or `null` when unavailable or over 4 KiB. |
| `executable_path` | `string \| null` | Executable path, or `null` when unavailable, invalid UTF-8, or over 128 KiB. |
| `command_line` | `string \| null` | Complete decoded command line, or `null` when unavailable or over 1 MiB. It is never silently truncated. |
| `parent_pid` | `u32 \| null` | Parent PID when available. |
| `parent_process_name` | `string \| null` | Parent process name when available. |
| `child_pids` | array of `u32` | Frozen `1.x` compatibility field with no backing data. It is always `[]`, on every row and every platform. Child processes are not part of this contract; use `inspect` for process relationships. |
| `protected` | boolean | Whether configured and built-in protection rules classify the process as protected. |
| `platform` | `"linux" \| "macos" \| "windows"` | Host collector platform. |
| `permission` | `"full" \| "partial"` | Legacy completeness flag. `full` means owner verification and optional process metadata were complete; `partial` means either was incomplete for any reason. The historical field name does not prove permission denial; use snapshot evidence gaps for the cause. |
| `label` | `string \| null` | Resolved configured endpoint label, or `null` when no selector matches. |

Process names and command lines preserve the established lossy decoding behavior: invalid Unix bytes or Windows UTF-16 sequences become U+FFFD. Executable paths do not use lossy conversion; invalid UTF-8 becomes `null` and makes metadata partial.

Human output appends `%<interface-index>` or `%unavailable` to IPv6 addresses so
distinct endpoint identities remain visible. That display convention does not
change this legacy JSON contract: `local_addr` remains bare canonical IP text,
and consumers that need structured scope identity should use snapshot JSON.

The array order follows the selected `--sort` mode, or the configured default sort when `--sort` is absent. Filtering occurs before serialization. An empty result is exactly `[]\n`. An empty result from an explicit selection or filter exits `3`; an unfiltered empty host is successful.

`label` is the only additive field introduced into this legacy contract. Exact protocol/address/port label selectors take precedence over explicit wildcard-address selectors. Exact IPv6 labels include scope identity; wildcard selectors deliberately ignore scope. Labels are validated visible Unicode, at most 128 UTF-8 bytes, and are not clipped in JSON.

**Illustrative example:** process metadata and labels vary by host.

```json
[
  {
    "protocol": "tcp",
    "local_addr": "127.0.0.1",
    "local_port": 3000,
    "state": "listen",
    "pid": 4242,
    "process_name": "dev-server",
    "executable_path": "/usr/local/bin/dev-server",
    "command_line": "dev-server --port 3000",
    "parent_pid": 4100,
    "parent_process_name": "shell",
    "child_pids": [],
    "protected": false,
    "platform": "linux",
    "permission": "full",
    "label": "web dev"
  }
]
```

## `kickoutchi.snapshot/1`

Run `kick list --snapshot-json`. This mode is mutually exclusive with `--json`, `--port`, `--process`, `--filter`, and `--sort`. It emits a complete within-scope native observation rather than the legacy visible-row projection. `hide_system_processes` does not remove snapshot data; validated labels still annotate endpoints.

```text
{
  schema: "kickoutchi.snapshot",
  version: 1,
  capture: {
    started_unix_ms: u64,
    completed_unix_ms: u64
  },
  scope: Scope,
  completeness: "complete" | "partial" | "raced",
  owner_completeness: "complete" | "partial" | "raced",
  evidence_gaps: [EvidenceGap],
  omitted_evidence_gap_count: u64,
  sockets: [SnapshotSocket],
  processes: [SnapshotProcess]
}
```

`completeness` describes the whole observation. `owner_completeness` separately describes global owner attribution. A failed collection does not become an empty snapshot; the command emits no JSON result and exits `1`.

At most 4,096 snapshot evidence gaps are retained. Further gaps increment `omitted_evidence_gap_count` and force partial completeness.

### `SnapshotSocket`

```text
{
  endpoint: Endpoint,
  state: SocketState,
  timer: TcpTimer | null,
  owners: OwnerSet,
  socket_token: SocketToken | null,
  label: string | null
}
```

`timer` is non-null only for Linux TCP observations that expose timer data. `socket_token` is present only when the native source exposes a retained Linux inode or macOS socket ID. Tokens are opaque within-capture association and ordering values; they are not guaranteed unique across captures and do not prove replacement or socket persistence. `label` follows the label rules described for list output.

`TcpTimer` is:

```text
{
  kind: "none" | "retransmit" | "other" | "time_wait" |
        "zero_window_probe" | "unknown",
  native_code: u32 | null,
  raw_ticks: u64,
  estimated_remaining_milliseconds: u64 | null,
  certainty: "estimated"
}
```

`native_code` is non-null if and only if `kind` is `unknown`. The remaining-time estimate is `null` if the host clock-tick rate is unavailable, nonpositive, or cannot be converted safely. Even when present, it is an estimate, not a release time or a promise that a future bind will succeed.

`SocketToken` is:

```text
{
  kind: "linux_inode" | "macos_socket_id",
  value: u64
}
```

Token values are nonzero in current collectors.

### `SnapshotProcess`

```text
{
  identity: ProcessIdentity,
  name: string | null,
  executable_path: string | null,
  parent_pid: u32 | null,
  metadata_completeness: "complete" | "partial"
}
```

`name`, `executable_path`, and `parent_pid` are `null` when unavailable. `metadata_completeness` describes optional metadata availability regardless of whether the cause was permission, a race, an unsupported native field, or a resource bound; details remain in `evidence_gaps`. Full command lines and parent process names are not included.

### Snapshot ordering

- `sockets`: endpoint protocol, address family, address bytes, IPv6 scope, port, state, token with null last, owner-set key, then timer. A null timer sorts before a present timer. Present timers sort by kind (`none`, `retransmit`, `other`, `time_wait`, `zero_window_probe`, `unknown`), unknown native code, raw ticks, then estimated remaining milliseconds with null before a value.
- `processes`: PID, marker kind, marker value.
- `evidence_gaps`: impact in `socket_set`, `ownership`, `metadata`, `scope` order; code lexicographically; endpoint key; PID; affected PID count; message. For equal impact and code, a null endpoint sorts before concrete endpoints.
- Owner, reason, limitation, state, token, and endpoint subarrays use the common canonical rules.

**Illustrative example:** scope, timestamps, PIDs, markers, sockets, and metadata vary by host.

```json
{
  "schema": "kickoutchi.snapshot",
  "version": 1,
  "capture": {
    "started_unix_ms": 1750000000000,
    "completed_unix_ms": 1750000000002
  },
  "scope": {
    "kind": "current_network_namespace",
    "identifier": "net:[4026531840]",
    "limitations": ["other_network_namespaces_excluded", "ipv6_scope_unavailable"]
  },
  "completeness": "complete",
  "owner_completeness": "complete",
  "evidence_gaps": [],
  "omitted_evidence_gap_count": 0,
  "sockets": [
    {
      "endpoint": {
        "protocol": "tcp",
        "address": "127.0.0.1",
        "port": 3000,
        "ipv6_scope": null
      },
      "state": { "kind": "listen", "native_code": null },
      "timer": null,
      "owners": {
        "owners": [
          {
            "kind": "verified",
            "identity": {
              "pid": 4242,
              "start_marker": { "kind": "linux_start_ticks", "ticks": 9001 }
            }
          }
        ],
        "omitted_owner_count": 0,
        "completeness": "complete",
        "reasons": []
      },
      "socket_token": { "kind": "linux_inode", "value": 123456 },
      "label": "web dev"
    }
  ],
  "processes": [
    {
      "identity": {
        "pid": 4242,
        "start_marker": { "kind": "linux_start_ticks", "ticks": 9001 }
      },
      "name": "dev-server",
      "executable_path": "/usr/local/bin/dev-server",
      "parent_pid": 4100,
      "metadata_completeness": "complete"
    }
  ]
}
```

## `kickoutchi.watch_event/1`

Run `kick watch --json`. Stdout is NDJSON, not one JSON array. Parse and process each line independently.

Every line has this envelope:

```text
{
  schema: "kickoutchi.watch_event",
  version: 1,
  sequence: u64,
  event: "baseline" | "bind" | "release" | "replacement" |
         "collection_gap",
  observation: {
    previous_completed_unix_ms: u64 | null,
    attempt_started_unix_ms: u64,
    attempt_completed_unix_ms: u64
  },
  data: EndpointEventData | CollectionGapData
}
```

`sequence` starts at `0` and increments by one for each emitted record. Checked sequence overflow is an operational failure. `previous_completed_unix_ms` is `null` for baseline records and non-null for later polling attempts. The observation interval brackets collection; it is not the exact bind, release, or replacement time.

### Endpoint event data

`baseline`, `bind`, `release`, and `replacement` use:

```text
{
  endpoint: Endpoint,
  state: SocketState,
  previous_owners: OwnerSet | null,
  current_owners: OwnerSet | null,
  previous_socket_token: SocketToken | null,
  current_socket_token: SocketToken | null,
  multiplicity: integer 1..4294967295,
  label: string | null,
  filter_result: "not_applied" | "matched" | "indeterminate",
  certainty: "proven" | "estimated" | "heuristic" | "unknown",
  evidence: [Evidence],
  omitted_evidence_count: u64,
  evidence_gaps: [EvidenceGap],
  omitted_evidence_gap_count: u64
}
```

Side rules are exact:

| Event | Previous side | Current side |
| --- | --- | --- |
| `baseline` | owners and token are `null` | current owners present; token may be present or `null` |
| `bind` | owners and token are `null` | current owners present; token may be present or `null` |
| `release` | previous owners present; token may be present or `null` | owners and token are `null` |
| `replacement` | previous owners present; token may be present or `null` | current owners present; token may be present or `null` |

A tokenless replacement has both token fields `null`. `multiplicity` is the number added, removed, or replaced, not the total number currently observed at the endpoint.

Watch diffs socket multiplicity, not owner edges. An owner descriptor disappearing while another owner retains the same native socket does not produce a release. A state transition is a release in the old state and a bind in the new state.

At most eight evidence items and eight applicable evidence gaps are retained per endpoint event; further items increment the corresponding omitted count. Current replacement events include `process_identity_changed` analysis evidence. Evidence gaps are attached when filtering is indeterminate; definite non-matches are suppressed.

`filter_result` is:

- `not_applied` when no selector or user filter is active.
- `matched` when the selected event side is a definite match.
- `indeterminate` when missing ownership or metadata prevents a definite answer. The event is emitted with applicable gaps so incomplete data cannot silently hide a possible match.

Baseline and bind evaluate the current side, release evaluates the previous side, and replacement matches when either complete side matches. Process-related AND terms must all match one conceptual owner row rather than different owners.

Baseline, bind, and release are `proven` within a diff-safe reported scope. Replacement is deliberately narrow:

- `proven` when previous and current multiplicity are exactly one, both owner sets are complete and contain exactly one verified owner, the PIDs are equal, and process-start markers differ.
- `heuristic` under the same complete exact-one conditions when verified identities differ but the same-PID rule does not hold.
- Not emitted when verified identities are equal, when ownership is incomplete or shared, or when multiplicity is greater than one.

Opaque token equality never proves persistence or replacement.

### Collection gap data

`collection_gap` uses a different shape and never fabricates an endpoint:

```text
{
  error: {
    code: OperationalCode,
    message: string
  },
  certainty: "unknown",
  consecutive_failures: integer 1..3,
  completeness: "partial" | "raced" | null,
  evidence_gaps: [EvidenceGap],
  omitted_evidence_gap_count: u64
}
```

`error.message` is sanitized and limited to 512 UTF-8 bytes; use `error.code` for program logic. `completeness` is `partial` or `raced` when collection returned an unusable snapshot, and `null` when collection returned an error instead of a snapshot. At most eight gaps are retained.

### Watch ordering and bounds

Within a successful attempt, endpoint events sort by:

1. Protocol, address family, address bytes, IPv6 scope, and port.
2. State order.
3. Event kind: `release`, `replacement`, `bind`; baseline uses the same key position.
4. Event token key. Replacement compares previous then current token; other events use their active side.
5. Event-side owner-set key. Replacement compares previous then current sets.
6. Label bytes.
7. Filter result.
8. Certainty.

A failed poll emits only its `collection_gap` record. Collection gaps bypass endpoint filters.

Watch retains no more than the previous valid snapshot, the current snapshot, and a 4,096-event streaming batch. A poll may produce at most 524,288 events. Event 524,289, checked overflow, or an oversized diff is an `event_limit_exceeded` operational failure. Starting a new batch after 4,096 records is normal and does not fail.

Each compact NDJSON record is built in a fresh buffer capped at 64 KiB, including its newline. If a record would exceed 65,536 bytes, watch emits no partial line for that record and exits `1` with a diagnostic on stderr when possible. This is classified as `event_limit_exceeded`, but stderr text is explanatory rather than a machine-readable contract. Valid records are never truncated.

### Watch collection failures

- Initial collection failure, an initial raced snapshot, or an initial snapshot with a `socket_set` gap emits no baseline or NDJSON record, writes a sanitized diagnostic to stderr, and exits `1`.
- After a valid baseline, each failed collection or unusable raced/partial-socket-set snapshot emits and flushes one `collection_gap`, retains the last valid snapshot, and waits before retrying. Recovery therefore cannot fabricate releases from a failed snapshot.
- A partial snapshot containing only metadata, scope, or ownership gaps may advance the baseline and reset the failure counter. Replacement still requires complete global and local ownership evidence.
- The third consecutive collection failure flushes its gap and exits `1`. A fourth attempt is not made. Exhaustion takes precedence over cancellation or duration expiry observed during the third failed poll.
- A wall-clock failure cannot produce conforming timestamps. It writes a diagnostic, emits no record for that attempt, and exits `1` immediately without consuming the three-failure budget.
- Ctrl-C, duration expiry, and a broken stdout pipe exit `0`.
- Intervals are `100ms..=60s`, default `1s`; explicit durations are `100ms..=7d`. Invalid values exit `2` before collection.

Watch never invokes Docker in its polling loop. It uses native socket/process observations and configured labels only.

**Illustrative baseline record:** endpoint facts vary by host.

```json
{"schema":"kickoutchi.watch_event","version":1,"sequence":0,"event":"baseline","observation":{"previous_completed_unix_ms":null,"attempt_started_unix_ms":1750000000000,"attempt_completed_unix_ms":1750000000002},"data":{"endpoint":{"protocol":"tcp","address":"127.0.0.1","port":3000,"ipv6_scope":null},"state":{"kind":"listen","native_code":null},"previous_owners":null,"current_owners":{"owners":[],"omitted_owner_count":0,"completeness":"complete","reasons":[]},"previous_socket_token":null,"current_socket_token":null,"multiplicity":1,"label":null,"filter_result":"not_applied","certainty":"proven","evidence":[],"omitted_evidence_count":0,"evidence_gaps":[],"omitted_evidence_gap_count":0}}
```

**Illustrative collection-gap record:** the error and timestamps vary by attempt.

```json
{"schema":"kickoutchi.watch_event","version":1,"sequence":1,"event":"collection_gap","observation":{"previous_completed_unix_ms":1750000000002,"attempt_started_unix_ms":1750000001000,"attempt_completed_unix_ms":1750000001001},"data":{"error":{"code":"socket_table_unavailable","message":"socket table was unavailable"},"certainty":"unknown","consecutive_failures":1,"completeness":null,"evidence_gaps":[],"omitted_evidence_gap_count":0}}
```

## `kickoutchi.why/1`

Run `kick why PORT --json`. Why collects one snapshot, then probes every exact endpoint sequentially. It emits one document only after all endpoints have been evaluated.

```text
{
  schema: "kickoutchi.why",
  version: 1,
  query: {
    port: integer 1..65535,
    protocols: ["tcp" | "udp"],
    addresses: [string],
    scope_id: integer 1..4294967295 | null,
    ipv6_mode: "system_default" | "v6_only" | "dual_stack",
    reuse_address: boolean
  },
  capture: {
    started_unix_ms: u64,
    completed_unix_ms: u64
  },
  scope: Scope,
  completeness: "complete" | "partial" | "raced",
  owner_completeness: "complete" | "partial" | "raced",
  results: [WhyResult],
  aggregate_exit_code: 0 | 1 | 3 | 4
}
```

`query` records the validated matrix inputs. `scope_id` is non-null only for one explicit IPv6 address. Addresses are canonical IP text without zones. Why has no general filter expression.

### Query matrix and result order

- Bare `kick why PORT` evaluates TCP on `127.0.0.1:PORT`, then TCP on `[::1]:PORT`.
- `--tcp` selects TCP, `--udp` selects UDP, and `--all-protocols` selects TCP then UDP. These selectors are mutually exclusive.
- Without an address option, addresses are `127.0.0.1`, then `::1`.
- `--address ADDRESS` evaluates one literal IP address of at most 64 bytes. Zone text such as `%eth0` or `%3` is rejected; use `--scope-id`.
- `--all-addresses` means exactly `127.0.0.1`, `0.0.0.0`, `::1`, then `::`. It does not enumerate interfaces.
- `--scope-id` must be `1..=4294967295`, requires one explicit IPv6 address, and is invalid for IPv4, default addresses, and `--all-addresses`.
- `--ipv6-only` and `--dual-stack` are mutually exclusive and require every selected address to be IPv6. Otherwise `ipv6_mode` is `system_default`.
- `--reuse-address` sets `reuse_address: true`; the default is `false`.
- The Cartesian product is capped at eight endpoints. An empty or larger matrix exits `2` before collection or probing.
- An unavailable IPv6 family remains an explicit result; it is never silently removed.

`results` preserves protocol-major, address-minor query order. It is not re-sorted into snapshot order.

### `WhyResult`

```text
{
  endpoint: Endpoint,
  label: string | null,
  verdict: Verdict,
  certainty: "proven" | "estimated" | "heuristic" | "unknown",
  probe: {
    outcome: "bindable_now" | "address_in_use" | "permission_denied" |
             "address_unavailable" | "unsupported" | "other",
    started_unix_ms: u64,
    completed_unix_ms: u64,
    raw_os_error: i32 | null,
    message: string | null
  },
  evidence: [Evidence],
  omitted_evidence_count: u64,
  evidence_gaps: [EvidenceGap],
  omitted_evidence_gap_count: u64
}
```

`label` is the resolved endpoint label or `null`. `probe.raw_os_error` and `probe.message` are `null` when the OS supplied neither. The message is sanitized and limited to 512 UTF-8 bytes and is not stable; use `outcome` and `raw_os_error` for program logic.

Each result contains at most 16 evidence items and 16 applicable evidence gaps. Additional items increment the separate omitted counts. Full command lines are never included.

Stable verdicts are:

- `bindable_now`
- `owned`
- `owner_hidden`
- `kernel_state_observed`
- `permission_denied`
- `address_unavailable`
- `reservation_or_policy_unknown`
- `observation_raced`
- `unsupported`
- `indeterminate`

### Verdict decision table

The exact bind probe is later than the snapshot and is authoritative for bindability at probe completion. The first matching row wins:

| Probe outcome and usable snapshot evidence | Verdict | Certainty |
| --- | --- | --- |
| Bind succeeds | `bindable_now` | `proven` at probe completion |
| Address unavailable | `address_unavailable` | `proven` |
| Family or requested option unsupported | `unsupported` | `proven` |
| Permission denied | `permission_denied` | `proven`; availability remains separately unknown |
| Other OS error plus raced snapshot | `observation_raced` | `unknown` |
| Other OS error with any non-raced snapshot | `indeterminate` | `unknown` |
| Address in use plus matching active socket with a verified owner | `owned` | `proven` |
| Address in use plus matching active socket with no verified owner and an unverified PID, incomplete local attribution, or an empty owner set while snapshot `owner_completeness` is not `complete` | `owner_hidden` | `unknown`; the failed bind remains proven separately |
| Address in use plus matching active socket with a complete empty local owner set and complete snapshot `owner_completeness` | `kernel_state_observed` | `proven`: no readable process holds the socket |
| Address in use plus matching non-listening TCP state | `kernel_state_observed` | `proven`; timer evidence remains estimated |
| Address in use without an authoritative explanation | `reservation_or_policy_unknown` | `unknown`; the failed bind remains proven separately |

An active socket is an exact or same-family wildcard TCP listener or bound UDP socket from a socket-set-stable snapshot.

An empty owner set proves that no process holds the socket only when every process could be read. When snapshot-wide attribution is incomplete, for example because other users' processes are unreadable, any of those processes could hold it, so the verdict is `owner_hidden` and its `visible_unreadable_owner` evidence names the UID that created the socket when Linux reports one. Relevant non-listening TCP states can explain address-in-use without claiming a visible listener.

IPv6 authoritative exact and wildcard relationships require known equal scopes. Unavailable or different scope information contributes only `potential_scope_overlap` unknown evidence. Potential IPv4/IPv6 dual-stack overlap is supporting context only unless a native source proves the relevant socket option. Address shape alone never proves dual-stack behavior.

### Evidence order

Why preserves this presentation order rather than canonical source sorting:

1. Verified visible listener or UDP owner.
2. Visible endpoint with unreadable ownership.
3. Non-listening kernel state.
4. Exact bind-probe result.
5. Platform, namespace, or container supporting evidence.
6. Explicit evidence gaps and scope limitations.

This is presentation order only. Verdict selection uses the probe-first decision table.

### Probe warning

Why binds each exact endpoint and immediately closes it. It does not listen, accept, send, or receive. Probes run sequentially to avoid interfering with one another.

`bindable_now` means the exact probe succeeded at its recorded completion time. It does not reserve the endpoint, guarantee that a later process will bind first, or promise future availability. The host may change after the probe. Conversely, a successful probe can coexist with an earlier snapshot observation because that socket may have closed or host bind semantics may allow coexistence; the earlier observation remains evidence but does not override the successful later probe.

Why does not request Docker enrichment in this release. Docker evidence cannot change a core verdict or exit code, and no Docker process is spawned by Why.

### Verdict exits and aggregation

| Verdict | Endpoint exit mapping |
| --- | ---: |
| `bindable_now` | 0 |
| `observation_raced`, `indeterminate` | 1 |
| `owned`, `owner_hidden`, `kernel_state_observed`, `address_unavailable`, `reservation_or_policy_unknown`, `unsupported` | 3 |
| `permission_denied` | 4 |

After mapping every completed endpoint, `aggregate_exit_code` uses fixed precedence: `1`, then `4`, then `3`, then `0`. It is `0` only when every endpoint is proven bindable now. An operational failure that prevents complete evaluation exits `1` and emits no incomplete Why document.

**Illustrative example:** host scope, evidence, timestamps, probe errors, and verdicts vary.

```json
{
  "schema": "kickoutchi.why",
  "version": 1,
  "query": {
    "port": 3000,
    "protocols": ["tcp"],
    "addresses": ["127.0.0.1"],
    "scope_id": null,
    "ipv6_mode": "system_default",
    "reuse_address": false
  },
  "capture": {
    "started_unix_ms": 1750000000000,
    "completed_unix_ms": 1750000000002
  },
  "scope": {
    "kind": "current_network_namespace",
    "identifier": "net:[4026531840]",
    "limitations": ["other_network_namespaces_excluded"]
  },
  "completeness": "complete",
  "owner_completeness": "complete",
  "results": [
    {
      "endpoint": {
        "protocol": "tcp",
        "address": "127.0.0.1",
        "port": 3000,
        "ipv6_scope": null
      },
      "label": null,
      "verdict": "bindable_now",
      "certainty": "proven",
      "probe": {
        "outcome": "bindable_now",
        "started_unix_ms": 1750000000003,
        "completed_unix_ms": 1750000000004,
        "raw_os_error": null,
        "message": null
      },
      "evidence": [
        {
          "code": "exact_bind_succeeded",
          "source": "bind_probe",
          "certainty": "proven",
          "message": "the exact bind probe succeeded"
        },
        {
          "code": "scope_limitation",
          "source": "analysis",
          "certainty": "unknown",
          "message": "other network namespaces are outside this observation scope"
        }
      ],
      "omitted_evidence_count": 0,
      "evidence_gaps": [],
      "omitted_evidence_gap_count": 0
    }
  ],
  "aggregate_exit_code": 0
}
```

## Exit Codes and Streams

The process-wide exit contract is:

| Code | Meaning |
| ---: | --- |
| 0 | Command completed and its requested positive condition holds. |
| 1 | Operational or internal failure. |
| 2 | Invalid arguments. |
| 3 | A valid query has no match, or the requested endpoint is unavailable. |
| 4 | Permissions prevented a reliable answer. |
| 5 | Kill was cancelled; not produced by the structured commands in this document. |
| 6 | A protected process requires confirmation; not produced by the structured commands in this document. |

Stdout contains only the requested JSON, NDJSON, or human result. Diagnostics, warnings, parse errors, and operational errors use stderr. Structured stdout is never mixed with prose.

A broken stdout pipe is successful consumer termination for list, snapshot, and watch. Why evaluates all endpoints before writing, so a broken pipe preserves the already-computed aggregate exit code rather than converting an unavailable endpoint into success. Any other write or flush failure exits `1`.

Invalid argument combinations fail before native collection, write diagnostics only to stderr, and exit `2`. This includes incompatible snapshot options and invalid Why matrices. Watch initial failures and Why failures that prevent complete evaluation emit no partial structured document.

## Privacy and Trust

Treat all structured output as sensitive local-system data.

- `kickoutchi.list/1` can contain process names, executable paths, parent metadata, and complete command lines. Command lines commonly contain tokens, credentials, URLs, file paths, and user data.
- Snapshot, watch, and Why omit complete command lines, but still expose endpoints, PIDs, stable process-start markers, names, executable paths where applicable, ownership, labels, scope identifiers, evidence, and OS errors.
- Configured labels may reveal project names, service roles, or local topology.
- JSON escaping prevents malformed JSON; it is not redaction. Host metadata remains raw structured data subject to the documented byte and decoding rules.
- Evidence and operational messages are sanitized and bounded, but they may still reveal host facts. Message text is not a stable API.
- Human terminal sanitization is independent from structured output and does not make JSON safe to publish.
- Global `--verbose`/`-v` writes internal diagnostics only to stderr and never changes structured stdout. Those diagnostics can still contain local process or operating-system details.

Redact structured output before sharing it. See [Security Policy](../SECURITY.md) for private vulnerability reporting.

## Compatibility

`kickoutchi.list/1` remains a top-level array throughout the `1.x` series. Its approved additive change is the always-present nullable `label` field; it does not gain a version envelope. Existing fields retain their meanings, including null metadata and legacy `permission` semantics.

The versioned contracts identify themselves with exact `schema` and integer `version` pairs. Consumers should reject unsupported schema/version pairs rather than guessing. Within a supported version:

- Existing field meanings, null rules, stable codes, enum values, and ordering rules do not change incompatibly.
- New stable evidence or operational codes are additive. Consumers should preserve or tolerate unknown additive codes where their application can do so safely.
- Additive fields may be introduced only when compatible with the contract's versioning policy; parsers should generally ignore unknown object fields.
- Consumers must not infer behavior from explanatory `message` text, JSON formatting, object field order, host-specific examples, or currently unused vocabulary values.
- A future incompatible shape or semantic change requires a new integer version and documentation for the new schema/version pair.

Resource-bound safety behavior is part of compatibility: values over their documented limits become explicit null/partial evidence where specified, increment omitted counts where specified, or fail operationally. They are never silently truncated into a value that appears complete.

## Related documentation

- [Documentation index](README.md)
- [Security policy](../SECURITY.md)
- [Configuration and filters](configuration.md)
- [Platform support and observation limits](platform-support.md)
