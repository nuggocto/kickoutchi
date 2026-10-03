# Platform Support and Observation Limits

Kickoutchi reports bounded observations from native operating-system sources. It
does not claim host-wide visibility where the selected native source cannot
provide it. Every result must be interpreted together with its observation
scope, completeness, evidence gaps, and certainty.

## Supported targets

Published releases support these native targets:

| Platform | Release targets | Native socket source | Declared observation scope | Principal exclusion |
| --- | --- | --- | --- | --- |
| Linux | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | `/proc/net/tcp*`, `/proc/net/udp*`, and `/proc/<pid>/fd` | Current network namespace | Other network namespaces |
| macOS | `x86_64-apple-darwin`, `aarch64-apple-darwin` | Process and descriptor enumeration through libproc | Current host process-visible sockets | Sockets not reachable through visible user-process descriptors |
| Windows | `x86_64-pc-windows-msvc` | IP Helper extended TCP and UDP owner tables | Current native Windows host network stack | The separate WSL network stack |

Linux listing works on kernels older than 5.3, but safe process termination
requires Linux 5.3 or later because it uses `pidfd`. Windows ARM64 and other Rust
targets are not release-supported unless they are added to the native test and
artifact matrix.

All three collectors retain IPv4 and IPv6 TCP rows and states exposed by their
native source, including unknown native TCP state codes, and retain exposed UDP
rows as bound endpoints. UDP is not assigned a portable TCP-style lifecycle
state.

## What complete means

`complete` means complete within the snapshot's declared observation scope and
the collector's documented native source. It does not mean every socket on the
machine, in every container, virtual machine, network namespace, or subsystem.
Permanent exclusions remain exclusions even when a snapshot is complete.

Completeness has distinct dimensions:

- Snapshot completeness describes whether the in-scope socket observation was
  collected without a known partial read or race.
- Owner completeness describes whether visible socket-to-process attribution was
  complete. A socket can be authoritative while its owner is unknown.
- Process metadata completeness describes optional names, paths, parents, and
  related metadata. Missing metadata does not erase an authoritative socket row.
- Evidence gaps identify known losses by impact: socket set, ownership, metadata,
  or scope. An omitted-evidence count means additional gaps could not be retained
  within the public bound and must itself be treated as uncertainty.

For a PID-scoped loss aggregated across a bounded scan, an evidence gap can carry
a positive `affected_pid_count` while its exact `pid` remains null. Exact PID
gaps carry `pid` and a null count. Repeated aggregate observations retain the
maximum count rather than summing potentially overlapping PID sets, and
`omitted_evidence_gap_count` separately counts unretained gap records rather than
affected PIDs.

`partial` preserves facts that were successfully observed but prevents stronger
claims affected by the reported gaps. `raced` means collection changed in a way
that makes the relevant comparison unsafe. A failed collection is an error, not
an empty complete snapshot.

Collection spans a bounded interval and is not an atomic kernel snapshot. A
process or socket can appear, disappear, or change while tables, descriptors,
owners, and metadata are read.

## Linux

The Linux collector reads socket tables from the procfs mounted at `/proc` and
associates their inode values with links under `/proc/<pid>/fd`. Process identity
comes from `/proc/<pid>/stat`. The current network namespace identifier is read
from `/proc/self/ns/net` when available.

Only the current network namespace is observed. Kickoutchi never enters another
network namespace implicitly. Running it in the host namespace, a container
namespace, or another explicitly selected namespace therefore produces different
socket sets by design.

Procfs and PID namespaces impose a separate ownership boundary. Kickoutchi can
enumerate only PIDs visible through its procfs mount and PID namespace. It treats
ownership visibility as initial-PID-namespace complete only when the bounded
`/proc/self/ns/pid` link matches Linux's reserved initial PID namespace identity,
`pid:[4026531836]`. A nested, missing, unreadable, or unrecognized namespace
identity makes global ownership and retained socket owner sets partial. An
ancestor-namespace process may share an otherwise visible socket inode.
`NSpid` alone cannot prove initial namespace visibility because its entries are
relative to the procfs mount; a container with its own procfs can have one entry.

A restricted, incomplete, or nonstandard procfs mount can hide socket tables,
PIDs, descriptor links, identities, or metadata. Permission denial while reading
a required socket table fails collection; denial or disappearance during owner
and metadata reads is retained as an explicit gap where possible.
`kill --port` refuses when an ownership gap has no endpoint provenance because
an unobserved process could share the selected socket. The CLI applies this
check to its first snapshot, so the refusal comes before the confirmation
prompt and names the `kill --pid` command for the verified owner.

Linux socket rows also report the UID that created each socket. Human output
uses it to explain an owner-less row, for example "the socket belongs to root
(uid 0)". It is a hint, not ownership evidence, because descriptors can be
inherited or passed between users, and it is not part of any JSON contract.

The legacy list/TUI `permission` field compresses these Unix outcomes for 1.x
compatibility. `partial` covers permission denial, process disappearance, races,
unsupported metadata, and bounded omission; it must not be interpreted as an
`EACCES`/`EPERM` diagnosis. Snapshot evidence gaps preserve the specific cause.

Linux `/proc/net/*6` rows do not expose an IPv6 scope identifier in the selected
format. Every observed IPv6 endpoint therefore has unavailable scope. Such a row
cannot support exact scoped-IPv6 matching or an exact-address proven observation,
although wildcard selectors can still match without scope equality. Human output
renders the missing identity as `%unavailable` rather than collapsing it into an
apparently unscoped address.

Root may make more procfs process descriptors and metadata readable, but it does
not widen the current network namespace, escape the PID namespace, repair an
incomplete procfs mount, or make IPv6 scope IDs appear. Elevation can reduce
permission gaps; it cannot turn out-of-scope data into in-scope data. Optional
PATH-resolved Docker enrichment is disabled while elevated or when privilege
status cannot be established safely.

## macOS

macOS collection is process-first. Kickoutchi enumerates PIDs with
`proc_listallpids`, enumerates each visible process's descriptors with
`proc_pidinfo(PROC_PIDLISTFDS)`, and reads socket details with
`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`. This is not a global PCB snapshot.

The declared scope contains sockets reachable through successfully enumerated
user-process file descriptors. Sockets with no visible user-process descriptor
are permanently outside that scope. A denied, truncated, malformed, or vanished
process or descriptor enumeration can hide entire socket rows and is therefore a
socket-set gap, not merely missing process metadata. Permissions may improve
visibility, but no privilege level changes this process-first source into a
global socket-table source.

The selected libproc socket data does not provide a supported IPv6 scope
identifier. macOS IPv6 observations therefore carry unavailable scope and cannot
support exact scoped-IPv6 observation claims.

macOS has no `pidfd` equivalent. Process identity uses the native process start
time, and destructive actions re-read and compare identity immediately before
signalling, but the process cannot be pinned to that identity across the final
instructions. This residual PID-reuse race is a platform limitation and is not
reported as Linux-style `pidfd` safety.

## Unix scoped termination limits

Unix tree and process-group termination uses a bounded freeze-and-verify
sequence, not an atomic kernel transaction. Kickoutchi observes whether each
member was stopped before its own `SIGSTOP` and normally sends cleanup `SIGCONT`
only for transitions it observed. Another actor can concurrently send
`SIGSTOP` or `SIGCONT` between those observations and signals, so ownership of a
stopped state cannot be attributed perfectly. After a successfully delivered
`SIGTERM`, Kickoutchi guardedly continues even a previously stopped target so
the pending termination can execute; refusal and failed-delivery cleanup leave
a target observed as previously stopped untouched.

Process-group membership can also change through concurrent joins, exits, and
external signals. Kickoutchi freezes enumerated members, repeats bounded
snapshots toward a fixed point, rechecks identity and group membership, and
queues every terminating signal before continuing members. This provides
best-effort convergence over the observed group, with fixed member, pass, and
operation-wide stop-acknowledgement bounds; it is not an absolute claim that a
concurrently mutating process group was terminated atomically.

## Windows

The Windows collector obtains IPv4 and IPv6 TCP rows from
`GetExtendedTcpTable` and UDP rows from `GetExtendedUdpTable`. These IP Helper
owner tables are authoritative for the observed native Windows socket rows.
Process creation time verifies PID identity; Toolhelp and bounded process APIs
provide optional process relationships and metadata.

The declared scope is the current native Windows host network stack. WSL uses a
separate Linux network stack and is excluded. Run the Linux build inside WSL to
observe WSL sockets and Linux process owners. A Windows-side result must not be
interpreted as evidence that a port is absent inside WSL.

IP Helper rows remain valid socket evidence when process handles, identity, or
metadata cannot be read. An owner PID that cannot be verified is retained as an
unverified owner; PID zero is never treated as a process owner. Toolhelp failure
during owner enrichment falls back to bounded direct reads of the socket-owner
PIDs and leaves metadata partial.

Elevation can grant access to additional process identities, metadata, or
termination handles, but it does not expand the IP Helper scope into WSL and does
not prove that an unexplained bind denial is a Hyper-V reservation or another
specific policy. Kickoutchi does not elevate itself.

Windows IP Helper exposes an IPv6 local scope ID. Kickoutchi converts it from
network byte order. IPv4-mapped IPv6 rows normalize to IPv4 and no longer carry
an IPv6 scope.

## Permissions and collection gaps

Across platforms, the ability to see a socket and the ability to identify its
owner are separate. Sandboxes, procfs mount options, privacy controls, protected
processes, access-control policy, and process exit can produce any of these
outcomes:

- A socket row is visible with a verified owner.
- A socket row is visible with an unverified PID or incomplete owner set.
- A process-first collection loses possible socket rows and reports a socket-set
  gap.
- Optional process metadata is unavailable while socket and owner facts remain
  usable.
- A required native source cannot be read and the collection fails.

Do not treat an empty partial owner set as proof that no owner exists. Do not
treat missing name, path, command line, parent, or child information as proof
that the process lacks that property. Running with more privilege may reduce
some gaps, but it is not required automatically and is not a cure for scope,
native-field, or timing limitations.

## Watch and polling

`kick watch` compares bounded native snapshots. Baseline, bind, and release
events can be proven within the reported scope when both snapshots are safe for
socket-set comparison, but their time is only an estimated interval between
captures. Polling cannot observe a socket that both opens and closes between
polls, and multiple changes between polls can collapse into only their net
snapshot difference. Owner-only changes are generally silent unless the narrow
verified replacement rule applies.

A failed poll emits a `collection_gap`; it never fabricates release events.
Recovery compares the next usable snapshot with the last valid snapshot. A
raced snapshot or socket-set gap is not safe for ordinary bind/release diffing.
Therefore absence of an event does not prove that no transient socket activity
occurred.

Watch never invokes Docker or another external network tool in its polling loop.
Its events use native socket and process observations plus configured labels, so
short polling intervals cannot become external-process spawn loops.

## Docker evidence

Docker is not an authoritative collector. Core socket facts always come from the
native operating-system source. Existing optional Docker details enrichment is
local-only: it is pinned to a local Unix socket or Windows named pipe, rejects a
remote Docker host or context, is bounded, and never upgrades the certainty of a
core verdict. Docker output can be stale, incomplete, unavailable, or describe a
publication that does not establish the current native socket owner.

Docker enrichment is disabled by default, which guarantees that Kickoutchi does
not resolve or execute the Docker CLI. Set `docker_enrichment = true` to opt in.
Enrichment is limited to qualifying TUI process-context requests; native
collection, CLI listing, watch, and Why do not depend on it.

`kick why` does not request Docker enrichment. It uses one native snapshot and
exact bind probes, so its output must not be read as a container inventory. This
keeps the diagnostic independent of an optional CLI and daemon, avoids PATH and
privilege-boundary risks, and prevents non-authoritative container metadata from
affecting the verdict. The absence of Docker evidence means only that Docker was
not consulted.

## Bind probes

Each `kick why` probe creates one socket, applies the requested reuse and IPv6
mode options, attempts one exact bind, records the result, and closes the socket
before returning. Multiple requested endpoints are probed sequentially. No probe
socket remains reserved for the caller.

A successful probe temporarily occupies the endpoint between its successful
bind and close. This interval is deliberately short but is observable and can
briefly deny a concurrent binder. Conversely, after the probe closes, another
process may bind before Kickoutchi renders the result or before the caller acts.
For sequential probes, the result for an earlier endpoint may already be stale
while a later endpoint is being tested.

`bindable_now` is therefore proven only at that probe's completion boundary. It
does not reserve the endpoint or promise future availability. `address_in_use`
proves that the exact bind attempt failed for that reason at that time; ownership
or policy explanations still depend on the earlier native snapshot and its
gaps. A successful probe can legitimately conflict with an earlier observed
socket because the socket closed between collection and probe or because native
binding semantics allowed coexistence.

## Interpreting certainty safely

- `proven` applies only to the specific stated claim and its observation time and
  scope. It does not make adjacent ownership, identity, timing, or future-state
  claims proven.
- `estimated` is derived from a polling interval or timer conversion. A Linux TCP
  timer estimate is not a release time and does not promise future bindability.
- `heuristic` is a plausible interpretation that authoritative facts do not
  establish.
- `unknown` is the correct result when permissions, scope, races, unsupported
  native fields, or conflicting evidence prevent a reliable conclusion.

The safest reading is conjunctive: use the verdict together with certainty,
scope, completeness, owner completeness, evidence gaps, and capture/probe times.
Never promote a complete in-scope snapshot to a machine-wide claim, a verified
socket to verified ownership, an estimated interval to an exact event time, or a
successful bind probe to a reservation.

## Related documentation

- [Documentation index](README.md)
- [Security policy](../SECURITY.md)
- [Configuration and filters](configuration.md)
- [Structured output](structured-output.md)
