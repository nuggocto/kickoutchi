# Platform support and observation limits

Kickoutchi reads sockets from each operating system's native sources. Each
source sees only part of the machine, and Kickoutchi never claims more than its
source can see. Read every result together with its scope, completeness,
evidence gaps, and certainty.

## Supported targets

| Platform | Release targets | Socket source | Scope | Main exclusion |
| --- | --- | --- | --- | --- |
| Linux | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | `/proc/net/tcp*`, `/proc/net/udp*`, and `/proc/<pid>/fd` | Current network namespace | Other network namespaces |
| macOS | `x86_64-apple-darwin`, `aarch64-apple-darwin` | Process and descriptor enumeration through libproc | Sockets held by visible processes | Sockets no visible user process holds |
| Windows | `x86_64-pc-windows-msvc` | IP Helper extended TCP and UDP owner tables | Native Windows network stack | The WSL network stack |

Listing works on Linux kernels older than 5.3, but stopping a process needs 5.3
or newer, because Kickoutchi uses `pidfd`. Windows ARM64 and other Rust targets
aren't supported releases until they join the native test and artifact matrix.

All three collectors keep every IPv4 and IPv6 TCP row and state their source
reports, including unknown native TCP state codes. UDP rows are reported as
`bound`; UDP has no TCP-style lifecycle.

## What "complete" means

`complete` means complete within the snapshot's scope and the collector's
documented source. It doesn't mean every socket on the machine, in every
container, virtual machine, network namespace, or subsystem. Excluded places
stay excluded even when a snapshot is complete.

Completeness has separate parts:

- Snapshot completeness says whether the sockets in scope were read without a
  known partial read or race.
- Owner completeness says whether Kickoutchi could match every visible socket
  to its processes. A socket can be certain while its owner is unknown.
- Process metadata completeness covers names, paths, parents, and similar
  optional details. Missing metadata never removes a socket row.
- Evidence gaps record known losses, tagged by what they affect (socket set,
  ownership, metadata, or scope). Gap records are capped. A non-zero
  `omitted_evidence_gap_count` means more gaps existed than were kept, and is
  itself a reason for doubt.

When a scan loses data for many PIDs at once, its gap carries a positive
`affected_pid_count` and a null `pid`. A gap about one PID carries that `pid`
and a null count. If the same aggregate loss shows up in several passes,
Kickoutchi keeps the largest count rather than adding them up, because the PID
sets may overlap. `omitted_evidence_gap_count` counts gap records that weren't
kept, not PIDs.

`partial` keeps the facts that were read but blocks stronger claims the gaps
would undermine. `raced` means something changed during collection in a way
that makes the comparison unsafe. A failed collection is an error, never an
empty `complete` snapshot.

Collection takes a short, bounded amount of time and isn't an atomic kernel
snapshot. Processes and sockets can appear, disappear, or change while
Kickoutchi reads tables, descriptors, owners, and metadata.

## Linux

The Linux collector reads the socket tables in the procfs mounted at `/proc`
and matches their inode numbers to links under `/proc/<pid>/fd`. Process
identity comes from `/proc/<pid>/stat`, and the network namespace identifier
from `/proc/self/ns/net` when it's readable.

Kickoutchi sees only the network namespace it runs in and never enters another.
Run it on the host, in a container, or in another namespace, and you get a
different socket set each time. That's by design.

Procfs and the PID namespace limit which owners Kickoutchi can see. It can only
enumerate PIDs visible through its procfs mount and PID namespace. It treats
ownership as complete only when the `/proc/self/ns/pid` link matches Linux's
fixed initial PID namespace, `pid:[4026531836]`. A nested, missing, unreadable,
or unrecognized namespace makes ownership partial, because a process in an
ancestor namespace could share a visible socket. `NSpid` alone can't prove
this: its entries are relative to the procfs mount, so a container with its own
procfs also shows a single entry.

A restricted, incomplete, or unusual procfs mount can hide socket tables, PIDs,
descriptor links, identities, or metadata. If Kickoutchi can't read a required
socket table, collection fails. Permission errors or vanished processes during
owner and metadata reads become explicit gaps where possible.

An ownership gap that isn't tied to a particular endpoint means some unseen
process could share any socket. `kill --port` then can't prove a port has a
single owner. When the port has exactly one owner Kickoutchi can verify, the
CLI prints a note and targets that owner. Before sending anything it checks the
port again: unrelated permission gaps elsewhere are tolerated, but a second
visible owner, or a gap specific to that port, makes it refuse. When the owner
itself can't be read, the CLI refuses before the prompt and says why.

Linux socket rows also record the UID that created each socket. Human output
uses it to explain a row without an owner, for example "the socket belongs to
root (uid 0)". It's a hint, not proof of ownership, because descriptors can be
inherited or passed between users. It isn't part of any JSON contract.

The legacy list/TUI `permission` field squeezes all of this into two values for
1.x compatibility. `partial` covers permission errors, vanished processes,
races, unsupported metadata, and capped data alike; don't read it as an
`EACCES` or `EPERM` diagnosis. Snapshot evidence gaps keep the real cause.

Linux `/proc/net/*6` rows don't include an IPv6 scope ID, so every Linux IPv6
endpoint has an unavailable scope. Such a row can't match an exact scoped IPv6
selector or prove an exact-address observation, although wildcard selectors
still match it. Human output shows these addresses without a `%` suffix, and
JSON records the scope as `unavailable`.

Running as root can make more process descriptors and metadata readable. It
doesn't widen the network namespace, escape the PID namespace, fix an
incomplete procfs mount, or produce IPv6 scope IDs. Root can close permission
gaps; it can't bring out-of-scope data into scope.

## macOS

The macOS collector starts from processes. It lists PIDs with
`proc_listallpids`, lists each visible process's descriptors with
`proc_pidinfo(PROC_PIDLISTFDS)`, and reads socket details with
`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`. It never reads a global socket table.

Its scope is the sockets reachable through file descriptors of user processes
it could list. A socket with no visible descriptor is always out of scope. If
listing a process or its descriptors is denied, truncated, malformed, or
interrupted by the process exiting, whole socket rows can go missing, so
Kickoutchi records a socket-set gap, not just missing metadata. More privilege
can help it see more processes, but it never turns this into a global socket
table.

The libproc socket data Kickoutchi uses has no supported IPv6 scope ID, so
macOS IPv6 observations carry an unavailable scope and can't back exact scoped
IPv6 claims.

macOS has no `pidfd`. Kickoutchi identifies a process by its start time and
re-checks that identity just before signalling, but nothing pins the process
across those final instructions. That leftover PID-reuse race is a platform
limit, and Kickoutchi doesn't describe it as Linux-style `pidfd` safety.

## Unix tree and group kills

Tree and group kills on Unix freeze, verify, and then signal in bounded steps;
they aren't one atomic kernel operation. Kickoutchi notes whether each member
was already stopped before its own `SIGSTOP`, and normally sends the cleanup
`SIGCONT` only to members it stopped itself. Another program can send `SIGSTOP`
or `SIGCONT` between those observations and signals, so who stopped a process
can't always be known for sure. After a `SIGTERM` is delivered, Kickoutchi
resumes even a target that was already stopped, so the termination can take
effect. When it refuses, or delivery fails, it leaves a target it saw as
already stopped alone.

Group membership can also change while Kickoutchi works, through processes
joining, exiting, or receiving signals from elsewhere. Kickoutchi freezes the
members it finds, repeats bounded snapshots until membership stops changing,
re-checks identity and membership, and queues every termination signal before
resuming members. Member counts, passes, and the total wait for stop
confirmations all have fixed limits. The result is a best effort over the group
it observed, not a guarantee that a group changing underneath it was stopped
atomically.

## Windows

The Windows collector reads IPv4 and IPv6 TCP rows from `GetExtendedTcpTable`
and UDP rows from `GetExtendedUdpTable`. These IP Helper owner tables are the
authority for the native Windows sockets they list. Process creation time
verifies each PID's identity; Toolhelp and bounded process APIs add optional
relationships and metadata.

The scope is the native Windows network stack. WSL runs its own Linux network
stack and is excluded. Run the Linux build inside WSL to see WSL sockets and
their Linux owners. A Windows result says nothing about whether a port is free
inside WSL.

IP Helper rows stay valid even when Kickoutchi can't open a process handle or
read identity or metadata. An owner PID it can't verify is kept as an
unverified owner, and PID 0 is never treated as an owner. If Toolhelp fails
while Kickoutchi adds owner details, it falls back to bounded direct reads of
the owner PIDs and marks metadata partial.

Running elevated can unlock more process identities, metadata, and termination
handles. It doesn't extend IP Helper into WSL, and it can't prove that an
unexplained bind refusal is a Hyper-V reservation or any other specific policy.
Kickoutchi never elevates itself.

Windows IP Helper does report an IPv6 local scope ID, which Kickoutchi converts
from network byte order. IPv4-mapped IPv6 rows become plain IPv4 and lose their
IPv6 scope.

## Permissions and collection gaps

On every platform, seeing a socket and identifying its owner are separate
abilities. Sandboxes, procfs mount options, privacy controls, protected
processes, access policy, and processes exiting can each lead to one of these:

- A visible socket with a verified owner.
- A visible socket with an unverified PID or an incomplete owner set.
- A process-first scan that loses possible sockets and reports a socket-set
  gap.
- Missing process metadata while the socket and owner facts stay usable.
- A required source that can't be read, so collection fails.

An empty partial owner set doesn't prove a socket has no owner. A missing name,
path, command line, parent, or child doesn't prove the process lacks one. More
privilege can close some gaps, but Kickoutchi never asks for it, and it can't
fix scope, missing native fields, or timing.

## Watch and polling

`kick watch` compares snapshots taken at intervals. Baseline, bind, and release
events are certain within the reported scope when both snapshots are safe to
compare, but their time is only the window between two captures. A socket that
opens and closes between polls is never seen, and several changes between
polls show up only as their net difference. A change of owner alone usually
produces no event, unless the narrow verified-replacement rule applies.

A failed poll prints a `collection_gap` and never invents release events. On
recovery, watch compares the next usable snapshot with the last good one. A
raced snapshot, or one with a socket-set gap, isn't safe for normal bind and
release comparison. So a missing event doesn't prove nothing happened.

Watch never runs an external program while polling. It uses native socket and
process data plus your configured labels, so a short interval can't turn into a
loop of process spawns.

## Bind probes

Each `kick why` probe creates one socket, applies the requested reuse and IPv6
options, tries one exact bind, records the result, and closes the socket before
moving on. Endpoints are probed one at a time. No probe socket stays open for
you.

A successful probe holds the endpoint between its bind and its close. That
moment is short but real, and another program binding at the same time can be
refused. After the probe closes, another process can bind before Kickoutchi
prints the result or before you act on it. With several endpoints, an earlier
result may already be out of date while a later one is being tested.

So `bindable_now` is proven only for the instant that probe finished. It doesn't
reserve the endpoint or promise anything later. `address_in_use` proves the
exact bind failed for that reason at that time; who owns the port, or which
policy blocked it, still comes from the earlier snapshot and its gaps. A
successful probe can contradict an earlier snapshot without either being wrong:
the socket may have closed in between, or the OS's bind rules may let both
coexist.

## Reading certainty

- `proven` covers only the specific claim, at its observation time and within
  its scope. It doesn't make nearby claims about ownership, identity, timing, or
  the future proven too.
- `estimated` comes from a polling interval or a timer conversion. A Linux TCP
  timer estimate isn't a release time and doesn't promise a later bind will
  work.
- `heuristic` is a plausible reading that the authoritative facts don't
  establish.
- `unknown` is the right answer when permissions, scope, races, unsupported
  native fields, or conflicting evidence rule out a reliable conclusion.

Read a verdict together with its certainty, scope, completeness, owner
completeness, evidence gaps, and capture and probe times. Never stretch a
complete in-scope snapshot into a machine-wide claim, a verified socket into
verified ownership, an estimated interval into an exact time, or a successful
probe into a reservation.

## Related documentation

- [Documentation index](README.md)
- [Security policy](../SECURITY.md)
- [Configuration and filters](configuration.md)
- [Structured output](structured-output.md)
