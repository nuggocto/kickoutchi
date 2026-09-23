# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `kick kill` no longer blames `--yes` when a target becomes protected after
  interactive confirmation. That refusal now says the process became protected
  and asks for a rerun; the `--yes` wording remains for `--yes` refusals.

## [1.4.5] - 2026-09-15

### Fixed

- macOS list and TUI rows, and watch filters, now recognize protected processes
  by executable basename as well as process name. This matches final kill
  validation, including when a process name is unavailable.
- TUI workers whose result receiver has closed now report panic diagnostics
  after the terminal session ends.

### Changed

- Confirmation modals own their confirmation data. Background workers retain
  their separate cancellation and completion lifecycle.
- Unix tree-stop operations pass deadlines and stop/cleanup results directly,
  removing the thread-local handoff between process adapters and tree execution.
- Simplified watch emission state, process-operation interfaces, and TUI flags.
  Removed redundant platform guards, historical comments, and assertions tied to
  implementation spelling. Added regressions for protection matching and
  abandoned worker diagnostics.

## [1.4.4] - 2026-09-12

### Fixed

- Unix process, tree, and group kills defer Ctrl-C, SIGTERM, and SIGHUP while
  targets are frozen. Interruption before delivery aborts the kill and resumes
  only processes Kickoutchi stopped. Once delivery starts, the bounded delivery
  and cleanup sequence finishes before the pending signal takes effect.
- Release artifact and installer checks now share the CLI tests' bounded
  subprocess runner. Each output stream is limited to 8 MiB; binary checks have
  a 10-second deadline and local installer checks have a two-minute deadline.
  The nested archive CLI suite has a 15-minute deadline. Timed-out child
  processes are killed and reaped.

### Changed

- Added real-binary interruption regressions for single-process, tree, and group
  kills, including interruption after SIGTERM is queued and preservation of an
  already-stopped child. Native Unix tests also verify signal-handler and mask
  restoration. Validator regressions cover oversized stdout/stderr and timeout
  diagnostics.

## [1.4.3] - 2026-09-05

### Changed

- The TUI redraws when input, worker results, resizing, or the displayed refresh
  age changes. Cached command and executable-path text avoids repeated
  sanitization. In local Linux tests with a 960 KB command line, idle CPU fell
  from about 19% of one core to 2–2.3% across three paired runs.
- Buffered list output reduces small stdout writes while preserving JSON,
  exit-code, flush-error, and broken-pipe behavior. With 5,000 additional TCP
  listeners, 30 paired local Linux runs measured median legacy JSON time falling
  from 44.8 to 37.1 ms and snapshot JSON time from 61.3 to 39.4 ms. Single-port
  queries measured about 3–4% slower in the larger fixtures; the stripped binary
  grew by 1.3%.
- CLI queries and rendering share the indexed borrowed projection used by the
  TUI, removing an intermediate row allocation and duplicate sorting code.
- Refresh tests now use the production worker channel and post-kill scheduling
  path. Added coverage for stale refresh completion, redraw and text-cache
  invalidation, worker startup failure, native metadata profiles, and bulk
  output failures.
- Removed unreachable platform fallbacks and tests tied only to fixture
  contents, help prose, or incidental workflow labels and tool versions.
  Workflow security and publication-order checks remain in place.

## [1.4.2] - 2026-09-05

### Fixed

- Linux now checks the kernel's initial PID namespace identity before claiming
  complete socket ownership. Nested PID namespaces with their own procfs retain
  partial ownership evidence, including sockets shared with invisible ancestor
  processes.
- Linux termination now handles process names truncated by the kernel midway
  through a Unicode character. Final validation uses the same bounded lossy
  decoding as collection and protection matching, while retaining process
  identity checks and name-size limits.
- Corrected the security policy to match the release workflow's existing
  pre-publication checks, updater smoke tests, Homebrew publication, and final
  manifest attestation coverage.
- Linux socket-helper cleanup tests now share the host observation lock, so
  their socket changes cannot race concurrent port-kill tests. Host port-kill
  tests also verify safe race refusals when namespace capabilities are required;
  those capabilities cannot prevent unrelated host sockets from changing.
  Linux CI now isolates test network traffic while retaining the runner's user
  and PID namespace for permission and ownership checks.
- Linux release archives are now executed on native runners before attestation
  and publication. Builds retain the Debian glibc compatibility floor, while
  termination tests no longer assume complete PID visibility inside a build
  container.

## [1.4.1] - 2026-08-13

### Changed

- Release artifacts and primary CI now use Rust 1.97.1, while Rust 1.95.0
  remains the minimum supported version and has a dedicated compatibility lane.
- Linux port-kill integration journeys now recognize a genuine pre-delivery
  observation race as a safe refusal on hosts without required capabilities.
  The capability-required CI gate still requires successful delivery.
- Clarified process identity and termination safety comments. Runtime behavior
  is unchanged.

## [1.4.0] - 2026-08-12

### Added

- Added global `--verbose`/`-v` diagnostics. Debug details are written only to
  stderr, leaving human, JSON, and NDJSON stdout contracts unchanged.
- Added a `docker_enrichment` configuration switch. Enabling it permits bounded,
  local-only Docker details in qualifying TUI views; disabling it guarantees
  that optional TUI process-context collection never resolves or executes the
  Docker CLI.

### Changed

- Reduced TUI rebuild work by caching the current snapshot's compact sorted
  source-index permutation across search edits and recording selection matches
  in a one-bit-per-row mask. Query matching now checks cheap exact predicates
  before metadata, specializes the common single-needle cache, skips impossible
  plain-text field formats, and avoids allocated scoped-endpoint strings and
  empty label-map lookups. Multi-needle results remain bounded and isolated;
  duplicate-row order, labels, Unicode matching, and selection behavior remain
  unchanged.
- Bundled each native socket with its owner PIDs and local completeness before
  canonicalization, making detached parallel-vector state unrepresentable and
  removing the indexed permutation and its temporary allocations.
- Replaced the immutable per-pass process-read `BTreeMap` with a validated,
  sorted contiguous table. Native adapters now return the exact requested PID
  batch, which is checked before binary-search lookup and deterministic
  metadata materialization.
- Pruned duplicated CLI and TUI orchestration tests for refusal paths already
  covered exhaustively by the collector, process-evidence, and process-tree
  layers. Representative interface mappings, delivery gates, and successful
  native journeys remain covered.
- Removed the dated v1.3.8 same-machine performance report and its duplicated
  README summary; the historical results remain available in Git history and
  the v1.3.9 changelog.
- Split the oversized observation, process, watch, scoped-kill, TUI app, and
  process-tree modules along existing responsibility boundaries. Limits, legacy
  projection, OS-specific termination, watch filtering and signal ownership,
  scoped outcome reporting, TUI helpers, tree actions, tree planning,
  freeze-first execution, and module-local tests now live in focused child
  modules without changing public behavior.
- Moved the remaining oversized inline test modules for the native platform
  adapters, Windows tree execution, Docker enrichment, collection, CLI kill and
  Why, UI rendering, diagnostics, and public output into child test files.
- Nested the Windows Job Object tree executor and its tests under the shared
  process-tree capability instead of exposing a separate crate-root module.
- Classified the library target as internal binary bootstrap plumbing and hid it
  from generated API documentation instead of presenting `run()` as a supported
  embedding contract with process-global arguments, I/O, and signal lifecycle.
- Kept termination warnings typed through their presentation boundary, removing
  prose suffix recognition and scope-specific rewrite helpers. Pruned the
  obsolete implementation-coupling test and two low-value private/trivial tests
  while preserving destructive-path and real-binary coverage.
- Simplified release maintenance by removing the duplicate quality matrix,
  pull-request packaging runs, post-publication revalidation, and the separate
  release-policy layer. Native archives and installers remain validated before
  attested Linux, macOS, Windows, and Homebrew publication.
- Reduced the release artifact validator from 2,252 to about 1,200 lines by
  relying on the archive libraries for XZ/ZIP framing, deleting elaborate
  corruption fixtures and the unreachable post-publication updater journey,
  and removing its unused test-only XZ encoder. Checksums, safe member paths,
  exact package layouts, executable/version journeys, the Linux glibc floor,
  updater smoke tests, and generated installer receipts remain enforced.
- Removed two repeated CI operations: Linux's full test suite is now the sole
  ordinary validator-test run, and the x86_64 Nix lane evaluates every declared
  system once while both x86_64 and aarch64 lanes still build and execute their
  native packages. Workflow contract helpers were shortened while retaining
  action pins, checkout isolation, least permissions, target coverage, and
  release publication ordering.
- Kept cargo-dist installed from its exact pinned source version in release
  jobs instead of switching to faster prebuilt binaries, preserving the
  existing supply-chain trust model for infrequent releases.
- Split the CLI contract suite by command and moved shared subprocess,
  socket/process, and workflow-parser fixtures under `tests/support/`. Contract
  names and safety behavior remain intact while individual files now have clear
  ownership.
- Added a documented, bounded mutation campaign for typed warnings and
  confirmation matching. Mutation evidence justified removing a redundant
  private decision table and exposed two warning branches plus a tree metadata
  wait diagnostic that now have focused behavioral coverage.
- Moved package-manager installation ahead of direct remote-installer commands
  in the README.
- Changed optional Docker enrichment from default-on to explicit opt-in.

### Fixed

- Updated the Ratatui dependency graph to require the panic-safe `lru` 0.18.2,
  removing the safe-Rust use-after-free reported as RUSTSEC-2026-0253.
- Kept local mutation campaigns from dirtying the checkout by ignoring
  cargo-mutants' root-level `mutants.out/` workspace.
- Moved scheduled and documented fuzz campaigns onto disposable working
  corpora. Checked-in seeds remain read-only, and only intentionally minimized
  regression fixtures are copied back.
- Strengthened the Windows private Job Object freeze preflight: a disposable
  helper now checks execution before freeze, suspension while frozen, and
  resumption after thaw before any selected target crosses the assignment
  boundary.
- Corrected the direct-PID documentation: an unscoped PID must own a visible
  open port, while tree and group targeting may resolve a live portless root.

### Removed

- Retired the source-built `kickoutchi` AUR package and its in-repository
  packaging. Arch users now have one supported AUR path, `kickoutchi-bin`,
  backed by the checksummed Linux release archives.

## [1.3.10] - 2026-08-02

### Changed

- Simplified internal maintenance code without changing public behavior:
  documented four module boundaries, reduced configuration-reader
  preallocation, replaced three infallible sequence serializers with their
  direct iterator form, and aligned local dependency-policy checks with CI's
  main and fuzz workspace coverage.
- Centralized narrowly shared test fixtures so synthetic TCP and UDP rows carry
  matching listen/bound states and permission-denied ownership scenarios have
  one source of truth.
- Made watch polling timing easier to audit by centralizing wall-clock
  projection, monotonic deadline arithmetic, and cancellation/deadline
  decisions without changing scheduling or output behavior.

### Fixed

- Linux `kill --port` now refuses to signal a visible owner when incomplete
  process or descriptor visibility leaves an ownership gap without endpoint
  provenance, since an unobserved process could share the selected socket.
- Release publication now attests cargo-dist's host-generated
  `dist-manifest.json` before the public installer journey or package-manager
  publication. This closes the provenance-gate mismatch found while publishing
  1.3.9, where the verifier correctly checked the manifest but the
  pre-publication attestation job could not yet include it.

## [1.3.9] - 2026-07-30

### Added

- Release assets now receive GitHub artifact attestations in a dedicated
  least-privileged job after native archive and installer validation. Release
  publication requires successful attestation, and the post-publication journey
  verifies every downloaded asset before executing the installer.
### Changed

- CI now starts supply-chain, Linux, Windows, macOS, and both Nix lanes
  concurrently, runs formatting and doctests once on Linux, and reports one
  fail-closed `CI Complete` result after every lane finishes. Push CI is limited
  to the default `shrek` branch while pull-request and scheduled coverage remain
  enabled; the existing cancellation policy and cache-free builds are unchanged.
- Recorded a dated, same-machine Linux performance snapshot for cold/warm
  startup, `list`, `list --json`, CPU, peak RSS, binary/package size, and exit
  correctness. Three fixed-seed interleaved sessions provide 3,000 observations
  per build and workload, including a higher-confidence p99; the v1.3.8
  comparison found no meaningful regression, and noisy latency measurements
  remain outside required pull-request CI.
- Distribution builds now strip symbol tables while retaining Rust's unwind
  strategy and cleanup behavior, reducing shipped and installed binary size
  without changing runtime code paths.
- Added three pure, bounded parser campaigns for configuration, synthetic Linux
  process data, and release-archive member paths. Small saved corpora replay in
  ordinary tests, while exact-toolchain 60-second campaigns run only weekly or
  on manual request; the auxiliary dependency lock receives the same advisory,
  license, ban, and source checks as the main crate.
- Windows tree preparation, containment, and post-commit reporting now share the
  same refusal vocabulary and semantic exit classification used by Unix tree
  handling. CLI and TUI renderers share stable tree-refusal causes and direct
  termination descriptions while retaining their interface-specific recovery
  details.
- Docker output-drain and child-cleanup workers now use one bounded capacity
  primitive with atomic multi-slot reservations and independently owned permits.
  Scoped tree/group confirmation shares only its identical prompt execution;
  the safety-critical revalidation, freeze/commit, and termination ordering
  remains explicit.
- Host-sensitive CLI tests no longer reserve and release an ephemeral port
  before launching a competing process. Linux no-match diagnostics run in an
  isolated user/network namespace, and workflow security tests assert native
  platform coverage and unprivileged metadata generation without pinning
  incidental runner labels or setup commands.
- Documented that direct PID termination intentionally permits an ordinary
  parent process, including the invoking shell, while PID 0, PID 1, Windows
  System PID 4, Kickoutchi itself, and scoped kills containing Kickoutchi remain
  refused.

### Removed

- Removed the temporary local benchmark harness and its harness-only tests after
  recording the reproducible performance snapshot. The bounded parser fuzzing
  campaigns and saved regression corpora remain part of normal and scheduled
  verification.

## [1.3.8] - 2026-07-29

### Changed

- Consolidated small internal policies without changing public behavior:
  optional process-context limits now live in one platform-neutral location,
  snapshot and watch sorting use one owner-completeness comparator, and Unix
  signal and tree-stop deadline mappings each have one implementation.
- Integration-test configuration directories now use exclusive creation with a
  process-local monotonic counter, preventing parallel tests from sharing and
  deleting one another's live directories. The Windows PID-existence probe also
  reports wait failures instead of treating them as a live process, and bounded
  synthetic tree fixtures avoid colliding with the running test process.
- Simplified bounded platform adapters and watch output handling while retaining
  their existing fail-closed limits, error classifications, and public output.

### Removed

- Removed a byte-for-byte duplicate ownership-authority test and stale internal
  branches, annotations, derives, and assignments that carried no behavior.

### Fixed

- A Windows port-selected `--tree` kill whose root exits during final preparation
  now reports `already exited` with the no-match exit status instead of
  misreporting a changed process identity as a failure.
- Linux protected-process matching now reproduces the kernel's raw 15-byte
  `/proc/<pid>/comm` truncation when it splits a UTF-8 code point, so configured
  non-ASCII protected names cannot silently lose protection after lossy decoding.
- The TUI details panel now renders one protected-process warning in its reserved
  row and retains the selected process's permission status at the minimum
  supported terminal size.

## [1.3.7] - 2026-07-28

### Added

- Added a copy-ready root `config.example.toml`, covered by the real config
  parser tests so its settings and endpoint-label examples cannot drift from the
  accepted schema.
- Release validation now executes every native updater, runs generated shell and
  PowerShell installers with isolated install, config, and temporary roots on
  Linux, macOS, and Windows before
  publication, and repeats the Linux install/update journey through the final
  public GitHub Release URLs. Arch metadata is also compared exactly with native
  `makepkg --printsrcinfo` output in a digest-pinned container. Linux updater
  artifacts are rebuilt from the locked `axoupdater-cli 0.10.0` source inside the
  Debian 11 release containers so they retain the documented glibc 2.31 floor.

### Changed

- Simplified internal maintenance code without changing public behavior: workflow
  security contracts now traverse parsed YAML instead of a handwritten
  indentation reader, public-output errors share one typed implementation, and
  unnecessary crate-wide visibility, serialization implementations, and stale
  license allowances were removed.
- Consolidated duplicated internal logic so each policy is encoded exactly once,
  without changing public behavior: the TUI tree-confirmation height budget now
  measures the rendered prompt lines it guards instead of a second copy of the
  prose, the Unix tree-freeze revalidation shares one gate helper with the
  Windows and group paths, exact bind-probe requests build on the shared
  endpoint-identity validator, inspect reports compute each
  ancestor/sibling/group selection once, snapshot and watch output share one
  owner-completeness ordering, and the Linux PID scans and platform
  command-line readers each collapse to a single bounded implementation.
- Release workflow contract tests now assert structural security properties —
  every release job carries a bounded timeout and Linux runner images are
  full-digest-pinned and identical across architectures — instead of
  hardcoding a second copy of the exact minutes and digest values.
- Human endpoint output now uses one formatter that retains IPv6 interface scope
  in list tables, TUI rows and details, inspect reports, watch and Why output,
  search text, ambiguity diagnostics, and kill confirmations. Legacy list JSON
  remains unchanged; versioned structured output continues to carry scope as a
  separate field.

### Removed

- Removed dead internal code: never-constructed evidence-source variants,
  unreachable trait defaults and bounds guards, write-only fields, a vestigial
  platform parameter, and single-caller wrapper functions, plus one unsafe
  UTF-8 block rewritten with the standard library's safe chunk iterator.
  Trimmed tautological and duplicate unit tests, and strengthened previously
  vacuous assertions so tree-thaw, docker-runner, and stale-refresh tests fail
  under the regressions they exist to catch. No user-visible behavior changed.
- Removed the inactive in-repository Scoop bootstrap mirror; the live
  `nuggocto/scoop-bucket` remains the only Scoop source of truth. Removed an
  opportunistic kernel-race integration test whose normal success path duplicated
  the mandatory group-kill journey without deterministically exercising a race.

### Fixed

- Concurrent embedded watch sessions now fail immediately instead of sharing and
  corrupting process-global Ctrl-C handler state. Handler ownership is reserved
  before cancellation state changes, released only after successful restoration,
  and retained fail-closed if restoration itself fails. Once observed, Ctrl-C
  cancellation remains latched for the process lifetime so a delayed callback
  cannot cancel a later embedded watch owner.

## [1.3.6] - 2026-07-26

### Added

- Versioned `EvidenceGap` output now carries an always-present nullable
  `affected_pid_count`. Linux owner scans aggregate PID-scoped losses that have
  no target socket edge into one positive bounded count while retaining exact
  target-relevant losses under `pid`; repeated aggregate observations merge by
  maximum rather than by an invented sum.

### Changed

- `list --process ""` is now an invalid-argument error (exit `2`) instead of
  quietly selecting every row whose process name was readable. An empty
  substring matches every name, so the old result narrowed the list instead of
  filtering it, and a script passing an unset variable got a wrong answer under
  a success exit code. Nonempty values are unchanged, whitespace included.

### Removed

- Removed Kickoutchi's automatic weekly GitHub release check, update cache,
  install-provenance-based notices, and the associated `ureq`/Rustls TLS
  dependency stack. The deprecated boolean `check_for_updates` key remains
  accepted and ignored so existing strict configuration files still load. The
  cargo-dist-generated standalone `kickoutchi-update` installed by release
  installers is unchanged.

### Fixed

- Snapshot, watch, and Why output no longer repeats an evidence gap that both
  consistency passes observed. The repeat carried no evidence the first copy did
  not and consumed half of each snapshot's gap retention budget, so a host with
  enough distinct gaps could overflow that budget and then have watch refuse to
  diff and kill refuse to signal on an observation that was complete enough to
  act on. A process that exhausts its optional-metadata budget on several fields
  now also reports one gap instead of one per field.
- Configuration diagnostics now preserve TOML source excerpts and caret
  placement while keeping hostile path and I/O text sanitized on one line.
- Oversized protected-process diagnostics now distinguish the merged total, raw
  configured entries, unique configured additions, and built-in defaults, so
  duplicate configured or default names cannot make the count misleading.
- Linux group-kill real-binary coverage now keeps the capability-required
  success journey separate from the opportunistic observation-race fail-closed
  journey, preventing a real race from satisfying the release success gate.
- TUI background-worker panics now cross a typed result channel to the owner
  thread, which restores the terminal before reporting the failure instead of a
  worker panic hook writing while the alternate screen is active.

## [1.3.5] - 2026-07-26

### Fixed

- Homebrew release validation now installs generated formulas in a pinned,
  disposable Homebrew container, avoiding hosted-runner temporary-volume
  incompatibilities while preserving version and provenance checks.
- Homebrew publication now initializes the Linuxbrew path before discovering
  the canonical tap directory on Ubuntu release runners.
- macOS release journeys now retain valid release assertions when bounded
  collection gaps occur both before and after the release event, while still
  requiring the terminal fail-closed sequence of three consecutive gaps.
- Homebrew release publication now validates generated formulas from the
  canonical `nuggocto/tap` path before pushing, matching current Homebrew path
  enforcement.
- The Arch source package disables makepkg link-time optimization, which is
  incompatible with the current Rust toolchain when linking the bundled TLS
  implementation.
- The foreground update check explicitly releases its cache lock before
  spawning the detached worker, preserving the worker's bounded lock-acquisition
  contract under load.
- macOS release journeys now validate bounded collection gaps when host socket
  visibility becomes partial after a valid watch baseline, matching the same
  fail-closed behavior already accepted before baseline publication.

## [1.3.1] - 2026-07-26

### Added

- Added a silent, timeout-bounded stable-release check that runs at most once
  every seven days outside the foreground command. New-release notices use
  install provenance to recommend Homebrew, Scoop, AUR, Linux Nix, Cargo, or the
  standalone updater without contaminating structured output; configuration can
  disable the check.

### Removed

- The release runbook and the product recap that `1.3.0` added. Both were
  maintainer-only working documents, never shipped in a package or archive, and
  the qualification state they tracked is now recorded in the release itself.

### Changed

- Nix flake outputs are now explicitly Linux-only. The package version is read
  from `Cargo.toml`, and Linux Nix, Homebrew, Scoop, and AUR installations carry
  closed provenance markers for manager-correct update instructions. Native
  macOS archives and Homebrew support are unchanged.
- Linux release archives are built in pinned Debian 11 containers with a
  declared glibc 2.31 floor, and release validation rejects newer symbol
  requirements.

- Every surface that only reads a port row now borrows it from the authoritative
  snapshot instead of receiving an owned legacy copy. List, single-process kill,
  scoped tree and group kill, inspect, Docker enrichment, and the TUI all speak
  the borrowed row; the owned form survives only where a row genuinely outlives
  its snapshot, which is the TUI's stored table, the collection seams whose
  closures own a snapshot internally, and test fixtures. Kill and inspect also
  resolve protected-process policy while projecting rows rather than marking
  them afterwards, removing a second pass over the same data. No command
  behavior, output, or exit code changes.

### Fixed

- Linux and macOS scoped termination now waits for observable suspension under
  one operation-wide deadline and tracks which stop transitions it observed.
  Cleanup after refusal or failed delivery leaves a pre-stopped process untouched;
  after successful `SIGTERM` delivery it guardedly continues even a pre-stopped
  target so the pending termination can execute. Concurrent external
  `SIGSTOP`/`SIGCONT` can still race stop-state attribution.
- Windows tree termination now reconciles every live pinned descendant with the
  frozen Job Object immediately before termination and thaws on every refusal.
- Hidden TUI confirmations are cancelled on undersized terminals, terminal state
  is restored before SIGTERM/SIGHUP is re-raised, the previous panic hook is
  restored after the TUI, and initial collection happens before raw mode.
- Windows Docker named-pipe validation now rejects remote, traversal, encoded,
  and normalization-ambiguous endpoints instead of relying on a string prefix.
- Corrected macOS dual-stack decoding and protected-process title matching,
  Windows snapshot and long-path diagnostics, terminal escape stripping,
  wrapped confirmation budgeting, Docker details clipping, filter help, and
  help/version broken-pipe handling.

- The macOS release-profile watch journey no longer fails when the host gives a
  partial observation for every attempt. That journey has two correct outcomes
  and the host decides which one: process-first `libproc` collection sees a
  partial machine-wide socket set whenever a protected process holds a socket,
  and watch then refuses to publish a baseline it cannot vouch for. Both paths
  are asserted — a complete observation must prove the baseline and release
  contract, a partial one must prove exit code 1, the exact refusal message, and
  zero emitted records — so the journey stops depending on which processes a
  shared runner happens to be running.

## [1.3.0] - 2026-07-24

### Added

- Native Linux, macOS, and Windows release gates now run formatting, strict
  lints, tests, doctests, dual-binary optimized builds, and real-binary journeys
  on the exact release commit before cargo-dist packaging or publication.
- Deterministic unit, contract, and real-binary coverage for observation
  completeness, metadata budgets, labels and filters, watch recovery and event
  ordering, bind diagnostics, output schemas, configuration boundaries, safe
  termination revalidation, and socket-helper cleanup across protocol, address
  family, wildcard, dual-stack, and shared-endpoint modes.
- `list --snapshot-json`, which emits one versioned `kickoutchi.snapshot/1`
  document containing the bounded full-state native socket observation,
  declared scope, completeness, owner attribution, process identities and
  metadata, evidence gaps, and configured labels. Unlike legacy `list --json`,
  snapshot mode bypasses list filters, sorting, and system-row hiding and does
  not serialize complete process command lines.
- Shared additive serialized contracts for endpoint labels, snapshots,
  `kickoutchi.watch_event/1` NDJSON, and `kickoutchi.why/1` documents, including
  bounded reusable endpoint, owner, process-identity, scope, evidence, gap,
  certainty, and operational-code shapes. The existing `kickoutchi.list/1`
  top-level array remains the compatibility interface and adds only its nullable
  `label` field.
- Native dependency contract tests for the approved socket lifecycle across TCP,
  UDP, IPv4, IPv6, wildcard, reuse-address, IPv6-only, and dual-stack modes,
  including immediate close and exact endpoint rebinding.
- Validated endpoint labels configured through exact literal-address or wildcard
  `[[ports]]` selectors, with exact-before-wildcard resolution and bounded safe
  Unicode labels. Labels appear in CLI and sufficiently wide TUI tables, list,
  snapshot, watch, and Why output, plain search, and `label:` filters.
- Shared AND-composed plain and structured filters across list, TUI, and watch,
  including normalized `address:`, numeric `scope_id:`, `family:ipv4|ipv6`, and
  label matching. Watch additionally supports the complete native `state:`
  vocabulary and uncertainty-preserving indeterminate matches.
- A bounded `watch` command that emits deterministic baseline, bind, release,
  replacement, and collection-gap events from full-state native socket snapshots.
  It supports human output or versioned `kickoutchi.watch_event/1` NDJSON,
  endpoint and full-state filters, configurable polling intervals and duration,
  clean Ctrl-C and broken-pipe termination, and explicit recovery from transient
  collection failures without fabricating releases.
- Exact TCP and UDP bind diagnostics across IPv4 and IPv6, with validated scope,
  reuse-address, IPv6-only, and dual-stack controls. Results distinguish current
  bindability, address conflicts, permission denial, unavailable addresses,
  unsupported native behavior, and other retained OS errors; every probe closes
  its socket immediately and makes no promise about a later bind race.
- A bounded `why` command that evaluates exact endpoint matrices from one native
  snapshot and sequential bind probes. Human and versioned `kickoutchi.why/1`
  JSON output report deterministic verdicts, certainty, labels, evidence,
  evidence gaps, omitted counts, and aggregate exit status without collecting
  full process command lines. Why does not request Docker enrichment or spawn a
  Docker process.

### Changed

- Documented `child_pids` in `list --json` as what it has always been: a frozen
  `1.x` compatibility field that is `[]` on every row and every platform, with
  no backing data. The wire output is unchanged; the field it mirrored is gone,
  so the empty array can no longer drift from a value behind it.
- Every lint suppression now states a reason, enforced by
  `clippy::allow_attributes_without_reason`. Suppressions that always apply use
  `expect`, which reports itself once it is no longer needed; `allow` is kept
  only where a suppression is target-specific. Adopting this removed three
  suppressions that no longer applied to the code they guarded.
- Replaced the Python release-archive validator and its tests with a test-only
  Rust target. CI and cargo-dist retain bounded checksum, path, archive-layout,
  member-type, expanded-size, permission, version, dual-entrypoint, timeout, and
  extracted-binary journey checks without requiring Python in the repository.
- Expanded installation, update, and security documentation to distinguish
  GitHub installers and archives, Homebrew, Scoop, Nix, Cargo Git installs, and
  future AUR packages, including their independent trust and update boundaries.
- Added a durable release runbook for exact-candidate qualification,
  publication approval, package synchronization, AUR preparation, and website
  deployment; the completed one-off feature checklist was removed.
- Reworked collection behind the existing list, TUI, inspect, and kill surfaces
  around one bounded, consistency-checked snapshot. Unprivileged `kill --port`
  remains supported when the selected endpoint has one verified owner; unrelated
  unreadable host processes no longer turn the flagship port-kill path into a
  root-only operation, while observed target-local ambiguity still refuses. On
  Linux, an unreadable same-inode co-holder can remain undiscovered and keep the
  port bound after the visible genuine owner is terminated; post-kill polling
  reports that accepted limitation.
- Windows tree kill now freezes the committed Job Object for its final bounded
  validation sweep through private information class 18, closing the
  descendant-spawn window before whole-job termination. An empty disposable job
  proves freeze/thaw support before target assignment. A live member that cannot
  join the job now withholds all termination instead of receiving racy individual
  fallback termination. Assignment, freeze, or final-validation failure reports
  that strict tree closure was not established and attempts thaw when required.
- Pinned `socket2` 0.6.5 with its empty default feature set for exact bind
  probes. Its dependency graph, license, MSRV, unsafe call surface, binary-size
  impact, and Linux, macOS, and Windows behavior were reviewed and accepted
  before probe implementation.
- Reorganized the CLI implementation into focused list, single-process kill,
  and scoped tree/group kill modules without changing command behavior, and
  documented the host-byte-order handling used by the Linux socket parser.
- Froze Linux TCP timer evidence and UDP-bound semantics before full native-state
  collection, and clarified watch interval, clock-failure, replacement, and full
  snapshot filtering contracts.
- Completed native full-state collection for Linux, macOS, and Windows while
  preserving the listener/bound-only legacy and destructive projections. Unknown
  native states retain their numeric code, and Linux snapshots retain typed TCP
  timer evidence without treating timer movement as socket replacement.
- Strengthened Darwin ABI validation with exact LP64 layout and offset checks,
  made process-first enumeration loss explicit socket-set evidence, and added
  complete raw IP Helper table fixtures for every Windows address-family and
  protocol combination.
- Documented the exact shipped target matrix, configuration, exit codes,
  checksum limits, and structured-output privacy.
- Endpoint selector matching now canonicalizes IPv4-mapped IPv6 addresses,
  preserves numeric IPv6 scope identity, applies exact matches before wildcard
  matches, and rejects unsafe Unicode before any terminal rendering.
- Structured snapshots and diagnostics now state permanent platform and timing
  limits instead of treating in-scope completeness as machine-wide visibility:
  Linux excludes other network namespaces and can have PID/procfs ownership
  gaps, native Windows excludes the WSL network stack, macOS is process-first,
  watch polling can miss transient activity, and Why's temporary bind and later
  close cannot reserve an endpoint or eliminate the post-probe race.

### Fixed

- Tree and group cleanup no longer reports a member that exited under the freeze
  as a thaw failure. Among Kickoutchi's cleanup results, a refused `SIGCONT` is
  the result that proves a process may still be stopped, so only refusals are
  named; concurrent external stop signals remain outside that attribution. A
  member the kernel reports as gone is not something the user can resume. This
  matches the classification the
  delivery paths and single-process termination already used, so a refusal such
  as a root that exits mid-freeze no longer prints a cleanup error naming a PID
  that no longer exists.
- macOS normal termination now distinguishes a process that exits between
  `SIGTERM` delivery and the guarded `SIGCONT` identity check from an unreadable
  or recycled PID, avoiding a false cleanup failure without signaling a new
  process.
- macOS release-profile watch journeys retry only the exact partial-initial-socket
  condition with a fixed three-attempt budget. The shared runner uses
  noninteractive elevation for that fixture-owned journey and now fails unless
  one attempt proves the baseline and release event contract.
- The public `kickoutchi::run()` entrypoint now preserves an embedding process's
  tracing subscriber, and repeated calls no longer panic during diagnostics
  initialization.
- Windows replacement coverage creates the replacement listener in a distinct
  process, proving changed owner identity instead of depending on incidental
  partial ownership from the host socket table.
- Confirmation input now applies its 128-byte limit to the entered UTF-8 payload
  rather than counting the terminal line ending, keeping CLI and TUI boundaries
  consistent while still rejecting the first excess payload byte.
- Real-binary test helpers now use bounded process and reader cleanup, own and
  verify every member of deep process-chain fixtures, and require broken-output
  watch tests to terminate through the closed consumer rather than duration.
- Release workflow contracts now require pinned Actions, credential-free
  checkout, exact-commit native gates, tag-only publication, and step-scoped
  repository and Homebrew credentials.
- macOS single-process termination now records the identity observed after
  `SIGSTOP` and uses that identity for guarded rollback, so a detected PID-reuse
  replacement is resumed without receiving the unauthorized terminating signal.
- Tree and process-group termination now captures rollback identity immediately
  after every successful stop and uses the same process snapshot to prove both
  sweep convergence and final frozen-set identity.
- Single-process confirmation content is bounded to the modal height without
  wrapping long process or port text over the actionable prompt, input, error,
  and cancellation lines.
- Linux and macOS related-process diagnostics now inspect at most 64 command
  lines and match tokens without a token index or per-token allocation. Windows
  retains its separately bounded process-snapshot path.
- Inspect now joins process, port, and command-line observations by PID and start
  identity, refusing a changed port owner instead of attributing sockets or
  metadata to a recycled PID. Human watch output now preserves IPv6 interface
  scope and explicitly reports unavailable scope.
- Docker enrichment stops reading each output pipe at the first byte beyond its
  retention cap and hands each timed-out direct child to a capped cleanup worker
  that terminates it and retains ownership through confirmed reap. An indeterminate
  wait permanently consumes its bounded slot instead of releasing ownership,
  preventing stuck waits from blocking the caller or accumulating unbounded work.
- macOS tree and group rollback now resumes the post-stop process identity when
  PID reuse is detected, while still withholding termination from identities the
  user did not authorize.
- Linux ownership collection now treats unreadable or unprovable procfs mount
  visibility as partial, and exact-fit procfs executable links no longer lose
  metadata because magic symlinks report a zero size.
- Why output now streams every legal bounded result shape instead of rejecting a
  valid document above 256 KiB, and its evidence order consistently keeps owner
  and kernel facts before the exact probe and supporting timer evidence.
- Docker enrichment no longer associates explicit IPv4 and IPv6 publications
  across address families, and oversized Linux privilege status is detected with
  a limit-plus-one read before any Docker command can run.
- Real-binary contract runners now enforce process and pipe-drain deadlines.
- Windows tree kills now reapply `--yes` warning authorization during every
  committed containment sweep and withhold all termination when a late child
  requires fresh review. Windows custom protected names and protected-name
  confirmation also use allocation-free Unicode-aware case matching.
- Linux full-state collection no longer applies the independently bounded
  legacy-row projection limit. Linux identity data, macOS aggregate FD limits,
  and Windows IP Helper buffer limits now retain their exact stable operational
  error categories.
- TUI kills invalidate an in-flight pre-kill refresh and queue exactly one fresh
  snapshot after it drains. Overlong confirmation input now stops after the
  bounded limit-plus-one read instead of draining an unbounded stream.
- Optional Docker enrichment now pins the CLI to a bounded local Unix socket or
  Windows named pipe and removes ambient host, context, and TLS selectors. A
  remote Docker context can no longer receive local port-diagnostic queries or
  be presented as local container ownership.
- Linux socket collection now rejects empty, malformed, and headerless procfs
  tables while accepting the kernel's family-specific IPv4 and IPv6 headers.
  Ownership remains explicitly partial when a nested or unverifiable PID
  namespace could hide an ancestor-namespace socket owner.
- macOS process enumeration now distinguishes genuine empty results from
  zero-plus-errno failures, reports IPv6 scope as unavailable instead of
  retaining an unsupported interface index, and classifies bounded parent-name
  omissions without exceeding the metadata allowance.
- Windows socket collection now converts IPv6 scope IDs from network byte order,
  normalizes IPv4-mapped IPv6 endpoints, and retains ownerless TCP and UDP
  endpoints as partial rather than treating PID zero as a process. Authoritative socket rows
  also survive Toolhelp metadata-enumeration failures through bounded direct
  owner-identity reads, while destructive tree collection remains fail closed.
- Linux process identity now parses the bounded ASCII tail of `/proc/<pid>/stat`
  from bytes, so a valid non-UTF-8 `comm` cannot abort collection. Restricted or
  incomplete procfs PID enumeration now marks global ownership partial instead
  of producing a false complete empty owner set.
- Destructive authority ignores non-listening TCP states, preserving existing
  kill semantics while native snapshots retain established and transitional
  connections.
- CLI, config, and startup diagnostics sanitize terminal controls and bidi
  formatting before output. Changed final protection evidence now exits as an
  operational failure while still proving zero signal delivery.
- TUI post-kill refresh schedules one authoritative snapshot instead of first
  materializing and discarding a complete legacy projection.
- macOS FD reads enforce the remaining aggregate allowance before allocation and
  reject native returned lengths beyond their supplied buffers.
- Docker cleanup and dual-stream draining use bounded shared deadlines; segment
  65 rejects its row and match truncation starts only when a ninth match exists.

### Security

- Release jobs install an exact locked cargo-dist version. Homebrew validation
  runs without tap credentials; validation failures stop before formula staging,
  and the tap token is introduced only for the final authenticated push. Release
  planning is read-only, and explicit repository-token environment values exist
  only on the three commands that plan or publish a release.
- Added a private vulnerability-reporting policy and documented the sensitivity
  of command lines exposed by the legacy JSON compatibility interface.

## [1.2.0] - 2026-07-11

### Changed

- Windows tree-kill reports now retain normalized PID lists instead of counters
  for Job Object delivery, verified individual fallback, and already-exited
  members. Partial-result output names every PID and counts every observed
  process without duplicating or losing state.

### Fixed

- Release publication now waits for Linux, Windows, and macOS tests plus the
  supply-chain policy on the exact tag SHA. Every artifact builder explicitly
  installs and selects Rust 1.95.0, and pull requests build/package cargo-dist
  artifacts instead of stopping at a plan.
- Regression coverage now exercises the production config-loading, Linux
  collector-limit, Windows snapshot, Windows failure-reporting, Docker
  privilege, and fully rendered modal paths instead of testing disconnected
  helpers. Locally executable release regressions were mutation-checked by
  restoring their prior faulty behavior and confirming the relevant test fails
  for the intended reason; Windows-only paths are compiled here and run in CI.
- CLI confirmations now reject and drain any line past the 128-byte cap instead
  of truncating it into a potentially valid destructive confirmation.
- Config files now fail closed past a 64 KiB byte cap rather than allowing a
  large file or special device to drive unbounded reads and allocation.
- Linux collection caches process metadata once per PID and fails closed at
  explicit aggregate file-descriptor traversal and emitted-row limits, bounding
  shared-socket owner fanout without collapsing ambiguous ownership.
- Windows tree parent links with equal child and parent creation timestamps are
  now marked unverified and refused instead of silently omitted. Completion uses
  one shared five-second deadline and reports each PID in exactly one outcome.
- Windows installer documentation now uses the `cargo-dist` PowerShell command
  with process-scoped `-ExecutionPolicy Bypass`, avoiding failures on the default
  restricted execution policy.
- A failed Windows `TerminateJobObject` call after containment commit now
  returns the complete partial-action report: fallback-terminated and
  already-exited PIDs remain visible, assigned members are explicitly marked
  unconfirmed, prior post-commit issues are preserved, and the CLI refreshes the
  confirmed target ports before exiting with failure.
- TUI process-details collection is now strictly single-flight. A different-row
  request occupies one bounded latest-request slot until the active worker
  drains, stale refresh-era results are ignored, and closing or cancelling the
  modal drops pending work instead of accumulating background threads and
  Docker processes.
- Docker enrichment now drains stdout and stderr concurrently from process
  start, retains at most 256 KiB per stream while continuing to drain overflow,
  and keeps the existing timeout/kill/reap behavior. Valid output larger than an
  OS pipe buffer no longer deadlocks into a false timeout, and the wait for the
  drain itself is bounded to 250 ms, so a grandchild that inherited the pipe
  (Docker Desktop shims, credential helpers) cannot stall the details view
  indefinitely. Stuck drain workers remain charged against a global cap so
  repeated inherited pipes cannot grow the process's thread count without bound.
- CLI table columns now align by terminal display width instead of byte
  length, so accented and CJK process names no longer shift the PROCESS and
  STATE columns in `list` output. Uses `unicode-width`, which was already in
  the dependency tree via ratatui.
- Port diagnostics now replace bidirectional-override and zero-width
  characters inside quoted command lines, matching the policy every other
  human-facing surface already applied; a process's command line can no longer
  visually reorder the hint text on the terminal.
- The tree-kill confirmation modal's preview budget now measures word-wrapped
  rows in terminal columns rather than estimating from character counts, so
  long unbroken process names at small modal sizes can no longer push the
  typed-word instruction, input echo, or Esc hint below the fold. The tree modal
  also reserves additional vertical space for wrapped warnings and validation
  errors at the minimum supported terminal size.
- Windows tree sweeps now report an unexpected OS error while opening a
  late-discovered child as a snapshot failure instead of mislabeling it as
  permission denied.
- The protected-process list size error now breaks its count into configured
  entries and built-in defaults, so the reported total matches something the
  user can see in their config file.

### Security

- PATH-resolved Docker enrichment is now disabled while Kickoutchi is elevated,
  preventing a user-writable executable search path from becoming privileged
  code execution on Windows or Unix setuid/setgid/root sessions.
- Release jobs no longer execute cargo-dist installer assets directly from the
  network. Both v0.32.0 shell and PowerShell installers are downloaded to a
  temporary file and verified against repository-pinned SHA-256 values on every
  Linux, macOS, and Windows release builder before execution.
- Release workflow scripts now receive the tag ref through environment
  variables instead of inline `${{ }}` interpolation, closing a
  script-injection shape that was reachable only by users who can already push
  tags.
- Linux `/proc` stat and status reads now fail closed past their byte caps
  instead of silently truncating — a truncated stat line could otherwise parse
  a prefix of the start-time identity marker as a valid but wrong value. The
  status cap is sized so even a pathologically long `Groups:` line still fits,
  and the `/proc` PID scan carries an explicit fail-closed cap matching the
  macOS collector.

## [1.1.2] - 2026-07-07

### Added

- Homebrew tap publishing for releases. `cargo-dist` now generates the formula,
  and the release workflow publishes it to `nuggocto/homebrew-tap` so macOS and
  Linux users can install with `brew install nuggocto/tap/kickoutchi`.
- Scoop bucket packaging for Windows. The repository now carries a seed manifest
  and Excavator workflow under `packaging/scoop/`, with the live bucket at
  `nuggocto/scoop-bucket` auto-updating from GitHub Release assets and their
  `.sha256` sidecars.

### Changed

- Install documentation now lists Homebrew, Scoop, AUR, Nix, Cargo, installers,
  and direct archives as supported release paths.
- The release workflow now waits for Homebrew publishing before announcing a
  release, keeps the tap push behind `HOMEBREW_TAP_TOKEN`, and skips unchanged
  Homebrew commits on safe reruns.

## [1.1.1] - 2026-07-05

### Fixed

- Protected-process defaults now cover Linux and macOS Docker owners including
  `dockerd`, `docker-proxy`, and `com.docker.backend`, and Linux protected-name
  matching accounts for `/proc/<pid>/comm` truncation of long configured names.
- CLI list and inspect output now handle broken pipes explicitly, so piping to
  short readers exits cleanly inside the documented exit-code contract instead
  of panicking.
- Tree kill no longer aborts when only the frozen root is reparented by an
  unfrozen parent exiting mid-sweep, while the frozen-set protection gate fails
  closed if process metadata unexpectedly loses a name.
- The TUI no longer performs selected-process metadata scans on the input path
  before opening kill confirmations; it uses the existing background worker and
  refuses submission until identity metadata has landed.
- Human-facing sanitization now replaces bidi and zero-width display controls,
  closing terminal display-spoofing gaps in names, paths, and status text.
- Inspect tree output now renders branchy descendants in parent order instead
  of depth-only order, so indentation matches the actual tree.
- Docker enrichment bounds its post-timeout output drain, and Windows tree
  fallback exit probes use zero-timeout waits instead of blocking per member.
- Linux `/proc/net` address decoding uses native-endian words, fixing
  big-endian Linux without changing little-endian behavior.

### Changed

- CI supply-chain checks now run on a schedule, GitHub Actions are pinned to
  commit SHAs, release workflow permissions are narrowed, and warnings are
  enforced by CI rather than the published Cargo manifest.
- Contract tests add real-binary coverage for configured protected-process
  refusal and UDP/IPv6 listing, avoid PID substring assertions, and use longer
  helper deadlines for slower CI hosts.

## [1.1.0] - 2026-07-04

### Added

- Windows `kickoutchi inspect --pid <PID>` / `--port <PORT>`: the read-only
  family view is available on Windows. It shows ancestors, descendants,
  siblings, ports, command lines, and the matching `kick kill --pid <root> --tree`
  hint without signalling anything. Windows reports parent links only
  after creation-time sanity checks, omits the POSIX process-group section, and
  states the native WSL2 limitation plainly. The Windows inspect renderer reuses
  one process snapshot for command-line lookups within a report instead of
  rebuilding process metadata per displayed PID.
- Windows CLI `kickoutchi kill --port <PORT> --tree` (and `--pid`, `--force`):
  terminates the descendant tree through Job Object containment. Normal
  `kick kill` remains single-PID precise, `--group` stays Unix-only, and the
  Windows TUI still does not bind or advertise `t`/`T` tree keys.
  - The Windows path preflights side-effect-free before assigning the root to a
    Job Object, treats that root assignment as the irreversible commit boundary,
    converges descendants under containment, then uses explicit
    `TerminateJobObject` for contained members. The root handle is verified
    against the user-confirmed creation marker before the Job Object commit, so
    a recycled PID cannot retarget the kill between confirmation and execution.
  - Windows tree termination is hard termination only. Members that cannot join
    the job after commit fall back to verified individual `TerminateProcess`
    handles when possible, and partial containment/not-terminated results are
    reported honestly instead of being collapsed into success. Post-commit
    convergence failures now keep their specific reason in the report, including
    protected descendants, unsafe PIDs, cap overflows, incomplete metadata, and
    snapshot failures.
  - Windows parent links with missing creation-time metadata now fail closed when
    they could point into the confirmed tree, so `--tree` refuses as incomplete
    metadata instead of silently omitting a possible descendant. Post-commit
    reporting also distinguishes already-exited pinned members and protected
    late children already contained by the job from real survivors.

## [1.0.1] - 2026-07-04

### Fixed

- macOS scoped kills now narrow process-table snapshots to the active tree or
  group during execution, so unrelated system `EPERM` rows do not hide real
  target-scope safety failures while unreadable in-scope members still fail
  closed.
- The TUI status line now sanitizes every value it renders — the active filter
  text and the filter-error, error, and kill-status fields — so a process name
  or error message carrying control or escape bytes cannot redraw the terminal
  or fake output through the status bar.
- The "no confirmed socket" port diagnostic now sanitizes the related
  process's name before printing it. This closes the one hint path where a
  process that named itself with terminal escape sequences could reach stderr
  unsanitized; the quoted command line in the same message was already
  escaped.

## [1.0.0] - 2026-07-03

### Added

- Linux and macOS `kickoutchi kill --port <PORT> --tree` (and `--pid`,
  `--force`) terminates the whole process tree rooted at the target, not just
  the single port-owning process — for cleaning up dev servers, agents, and
  runners that leave worker children behind. It is opt-in: normal `kick kill`
  is unchanged and still signals exactly one PID.
  - Tree kill does a fresh bounded tree count before any signal is sent, then
    freezes before it kills: it `SIGSTOP`s the root first to prevent ordinary
    child creation while the root remains stopped, sweeps descendants toward a
    bounded fixed point, and re-verifies every process's identity before
    signalling. External stop/continue actors can still race this sequence; it
    is not an atomic kernel transaction.
  - It signals leaves-first, root last, sending `SIGTERM` then `SIGCONT` for a
    normal kill (or `SIGKILL` for `--force`). Any refusal after freezing —
    identity drift, a protected descendant, an unsafe PID, or exceeding the
    256-process cap — thaws each process it observed transition into stopped and
    sends no termination. A process already stopped is left untouched on
    refusal; after successful `SIGTERM`, it is continued so the pending signal
    can execute.
  - Interactive confirmation requires typing `tree` (or `force` for
    `--force`); a protected root requires typing its PID or name and then the
    tree confirmation word. `--yes` only skips the prompt for an all-clear tree,
    cannot bypass a protected root, and is refused if the fresh execution-time
    scan would have required warnings to be reviewed — a condition that is
    applied once more to the final frozen member set, because a tree can grow
    between the skip and the end of the freeze.
  - Root protection is decided from both readers, not just the socket row: a
    root whose port row has no readable name but whose process-table entry is
    on the protected list still requires the protected confirmation, and
    execution re-checks the fresh scan's root classification — a root that
    turns out protected only at kill time (for example after an `exec` into a
    protected name, which keeps its PID and start marker) is refused unless
    the protected confirmation was actually completed. Both the CLI and the
    TUI share this gate.
  - A tree that exceeds the process cap is refused rather than partially
    killed, so a runaway fork bomb is reported and left intact instead of half
    signalled. The `--tree` flag exists only on Linux and macOS builds;
    Windows has no freeze primitive, so it does not get a weaker tree kill
    under the same name.
  - On Linux every member is pinned with a pidfd before its first `SIGSTOP`,
    and the same handle is used for thaw and final delivery. macOS has no
    pidfd, so delivery is layered instead: every member is stopped and
    identity-verified first (a stopped process cannot fork, exec, or exit on
    its own), and the verified start marker is re-checked immediately before
    each terminating signal, so a PID that was recycled under an external
    `SIGKILL` is reported as exited rather than signalled.
  - `kill --pid <PID> --tree` can start from a live parent PID even when that
    root owns no visible port, so cases where a child owns the port but the
    parent supervises the tree can be cleaned up from the parent. The banner
    for such a root carries the same ownership warning as a port-owning one
    when the process belongs to another user.
- The TUI now has tree kill too: `t` requests tree termination of the selected
  row's process and `T` (Shift) requests a tree force-kill, mirroring the
  `x`/`X` convention including its Caps Lock handling. The confirmation modal
  enumerates the tree on a background worker (the table stays responsive and
  shows the count once the scan lands), lists the members with depth
  indentation, shows the same warnings as the CLI banner, and requires typing
  `tree` (or `force`); a protected root asks for its PID or name first and the
  word second, exactly like the CLI. Execution never trusts the previewed
  tree: it revalidates the root identity and re-runs the bounded pre-flight
  gates against a fresh scan before the first freeze signal. The header and
  help modal advertise the keys only on Linux/macOS builds, and the normal
  `x`/`X` kill flow is unchanged. The modal budgets its member preview from
  the terminal height, so the typed-word instruction, the input echo, and the
  Esc hint stay visible even at the smallest supported size.

- Linux and macOS `kickoutchi inspect --pid <PID>` / `--port <PORT>`: a
  strictly read-only family view for picking the right root before a tree
  kill. It shows the target with its command line, ports, and process group;
  the ancestor chain nearest-first with command lines (so a supervisor like an
  agent or package runner is identifiable); siblings; the bounded descendant
  tree with per-member ports; and the process-group members with the ones
  *outside* the descendant tree called out — exactly the processes a tree kill
  from that target would leave alive. Protected names are marked, every
  OS-provided string is sanitized, all sections are display-capped with honest
  "and N more" lines, and the report ends with the matching
  `kick kill --pid <root> --tree` command. It never signals anything: killing
  upward stays a human decision made with the family in view.
  - `inspect --port` follows the same resolution rules as `kill --port`
    (refuses ambiguous multi-owner ports, reports unreadable owners as a
    permission problem), while `inspect --pid` accepts any live PID including
    portless supervisors — and, being read-only, even PID 1.
  - Tree snapshots now also carry the process group ID (from `stat` on Linux
    and `proc_bsdinfo` on macOS, read in the same pass as before). Because
    group kill derives its membership from this field, it is read as
    fail-closed as the start marker: a live process whose group cannot be read
    fails the scan, and the kernel's own group `0` maps to "no targetable
    group". The read-only inspect view renders an untargetable group as
    unknown.
  - When the process group has members outside the descendant tree — exactly
    the processes a tree kill would leave alive — the inspect report's footer
    now also offers the matching `kick kill --pid <root> --group` command.

- Linux and macOS `kickoutchi kill --port <PORT> --group` (and `--pid`,
  `--force`): terminates the target's whole POSIX process group — every
  process sharing its group ID — instead of its parent-link tree. This is the
  honest tool for the two cases tree scope cannot cover: survivors that
  reparented away from the tree (double-fork daemons, orphaned workers whose
  spawner exited) and runaway spawners whose tree outgrows the 256-process
  tree cap. `--group` conflicts with `--tree` at parse time, exists only on
  Linux/macOS builds like `--tree`, and leaves normal `kick kill` unchanged.
  - Same freeze-first pipeline and refusal gates as tree kill: the confirmed
    root is `SIGSTOP`ped first, members are swept to a fixed point, every
    frozen member's identity is re-verified while stopped, and any refusal
    thaws members Kickoutchi observed transition into stopped. Group membership
    is re-proven after every stop (a
    member whose group changed under the freeze refuses the whole kill), but
    a member whose *parent* died mid-kill is fine — reparenting does not
    change group membership, which is the point of the scope.
  - Normal group termination queues `SIGTERM` to every frozen member before any
    `SIGCONT`, so parent-like group members cannot wake up and spawn survivors
    while other members are still only frozen.
  - It is deliberately never implemented as `kill(-pgid, ...)`: every member
    is enumerated, frozen, verified, and signalled individually through the
    same delivery path as tree kill (per-member pidfds on Linux), so the
    unsafe-PID, protected-process, and identity gates apply to every PID. If
    Kickoutchi itself sits in the target group (a plain `sh -c` script puts
    everything in one group), the kill refuses before anything is stopped.
  - The group cap is 512 processes — double the tree cap, because group scope
    is the designated tool for over-cap spawner trees — and past it the kill
    refuses rather than executing partially.
  - Interactive confirmation requires typing `group` (or `force` for
    `--force`) after a banner that names the group ID and lists **every**
    member: a process group can contain unrelated commands launched from the
    same shell, so the full blast radius is always shown. A protected root
    requires its PID or name first; a protected member refuses the whole group.
    `--yes` is stricter than tree scope: it only skips the prompt for a group
    of at most 8 members with no warnings anywhere, and both the fresh
    execution-time scan and the final frozen member set must still pass that
    same all-clear gate (size cap included), because a group has no structural
    tie to the confirmed target and can grow mid-freeze.
  - Execution revalidates the root against a fresh scan and additionally
    requires it to still sit in the confirmed group — a root that moved
    groups between confirmation and execution would silently retarget the
    sweep, so it refuses instead.

### Changed

- Cargo metadata now declares `rust-version = "1.95.0"`, matching the README,
  `mise.toml`, and GitHub Actions, so crates.io consumers get the same
  machine-readable MSRV as local and CI builds.
- Nix release installs are prepared for reproducible builds with a committed
  `flake.lock` instead of a floating `nixos-unstable` input.
- AUR packaging notes now make the release order explicit: keep package
  metadata pinned to the last published assets until the `v1.0.0` GitHub
  Release exists, then update checksums and `.SRCINFO`; actual AUR publication
  still waits for account creation to reopen.
- Internal restructure, no behavior change: system/service process
  classification now lives in a shared `SystemProcessCheck` fields struct in
  the model, and `PortEntry::is_system_process` delegates to it. Kill-time
  process-tree nodes reuse the exact same policy without duplicating it, and
  the named fields keep the same-typed PID and name pairs from being silently
  swapped at call sites.

### Fixed

- Portless `--pid --tree` and `--pid --group` root revalidation now refuses a
  missing start-time marker before any freeze signal is sent, even across test
  seams. The real Linux/macOS snapshots already fail closed, but the shared CLI
  safety gate now enforces the same identity contract directly.
- macOS tree/group kills and `inspect` no longer abort when `proc_listallpids`
  exposes protected system PIDs whose BSD info is denied to the current user;
  those restricted rows are skipped while the selected target is still
  revalidated before signalling.
- CLI kill success reporting no longer races process shutdown: after a
  successful termination (single-process or tree), the post-kill port check
  now polls for up to about one second before deciding between "confirmed
  target ports are no longer visible" and the still-visible warning. `SIGTERM`
  teardown is asynchronous, so the immediate re-collect could warn about a
  still-visible port on perfectly successful kills; a port that genuinely
  stays open is still reported honestly after the settle window.

## [0.1.2] - 2026-06-28

### Added

- Release installers now include the `kickoutchi-update` helper from
  `cargo-dist`, so installer-based Linux, macOS, and Windows users can update to
  newer releases by running `kickoutchi-update` after installing this version or
  newer.
- The README now documents how installer users get the updater helper and how
  existing `0.1.0`/`0.1.1` installs can opt in by rerunning the latest installer
  once.

## [0.1.1] - 2026-06-27

### Added

- Added a `cargo-deny` policy for dependency advisories, duplicate/wildcard
  dependency rules, allowed source registries, and dependency licenses.
- GitHub Actions CI and the local `mise run check` task now run
  `cargo deny check` alongside formatting, strict Clippy, and tests.

### Changed

- Cargo source packages now exclude local `mise.toml`, keeping local tool-trust
  config out of published crate sources.

### Fixed

- The source Arch `kickoutchi` PKGBUILD now invokes `/usr/bin/cargo`,
  `/usr/bin/rustc`, and `/usr/bin/rustdoc` directly during prepare/build/check,
  so user tool shims cannot break `makepkg` builds or doctests.

## [0.1.0] - 2026-06-27

### Changed

- Windows TUI/CLI termination now separates user intent from the underlying
  delivery mechanism: lowercase `x` / non-`--force` is a normal termination
  request with `y` confirmation, while uppercase `X` / `--force` keeps the
  stronger typed `force` confirmation. Windows still delivers both through
  `TerminateProcess` because Kickoutchi does not have a reliable graceful
  process-handle equivalent; the confirmation copy and project notes now state
  that plainly instead of making lowercase `x` look like an accidental force key.
- The Windows protected-process defaults now include core Windows process names
  such as `System`, `svchost.exe`, `services.exe`, `lsass.exe`, `wininit.exe`,
  and Docker/Postgres `.exe` variants. The system/service classifier also treats
  PID 4, known Windows OS process names, and children of `services.exe` as
  system/service rows for warning and optional hiding.
- CLI kill now performs a best-effort post-kill port refresh after a successful
  termination and reports whether the confirmed target ports are still visible,
  instead of only telling the user to refresh manually.

- Linux termination now opens a pidfd before the mandatory pre-signal
  revalidation and sends `SIGTERM`/`SIGKILL` through `pidfd_send_signal` instead
  of raw `kill(pid, signal)`. This keeps the signal tied to the prepared process
  handle after the PID/start-time/port checks pass. It raises the floor for
  termination to Linux 5.3+ (`pidfd_open`); older kernels fail closed with an
  actionable error that names the requirement, without sending a signal.
- TUI refresh now uses a single in-flight background worker instead of running
  the full Linux `/proc/<pid>/fd` owner scan on the render/input loop. The last
  good snapshot remains visible while refresh is running. The first snapshot is
  still collected synchronously so the TUI opens onto real rows instead of a
  blank table, and any in-flight background refresh is abandoned when a
  synchronous snapshot (such as the post-kill refresh) is applied, so a stale
  scan cannot overwrite newer rows.
- Safe termination now carries an internal Linux process-start identity from
  `/proc/<pid>/stat` through confirmation and pre-signal revalidation. The raw
  tick value is not rendered or serialized, but it lets Kickoutchi refuse a kill
  if PID reuse is detected before the signal boundary.
- Internal cleanup, no external behavior change: collapsed the
  duplicate `KillTarget` constructor into a single `from_entries`, switched the
  confirmation modal's force-mode check from a signal-label string comparison to
  `KillMode` equality, and narrowed `current_user_id` to private.
- Comment accuracy, no behavior change: `PortEntry.child_pids` is now documented
  as a reserved field that stays empty on real rows (the Linux collector never
  fills it; selected-row children live in `ProcessContext`, and it remains only
  for the `list --json` shape and the fake fixture); the already-exited TUI kill
  test no longer describes the removed "refreshed snapshot" status wording; and
  `parse_process_start_time_ticks` now explains why it right-splits on `") "` so
  an unescaped `)` inside `comm` cannot be mistaken for the field terminator.
- The `KillTarget` construction invariants are now release assertions instead of
  debug-only ones: the target must contain at least one row, and every row's PID
  must match the target PID. Another caller that builds a kill target from no
  rows, or from rows owned by another PID, now fails fast on the termination path
  instead of carrying a degenerate, port-less, or mis-targeted target forward.
- Linux collector owner resolution now only records owners for socket inodes
  found in the collected `/proc/net/*` rows. It keeps every PID that references a
  target socket inode, so forked or inherited listening sockets are represented
  as multiple candidate owners instead of being collapsed to whichever PID was
  scanned first.
- Linux collector now reads `/proc/<pid>/status` through a byte-bounded reader,
  matching the existing cap on `/proc/<pid>/cmdline`, so every `/proc` read in the
  collector is explicitly limited; `PPid` sits near the top of `status`, so the
  cap never truncates the parent PID.
- TUI/CLI query matching now normalizes text filter needles once per query and
  avoids formatting socket-address strings unless the search text is
  socket-shaped, reducing per-keypress allocations in search mode.
- Removed the unused direct `anyhow` dependency from `Cargo.toml`; typed module
  errors remain the current error boundary.
- No-match port related-process diagnostics now use stricter rules that keep the
  main table limited to OS-confirmed sockets, preserve CLI exit codes, avoid
  polluting JSON output, and require port-shaped matchers instead of raw
  substring matching.
- `protected_processes` in the config file now extends the built-in defaults
  instead of replacing them, with exact-match de-duplication. Adding `redis`
  no longer silently removes protection from `systemd`, `postgres`, and the
  other defaults; this matches the documented "can be extended in config"
  behavior.
- Internal restructure: shared application code moved from `src/main.rs` to
  `src/lib.rs` (public surface: a single `kickoutchi::run()`), with thin
  binary wrappers in `src/bin/kickoutchi.rs` and `src/bin/kick.rs`. Behavior
  is unchanged; the shared code now compiles once for both binaries, unit
  tests no longer run twice, and the duplicate-target Cargo warning is gone.

### Fixed

- Docker details enrichment now runs through a selected-row background worker, so
  opening details on a slow Docker host no longer blocks TUI input. Docker
  enrichment also works for partial-metadata rows with no readable process name
  when Docker reports a matching published host port.

- Windows termination liveness check now uses `WaitForSingleObject(handle, 0)`
  instead of comparing `GetExitCodeProcess` against `STILL_ACTIVE`, removing
  the ambiguity where exit code 259 was indistinguishable from "still running".

- Protected-process confirmation now compares user input against the
  sanitized process name, so what the prompt displays is exactly what the
  user must type (PID fallback still works).

- Windows TUI Caps Lock behavior no longer turns an intended lowercase `x` into
  force-kill. The force-kill key now requires an explicit Shift-modified `X`, so
  a Caps Lock uppercase `X` stays on the normal termination path.
- Typed force confirmation now accepts `force` case-insensitively, so `FORCE`
  does not trap users who entered the confirmation prompt with Caps Lock enabled.
- Protected-process confirmation now matches process names case-insensitively on
  Windows, matching Windows protected-name policy.
- Windows termination now waits briefly for a successful `TerminateProcess` call
  to complete before reporting success, reducing stale post-kill refreshes where
  a port can still appear immediately after the kill request.
- No-match related-process diagnostics now skip Kickoutchi's current process and
  its ancestors, avoiding false hints for the parent PowerShell/cargo command
  that launched `kick list --port <PORT>`.

- CLI `kill --yes` now prints the target banner — identity, ports, equivalent
  command, and any safety warnings (system/service process, ownership by another
  uid, partial metadata, child processes) — to stderr before signalling, instead
  of showing them only on the interactive confirmation path. `--yes` opts out of
  the prompt, not the warnings; the protected-process and unsafe-PID gates are
  unchanged, and stdout and exit codes are untouched so scripts are unaffected.
- TUI kill status lines now report only the signal outcome instead of also
  claiming a refreshed snapshot before the post-kill re-collect has run. The freed
  port still drops from the table via the best-effort refresh, but a failed
  re-collect surfaces as the usual error line rather than a status that overstates
  a refresh that did not happen.
- TUI header now lists `x/X kill` so the force-kill key is discoverable from the
  main screen, matching the input handling and the help modal.
- TUI termination now re-collects the port snapshot when a target exits between
  confirmation and `pidfd_open`. The prepare-error already-exited path returned
  without re-collecting, leaving the freed port on the table for up to one refresh
  interval. Other prepare failures (permission denied, an old kernel) leave the
  process running, so the table is already current for them.
- Termination confirmations now warn when a target is classified as a
  system/service process, not only when it is on the protected-process list.
- Pre-signal revalidation now reports ownership unavailable if any confirmed
  target port becomes visible without a readable PID, including mixed cases where
  another confirmed port still has the original PID.
- No-match related-process diagnostics no longer treat colon-shaped incidental
  tokens such as `duration:3000ms` or `host:3000abc` as socket evidence.
- `kill --port` now refuses inherited/shared listening sockets instead of
  signaling one arbitrary owner and reporting success while another process keeps
  the port open. The Linux collector emits one row per PID referencing the same
  socket inode, which lets the existing ambiguous-target guard list every
  candidate and require `--pid`.
- `kill --port` on a visible port whose owning PID is unavailable now exits with
  the documented permission-denied code `4` instead of the no-match code `3`,
  including when ownership becomes unavailable during the mandatory pre-signal
  revalidation.
- `kill --pid` now matches `kill --port` and the TUI when a confirmed target port
  stays visible but its owning PID becomes unreadable during pre-signal
  revalidation: it exits with the permission-denied code `4` instead of the
  no-match code `3`, and still sends no signal. A shared ownership-unavailable
  check now backs all three paths so they cannot drift.
- TUI pre-signal revalidation now reports an owner whose PID became unreadable as
  ownership-unavailable, matching the CLI, instead of labelling it a changed
  target; both still refuse to send a signal.
- Removed the stale `#[allow(dead_code)]` from `ExitReason`; every variant is
  now constructed by the CLI exit path, so the lint suppression would have
  hidden genuinely unreachable variants in later refactors.
- TUI `Esc` no longer quits when a filter is still applied after search editing
  finished: with no modal open and a non-empty filter, `Esc` now clears the
  filter and only quits on a second press once nothing is left to clear. An open
  modal still takes precedence. Previously, pressing `Enter` to finish a search
  and then reflexively pressing `Esc` ended the session instead of dropping the
  filter.
- TUI auto-refresh now schedules the next refresh from collection completion
  time instead of collection start time, avoiding an immediate repeat refresh
  when a slow `/proc` scan takes longer than the configured interval.
- CLI `list` now prints `no open ports visible` when `hide_system_processes`
  suppresses every collected row, instead of implying the machine has no open
  ports at all.
- TUI help modal title now reads `Kickoutchi` instead of an outdated numbered
  title.
- TUI status bar, borders, titles, and muted text now use terminal-default or
  bold-reversed styles instead of fixed dark-gray/black combinations, so the
  interface remains readable in both light and dark terminal themes.
- Linux collection no longer fails the whole scan when optional IPv6 socket
  tables such as `/proc/net/tcp6` or `/proc/net/udp6` are absent; IPv4 socket
  tables remain required.
- IPv4-mapped IPv6 socket addresses such as `::ffff:127.0.0.1` are normalized
  or classified as IPv4 loopback/local addresses instead of being mislabeled as
  generic local IPv6 binds.
- Terminal-state leak on TUI startup errors: a failure between enabling raw
  mode and constructing the terminal (entering the alternate screen, or the
  terminal's initial size query) now restores the terminal before the error
  propagates, instead of leaving the shell stuck in raw mode. Clean exits,
  propagated errors after startup, and panics were already covered by the
  guard and panic hook; this closes the remaining error window during setup.

### Added

- Release/distribution setup: `cargo-dist` now generates a GitHub Release
  workflow for Linux, macOS, and Windows archives, with shell and PowerShell
  installers, per-artifact checksums, `sha256.sum`, and `dist-manifest.json`.
  The repository also includes a Nix flake for `nix run` / `nix profile install`
  and Arch `kickoutchi` / `kickoutchi-bin` PKGBUILD templates.

- Optional Docker port-ownership enrichment in TUI details: Docker-looking or
  metadata-hidden port owners can be matched to running containers by published
  host port, protocol, and host address through a bounded
  `docker container ls --filter publish=...` lookup. Details can show container
  name/ID, Compose project/service labels, and a safer `docker stop <container>`
  command when exactly one container matches; Docker failures remain non-fatal
  enrichment misses.

- Native macOS support: `kickoutchi`/`kick` now lists TCP listeners and bound UDP
  sockets through `libproc` / `sysctl`, enriches rows with process metadata when
  available, uses start-time-guarded single-PID `SIGTERM` / `SIGKILL`
  termination, and renders macOS equivalent commands as `kill <PID>` or
  `kill -9 <PID>`. The default macOS path has no `lsof` dependency.
- macOS validation coverage now includes Darwin socket/procargs unit tests,
  a macOS-only CLI listener/interactive-kill smoke test, a GitHub Actions macOS
  job, and `mise` tasks for Linux-hosted Darwin `cargo check` / strict Clippy
  runs on both `x86_64-apple-darwin` and `aarch64-apple-darwin`.

- Human-display sanitizer that strips control characters, newlines, and ANSI
  escape sequences from OS-provided process metadata before rendering it in
  CLI table output, TUI table/details/confirm modals, kill banners, and
  confirmation prompts. JSON output stays raw and structured.

- Short `kick` binary integration test verifying that `--help` reports
  `Usage: kick`, `--version` reports the canonical `kickoutchi` name, and
  `list --json` prints valid JSON.

- Windows CLI contract coverage now starts a real local TCP listener, verifies
  `list --port` sees it, confirms `kill --pid` interactively with `y`, waits for
  the helper to exit, and verifies the port disappears. This complements the
  existing Windows unit coverage for IP Helper row normalization and Windows
  termination error mapping.

- `mise.toml` now includes local task aliases for formatting, strict Clippy,
  tests, the combined CI-equivalent check, and common `run`/`list` commands.
- Linux `/proc/<pid>/stat` start-time parsing is now tested for a `comm` that
  contains `) `, pinning the right-split that keeps the parse robust against
  unescaped parentheses in the process name.
- Linux CLI contract coverage now includes a real `SIGTERM` path: a controlled
  helper process binds a TCP listener, `kickoutchi kill --pid --yes` terminates
  it, and a follow-up list confirms the port disappears.
- TUI confirmed-kill execution is now covered with injected collection/context/
  termination seams, including successful refresh and stale process-identity
  refusal without sending a signal.
- GitHub Actions CI now runs on Linux pushes and pull requests, using the pinned
  Rust toolchain to check formatting, strict Clippy, and the full test suite.
  Release/CD automation is handled by the dedicated `cargo-dist` workflow.
- CLI contract integration tests now exercise script-facing `list` behavior with
  the real binary: human no-match diagnostics go to stderr, `list --json` stays
  unpolluted, and explicit no-match filters exit `3`. The helper process uses
  `sh`, so the suite needs no Python (or any other interpreter) on PATH.

- Safe termination MVP: Linux `kill` now sends real `SIGTERM` or
  `SIGKILL` through a small `libc` boundary instead of shelling out, with typed
  outcomes for success, permission denied, already exited, cancelled, protected
  process, stale confirmed target, unsafe PID, and unknown failure. Real signal
  delivery is Linux-only until native non-Linux collectors exist.
- Shared kill command rendering in `command.rs` shows the equivalent user-facing
  command (`kill <PID>`, `kill -9 <PID>`, or platform-specific equivalents) in both
  CLI and TUI confirmation flows.
- CLI `kickoutchi kill --pid <PID>` and `kickoutchi kill --port <PORT>` now use
  the same safety rules as the TUI: PID `0`, PID `1`, and Kickoutchi's own PID
  are blocked; protected processes require typing the PID or process name;
  `--yes` cannot bypass protected-process confirmation; and `kill --port`
  refuses ambiguous targets instead of guessing. After confirmation, the target
  is re-collected and must still match the confirmed PID and port rows before a
  signal is sent.
- TUI termination flow: `x` opens normal termination confirmation, `X` opens
  force-kill confirmation, force kill requires typing `force`, protected
  processes require typing the PID or process name, child/owner/permission
  warnings are shown when available, and the table refreshes immediately after a
  kill attempt.
- Safe-termination tests cover PID guardrails, target ambiguity, confirmation decisions,
  command rendering, TUI confirmation state/rendering, and CLI exit-code mapping.
- TUI kill confirmation now lists every port owned by the target PID, gathered
  from the full snapshot so active filters cannot hide a port the signal will
  still free.

- Process context and protected-process policy: the selected TUI row
  now resolves direct child PIDs and child process names only when the user opens
  the details modal, shows owner UID when available, and keeps the child scan
  bounded so scrolling the table does not walk the process list.
- Protected-process matching now lives in `protection.rs`, with exact
  case-sensitive matching on Unix-like platforms and exact case-insensitive
  matching ready for Windows.
- No-match port diagnostics for human CLI output: when an explicit port query
  finds no confirmed listening TCP or bound UDP socket, Kickoutchi can print
  evidence-only related-process hints to stderr based on strict port-shaped
  command-line matches such as `:3000`, `--port 3000`, `--port=3000`, `-p 3000`,
  `PORT=3000`, and `python3 -m http.server 3000`.
- Diagnostic hints do not create fake table rows, do not claim ownership, do not
  change the `list --port` no-match exit code, and do not pollute `list --json`.

- Filtering, sorting, and refresh: the TUI now supports manual
  refresh with `r`, automatic refresh using the configured interval, search mode
  with `/`, and sort cycling with `s`.
- Shared query engine for CLI and TUI filtering: plain search matches visible
  row fields such as port, PID, protocol, address, process name, executable
  path, command line, bind scope, and parent process; structured filters support
  `pid:`, `port:`, `proto:`, `scope:`, `protected:`, and `parent:`.
- Additional sort modes for parent process and bind scope, with scope sorting
  surfacing public binds before local and loopback binds.
- Linux parent-process collection backing the parent filter and sort: `parent_pid`
  from `/proc/<pid>/status` and the parent name from `/proc/<ppid>/comm`, feeding
  the `parent:` filter, parent sorting, the details-panel parent line, and PID-1
  child hiding. Implemented alongside filtering and sorting so the parent filter
  and sort operate on real data instead of always-empty fields.
- TUI refresh state now keeps the last successful snapshot separate from the
  latest collector error, so a failed refresh reports the error without erasing
  the last good table.
- Selection preservation across refresh/filter/sort by PID, protocol, local
  address, and port, falling back to the nearest sensible row when the selected
  process disappears.
- `kickoutchi list --filter <TEXT>` and `kickoutchi list --sort <MODE>` for the
  same search/filter/sort behavior used by the TUI.
- Config support for `hide_system_processes`, implemented conservatively for
  PID 0/1, direct PID-1 children, and known OS process names without hiding
  protected app processes such as `postgres` by default.

- Linux native collector: on Linux, `kickoutchi`/`kick` now reads
  `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`
  directly, keeps TCP `LISTEN` sockets and bound UDP sockets, decodes IPv4 and
  IPv6 local addresses, extracts socket inodes, and maps them to owning PIDs by
  walking `/proc/<pid>/fd` symlinks.
- Linux process metadata enrichment: readable owners now include process name,
  executable path, and command line from `/proc/<pid>/comm`, `/proc/<pid>/exe`,
  and `/proc/<pid>/cmdline`; restricted or raced metadata keeps the port row and
  marks it partial instead of dropping it.
- Deterministic Linux collector tests for `/proc/net` parsing, TCP state filtering, UDP
  bound rows, IPv4/IPv6 decoding, malformed rows, socket inode parsing,
  command-line decoding, and partial metadata behavior.

- Static TUI skeleton: the bare `kickoutchi`/`kick` command now opens
  a full fake-data TUI with a header, the open-ports table, a selected-row
  details panel, and a status bar showing row count, refresh age, sort mode,
  and filter state.
- TUI app state (`app.rs`) and key-to-action input mapping (`input.rs`):
  bounded `j`/`k`/Up/Down selection, `Enter` for a details modal, `?` for a
  help modal, `Esc` closing modals (or quitting when none is open), and rows
  marked protected and sorted through the same shared model code as the CLI.
- UI modules `table`, `details`, `help`, and `theme`: missing metadata renders
  as `-`, partial-permission and protected rows get distinct styling with the
  reason explained in the details panel, child PIDs distinguish "not loaded"
  from none, and `NO_COLOR` disables colors while keeping non-color emphasis.
- Terminal-size fallback message when the viewport is smaller than 80x20.
- Render tests over a ratatui `TestBackend` (default frame, help modal,
  details modal, too-small fallback) plus app-state transition tests for
  selection bounds, modal flow, and empty-row behavior.

- Short binary name `kick`: the crate now installs both `kickoutchi`
  (canonical) and `kick` (short alias for CLI use) from the same source, with
  `default-run` keeping `cargo run` on the canonical binary. The help usage
  line follows the invoked name; `--version` reports the canonical name.

- Shared domain model: `PortEntry` with the full
  protocol/address/port/state/process/parent/permission shape, plus the
  `Protocol`, `SocketState`, `Platform`, `PermissionStatus`, and `SortMode`
  vocabulary shared by the CLI, TUI, and additional collectors.
- `Collector` trait with a deterministic `FakeCollector` covering full
  metadata, permission-restricted partial rows, IPv6, bound UDP, and a
  default-protected process name.
- Config file support: `~/.config/kickoutchi/config.toml` (XDG via `dirs`)
  with `refresh_interval_seconds`, `default_sort`, `confirm_force_kill`, and
  `protected_processes`; missing file means safe defaults, invalid file is a
  hard error naming the file and the bad value; bounded values and a capped
  protected list.
- Non-TUI CLI: `kickoutchi list` (`--port`, `--process`, `--json`) and the
  `kickoutchi kill` command shape (`--pid`/`--port`, `--force`, `--yes`) with
  confirmation prompts routed to a stub until real termination lands; CLI
  commands never open the TUI.
- Stable script-facing exit codes (0–6) defined and tested in one place;
  `--yes` never bypasses the protected-process path (exit 6).
- CLI-over-config precedence via global `--config <FILE>` and
  `--refresh-interval <SECONDS>` flags, with shared bounds enforced by clap at
  parse time.
- Table and JSON output layer; missing metadata renders as `-` in tables and
  `null` in JSON, and the JSON field/enum shape is pinned by tests.
- Cargo manifest metadata (`description`, `license`, `repository`, `authors`,
  `readme`) required for later `cargo publish`/`cargo-dist` release work.
- Project foundation: Rust 1.95.0 pinned via `mise.toml`, edition
  2024, and strict lints (`warnings = "deny"`, `clippy::pedantic`).
- Core dependency set: ratatui, crossterm, clap, serde, serde_json, toml,
  thiserror, anyhow, tracing, and tracing-subscriber.
- Module boundaries: `main`, `config`, `error`, and `ui`.
- Safe terminal lifecycle: an RAII `TerminalGuard` that enters raw mode and the
  alternate screen and restores both on drop (clean exit, propagated error, or
  panic), plus a panic hook that restores the terminal before the message prints.
- Minimal event loop with a bounded poll that quits on `q`, `Esc`, or `Ctrl+C`.
- `tracing` diagnostics routed to stderr only, never the TUI surface.
- Unit tests for the quit predicate, including the key-release edge case.

[Unreleased]: https://github.com/nuggocto/kickoutchi/compare/v1.4.5...HEAD
[1.4.5]: https://github.com/nuggocto/kickoutchi/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/nuggocto/kickoutchi/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/nuggocto/kickoutchi/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/nuggocto/kickoutchi/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/nuggocto/kickoutchi/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/nuggocto/kickoutchi/compare/v1.3.10...v1.4.0
[1.3.10]: https://github.com/nuggocto/kickoutchi/compare/v1.3.9...v1.3.10
[1.3.9]: https://github.com/nuggocto/kickoutchi/compare/v1.3.8...v1.3.9
[1.3.8]: https://github.com/nuggocto/kickoutchi/compare/v1.3.7...v1.3.8
[1.3.7]: https://github.com/nuggocto/kickoutchi/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/nuggocto/kickoutchi/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/nuggocto/kickoutchi/compare/v1.3.1...v1.3.5
[1.3.1]: https://github.com/nuggocto/kickoutchi/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/nuggocto/kickoutchi/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/nuggocto/kickoutchi/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/nuggocto/kickoutchi/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/nuggocto/kickoutchi/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/nuggocto/kickoutchi/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/nuggocto/kickoutchi/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/nuggocto/kickoutchi/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/nuggocto/kickoutchi/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nuggocto/kickoutchi/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nuggocto/kickoutchi/releases/tag/v0.1.0
