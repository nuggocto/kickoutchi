# Security Policy

## Supported Versions

Security fixes are provided for the latest published release. Upgrade to the
newest GitHub Release before reporting behavior that may already be fixed.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form for this repository:

<https://github.com/nuggocto/kickoutchi/security/advisories/new>

Include the affected version and platform, the required local permissions,
reproduction steps, impact, and the least sensitive evidence needed to explain
the issue. Do not include credentials, personal command lines, or another
user's process metadata.

You should receive an acknowledgement within seven days. No testing against
third-party or production systems is authorized by this policy.

## Sensitive Output

Treat output from `list`, `list --snapshot-json`, `watch`, `why`, and `inspect` as
sensitive local-system data, whether it is human-readable or structured.

`list --json` is a compatibility interface that can include process and parent
names, executable paths, and complete command lines. `inspect` can expose command
lines, names, paths, parent and child relationships, PIDs, and ports. Command
lines commonly contain tokens, credentials, URLs, file paths, or user data.

Snapshot, watch, and Why never collect or serialize complete process command
lines. They can still expose endpoints, PIDs, stable process-start markers,
process and parent names, executable paths where applicable, ownership,
configured labels, namespace or scope identifiers, evidence, evidence gaps, and
raw or explanatory OS errors. Labels can reveal project names, service roles,
and local topology.

Terminal sanitization protects human output, and JSON escaping preserves JSON
syntax. Structured host strings can still contain terminal-significant Unicode,
so JSON is not safe for direct terminal display. Neither mechanism is redaction.
Before sharing output, remove or replace command lines, PIDs and start markers,
names, paths, parent relationships, addresses and ports, labels, scope
identifiers, and evidence and error messages. Prefer the smallest excerpt needed
to report the issue, and preserve stable schema codes only when they are
relevant.

## Observation And Probe Limits

A complete result is complete only inside the collector's declared scope. Linux
observes the current network namespace and can have separate procfs/PID namespace
ownership gaps. Native Windows does not observe the WSL network stack. macOS
collection is process-first and cannot include sockets without a visible
user-process descriptor. Elevation may reveal more identities, metadata, or
termination handles, but it does not remove these scope boundaries; Kickoutchi
does not elevate itself.

Watch compares periodic snapshots. Activity that starts and ends between polls
can be missed, multiple changes can collapse into one net difference, and event
timestamps are observation intervals rather than exact kernel times. A missing
event is not proof that no transient activity occurred.

Why takes one snapshot and then performs sequential exact bind probes. A
successful probe temporarily occupies the endpoint until its immediate close
and can briefly race a concurrent binder. After close, another process can bind
before output is rendered or acted upon, so `bindable_now` is not a reservation
or future guarantee. Snapshot ownership evidence can also change before a later
probe. Run Why only against endpoints where this short-lived bind is acceptable.

The optional related-process hint shown after an empty human `list --port`
result is best-effort evidence. Linux and macOS read at most 64 command lines;
Windows uses the separately bounded process snapshot. A hint may omit a process,
never creates an ownership claim, and never changes structured output.
A synchronous OS operation can still exceed an application-controlled duration.

## Process Authority

Kickoutchi uses only the authority already held by the current process and never
elevates itself. Linux termination retains pidfds and Windows termination retains
process handles across final validation and delivery. macOS has no equivalent
stable process handle: it stops the numeric PID, validates fresh identity and
protection evidence, and guards continuation with the identity observed after
the stop. This prevents a detected first PID replacement from being left stopped,
but a small unavoidable race remains between the final marker read and each raw
PID signal. A second replacement during that interval can make guarded cleanup
fail closed and require manual recovery.

Kickoutchi does not require elevated privileges for ordinary use. Do not run it
as root or Administrator merely to obtain more metadata unless you understand
the expanded process visibility and termination authority. Structured host data
remains sensitive.

Under `sudo` on Linux and macOS, Kickoutchi reads the configuration file of the
user who ran sudo, so that user's protected names and confirmation settings
still apply. That path is controlled by an unprivileged user, so root reads it
only when the opened file is a regular file owned by that user. A symlink to
another user's file is an error and its contents are never printed. `SUDO_UID`
is ignored unless the process is running as root.

## Security Model

The relevant attacker is a local unprivileged user or process able to influence
configuration, CLI arguments, process metadata, socket churn, child-process
output, or a downstream output consumer. Kernel and native APIs provide
authority but are not trusted for stable sizes or timing. Downloaded build
tools, GitHub Actions, package registries, release hosting, installer and
updater execution, the Homebrew tap, the Scoop bucket, Git and Nix source
installs, and AUR maintainers cross distinct trust boundaries.

Security objectives are correct process identity and signal delivery, truthful
scope and certainty claims, memory safety at native boundaries, bounded resource
use, terminal and structured-output integrity, process-metadata privacy, and
reproducible dependency and release inputs. Config and native input are bounded
before retention; terminal sinks sanitize hostile text; structured output uses
dedicated serializers; destructive actions revalidate fresh identity and
protection evidence; retries and retained event state have fixed limits;
Kickoutchi never runs external tools to collect socket evidence.

Release workflows pin actions by full commit SHA and install the exact
`cargo-dist 0.34.0` crate with Cargo's locked dependency resolution. A test-only
Rust target verifies each native archive's checksum, extracts it with the
runner's own `tar`, and rejects unexpected layouts, links, special files, wrong
executable permissions, wrong versions, and missing binary entry points, then
runs the real CLI journeys against the extracted binaries. The same target
executes every native updater and installs same-run artifacts through generated
shell and PowerShell installers on native Linux, macOS, and Windows runners before
publication. Linux updater artifacts are rebuilt from the locked
`axoupdater-cli 0.10.3` crate in the same Debian 11 containers as the application
archives, then rejected if either binary requires symbols above glibc 2.31.

Release planning has read-only repository permission; checkout never persists
GitHub credentials, and no write-scoped token is exported to release-tool
installation. Explicit repository `GH_TOKEN` values exist only on the dist
planning, hosting, and GitHub Release steps that require them. The Homebrew token
exists only on the final tap push step. GitHub permissions remain job-scoped, so
pinned actions in the host job still execute where `contents: write` is
available. A manual workflow dispatch exercises the artifact graph without tag
publication; tag runs repeat verification on their exact commit before any
release is created.

After hosting succeeds, the Homebrew publisher copies the generated formula into
the tap's `Formula` directory, commits changes, and pushes them. It does not
install or execute the formula. The tap-scoped `HOMEBREW_TAP_TOKEN` exists only
for the final push. Stable GitHub Releases are observed independently by the
public Scoop bucket's scheduled Excavator workflow, which regenerates and commits
its manifest URL and hash; Kickoutchi's release workflow does not hold a Scoop
write token. Either package repository can lag a new release or fail independently.

The documented Unix and PowerShell installer commands execute content from the
mutable GitHub Release `latest` URL. TLS and the GitHub repository are therefore
part of the trust decision before the installer can be inspected locally.
The cargo-dist-generated standalone `kickoutchi-update` uses the same release
authority. An unqualified `cargo install --git` or `github:nuggocto/kickoutchi`
Linux Nix flake reference follows the repository's default branch and can select unreleased code; `--locked` pins
the selected checkout's Cargo dependency graph, not that checkout. Select an
explicit tag or commit when reproducibility matters. The committed Nix lock pins
the flake's `nixpkgs` input, not Kickoutchi's own source revision.

The AUR account and package maintainer are another independent publisher
boundary, on the same footing as the Homebrew tap and the Scoop bucket. Arch
metadata is updated only from real public release URLs and checksums, never
placeholder hashes, and is pushed only after the corresponding GitHub Release
assets exist.

Release checksums are published through the same repository authority as their
artifacts. They detect accidental corruption but are not an independent
signature channel. After archive and installer validation, a dedicated
least-privileged job creates GitHub artifact attestations for every prepared
publication asset. Those attestations bind each file digest to the repository,
workflow, commit, and triggering event. The host cannot publish those assets
unless attestation and same-run verification succeed. The final
`dist-manifest.json` is generated during hosting, after that attestation job,
and is published without its own artifact attestation. Internal build manifests
are excluded from publication.

Release verification builds the native binaries for the exact workflow commit,
then validates each native binary archive's checksum, layout, executable
permissions where applicable, both binary entry points, runtime version, and
updater startup before publication. Linux archives are built in the Debian
containers, then downloaded from the same workflow run and validated on
native runners with the initial PID namespace and isolated network traffic.
These Linux archive checks gate both artifact attestation and publication.
Generated installers execute against local copies of those same-run artifacts
before publication. Updater smoke tests invoke
`--help`; they do not perform an update from an older installation. The workflow
does not validate installation or updating through public URLs after publication.
Homebrew publication waits for hosting, with no post-publication validation gate.
Source archives do not receive an executable journey.

GitHub remains the identity and storage trust anchor for both release assets and
their attestations. The attestations provide verifiable build provenance, but
they are not an independent publisher outside GitHub.
Users must still decide whether they trust the GitHub repository and each
package-manager publisher boundary.

Read-only inspect reports join socket owners, process-table rows, and optional
command lines only when PID and process start identity agree. A port owner that
changes between network and process collection is refused rather than attached
to the replacement process. Human endpoint output shows a known IPv6 interface
index as `%index`; addresses whose index the collector cannot report have no
suffix.

The canonical contracts and privacy distinctions are documented in the
[structured output reference](docs/structured-output.md). Configuration labels
and filters are documented in the [configuration reference](docs/configuration.md),
and permanent scope, polling, WSL, and bind-probe limitations are documented in
[platform support](docs/platform-support.md).
