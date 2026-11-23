# Security policy

## Supported versions

Security fixes go into the latest published release. Upgrade to the newest
GitHub Release before reporting something that may already be fixed.

## Reporting a vulnerability

Don't open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form for this repository:

<https://github.com/nuggocto/kickoutchi/security/advisories/new>

Include the affected version and platform, the local permissions needed,
reproduction steps, the impact, and the least sensitive evidence that explains
the issue. Leave out credentials, personal command lines, and other users'
process details.

You should get an acknowledgement within seven days. This policy doesn't
authorize testing against third-party or production systems.

## Sensitive output

Treat the output of `list`, `list --snapshot-json`, `watch`, `why`, and
`inspect` as sensitive, whether it's a human table or JSON.

`list --json` is a compatibility format that can include process and parent
names, executable paths, and full command lines. `inspect` can show command
lines, names, paths, parent and child relationships, PIDs, and ports. Command
lines often contain tokens, credentials, URLs, file paths, or user data.

Snapshot, watch, and why never collect or print full command lines. They can
still show endpoints, PIDs, process start markers, process and parent names,
executable paths, ownership, labels, namespace and scope identifiers, evidence,
evidence gaps, and OS error messages. Labels can reveal project names, service
roles, and how your machine is laid out.

Terminal sanitizing protects what a person reads, and JSON escaping keeps JSON
valid. Neither one redacts anything. JSON strings can still hold characters a
terminal would interpret, so don't print JSON straight to a terminal either.
Before you share output, remove or replace command lines, PIDs and start
markers, names, paths, parent relationships, addresses and ports, labels, scope
identifiers, and evidence and error messages. Share the smallest excerpt that
shows the issue, and keep stable schema codes only when they matter.

## What observations can and can't prove

A `complete` result is complete only within the collector's declared scope:

- Linux sees the current network namespace. The procfs mount and PID namespace
  can separately hide owners.
- Windows doesn't see the WSL network stack.
- macOS finds sockets through user-process file descriptors, so a socket that
  no visible process holds is out of scope.

Running elevated can reveal more owners, metadata, and termination handles, but
it doesn't remove these scope limits. Kickoutchi never elevates itself.

Watch compares snapshots taken at intervals. Activity that starts and ends
between two polls can be missed, several changes can collapse into one
difference, and event times are capture windows, not exact kernel times. No
event doesn't prove nothing happened.

Why takes one snapshot, then tries exact binds one endpoint at a time. A
successful probe holds the endpoint until it closes the socket a moment later,
and can briefly collide with another program binding at the same time. After
the probe closes, another process can bind before you read or act on the
result, so `bindable_now` is not a reservation. Ownership can also change
between the snapshot and a later probe. Only run why against endpoints where a
short-lived bind is acceptable.

When `list --port` finds nothing, the human output may suggest related
processes. That hint is best-effort: Linux and macOS read at most 64 command
lines, and Windows uses its separately bounded process snapshot. A hint can
miss a process, never claims ownership, and never changes JSON output. A system
call can still take longer than any limit Kickoutchi sets.

## Process authority

Kickoutchi uses only the authority the current process already has. On Linux it
holds a pidfd, and on Windows a process handle, from the final identity check
through signal delivery. macOS has no such handle. There, Kickoutchi stops the
numeric PID, checks its identity and protection again, and resumes it only if
the identity seen after the stop still matches. That keeps a detected PID
replacement from being left stopped. A small race remains between the last
identity read and each signal; if the PID is replaced a second time in that
window, cleanup refuses and may need manual recovery.

Normal use doesn't need elevated privileges. Don't run Kickoutchi as root or
Administrator just to see more metadata unless you accept the wider process
visibility and termination power that comes with it.

Under `sudo` on Linux and macOS, Kickoutchi reads the configuration of the user
who ran sudo, so that user's protected names and confirmation settings still
apply. That user controls the path, so root reads the file only if it's a
regular file owned by that user. A symlink to someone else's file is an error,
and its contents are never printed. Kickoutchi ignores `SUDO_UID` unless it is
running as root.

## Threat model

The attacker we design against is a local unprivileged user or process that can
influence configuration, CLI arguments, process metadata, socket churn,
child-process output, or a program that consumes Kickoutchi's output. Kernel
and native APIs provide authority, but Kickoutchi doesn't trust them for sizes
or timing.

The goals are:

- signals reach exactly the process that was checked;
- reports state their scope and certainty truthfully;
- native boundaries stay memory-safe;
- resource use stays bounded;
- terminal and JSON output can't be corrupted by hostile text;
- process metadata stays private;
- builds and releases come from reproducible inputs.

In practice, Kickoutchi bounds configuration and native input before keeping
it, sanitizes hostile text before it reaches a terminal, writes JSON through
dedicated serializers, re-checks fresh identity and protection evidence before
any destructive action, keeps retries and stored event state within fixed
limits, and never runs external tools to collect socket evidence.

Read-only `inspect` joins socket owners, process-table rows, and command lines
only when PID and process start time agree. If a port's owner changes between
network and process collection, Kickoutchi refuses rather than attach the new
process. Human output shows a known IPv6 interface index as `%index`; addresses
whose index the collector can't report have no suffix.

## Supply chain and releases

Build tools, GitHub Actions, package registries, release hosting, installers and
the updater, the Homebrew tap, the Scoop bucket, Git and Nix source installs,
and AUR maintainers are each a separate trust boundary.

### Build and verification

- Release workflows pin every action by full commit SHA and install exactly
  `cargo-dist 0.34.0` with Cargo's locked dependencies.
- Release planning has read-only repository access. Checkout never keeps GitHub
  credentials, and no write-scoped token reaches release-tool installation.
- `GH_TOKEN` exists only on the dist planning, hosting, and GitHub Release
  steps that need it. GitHub permissions stay job-scoped, so pinned actions in
  the hosting job still run where `contents: write` is available.
- A test-only Rust target checks each archive's checksum, extracts it with the
  runner's `tar`, and rejects unexpected layouts, links, special files, wrong
  executable permissions, wrong versions, and missing binaries. It then runs the
  real CLI journeys against the extracted binaries.
- The same target runs every native updater and installs same-run artifacts
  through the generated shell and PowerShell installers on Linux, macOS, and
  Windows runners before anything is published.
- Linux archives and updaters are built from locked crates (`axoupdater-cli
  0.10.3` for the updater) in Debian 11 containers, then rejected if either
  binary needs symbols newer than glibc 2.31. They are validated on native
  runners in the initial PID namespace with isolated network traffic before
  attestation and publication.
- Updater smoke tests run `--help`; they don't update from an older install.
- A manual workflow dispatch runs the whole artifact graph without publishing.
  Tag runs repeat verification on the exact tagged commit before creating a
  release.

### Attestations and checksums

Release checksums come from the same repository as the artifacts. They catch
accidental corruption; they are not an independent signature.

After archive and installer validation, a dedicated least-privilege job creates
GitHub artifact attestations for every asset to be published. Each attestation
ties the file's digest to the repository, workflow, commit, and triggering
event. Hosting can't publish unless attestation and same-run verification pass.
The final `dist-manifest.json` is generated during hosting, after attestation,
so it has no attestation of its own. Internal build manifests aren't published.

GitHub stays the identity and storage anchor for both the assets and their
attestations. Attestations give verifiable build provenance, but they don't add
a publisher outside GitHub. You still decide whether you trust the GitHub
repository and each package-manager publisher.

### Installers

The documented Unix command runs `kickoutchi.com/install.sh`, a copy of the
current release's `kickoutchi-installer.sh`. The website build checks it against
a recorded SHA-256 and version, which makes the website's hosting part of the
trust decision. The installer downloads archives from the pinned release and
checks each one against an embedded SHA-256.

The PowerShell command runs whatever the GitHub Release `latest` URL serves. The
release workflow embeds SHA-256 digests of the same-run Windows ZIP and updater
in that installer before validation and publication. The installer checks the
ZIP before unpacking it and the updater before writing any installed file.

These checks don't authenticate the installers themselves; TLS and the GitHub
repository are still part of the trust decision. The standalone
`kickoutchi-update` relies on the same release authority.

The workflow doesn't validate installing or updating through the public URLs
after publication. Source archives get no executable test.

### Package managers

After hosting succeeds, the release workflow copies the generated Homebrew
formula into the tap's `Formula` directory, commits, and pushes. It doesn't
install or run the formula, and nothing validates it after publication. The
tap-scoped `HOMEBREW_TAP_TOKEN` exists only for that final push.

The public Scoop bucket watches stable GitHub Releases on its own schedule and
regenerates its manifest URL and hash. Kickoutchi's release workflow holds no
Scoop write token. Either package repository can lag a release or fail
independently.

The AUR account and package maintainer are another independent publisher, like
the Homebrew tap and the Scoop bucket. Arch metadata is updated only from real
release URLs and checksums, never placeholders, and only after the matching
GitHub Release assets exist.

`cargo install --git` without a tag, and the Linux Nix flake reference
`github:nuggocto/kickoutchi`, follow the default branch and can pick up
unreleased code. `--locked` pins Cargo dependencies, not the checkout. Name a
tag or commit when you need reproducibility. The committed Nix lock pins the
flake's `nixpkgs` input, not Kickoutchi's own source revision.

## Related documentation

- [Structured output](docs/structured-output.md): the JSON contracts and their
  privacy notes.
- [Configuration](docs/configuration.md): labels and filters.
- [Platform support](docs/platform-support.md): scope, polling, WSL, and bind
  probe limits.
