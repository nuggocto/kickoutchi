# Kickoutchi ༼⁠ ⁠つ⁠ ⁠◕⁠‿⁠◕⁠ ⁠༽⁠つ

**"What are you doing in my swamp?!"**, but for whatever is squatting on your
local ports.

Kickoutchi is a terminal UI and CLI that lists local TCP and UDP sockets, shows
which process owns each one, and stops stale development servers without
touching the wrong process. Type `kickoutchi` or the short alias `kick`; both
run the same program.

Website: <https://kickoutchi.com>

## What it does

- Lists listening TCP and bound UDP sockets in a terminal UI.
- Prints the same data as a table, as legacy JSON, or as a versioned snapshot
  for scripts.
- Lets you name endpoints, such as `web dev` for `127.0.0.1:3000`.
- Streams bind and release events with `kick watch`.
- Tells you whether a port is free right now with `kick why`.
- Shows a process's parent and children before you act on it.
- Stops one process, a process tree, or a POSIX process group, after asking.
- Reads sockets through each OS's native API. It never parses `ss`, `netstat`,
  or `lsof` output.

Kickoutchi asks before it terminates anything, unless you pass `--yes`. It
refuses when it can't tell who owns a port, when the PID is unsafe, when the
process changed since you confirmed, and when the target is a protected process
you didn't confirm by name or PID.

## Install

### Package managers

```sh
# Homebrew (Linux and macOS)
brew install nuggocto/tap/kickoutchi

# Arch (AUR), prebuilt binary
yay -S kickoutchi-bin

# Cargo, from Git
cargo install --locked --git https://github.com/nuggocto/kickoutchi

# Nix (Linux only)
nix run github:nuggocto/kickoutchi
nix profile install github:nuggocto/kickoutchi
```

```powershell
# Scoop
scoop bucket add nuggocto https://github.com/nuggocto/scoop-bucket
scoop install kickoutchi
```

The release workflow updates the [Homebrew tap](https://github.com/nuggocto/homebrew-tap)
itself. The [Scoop bucket](https://github.com/nuggocto/scoop-bucket) checks for
new releases every four hours, and the AUR package is updated only once a
release's assets exist, so both can trail a release for a while. Nix builds from
this repository's flake. The AUR package source lives in
[`packaging/arch/`](packaging/arch/README.md).

### Installer script

Linux and macOS:

```sh
curl -fsS https://kickoutchi.com/install.sh | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://kickoutchi.com/install.ps1 | iex"
```

Both installers put `kick`, `kickoutchi`, and the `kickoutchi-update` updater in
`~/.cargo/bin` and add that directory to your PATH. Open a new terminal before
running `kick`. The prebuilt Linux binaries need glibc 2.31 or newer.

Each installer checks the archive and the updater against SHA-256 digests baked
into it, and stops if it can't verify them. `kickoutchi.com/install.sh` is a
byte-for-byte copy of the current release's `kickoutchi-installer.sh`;
`install.ps1` redirects to `kickoutchi-installer.ps1` on the latest GitHub
Release.

Release pages also offer the archives directly, with a `.sha256` file per
archive and a `sha256.sum` for the whole release. Those checksums catch a
corrupted download. They come from the same GitHub repository as the archives,
so they are not an independent signature.

### Updating

Kickoutchi never checks for updates on its own. Update with whatever installed
it:

```sh
# Installer script
kickoutchi-update

# Homebrew
brew update && brew upgrade nuggocto/tap/kickoutchi

# Arch (AUR): a normal system upgrade covers it
yay -Syu

# Nix profile (Linux only)
nix profile upgrade kickoutchi

# Cargo, from Git
cargo install --force --locked --git https://github.com/nuggocto/kickoutchi
```

```powershell
# Scoop
scoop update
scoop update kickoutchi
```

A Git or Nix install without a tag follows the default branch, which can be
ahead of the latest release. To pin a release, name its tag: add `--tag v1.7.1`
to `cargo install`, or use `github:nuggocto/kickoutchi/v1.7.1` with Nix. Replace
a direct-archive install by hand, after checking the new archive's checksum.

## Quick start

```sh
kickoutchi                              # open the TUI
kick list                               # list visible ports
kick list --port 3000                   # one port
kick list --process node --sort pid     # match a process name, sort by PID
kick list --json                        # stable array for scripts
kick list --snapshot-json               # full versioned snapshot
kick inspect --port 3000                # the owner's process family
kick watch --port 3000 --duration 30s   # stream socket changes
kick why 3000                           # is TCP 3000 free on loopback?
kick kill --port 3000                   # confirm, then stop the owner
kick kill --pid 4242,4243,4244 --yes    # several processes, one summary
kick kill --pid 12345 --tree            # a process and its descendants
kick kill --pid 12345 --group           # a process group (Linux, macOS)
```

Running `kick` or `kickoutchi` with no subcommand opens the TUI.

### TUI keys

| Key | Action |
| --- | --- |
| `j` / `k`, arrows | Move the selection |
| `Enter` | Open details for the selected row |
| `/` | Edit the search filter; `Enter` keeps it, `Esc` clears it |
| `s` | Cycle the sort mode |
| `r` | Refresh now |
| `x` / `X` | Terminate / force-kill the selected process |
| `t` / `T` | Terminate / force-kill the selected process tree (Linux and macOS) |
| `m` | Show full kill results and errors |
| `?` | Help |
| `Esc` | Clear the search, close a modal, or quit |
| `q`, `Ctrl+C` | Quit |

The table refreshes every `refresh_interval_seconds` (3 by default), or at the
rate you pass with `--refresh-interval SECONDS`.

On Linux and macOS, closing the terminal window ends the TUI at once, by
`SIGHUP`, unless it was started with `SIGHUP` ignored (for example under
`nohup`). `SIGTERM`, as sent at shutdown, restores the terminal first and then
ends it.

Row colors tell you what you can act on:

- Bold rows have an owner Kickoutchi could read, usually one of your own
  processes.
- Plain rows have a hidden owner: the socket is visible, but its process
  belongs to someone Kickoutchi can't read, usually another user.
- Yellow rows have a known PID with some details unreadable.
- Red rows are protected processes. Killing one asks you to type its PID or
  name.

Set `NO_COLOR` to drop the colors. Bold and reverse video stay. The colors come
from your terminal's palette, so the table follows your theme.

### Running with sudo

As a normal user you see `-` for the PID and process of most system sockets,
and you can only stop your own processes. Under `sudo kick` every owner shows,
the plain rows turn bold, and protected services such as `postgres` or
`docker-proxy` show in red.

`sudo kick` still reads your configuration, not root's. On Linux and macOS it
looks in the home directory of the user who ran sudo, and reads the file only if
that user owns it. [`docs/configuration.md`](docs/configuration.md#running-under-sudo)
has the details.

### What `kill` will and won't target

A plain `kill --pid PID` acts only if a fresh socket snapshot shows that the
PID owns at least one visible open port. If the process is alive but owns no
port, Kickoutchi says so and suggests `--tree`. `--tree` and `--group` (Linux
and macOS) can target a portless process, because they look it up in the
process table instead.

On a normal desktop Kickoutchi can't read root and service processes, so it
can't prove nobody else shares a port's socket. When the port has exactly one
owner it can verify, `kill --port` prints a note and targets that owner. Before
sending anything it checks the port again, and refuses if a second visible
owner, or a gap in what it can see for that port, has appeared. If a hidden
process did share the socket, the report afterwards says the port is still
open. A port whose owner it can't read at all is refused, with the reason, such
as "the socket belongs to another user".

`--yes` skips the prompt for exactly the target that was resolved. It doesn't
widen the target or skip any check.

Kickoutchi always refuses PID 0, PID 1, the Windows System process (PID 4), and
itself. Tree and group kills also refuse any scope that contains Kickoutchi, so
it can't stop itself halfway through its own cleanup.

### Several targets

Repeat `--pid` or `--port`, or separate values with commas, to stop up to 128
processes in one command. Each target gets the same checks as a single kill.
Kickoutchi resolves every target first. If any target is unresolved, protected,
or can't be shown to own its port, it lists every refusal and sends nothing.
Otherwise it shows one banner, asks once, and prints one summary:

```text
summary: sent SIGTERM to 31 of 31 process(es); 31 exited; 31 of 31 confirmed port(s) no longer visible; 0 failed
```

Failures, survivors, and ports still open get their own lines below. The exit
code is the most serious outcome across all targets, in the order 1, 4, 6, 3.
`--tree` and `--group` take a single target, and one command can't mix PIDs and
ports.

### After the signal

A delivered signal doesn't mean the process exited, and a closed listener
doesn't either. After delivery, `kill` waits up to two seconds and reports, on
separate lines, whether each process exited and whether the ports are still
open.

If a process closes its port but keeps running, Kickoutchi warns you and prints
the command to force it on Linux and macOS: `kick kill --pid PID --force` while
it still owns a port, or `kick kill --pid PID --tree --force` once its ports are
closed (that also stops its children). Tree and group kills report how many
members exited and list the PIDs still running.

Exit code 0 means the signal was accepted. Read the report to learn whether the
process is gone.

## Watching changes

`kick watch` takes a snapshot on every interval and reports what changed:

```sh
kick watch
kick watch --tcp --address 127.0.0.1 --port 3000
kick watch --filter label:web --interval 500ms
kick watch --filter state:established --duration 30s --json
kick watch --filter pid:4242 --matched-only
```

The interval is 1 second by default and accepts `100ms` to `60s`. `--duration`
accepts `100ms` to `7d`. With `--json`, each line is one
`kickoutchi.watch_event/1` object.

Watch polls; it doesn't receive kernel events. A socket that opens and closes
between two polls is never seen, and event times are the capture window, not
the exact moment. A failed poll prints a `collection_gap`; three failures in a
row stop the command. Ctrl-C, the end of `--duration`, and a closed stdout all
exit successfully.

When a filter depends on something Kickoutchi can't read, such as the owner of
another user's socket, watch reports the event as `indeterminate` rather than
hiding a possible match. That means a PID filter can print events for unrelated
sockets. `--matched-only` keeps only definite matches, at the cost of missing a
match behind a permission boundary. Collection gaps always print.

## Is a port free?

`kick why PORT` takes one snapshot, then tries an exact bind on each endpoint in
turn, and prints one line per endpoint. It never stops a process.

```text
TCP 127.0.0.1:3000  in use by PID 4242 (node)
TCP [::1]:3000      free
```

`--verbose` prints every probe result, piece of evidence, and collection gap.
`--json` prints a `kickoutchi.why/1` document.

```sh
kick why 3000
kick why 5353 --udp --address 127.0.0.1
kick why 3000 --tcp --address :: --ipv6-only --json
kick why 3000 --all-protocols --all-addresses --json
```

A successful probe holds the port for an instant and then lets it go. It shows
the bind worked at that moment; it doesn't reserve the port, and another process
can take it right after.

## Configuration

The file lives at `~/.config/kickoutchi/config.toml` on Linux, and in the
platform config directory on macOS and Windows. `--config FILE` picks another
file. On Linux and macOS that file must be a regular file, a symlink to one, or
`/dev/null`; a FIFO is rejected. Unknown keys, and files over 64 KiB, are
errors. [`config.example.toml`](config.example.toml) is a ready-to-copy
starting point.

```toml
refresh_interval_seconds = 3
default_sort = "port"
hide_system_processes = false
confirm_force_kill = true
protected_processes = ["redis-server"]

[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "tcp"
address = "*"
port = 8080
label = "local web services"
```

- `hide_system_processes` hides rows Kickoutchi classifies as system or service
  processes from `list` and the TUI. It can't classify a row whose owner is
  hidden, so those stay visible, and the option hides more under `sudo`.
- `protected_processes` adds names to the built-in list; it never replaces it.
- An exact endpoint label wins over a wildcard (`"*"`) label for the same port.
- The old `docker_enrichment` and `check_for_updates` keys are still accepted
  and ignored, so older files keep loading.

`list`, the TUI search, and `watch` accept plain search words plus `pid:`,
`port:`, `proto:`, `scope:`, `protected:`, `parent:`, `label:`, `address:`,
`scope_id:`, and `family:` terms; `watch` also takes `state:`. Every term must
match. A misspelled field such as `prot:tcp` is an error that suggests `proto:`,
while other text with a colon, such as `localhost:3000`, is a plain search.

[`docs/configuration.md`](docs/configuration.md) covers paths, precedence,
validation, and every filter field.

## Structured output

- `list --json` prints the `kickoutchi.list/1` array. It can include process
  names, paths, parent details, and full command lines.
- `list --snapshot-json` prints one `kickoutchi.snapshot/1` object: everything
  the collector saw, within its platform's limits.
- `watch --json` prints `kickoutchi.watch_event/1` lines (NDJSON).
- `why --json` prints one `kickoutchi.why/1` document.

This output can contain sensitive local details: endpoints, PIDs, names,
executable paths, labels, and command lines. JSON escaping and terminal
sanitizing are not redaction, so review it before you share it. The schemas are
in [`docs/structured-output.md`](docs/structured-output.md).

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | The command finished and what you asked for holds |
| 1 | Operational or internal failure |
| 2 | Invalid arguments |
| 3 | No match, or a requested endpoint is unavailable |
| 4 | Permissions prevented a reliable answer |
| 5 | You cancelled the kill |
| 6 | A protected process needs confirmation |

## Platform support

| Platform | Release targets | Notes |
| --- | --- | --- |
| Linux | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | Stopping processes needs Linux 5.3+ (pidfd) |
| macOS | `x86_64-apple-darwin`, `aarch64-apple-darwin` | Intel and Apple Silicon |
| Windows | `x86_64-pc-windows-msvc` | x64; termination through process handles and Job Objects |

- Linux reads `/proc` and sees the current network namespace. The PID namespace
  and procfs permissions can hide some owners.
- macOS finds sockets through each visible process's file descriptors, so a
  socket no visible process holds doesn't appear.
- Windows reads the IP Helper tables and doesn't see WSL, which has its own
  network stack. Run the Linux build inside WSL to see WSL sockets.
- `kill --tree` works on all three. The TUI's `t` / `T` keys and `kill --group`
  are Linux and macOS only.

### Reading the output

- `127.0.0.1` and `::1` are loopback addresses.
- `0.0.0.0` and `::` listen on every interface. Kickoutchi labels them
  `public`, but your firewall still decides whether anything outside can reach
  them.
- `fe80::/10` addresses are IPv6 link-local and stay on the local link.
- An IPv6 suffix such as `%3` is an interface index. Linux and macOS can't
  report it, so their IPv6 addresses show no suffix and JSON records the scope
  as `unavailable`.
- `-` in the PID or process column means Kickoutchi couldn't read the owner,
  not that there is none. `kick list` explains these rows on stderr: sockets of
  other users' processes (named by account on Linux), sockets with no owner it
  could attribute, and sockets no readable process holds, such as kernel-held
  ones.
- On Linux, a process whose executable was deleted or replaced after it started
  (often a stale build, or a leftover from a package upgrade) is flagged in
  `kick list`, `kick inspect`, and the kill banner. `kick inspect` also notes
  when init or a service manager adopted the process, a hint that its launcher
  exited and it may be orphaned.

The TUI's `SCOPE` column, `--sort scope`, and the `scope:` filter call wildcard
addresses `public`, loopback addresses `loopback`, and other concrete addresses
`local`. The `kick list` table has no `SCOPE` column.

"Complete" always means complete within what the platform's collector can see.
[`docs/platform-support.md`](docs/platform-support.md) explains those limits.

## Security

Kickoutchi never raises its own privileges. Kills need confirmation by default,
refuse unclear or incomplete ownership, and re-check the process's identity just
before the signal. Linux keeps a pidfd and Windows keeps a process handle from
that check through delivery, so a recycled PID can't redirect the signal. macOS
has no equivalent, so a small race remains there between the last check and the
signal.

Seeing a socket, seeing its owner, and reading the owner's details are separate
permissions. An empty or partial result doesn't prove that an endpoint or owner
doesn't exist.

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/nuggocto/kickoutchi/security/advisories/new).
[`SECURITY.md`](SECURITY.md) has the full threat model and release controls.

## Build from source

You need Rust 1.95.0 or newer.

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
cargo build --locked
cargo test --locked --all-features
cargo run --bin kick -- list
```

Install your local checkout with:

```sh
cargo install --path . --locked
```

## License

[MIT](LICENSE)
