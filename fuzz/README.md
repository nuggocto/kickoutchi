# Bounded parser campaigns

These Linux-only targets feed raw bytes to the parsers:

- `config`: bounded config reads, UTF-8 decoding, TOML parsing, and validation.
- `linux_proc`: synthetic `/proc` stat, status, and socket-table text.

They never stop processes, inspect the host, or touch the network. Each entry
point rejects input over its byte limit before parsing, and the workflow also
caps time per input, total campaign time, and memory.

Ordinary Rust tests replay the small checked-in corpora on every CI run. Longer
mutation campaigns run weekly, or when you dispatch the workflow by hand:

```console
(
  campaign_corpus="$(mktemp -d)"
  trap 'rm -rf "$campaign_corpus"' EXIT
  cp -a fuzz/corpus/config/. "$campaign_corpus"/
  cargo +nightly-2026-11-09 fuzz run config "$campaign_corpus" -- \
    -max_total_time=60 -max_len=65537 -timeout=5 -rss_limit_mb=1024
)
```

Regular CI runs cargo-deny on this crate and its exact dependency lock. Git
ignores campaign build output, coverage, and failure artifacts, and the command
above deletes its working corpus when it ends.

When a scheduled campaign fails, the workflow uploads `fuzz/artifacts/<target>/`
as `parser-campaign-failure-<target>` for 14 days, with a `REPRODUCE.txt` that
records the commit, toolchain, and replay command. To keep a failure, minimize
the input from `fuzz/artifacts/config/` and copy only the chosen regression
fixture into `fuzz/corpus/config/`. For the other target, swap in its name and
corpus directory.
