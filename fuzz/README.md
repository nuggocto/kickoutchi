# Bounded parser campaigns

These Linux-only targets exercise pure byte-to-data adapters:

- `config`: bounded config reads, UTF-8 decoding, TOML parsing, and semantic
  validation;
- `linux_proc`: synthetic process-stat, process-status, and socket-table text;
- `archive_member_path`: release-archive member-path canonicalization.

They do not terminate processes, inspect the host, invoke Docker, or use the
network. Each entry point rejects input beyond its stated byte limit before
parsing, and the workflow also enforces per-input time, total campaign time, and
resident-memory limits.

The small checked-in corpora are replayed by ordinary Rust tests on every CI
run. Longer mutation campaigns run weekly or through manual workflow dispatch:

```console
(
  campaign_corpus="$(mktemp -d)"
  trap 'rm -rf "$campaign_corpus"' EXIT
  cp -a fuzz/corpus/config/. "$campaign_corpus"/
  cargo +nightly-2026-07-01 fuzz run config "$campaign_corpus" -- \
    -max_total_time=60 -max_len=65537 -timeout=5 -rss_limit_mb=1024
)
```

The auxiliary crate and its exact dependency lock are checked by cargo-deny in
ordinary CI. Campaign build output, coverage, and failure artifacts are ignored
by git, and the working corpus above is deleted when the campaign ends. When a
scheduled campaign fails, the workflow uploads `fuzz/artifacts/<target>/` as
`parser-campaign-failure-<target>` for 14 days. The upload includes
`REPRODUCE.txt` with the commit, toolchain, and replay command. To keep a
failure, minimize the input from `fuzz/artifacts/config/` and copy only the
chosen regression fixture into `fuzz/corpus/config/`. Substitute the matching
target and saved-corpus directory when running the other campaigns.
