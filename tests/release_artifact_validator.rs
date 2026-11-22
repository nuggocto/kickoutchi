use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str;
use std::time::Duration;

#[path = "support/command.rs"]
mod command;

use std::sync::atomic::{AtomicU64, Ordering};

// Installers use local artifacts, but extraction and PowerShell startup need
// more time than a binary version check on the slowest supported runner.
const RELEASE_COMMAND_WAIT: Duration = Duration::from_mins(2);
const BINARY_COMMAND_WAIT: Duration = Duration::from_secs(10);
const ARCHIVE_JOURNEY_WAIT: Duration = Duration::from_mins(15);

const ARCHIVE_BYTES_MAX: u64 = 256 * 1024 * 1024;
const BINARY_BYTES_MAX: u64 = 256 * 1024 * 1024;
const INSTALLER_BYTES_MAX: u64 = 4 * 1024 * 1024;
const RECEIPT_BYTES_MAX: usize = 64 * 1024;
const MAXIMUM_GLIBC_VERSION: &[u32] = &[2, 31];
const HEX: &[u8; 16] = b"0123456789abcdef";

type ValidationResult<T> = Result<T, String>;

#[derive(Clone, Copy)]
struct NativeTarget {
    triple: &'static str,
    windows: bool,
}

fn native_target(runner_os: &str, runner_arch: &str) -> ValidationResult<NativeTarget> {
    let (triple, windows) = match (runner_os, runner_arch) {
        ("Linux", "X64") => ("x86_64-unknown-linux-gnu", false),
        ("Linux", "ARM64") => ("aarch64-unknown-linux-gnu", false),
        ("macOS", "X64") => ("x86_64-apple-darwin", false),
        ("macOS", "ARM64") => ("aarch64-apple-darwin", false),
        ("Windows", "X64") => ("x86_64-pc-windows-msvc", true),
        _ => {
            return Err(format!(
                "unsupported native runner: {runner_os}/{runner_arch}"
            ));
        }
    };
    Ok(NativeTarget { triple, windows })
}

fn require_native_target(raw: &str, target: &str) -> ValidationResult<()> {
    let targets: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| format!("targets must be valid JSON: {error}"))?;
    if targets.len() == 1 && targets[0] == target {
        return Ok(());
    }
    Err(format!(
        "matrix targets {targets:?} must contain only native runner target {target}; \
         release archives require one matching native execution per job"
    ))
}

/// SHA-256 of a file, computed with the runner's own tool so the validator
/// needs no hashing dependency. Windows uses `certutil`, which ships with the
/// OS; PowerShell's `Get-FileHash` fails to load when a runner's module path
/// points Windows PowerShell at PowerShell 7 modules.
fn sha256(path: &Path) -> ValidationResult<String> {
    let path = external_tool_path(path);
    let mut command = if cfg!(windows) {
        let mut command = Command::new("certutil");
        command.arg("-hashfile").arg(&path).arg("SHA256");
        command
    } else if cfg!(target_os = "macos") {
        let mut command = Command::new("shasum");
        command.args(["-a", "256"]).arg(&path);
        command
    } else {
        let mut command = Command::new("sha256sum");
        command.arg(&path);
        command
    };
    let description = format!("SHA-256 of {}", path.display());
    let output = run_command(&mut command, &description, BINARY_COMMAND_WAIT)?;
    match parse_sha256_output(&output.stdout) {
        Some(digest) if output.status.success() => Ok(digest),
        _ => Err(format!(
            "could not compute {description}: status={}, stdout={:?}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

/// The digest from `sha256sum`/`shasum` (`HEX  FILE`) or `certutil` (a
/// header line, the hex digest, possibly space-separated, then a status line).
/// Only the hex is needed; localized tool output is not always UTF-8.
fn parse_sha256_output(stdout: &[u8]) -> Option<String> {
    let is_digest =
        |text: &str| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        let first = line.split_ascii_whitespace().next()?;
        if is_digest(first) {
            return Some(first.to_ascii_lowercase());
        }
        let joined = line.split_ascii_whitespace().collect::<String>();
        is_digest(&joined).then(|| joined.to_ascii_lowercase())
    })
}

/// Drop the Windows verbatim prefix (`\\?\`) that `canonicalize` adds, which
/// not every external tool accepts. Other paths are returned unchanged.
fn external_tool_path(path: &Path) -> PathBuf {
    path.to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .filter(|rest| !rest.starts_with(r"UNC\"))
        .map_or_else(|| path.to_path_buf(), PathBuf::from)
}

fn verify_checksum(archive: &Path, digest: &str) -> ValidationResult<()> {
    let checksum_path = PathBuf::from(format!("{}.sha256", archive.display()));
    let archive_name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "release archive filename must be UTF-8".to_owned())?;
    let metadata = fs::symlink_metadata(&checksum_path)
        .map_err(|error| format!("missing checksum for {archive_name}: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("checksum must be a regular file: {archive_name}"));
    }
    if !(1..=1024).contains(&metadata.len()) {
        return Err(format!(
            "checksum size is outside its bound: {archive_name}"
        ));
    }
    let text = fs::read_to_string(&checksum_path)
        .map_err(|error| format!("could not read {}: {error}", checksum_path.display()))?;
    if !text.is_ascii() {
        return Err(format!(
            "checksum is not ASCII: {}",
            checksum_path.display()
        ));
    }
    let mut fields = text.split_ascii_whitespace();
    let record_digest = fields.next();
    let filename = fields
        .next()
        .map(|name| name.strip_prefix('*').unwrap_or(name));
    if record_digest.is_none_or(|value| !value.eq_ignore_ascii_case(digest))
        || filename != Some(archive_name)
        || fields.next().is_some()
    {
        return Err(format!("invalid checksum for {archive_name}"));
    }
    Ok(())
}

fn expected_archive_paths(target: &str, windows: bool) -> (BTreeSet<String>, BTreeSet<String>) {
    let suffix = if windows { ".exe" } else { "" };
    let names = [
        "CHANGELOG.md".to_owned(),
        "LICENSE".to_owned(),
        "README.md".to_owned(),
        format!("kickoutchi{suffix}"),
        format!("kick{suffix}"),
    ];
    if windows {
        return (names.into_iter().collect(), BTreeSet::new());
    }
    let root = format!("kickoutchi-{target}");
    (
        names
            .into_iter()
            .map(|name| format!("{root}/{name}"))
            .collect(),
        BTreeSet::from([root]),
    )
}

fn require_exact_read(copied: u64, expected: u64, name: &str) -> ValidationResult<()> {
    if copied != expected {
        return Err(format!("release member size changed while reading: {name}"));
    }
    Ok(())
}

/// Extract a release archive with the runner's `tar` and check its layout.
///
/// GNU tar on Linux, bsdtar on macOS, and the bsdtar in Windows' System32 all
/// read their platform's archive format. The archives are this project's own
/// CI output, so the system extractor is trusted; the layout check still
/// catches a packaging change.
fn extract_release_binaries(
    archive: &Path,
    destination: &Path,
    target: NativeTarget,
    expected_binaries: &BTreeSet<String>,
) -> ValidationResult<BTreeMap<String, PathBuf>> {
    let tar = if target.windows {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "SystemRoot is not set; cannot locate tar.exe".to_owned())?;
        PathBuf::from(system_root).join("System32").join("tar.exe")
    } else {
        PathBuf::from("tar")
    };
    let description = format!("tar -xf {}", archive.display());
    let output = run_command(
        Command::new(tar)
            .arg("-xf")
            .arg(external_tool_path(archive))
            .arg("-C")
            .arg(external_tool_path(destination)),
        &description,
        RELEASE_COMMAND_WAIT,
    )?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed: status={}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    check_archive_layout(destination, target, expected_binaries)
}

/// Compare an extracted archive with the cargo-dist layout and return the
/// paths of the expected binaries.
fn check_archive_layout(
    extracted: &Path,
    target: NativeTarget,
    expected_binaries: &BTreeSet<String>,
) -> ValidationResult<BTreeMap<String, PathBuf>> {
    let (expected_files, expected_directories) =
        expected_archive_paths(target.triple, target.windows);
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let entries = fs::read_dir(extracted.join(&relative))
            .map_err(|error| format!("could not list extracted archive: {error}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not list extracted archive: {error}"))?;
            let path = relative.join(entry.file_name());
            let name = path
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let file_type = entry
                .file_type()
                .map_err(|error| format!("could not inspect {name}: {error}"))?;
            if file_type.is_dir() {
                directories.insert(name);
                pending.push(path);
            } else if file_type.is_file() {
                files.insert(name);
            } else {
                return Err(format!(
                    "release archive contains a non-regular member: {name}"
                ));
            }
        }
    }
    if files != expected_files || directories != expected_directories {
        return Err(format!(
            "release archive layout differs from the cargo-dist contract: files={files:?}, directories={directories:?}"
        ));
    }
    let mut selected = BTreeMap::new();
    for name in &expected_files {
        let basename = name.rsplit('/').next().unwrap_or_default();
        if !expected_binaries.contains(basename) {
            continue;
        }
        let path = extracted.join(name);
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("could not inspect release binary {basename}: {error}"))?;
        if !(1..=BINARY_BYTES_MAX).contains(&metadata.len()) {
            return Err(format!(
                "release binary size is outside the approved bound: {basename}"
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!("release binary is not executable: {basename}"));
            }
        }
        selected.insert(basename.to_owned(), path);
    }
    Ok(selected)
}

fn read_bounded(mut reader: impl Read, limit: usize) -> ValidationResult<Vec<u8>> {
    let read_limit = u64::try_from(limit)
        .map_err(|_| "output byte limit could not be represented".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "output byte limit overflowed".to_owned())?;
    let mut retained = Vec::with_capacity(limit.saturating_add(1));
    reader
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut retained)
        .map_err(|error| format!("could not read process output: {error}"))?;
    if retained.len() > limit {
        return Err("process output exceeded its byte limit".to_owned());
    }
    Ok(retained)
}

fn parse_glibc_version(tail: &[u8]) -> ValidationResult<Option<Vec<u32>>> {
    if !tail.first().is_some_and(u8::is_ascii_digit) {
        return Ok(None);
    }
    let end = tail
        .iter()
        .position(|byte| !byte.is_ascii_digit() && *byte != b'.')
        .unwrap_or(tail.len());
    if tail
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err("readelf reported a malformed GLIBC symbol version".to_owned());
    }

    let mut components = Vec::new();
    let mut component = None::<u32>;
    for byte in &tail[..end] {
        if *byte == b'.' {
            components.push(
                component.take().ok_or_else(|| {
                    "readelf reported a malformed GLIBC symbol version".to_owned()
                })?,
            );
            continue;
        }
        let digit = u32::from(*byte - b'0');
        component = Some(
            component
                .unwrap_or(0)
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| "readelf reported an oversized GLIBC symbol version".to_owned())?,
        );
    }
    components.push(
        component.ok_or_else(|| "readelf reported a malformed GLIBC symbol version".to_owned())?,
    );
    if components.len() < 2 {
        return Err("readelf reported a malformed GLIBC symbol version".to_owned());
    }
    while components.len() > 2 && components.last() == Some(&0) {
        components.pop();
    }
    Ok(Some(components))
}

fn maximum_glibc_requirement(output: &str) -> ValidationResult<Vec<u32>> {
    const PREFIX: &[u8] = b"GLIBC_";

    let mut remainder = output.as_bytes();
    let mut maximum: Option<Vec<u32>> = None;
    while let Some(offset) = remainder
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)
    {
        remainder = &remainder[offset + PREFIX.len()..];
        let Some(version) = parse_glibc_version(remainder)? else {
            continue;
        };
        if maximum.as_ref().is_none_or(|current| version > *current) {
            maximum = Some(version);
        }
    }
    maximum.ok_or_else(|| "readelf output contained no parseable GLIBC requirement".to_owned())
}

fn format_numeric_version(version: &[u32]) -> String {
    version
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn validate_glibc_requirements(output: &str) -> ValidationResult<Vec<u32>> {
    let maximum = maximum_glibc_requirement(output)?;
    if maximum.as_slice() > MAXIMUM_GLIBC_VERSION {
        return Err(format!(
            "release binary requires GLIBC_{}, above supported maximum GLIBC_{}",
            format_numeric_version(&maximum),
            format_numeric_version(MAXIMUM_GLIBC_VERSION)
        ));
    }
    Ok(maximum)
}

fn run_command(
    command: &mut Command,
    description: &str,
    wait: Duration,
) -> ValidationResult<Output> {
    command::run_command_with_deadline(command.stdin(Stdio::null()), None, wait)
        .map_err(|error| format!("could not execute {description}: {error}"))
}

fn run_version(binary: &Path, expected_version: &str) -> ValidationResult<()> {
    let description = format!("{} --version", binary.display());
    let output = run_command(
        Command::new(binary).arg("--version"),
        &description,
        BINARY_COMMAND_WAIT,
    )?;
    let stdout = str::from_utf8(&output.stdout)
        .map_err(|_| format!("version output was not UTF-8 for {}", binary.display()))?;
    let stderr = str::from_utf8(&output.stderr)
        .map_err(|_| format!("version stderr was not UTF-8 for {}", binary.display()))?;
    let expected = format!("kickoutchi {expected_version}\n");
    if !output.status.success() || stdout != expected || !stderr.is_empty() {
        return Err(format!(
            "unexpected version output from {}: status={}, stdout={stdout:?}, stderr={stderr:?}",
            binary.display(),
            output.status,
        ));
    }
    Ok(())
}

fn run_updater_help(updater: &Path) -> ValidationResult<()> {
    let description = format!("{} --help", updater.display());
    let output = run_command(
        Command::new(updater).arg("--help"),
        &description,
        BINARY_COMMAND_WAIT,
    )?;
    let stdout = str::from_utf8(&output.stdout)
        .map_err(|_| format!("updater help was not UTF-8 for {}", updater.display()))?;
    if !output.status.success() || !stdout.contains("Usage:") || !stdout.contains("--tag") {
        return Err(format!(
            "unexpected updater help from {}: status={}, stdout={stdout:?}, stderr={:?}",
            updater.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

fn validate_updater_artifact(
    distrib: &Path,
    target: NativeTarget,
    destination: &Path,
    runner_os: &str,
) -> ValidationResult<(PathBuf, String)> {
    let source = distrib.join(format!("kickoutchi-{}-update", target.triple));
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| format!("missing native updater {}: {error}", source.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "native updater must be a regular file: {}",
            source.display()
        ));
    }
    if !(1..=BINARY_BYTES_MAX).contains(&metadata.len()) {
        return Err(format!(
            "native updater size is outside the approved bound: {}",
            source.display()
        ));
    }
    let updater_name = if target.windows {
        "kickoutchi-update.exe"
    } else {
        "kickoutchi-update"
    };
    let updater = destination.join(updater_name);
    let copied = fs::copy(&source, &updater).map_err(|error| {
        format!(
            "could not copy native updater {}: {error}",
            source.display()
        )
    })?;
    require_exact_read(copied, metadata.len(), updater_name)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&updater, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "could not make updater executable {}: {error}",
                updater.display()
            )
        })?;
    }
    if runner_os == "Linux" {
        inspect_glibc_abi(&updater)?;
    }
    run_updater_help(&updater)?;
    Ok((updater, sha256(&source)?))
}

fn inspect_glibc_abi(binary: &Path) -> ValidationResult<()> {
    let description = format!("readelf --version-info {}", binary.display());
    let output = run_command(
        Command::new("readelf")
            .arg("--version-info")
            .arg(binary)
            .env("LC_ALL", "C"),
        &description,
        BINARY_COMMAND_WAIT,
    )?;
    if !output.status.success() {
        return Err(format!(
            "readelf failed for {}: status={}, stdout={:?}, stderr={:?}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = str::from_utf8(&output.stdout)
        .map_err(|_| format!("readelf output was not UTF-8 for {}", binary.display()))?;
    let maximum = validate_glibc_requirements(stdout)
        .map_err(|error| format!("{}: {error}", binary.display()))?;
    println!(
        "validated GLIBC ABI: binary={}, maximum=GLIBC_{}",
        binary.display(),
        format_numeric_version(&maximum)
    );
    Ok(())
}

fn run_archive_journeys(canonical: &Path, short: &Path, runner_os: &str) -> ValidationResult<()> {
    let mut command = Command::new("cargo");
    command
        .args([
            "test",
            "--locked",
            "--all-features",
            "--test",
            "cli_contract",
        ])
        .env("KICKOUTCHI_RELEASE_E2E_REQUIRED", "1")
        .env("KICKOUTCHI_E2E_KICKOUTCHI", canonical)
        .env("KICKOUTCHI_E2E_KICK", short);
    let release_container = matches!(
        std::env::var("KICKOUTCHI_RELEASE_CONTAINER").as_deref(),
        Ok("1")
    );
    if runner_os == "Linux" && !release_container {
        command.env("KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES", "1");
    }
    let output = run_command(
        &mut command,
        "release archive journeys",
        ARCHIVE_JOURNEY_WAIT,
    )?;
    io::stdout()
        .write_all(&output.stdout)
        .and_then(|()| io::stderr().write_all(&output.stderr))
        .map_err(|error| format!("could not write archive journey output: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "release archive journeys failed with status {}",
            output.status
        ));
    }
    Ok(())
}

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> ValidationResult<Self> {
        for _attempt in 0..16 {
            let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{counter}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "could not create temporary directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("could not reserve a unique temporary directory".to_owned())
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}

fn file_url_text(path: &str, windows: bool) -> ValidationResult<String> {
    let normalized = if windows {
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);
        if path.starts_with(r"UNC\") || path.starts_with(r"\\") {
            return Err("UNC artifact directories are not supported by this validator".to_owned());
        }
        path.replace('\\', "/")
    } else {
        path.to_owned()
    };
    let mut url = if windows {
        String::from("file:///")
    } else {
        String::from("file://")
    };
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':') {
            url.push(char::from(byte));
        } else {
            url.push('%');
            url.push(char::from(HEX[usize::from(byte >> 4)]));
            url.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(url)
}

fn percent_encode_file_path(path: &Path, windows: bool) -> ValidationResult<String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("artifact directory could not be resolved: {error}"))?;
    let text = canonical
        .to_str()
        .ok_or_else(|| "artifact directory path must be UTF-8".to_owned())?;
    file_url_text(text, windows)
}

fn copy_exact_file(source: &Path, destination: &Path) -> ValidationResult<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("missing installer input {}: {error}", source.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "installer input must be a regular file: {}",
            source.display()
        ));
    }
    let copied = fs::copy(source, destination).map_err(|error| {
        format!(
            "could not copy installer input {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    require_exact_read(
        copied,
        metadata.len(),
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("installer input"),
    )
}

fn configure_installer_environment(
    command: &mut Command,
    temporary: &Path,
    install_root: &Path,
    download_url: Option<&str>,
) {
    for variable in [
        "GITHUB_PATH",
        "CARGO_DIST_FORCE_INSTALL_DIR",
        "INSTALLER_DOWNLOAD_URL",
        "INSTALLER_NO_MODIFY_PATH",
        "KICKOUTCHI_UNMANAGED_INSTALL",
        "KICKOUTCHI_DISABLE_UPDATE",
        "KICKOUTCHI_DOWNLOAD_URL",
        "KICKOUTCHI_INSTALLER_GITHUB_BASE_URL",
        "KICKOUTCHI_INSTALLER_GHE_BASE_URL",
        "KICKOUTCHI_GITHUB_TOKEN",
        "KICKOUTCHI_RELEASE_GITHUB_TOKEN",
    ] {
        command.env_remove(variable);
    }
    command
        .env("XDG_CONFIG_HOME", temporary.join("config"))
        .env("KICKOUTCHI_INSTALL_DIR", install_root)
        .env("KICKOUTCHI_NO_MODIFY_PATH", "1")
        .env("KICKOUTCHI_PRINT_QUIET", "1")
        .env("TEMP", temporary.join("tmp"))
        .env("TMP", temporary.join("tmp"));
    if !cfg!(windows) {
        command
            .env("HOME", temporary.join("home"))
            .env("TMPDIR", temporary.join("tmp"));
    }
    if let Some(download_url) = download_url {
        command.env("KICKOUTCHI_DOWNLOAD_URL", download_url);
    }
}

fn require_installed_binary(path: &Path) -> ValidationResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("installed binary is missing {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || !(1..=BINARY_BYTES_MAX).contains(&metadata.len())
    {
        return Err(format!(
            "installed binary is not a bounded regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_installer_receipt(
    path: &Path,
    install_root: &Path,
    expected_version: &str,
) -> ValidationResult<()> {
    let mut file = File::open(path)
        .map_err(|error| format!("installer receipt is missing {}: {error}", path.display()))?;
    let bytes = read_bounded(&mut file, RECEIPT_BYTES_MAX)?;
    let receipt: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("installer receipt is invalid JSON: {error}"))?;
    if receipt["version"] != expected_version
        || receipt["provider"]["source"] != "cargo-dist"
        || receipt["install_prefix"] != install_root.to_string_lossy().as_ref()
    {
        return Err(format!(
            "installer receipt has unexpected contents: {receipt}"
        ));
    }
    Ok(())
}

fn run_generated_installer(
    shell: &str,
    installer: &Path,
    temporary: &Path,
    install_root: &Path,
    artifact_url: &str,
) -> ValidationResult<Output> {
    let mut command = Command::new(shell);
    if shell != "sh" {
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ]);
    }
    if shell == "powershell.exe" {
        // A PowerShell 7 runner's module path is not safe to reuse in 5.1.
        command.env_remove("PSModulePath");
    }
    command.arg(installer);
    configure_installer_environment(&mut command, temporary, install_root, Some(artifact_url));
    run_command(
        &mut command,
        "generated release installer",
        RELEASE_COMMAND_WAIT,
    )
}

fn validate_installer_checksum_refusals(
    installer: &Path,
    temporary: &Path,
    artifact_source: &Path,
    archive_name: &str,
    updater_name: &str,
    windows: bool,
) -> ValidationResult<()> {
    let install_root = temporary.join("previous-install");
    let bin = install_root.join("bin");
    fs::create_dir_all(&bin).map_err(|error| format!("could not seed install: {error}"))?;
    let receipt = temporary.join("config/kickoutchi/kickoutchi-receipt.json");
    let suffix = if windows { ".exe" } else { "" };
    let previous_files = [
        (
            bin.join(format!("kick{suffix}")),
            b"previous short binary".as_slice(),
        ),
        (
            bin.join(format!("kickoutchi{suffix}")),
            b"previous binary".as_slice(),
        ),
        (
            bin.join(format!("kickoutchi-update{suffix}")),
            b"previous updater".as_slice(),
        ),
        (receipt, b"previous receipt".as_slice()),
    ];
    for (path, contents) in &previous_files {
        fs::write(path, contents).map_err(|error| format!("could not seed {path:?}: {error}"))?;
    }

    let artifact_url = percent_encode_file_path(artifact_source, windows)?;
    let shell = if windows { "powershell.exe" } else { "sh" };
    for name in [archive_name, updater_name] {
        // Appending a byte changes the digest while leaving the archive/binary
        // downloadable and parseable enough to prove the hash gate caught it.
        let valid = artifact_source.join(name);
        let backup = valid.with_extension("original");
        fs::rename(&valid, &backup)
            .map_err(|error| format!("could not save valid {name}: {error}"))?;
        copy_exact_file(&backup, &valid)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&valid)
            .and_then(|mut file| file.write_all(b"\0"))
            .map_err(|error| format!("could not alter local copy of {name}: {error}"))?;

        let output =
            run_generated_installer(shell, installer, temporary, &install_root, &artifact_url)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let diagnostic = format!("SHA-256 mismatch for {name}");
        if output.status.success()
            || !(stdout.contains(&diagnostic) || stderr.contains(&diagnostic))
        {
            return Err(format!(
                "expected a checksum refusal for {name}: status={}, stdout={stdout:?}, stderr={stderr:?}",
                output.status
            ));
        }
        for (path, expected) in &previous_files {
            let actual =
                fs::read(path).map_err(|error| format!("could not read {path:?}: {error}"))?;
            if actual != *expected {
                return Err(format!("refusing {name} changed installed file {path:?}"));
            }
        }
        fs::remove_file(&valid)
            .and_then(|()| fs::rename(&backup, &valid))
            .map_err(|error| format!("could not restore local copy of {name}: {error}"))?;
    }
    #[cfg(unix)]
    if !windows {
        validate_unix_missing_verifier_refusal(
            installer,
            temporary,
            &install_root,
            &artifact_url,
            &previous_files,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_missing_verifier_refusal(
    installer: &Path,
    temporary: &Path,
    install_root: &Path,
    artifact_url: &str,
    previous_files: &[(PathBuf, &[u8])],
) -> ValidationResult<()> {
    let restricted_bin = temporary.join("no-sha256-bin");
    fs::create_dir_all(&restricted_bin)
        .map_err(|error| format!("could not create restricted PATH dir: {error}"))?;
    let host_path = std::env::var_os("PATH").unwrap_or_default();
    let search_dirs: Vec<PathBuf> = std::env::split_paths(&host_path).collect();
    for tool in [
        "sh", "uname", "mktemp", "chmod", "mkdir", "rm", "tar", "grep", "cat", "sed", "awk", "tr",
        "curl", "wget", "cp", "mv", "env", "dirname", "basename", "head", "tail", "cut", "id",
        "sysctl", "sw_vers", "file", "od", "dd", "ldd", "getconf", "getent", "sort", "tput",
    ] {
        if let Some(found) = search_dirs
            .iter()
            .map(|dir| dir.join(tool))
            .find(|candidate| candidate.is_file())
        {
            let link = restricted_bin.join(tool);
            if !link.exists() {
                std::os::unix::fs::symlink(&found, &link).map_err(|error| {
                    format!("could not link {tool} into restricted PATH: {error}")
                })?;
            }
        }
    }
    let mut command = Command::new("sh");
    command.arg(installer);
    configure_installer_environment(&mut command, temporary, install_root, Some(artifact_url));
    command.env("PATH", &restricted_bin);
    let output = run_command(
        &mut command,
        "generated Unix installer without SHA-256 tool",
        RELEASE_COMMAND_WAIT,
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let diagnostic = "cannot verify SHA-256 checksum";
    if output.status.success() || !(stdout.contains(diagnostic) || stderr.contains(diagnostic)) {
        return Err(format!(
            "expected a fail-closed refusal when no SHA-256 tool is on PATH: status={}, stdout={stdout:?}, stderr={stderr:?}",
            output.status
        ));
    }
    for (path, expected) in previous_files {
        let actual = fs::read(path).map_err(|error| format!("could not read {path:?}: {error}"))?;
        if actual != *expected {
            return Err(format!(
                "refusing missing SHA-256 verifier changed installed file {path:?}"
            ));
        }
    }
    Ok(())
}

fn validate_generated_installer(
    distrib_path: &Path,
    installer_path: &Path,
    targets_json: &str,
    runner_os: &str,
    runner_arch: &str,
) -> ValidationResult<()> {
    let target = native_target(runner_os, runner_arch)?;
    require_native_target(targets_json, target.triple)?;
    let distrib = distrib_path
        .canonicalize()
        .map_err(|error| format!("distribution path could not be resolved: {error}"))?;
    let installer = if installer_path.is_absolute() {
        installer_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("working directory could not be resolved: {error}"))?
            .join(installer_path)
    };
    let installer_name = if target.windows {
        "kickoutchi-installer.ps1"
    } else {
        "kickoutchi-installer.sh"
    };
    if installer.file_name().and_then(|name| name.to_str()) != Some(installer_name) {
        return Err(format!(
            "unexpected installer filename: {}",
            installer.display()
        ));
    }
    let installer_metadata = fs::symlink_metadata(&installer)
        .map_err(|error| format!("installer metadata is unavailable: {error}"))?;
    if !installer_metadata.file_type().is_file()
        || installer_metadata.file_type().is_symlink()
        || !(1..=INSTALLER_BYTES_MAX).contains(&installer_metadata.len())
    {
        return Err("installer must be a bounded regular file".to_owned());
    }
    let temporary = TemporaryDirectory::new("kickoutchi-installer-e2e")?;
    for directory in ["home", "config", "tmp"] {
        fs::create_dir(temporary.path.join(directory))
            .map_err(|error| format!("could not create isolated {directory} directory: {error}"))?;
    }
    let install_root = temporary.path.join("install");
    let artifact_source = temporary.path.join("artifacts");
    fs::create_dir(&artifact_source)
        .map_err(|error| format!("could not create local artifact directory: {error}"))?;
    let archive_suffix = if target.windows { ".zip" } else { ".tar.xz" };
    let archive_name = format!("kickoutchi-{}{archive_suffix}", target.triple);
    let updater_name = format!("kickoutchi-{}-update", target.triple);
    for name in [&archive_name, &updater_name] {
        copy_exact_file(&distrib.join(name), &artifact_source.join(name))?;
    }
    let local_url = percent_encode_file_path(&artifact_source, target.windows)?;

    let output = run_generated_installer(
        if target.windows { "pwsh.exe" } else { "sh" },
        &installer,
        &temporary.path,
        &install_root,
        &local_url,
    )?;
    if !output.status.success() {
        return Err(format!(
            "generated installer failed: status={}, stdout={:?}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let suffix = if target.windows { ".exe" } else { "" };
    let bin = install_root.join("bin");
    let canonical = bin.join(format!("kickoutchi{suffix}"));
    let short = bin.join(format!("kick{suffix}"));
    let updater = bin.join(format!("kickoutchi-update{suffix}"));
    for path in [&canonical, &short, &updater] {
        require_installed_binary(path)?;
    }
    run_version(&canonical, env!("CARGO_PKG_VERSION"))?;
    run_version(&short, env!("CARGO_PKG_VERSION"))?;
    run_updater_help(&updater)?;
    let receipt = temporary
        .path
        .join("config/kickoutchi/kickoutchi-receipt.json");
    validate_installer_receipt(&receipt, &install_root, env!("CARGO_PKG_VERSION"))?;

    validate_installer_checksum_refusals(
        &installer,
        &temporary.path,
        &artifact_source,
        &archive_name,
        &updater_name,
        target.windows,
    )?;

    println!(
        "validated generated release installer: target={}, installer={}",
        target.triple,
        installer.display(),
    );
    Ok(())
}

fn validate_release_artifact(
    distrib_path: &Path,
    targets_json: &str,
    runner_os: &str,
    runner_arch: &str,
) -> ValidationResult<()> {
    let target = native_target(runner_os, runner_arch)?;
    require_native_target(targets_json, target.triple)?;
    let distrib = distrib_path
        .canonicalize()
        .map_err(|error| format!("distribution path could not be resolved: {error}"))?;
    if !distrib.is_dir() {
        return Err("distribution path must be a directory".to_owned());
    }
    let suffix = if target.windows { ".zip" } else { ".tar.xz" };
    let archive = distrib.join(format!("kickoutchi-{}{suffix}", target.triple));
    let metadata = fs::symlink_metadata(&archive).map_err(|error| {
        format!(
            "missing regular native release archive {}: {error}",
            archive.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "missing regular native release archive {}",
            archive.display()
        ));
    }
    if !(1..=ARCHIVE_BYTES_MAX).contains(&metadata.len()) {
        return Err("release archive size is outside the approved bound".to_owned());
    }
    let archive_sha256 = sha256(&archive)?;
    verify_checksum(&archive, &archive_sha256)?;
    let executable_suffix = if target.windows { ".exe" } else { "" };
    let expected_binaries = BTreeSet::from([
        format!("kickoutchi{executable_suffix}"),
        format!("kick{executable_suffix}"),
    ]);
    let temporary = TemporaryDirectory::new("kickoutchi-release-e2e")?;
    let (updater, updater_sha256) =
        validate_updater_artifact(&distrib, target, &temporary.path, runner_os)?;
    let extracted = temporary.path.join("archive");
    fs::create_dir(&extracted)
        .map_err(|error| format!("could not create extraction directory: {error}"))?;
    let binaries = extract_release_binaries(&archive, &extracted, target, &expected_binaries)?;
    let found: BTreeSet<String> = binaries.keys().cloned().collect();
    if found != expected_binaries {
        return Err(format!(
            "release archive binaries differ: expected {expected_binaries:?}, found {found:?}"
        ));
    }
    let canonical_name = format!("kickoutchi{executable_suffix}");
    let short_name = format!("kick{executable_suffix}");
    let canonical = binaries
        .get(&canonical_name)
        .ok_or_else(|| "canonical release binary was not extracted".to_owned())?;
    let short = binaries
        .get(&short_name)
        .ok_or_else(|| "short release binary was not extracted".to_owned())?;
    if runner_os == "Linux" {
        inspect_glibc_abi(canonical)?;
        inspect_glibc_abi(short)?;
    }
    run_version(canonical, env!("CARGO_PKG_VERSION"))?;
    run_version(short, env!("CARGO_PKG_VERSION"))?;
    run_archive_journeys(canonical, short, runner_os)?;
    println!(
        "validated native release archive and updater: target={}, archive={}, bytes={}, \
         archive_sha256={archive_sha256}, updater={}, updater_sha256={updater_sha256}",
        target.triple,
        archive.display(),
        metadata.len(),
        updater.display(),
    );
    Ok(())
}

#[test]
#[ignore = "requires cargo-dist output and an explicit native runner contract"]
fn validate_generated_native_archive() {
    let distrib = std::env::var_os("KICKOUTCHI_RELEASE_DISTRIB")
        .map(PathBuf::from)
        .expect("KICKOUTCHI_RELEASE_DISTRIB must identify cargo-dist output");
    let targets = std::env::var("KICKOUTCHI_RELEASE_TARGETS_JSON")
        .expect("KICKOUTCHI_RELEASE_TARGETS_JSON must contain the matrix targets");
    let runner_os = std::env::var("KICKOUTCHI_RELEASE_RUNNER_OS")
        .expect("KICKOUTCHI_RELEASE_RUNNER_OS must identify the native runner OS");
    let runner_arch = std::env::var("KICKOUTCHI_RELEASE_RUNNER_ARCH")
        .expect("KICKOUTCHI_RELEASE_RUNNER_ARCH must identify the native runner architecture");
    validate_release_artifact(&distrib, &targets, &runner_os, &runner_arch)
        .expect("generated native release archive must satisfy the release contract");
}

#[test]
#[ignore = "requires cargo-dist installers and an explicit native runner contract"]
fn validate_generated_native_installer() {
    let distrib = std::env::var_os("KICKOUTCHI_RELEASE_DISTRIB")
        .map(PathBuf::from)
        .expect("KICKOUTCHI_RELEASE_DISTRIB must identify cargo-dist output");
    let installer = std::env::var_os("KICKOUTCHI_RELEASE_INSTALLER")
        .map(PathBuf::from)
        .expect("KICKOUTCHI_RELEASE_INSTALLER must identify the generated installer");
    let targets = std::env::var("KICKOUTCHI_RELEASE_TARGETS_JSON")
        .expect("KICKOUTCHI_RELEASE_TARGETS_JSON must contain the matrix targets");
    let runner_os = std::env::var("KICKOUTCHI_RELEASE_RUNNER_OS")
        .expect("KICKOUTCHI_RELEASE_RUNNER_OS must identify the native runner OS");
    let runner_arch = std::env::var("KICKOUTCHI_RELEASE_RUNNER_ARCH")
        .expect("KICKOUTCHI_RELEASE_RUNNER_ARCH must identify the native runner architecture");
    validate_generated_installer(&distrib, &installer, &targets, &runner_os, &runner_arch)
        .expect("generated native installer must satisfy the release contract");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by validator runner tests"]
    fn validator_command_helper() {
        match std::env::var("KICKOUTCHI_VALIDATOR_COMMAND_HELPER").as_deref() {
            Ok("stdout") => {
                let bytes =
                    vec![0xa5; usize::try_from(command::COMMAND_OUTPUT_BYTES_MAX + 1).unwrap()];
                let _ = io::stdout().write_all(&bytes);
            }
            Ok("stderr") => {
                let bytes =
                    vec![0xa5; usize::try_from(command::COMMAND_OUTPUT_BYTES_MAX + 1).unwrap()];
                let _ = io::stderr().write_all(&bytes);
            }
            Ok("park") => std::thread::sleep(Duration::from_secs(30)),
            _ => {}
        }
    }

    fn helper_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "tests::validator_command_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("KICKOUTCHI_VALIDATOR_COMMAND_HELPER", mode);
        command
    }

    #[test]
    fn validator_rejects_oversized_stdout_and_stderr() {
        for stream in ["stdout", "stderr"] {
            let Err(error) = run_command(
                &mut helper_command(stream),
                "validator probe",
                BINARY_COMMAND_WAIT,
            ) else {
                panic!("oversized validator {stream} must fail");
            };
            assert!(error.contains("validator probe"), "{error}");
            assert!(error.contains("byte limit"), "{error}");
        }
    }

    #[test]
    fn validator_reports_command_deadline_with_context() {
        let error = run_command(
            &mut helper_command("park"),
            "validator probe",
            Duration::from_millis(100),
        )
        .expect_err("stuck validator command must fail");
        assert!(error.contains("validator probe"), "{error}");
        assert!(error.contains("exit deadline"), "{error}");
    }

    const LINUX_TARGET: &str = "x86_64-unknown-linux-gnu";
    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";

    fn temporary_directory(prefix: &str) -> TemporaryDirectory {
        TemporaryDirectory::new(prefix).expect("test temporary directory must be created")
    }

    #[test]
    fn windows_file_urls_strip_verbatim_prefix_and_reject_unc_paths() {
        assert_eq!(
            file_url_text(r"\\?\D:\a path\artifacts", true).unwrap(),
            "file:///D:/a%20path/artifacts"
        );
        assert!(file_url_text(r"\\?\UNC\server\share", true).is_err());
        assert!(file_url_text(r"\\server\share", true).is_err());
    }

    #[test]
    fn matrix_must_contain_only_the_native_target() {
        assert!(require_native_target(&format!(r#"["{LINUX_TARGET}"]"#), LINUX_TARGET).is_ok());
        for invalid in [
            "[]",
            r#""not-a-list""#,
            r#"["x86_64-unknown-linux-gnu","aarch64-unknown-linux-gnu"]"#,
        ] {
            assert!(require_native_target(invalid, LINUX_TARGET).is_err());
        }
    }

    #[test]
    fn checksum_requires_one_record_for_the_exact_archive() {
        let temporary = temporary_directory("kickoutchi-checksum-test");
        let archive = temporary.path.join("artifact.tar.xz");
        fs::write(&archive, b"archive").expect("archive fixture");
        let digest = "ab".repeat(32);
        let checksum = PathBuf::from(format!("{}.sha256", archive.display()));
        fs::write(&checksum, format!("{digest} *artifact.tar.xz\n")).expect("checksum fixture");
        assert!(verify_checksum(&archive, &digest).is_ok());
        for invalid in [
            format!("{digest} *other.tar.xz\n"),
            format!("{digest}\n"),
            format!("{digest} *artifact.tar.xz\n{digest} *artifact.tar.xz\n"),
            format!("{} *artifact.tar.xz\n", "0".repeat(64)),
        ] {
            fs::write(&checksum, invalid).expect("invalid checksum fixture");
            assert!(verify_checksum(&archive, &digest).is_err());
        }
        fs::write(&checksum, vec![b'x'; 1025]).expect("oversized checksum fixture");
        assert!(verify_checksum(&archive, &digest).is_err());
    }

    #[test]
    fn archive_layout_must_match_the_cargo_dist_contract() {
        let target = native_target("Linux", "X64").expect("supported runner");
        let temporary = temporary_directory("kickoutchi-layout-test");
        let root = temporary.path.join(format!("kickoutchi-{LINUX_TARGET}"));
        fs::create_dir(&root).expect("archive root");
        for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi", "kick"] {
            fs::write(root.join(name), name).expect("archive member");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o755))
                    .expect("member mode");
            }
        }
        let binaries = BTreeSet::from(["kickoutchi".to_owned(), "kick".to_owned()]);

        let selected =
            check_archive_layout(&temporary.path, target, &binaries).expect("contract layout");
        assert_eq!(
            selected.keys().map(String::as_str).collect::<Vec<_>>(),
            ["kick", "kickoutchi"]
        );

        fs::write(root.join("extra"), "extra").expect("unexpected member");
        let error = check_archive_layout(&temporary.path, target, &binaries)
            .expect_err("an unexpected member must be rejected");
        assert!(error.contains("layout differs"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn system_tar_extracts_a_contract_archive() {
        use std::os::unix::fs::PermissionsExt;

        let target = native_target("Linux", "X64").expect("supported runner");
        let temporary = temporary_directory("kickoutchi-tar-test");
        let staging = temporary.path.join("staging");
        let root_name = format!("kickoutchi-{LINUX_TARGET}");
        fs::create_dir_all(staging.join(&root_name)).expect("staging root");
        for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi", "kick"] {
            let path = staging.join(&root_name).join(name);
            fs::write(&path, name).expect("staged member");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("member mode");
        }
        let archive = temporary.path.join("fixture.tar.xz");
        let output = run_command(
            Command::new("tar")
                .arg("-cJf")
                .arg(&archive)
                .arg("-C")
                .arg(&staging)
                .arg(&root_name),
            "tar -cJf fixture",
            BINARY_COMMAND_WAIT,
        )
        .expect("fixture archive builds");
        assert!(output.status.success(), "{output:?}");
        let extracted = temporary.path.join("extracted");
        fs::create_dir(&extracted).expect("extraction directory");
        let binaries = BTreeSet::from(["kickoutchi".to_owned(), "kick".to_owned()]);

        let selected = extract_release_binaries(&archive, &extracted, target, &binaries)
            .expect("a contract archive extracts");
        assert_eq!(
            fs::read_to_string(&selected["kick"]).expect("extracted alias"),
            "kick"
        );
    }

    #[test]
    fn hash_output_parser_reads_unix_and_certutil_formats() {
        let digest = "ab".repeat(32);
        assert_eq!(
            parse_sha256_output(format!("{digest}  artifact.zip\n").as_bytes()).as_deref(),
            Some(digest.as_str())
        );
        let certutil = format!(
            "SHA256 hash of D:\\a\\artifact.zip:\r\n{}\r\nCertUtil: -hashfile command completed successfully.\r\n",
            digest.to_ascii_uppercase()
        );
        assert_eq!(
            parse_sha256_output(certutil.as_bytes()).as_deref(),
            Some(digest.as_str())
        );
        let spaced = format!(
            "SHA256 hash of artifact.zip:\n{}\nCertUtil: done\n",
            digest
                .as_bytes()
                .chunks(2)
                .map(|pair| str::from_utf8(pair).expect("hex is ASCII"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            parse_sha256_output(spaced.as_bytes()).as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(parse_sha256_output(b"CertUtil: error\n"), None);
    }

    #[test]
    fn hash_output_parser_accepts_localized_non_utf8_certutil_output() {
        let digest = "ab".repeat(32);
        let mut output = b"Hachage SHA256 de artifact.zip\xa0:\r\n".to_vec();
        output.extend(digest.as_bytes());
        output.extend(b"\r\nCertUtil: La commande s'est termin\x82e.\r\n");
        assert_eq!(
            parse_sha256_output(&output).as_deref(),
            Some(digest.as_str())
        );
    }

    #[test]
    fn external_tool_paths_drop_only_the_local_verbatim_prefix() {
        assert_eq!(
            external_tool_path(Path::new(r"\\?\D:\a\artifact.zip")),
            PathBuf::from(r"D:\a\artifact.zip")
        );
        assert_eq!(
            external_tool_path(Path::new(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\?\UNC\server\share")
        );
        assert_eq!(
            external_tool_path(Path::new("/tmp/artifact.tar.xz")),
            PathBuf::from("/tmp/artifact.tar.xz")
        );
    }

    #[test]
    fn process_output_reader_rejects_the_first_excess_byte() {
        assert_eq!(read_bounded(&b"abcd"[..], 4).expect("exact limit"), b"abcd");
        assert!(read_bounded(&b"abcde"[..], 4).is_err());
    }

    #[test]
    fn glibc_parser_selects_the_highest_numeric_requirement() {
        let output = r"
          0x0010: Name: GLIBC_2.9 Flags: none Version: 8
          0x0020: Name: GLIBC_PRIVATE Flags: none Version: 7
          0x0030: Name: GLIBC_2.31.0 Flags: none Version: 6
          004: 2 (GLIBC_2.10) 3 (GLIBC_2.2.5)
        ";
        assert_eq!(
            maximum_glibc_requirement(output).expect("parseable readelf output"),
            [2, 31]
        );
    }

    #[test]
    fn glibc_threshold_accepts_2_31_and_rejects_newer_versions() {
        for accepted in ["GLIBC_2.30.99", "GLIBC_2.31", "GLIBC_2.31.0"] {
            assert!(
                validate_glibc_requirements(accepted).is_ok(),
                "rejected {accepted}"
            );
        }
        for rejected in ["GLIBC_2.31.1", "GLIBC_2.32", "GLIBC_3.0"] {
            let error = validate_glibc_requirements(rejected)
                .expect_err("newer GLIBC requirement must be rejected");
            assert!(error.contains("above supported maximum GLIBC_2.31"));
        }
    }

    #[test]
    fn glibc_parser_rejects_missing_and_malformed_requirements() {
        assert!(maximum_glibc_requirement("GLIBC_PRIVATE").is_err());
        assert!(maximum_glibc_requirement("Name: GLIBC_2").is_err());
        assert!(maximum_glibc_requirement("Name: GLIBC_2.31.future").is_err());
    }

    #[test]
    fn runner_mapping_rejects_unsupported_pairs() {
        assert_eq!(
            native_target("Windows", "X64")
                .expect("supported runner")
                .triple,
            WINDOWS_TARGET
        );
        assert!(native_target("Windows", "ARM64").is_err());
        assert!(native_target("unknown", "X64").is_err());
    }

    #[cfg(unix)]
    fn unix_installer_template(
        archive_name: &str,
        archive_hash: &str,
        updater_name: &str,
    ) -> String {
        // cargo-dist 0.34.0 emits a trailing space after `in` in the case header;
        // build it here so source files stay clean under `git diff --check`.
        let case_header = "case \"$_artifact_name\" in ";
        format!(
            r#"#!/bin/sh
set -u
APP_NAME="kickoutchi"
INSTALL_UPDATER=1
ARTIFACT_DOWNLOAD_URLS="${{KICKOUTCHI_DOWNLOAD_URL}}"
INSTALL_DIR="${{KICKOUTCHI_INSTALL_DIR}}/bin"
RECEIPT_HOME="${{XDG_CONFIG_HOME}}/kickoutchi"
say() {{ [ "${{KICKOUTCHI_PRINT_QUIET:-0}}" = "0" ] && printf '%s\n' "$1"; }}
err() {{ [ "${{KICKOUTCHI_PRINT_QUIET:-0}}" = "0" ] && printf 'ERROR: %s\n' "$1" >&2; exit 1; }}
check_cmd() {{ command -v "$1" > /dev/null 2>&1; }}
ensure() {{ "$@" || err "command failed: $*"; }}
downloader() {{
    local _src="${{1#file://}}"
    cp "$_src" "$2"
}}
download_binary_and_run_installer() {{
    local _artifact_name="{archive_name}"
    local _bins
    local _zip_ext
    local _arch
    local _checksum_style
    local _checksum_value

    {case_header}
        "{archive_name}")
            _arch="x86_64-unknown-linux-gnu"
            _zip_ext=".tar.xz"
            _checksum_style="sha256"
            _checksum_value="{archive_hash}"
            _bins="kick kickoutchi"
            _updater_name="{updater_name}"
            _updater_bin="{updater_name}"
            ;;
        *)
            err "unknown artifact"
            ;;
    esac

    local _dir
    local _download_result=0
    for _base_url in $ARTIFACT_DOWNLOAD_URLS; do
        local _url="$_base_url/$_artifact_name"
        _dir="$(ensure mktemp -d)" || return 1
        local _file="$_dir/input$_zip_ext"
        if ! downloader "$_url" "$_file"; then
            say "failed to download $_url" 1>&2
            continue
        fi

        if [ -n "${{_checksum_style:-}}" ]; then
            verify_checksum "$_file" "$_checksum_style" "$_checksum_value"
        else
            say "no checksums to verify" 1>&2
        fi

        if [ -n "$_updater_name" ] && [ "$INSTALL_UPDATER" = "1" ]; then
            local _updater_url="$_base_url/$_updater_name"
            local _updater_file="$_dir/$APP_NAME-update"

            if ! downloader "$_updater_url" "$_updater_file"; then
                say "failed to download $_updater_url"
                continue
            fi

            # Add the updater to the list of binaries to install
            _bins="$_bins $APP_NAME-update"
        fi

        _download_result=1
        break
    done
    [ "$_download_result" = "1" ] || exit 1
    mkdir -p "$INSTALL_DIR" "$RECEIPT_HOME"
    printf 'installed' > "$INSTALL_DIR/kick"
    printf 'installed' > "$INSTALL_DIR/kickoutchi"
    printf 'installed' > "$INSTALL_DIR/kickoutchi-update"
    printf 'receipt' > "$RECEIPT_HOME/kickoutchi-receipt.json"
    rm -rf "$_dir"
}}

verify_checksum() {{
    local _file="$1"
    local _checksum_style="$2"
    local _checksum_value="$3"
    if [ -z "$_checksum_value" ]; then
        return 0
    fi
    return 0
}}

download_binary_and_run_installer "$@" || exit 1
"#
        )
    }

    #[cfg(unix)]
    #[test]
    fn unix_protect_installer_hardens_archive_and_updater_checksum_verification() {
        let dir = temporary_directory("kickoutchi-protect-unix");
        let distrib = dir.path.join("distrib");
        let source = dir.path.join("source");
        let install_root = dir.path.join("install");
        fs::create_dir_all(&distrib).expect("distrib dir");
        fs::create_dir_all(&source).expect("source dir");
        fs::create_dir_all(dir.path.join("home")).expect("home dir");
        fs::create_dir_all(dir.path.join("config")).expect("config dir");
        fs::create_dir_all(dir.path.join("tmp")).expect("tmp dir");

        let archive_name = "kickoutchi-x86_64-unknown-linux-gnu.tar.xz";
        let updater_name = "kickoutchi-x86_64-unknown-linux-gnu-update";
        let archive_path = distrib.join(archive_name);
        let updater_path = distrib.join(updater_name);
        fs::write(&archive_path, b"fake release archive payload").expect("write archive");
        fs::write(&updater_path, b"fake release updater payload").expect("write updater");
        let archive_hash = sha256(&archive_path).expect("hash archive");

        let installer_path = distrib.join("kickoutchi-installer.sh");
        fs::write(
            &installer_path,
            unix_installer_template(archive_name, &archive_hash, updater_name),
        )
        .expect("write installer template");

        let protect_script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/unix/protect-installer.sh");
        let mut protect = Command::new("bash");
        protect
            .arg(&protect_script)
            .args(["--distrib"])
            .arg(&distrib);
        let protect_output = run_command(&mut protect, "protect-installer.sh", BINARY_COMMAND_WAIT)
            .expect("protect-installer.sh runs");
        assert!(
            protect_output.status.success(),
            "protect-installer.sh failed: stderr={}",
            String::from_utf8_lossy(&protect_output.stderr)
        );

        // Running protect-installer.sh a second time must fail closed.
        let mut protect_again = Command::new("bash");
        protect_again
            .arg(&protect_script)
            .args(["--distrib"])
            .arg(&distrib);
        let again_output = run_command(
            &mut protect_again,
            "protect-installer.sh rerun",
            BINARY_COMMAND_WAIT,
        )
        .expect("second run executes");
        assert!(!again_output.status.success());

        for name in [archive_name, updater_name] {
            copy_exact_file(&distrib.join(name), &source.join(name)).expect("stage artifact");
        }
        let url = percent_encode_file_path(&source, false).expect("file url");

        // Valid archive + valid updater installs cleanly.
        let valid = run_generated_installer("sh", &installer_path, &dir.path, &install_root, &url)
            .expect("valid installer runs");
        assert!(
            valid.status.success(),
            "hardened installer rejected valid artifacts: stderr={}",
            String::from_utf8_lossy(&valid.stderr)
        );

        // Corrupted archive, corrupted updater, and missing SHA-256 tool must
        // all fail closed without modifying pre-existing installed files.
        validate_installer_checksum_refusals(
            &installer_path,
            &dir.path,
            &source,
            archive_name,
            updater_name,
            false,
        )
        .expect("Unix checksum refusals must hold");
    }
}
