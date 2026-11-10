//! The `why` command's read-only bindability diagnosis and stable reports.
//!
//! Each bounded endpoint query combines one collected network snapshot with one
//! exact bind probe; it never terminates or otherwise mutates a process.

use std::io::{self, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};
use std::time::SystemTime;

use clap::Args;
use serde::{Serialize, Serializer};

use crate::collector::{self, CollectorError};
use crate::config::Config;
use crate::diagnostic::verdict::{
    Evidence, Verdict, VerdictResult, WHY_ENDPOINTS_MAX, analyze, dual_stack_blockers,
};
use crate::display::{human_endpoint_text, sanitize, sanitize_bounded};
use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, normalize_ip_address};
use crate::model::Protocol;
use crate::observation::{EndpointIdentity, Ipv6Scope, MetadataProfile, NetworkSnapshot};
use crate::probe::{Ipv6Mode, ProbeRequest, ProbeResult, ReuseAddressMode, probe};
use crate::public_output::{
    CaptureDto, EndpointDto, EvidenceDto, EvidenceGapDto, PublicOutputError, ScopeDto,
    certainty_name, evidence_code_name, evidence_gap_code_name, evidence_impact_name,
    evidence_source_name, owner_completeness_name, protocol_name, scope_kind_name,
    scope_limitation_name, snapshot_completeness_name,
};

use super::ExitReason;

const PUBLIC_MESSAGE_MAX_BYTES: usize = 512;

#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent CLI flag; clap's derive requires bools, and the contradictory combinations are rejected at parse time"
)]
#[derive(Debug, Args)]
pub(crate) struct WhyArgs {
    /// Port to diagnose (1..=65535).
    #[arg(value_parser = super::parse_port)]
    pub(crate) port: u16,

    /// Evaluate TCP only (default; ordered before UDP in a matrix).
    #[arg(long, conflicts_with_all = ["udp", "all_protocols"])]
    tcp: bool,

    /// Evaluate UDP endpoints only.
    #[arg(long, conflicts_with_all = ["tcp", "all_protocols"])]
    udp: bool,

    /// Evaluate TCP then UDP endpoints.
    #[arg(long, conflicts_with_all = ["tcp", "udp"])]
    pub(crate) all_protocols: bool,

    /// Evaluate one literal local IP address (no `%zone`; use --scope-id).
    #[arg(long, value_name = "ADDRESS", conflicts_with = "all_addresses")]
    address: Option<String>,

    /// Use `127.0.0.1`, `0.0.0.0`, `::1`, then `::`; do not enumerate interfaces.
    #[arg(long, conflicts_with = "address")]
    pub(crate) all_addresses: bool,

    /// Nonzero IPv6 interface index; requires one explicit IPv6 --address.
    #[arg(long, value_name = "ID")]
    scope_id: Option<u32>,

    /// Require IPv6-only behavior; valid only when every address is IPv6.
    #[arg(long, conflicts_with = "dual_stack")]
    ipv6_only: bool,

    /// Require dual-stack behavior; valid only when every address is IPv6.
    #[arg(long, conflicts_with = "ipv6_only")]
    dual_stack: bool,

    /// Explicitly enable address reuse for the diagnostic bind.
    #[arg(long)]
    pub(crate) reuse_address: bool,

    /// Print one `kickoutchi.why/1` JSON document instead of human evidence.
    #[arg(long)]
    pub(crate) json: bool,

    /// Print every probe, evidence item, and gap instead of one line per
    /// endpoint. Set from the global `--verbose` flag.
    #[arg(skip)]
    pub(crate) detailed: bool,
}

#[derive(Debug)]
struct WhyOptions {
    port: u16,
    protocols: Vec<Protocol>,
    addresses: Vec<IpAddr>,
    scope_id: Option<NonZeroU32>,
    ipv6_mode: Ipv6Mode,
    reuse_address: ReuseAddressMode,
    endpoints: Vec<RequestedEndpoint>,
    json: bool,
    detailed: bool,
}

#[derive(Debug, Clone)]
struct RequestedEndpoint {
    identity: EndpointIdentity,
    probe_request: ProbeRequest,
}

#[derive(Debug)]
struct TimedProbe {
    result: ProbeResult,
    capture: CaptureDto,
}

#[derive(Debug)]
struct CompletedResult {
    verdict: VerdictResult,
    probe: TimedProbe,
}

trait WhyRuntime {
    fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError>;
    fn now(&mut self) -> SystemTime;
    fn probe(&mut self, request: ProbeRequest) -> ProbeResult;
}

struct ProductionRuntime;

impl WhyRuntime for ProductionRuntime {
    fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        collector::collect_snapshot(profile)
    }

    fn now(&mut self) -> SystemTime {
        SystemTime::now()
    }

    fn probe(&mut self, request: ProbeRequest) -> ProbeResult {
        probe(request)
    }
}

pub(super) fn run_why(args: &WhyArgs, config: &Config) -> ExitReason {
    let mut runtime = ProductionRuntime;
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_why_with(
        args,
        config,
        &mut runtime,
        &mut stdout.lock(),
        &mut stderr.lock(),
    )
}

fn run_why_with(
    args: &WhyArgs,
    config: &Config,
    runtime: &mut impl WhyRuntime,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> ExitReason {
    let options = match WhyOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            write_diagnostic(diagnostics, &format!("invalid why query: {error}"));
            return ExitReason::InvalidArguments;
        }
    };
    let snapshot = match runtime.collect(MetadataProfile::Display) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            write_diagnostic(
                diagnostics,
                &format!("collecting endpoint evidence failed: {error}"),
            );
            return ExitReason::Failure;
        }
    };

    let mut completed = Vec::with_capacity(options.endpoints.len());
    for endpoint in &options.endpoints {
        let started = runtime.now();
        let result = runtime.probe(endpoint.probe_request);
        let finished = runtime.now();
        let capture = match CaptureDto::new(started, finished) {
            Ok(capture) => capture,
            Err(error) => {
                write_diagnostic(
                    diagnostics,
                    &format!("recording probe time failed: {error}"),
                );
                return ExitReason::Failure;
            }
        };
        let label = config.labels.resolve(&endpoint.identity);
        completed.push(CompletedResult {
            verdict: analyze(
                &endpoint.identity,
                options.ipv6_mode,
                &snapshot,
                &result,
                label,
            ),
            probe: TimedProbe { result, capture },
        });
    }

    let aggregate = aggregate_exit(completed.iter().map(|result| result.verdict.verdict));
    match render_document(output, &options, &snapshot, &completed, aggregate)
        .and_then(|()| output.flush().map_err(PublicOutputError::from))
    {
        Ok(()) => aggregate,
        Err(error) if error.io_error_kind() == Some(ErrorKind::BrokenPipe) => aggregate,
        Err(error) => {
            write_diagnostic(diagnostics, &format!("writing why output failed: {error}"));
            ExitReason::Failure
        }
    }
}

impl WhyOptions {
    fn parse(args: &WhyArgs) -> Result<Self, String> {
        let port = NonZeroU16::new(args.port)
            .ok_or_else(|| "port must be in 1..=65535".to_owned())?
            .get();
        // `--tcp` is read here rather than left to fall through the `else`.
        // Both mean TCP today, but a flag that works only because it matches
        // the default is a flag that breaks silently when the default moves.
        // Same shape as watch's `protocol_selected`. clap rejects any two
        // protocol flags together, so at most one is set.
        let tcp_selected = args.tcp || !(args.udp || args.all_protocols);
        let protocols = if args.all_protocols {
            vec![Protocol::Tcp, Protocol::Udp]
        } else if tcp_selected {
            vec![Protocol::Tcp]
        } else {
            vec![Protocol::Udp]
        };
        let addresses = parse_addresses(args)?;
        let scope_id = args.scope_id.and_then(NonZeroU32::new);
        if args.scope_id.is_some() && scope_id.is_none() {
            return Err("scope ID must be in 1..=4294967295".to_owned());
        }
        if scope_id.is_some() && args.address.is_none() {
            return Err("scope ID requires one explicit IPv6 address".to_owned());
        }
        if scope_id.is_some() && addresses.first().is_none_or(IpAddr::is_ipv4) {
            return Err("scope ID is valid only with an explicit IPv6 address".to_owned());
        }
        let ipv6_mode = if args.ipv6_only {
            Ipv6Mode::V6Only
        } else if args.dual_stack {
            Ipv6Mode::DualStack
        } else {
            Ipv6Mode::SystemDefault
        };
        if ipv6_mode != Ipv6Mode::SystemDefault && addresses.iter().any(IpAddr::is_ipv4) {
            return Err("IPv6-only and dual-stack modes require only IPv6 addresses".to_owned());
        }
        let reuse_address = if args.reuse_address {
            ReuseAddressMode::Enabled
        } else {
            ReuseAddressMode::Disabled
        };
        let endpoint_count = endpoint_count(protocols.len(), addresses.len())?;
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for protocol in &protocols {
            for address in &addresses {
                let ipv6_scope = match address {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(_) => {
                        Some(scope_id.map_or(Ipv6Scope::Unscoped, Ipv6Scope::InterfaceIndex))
                    }
                };
                let identity =
                    EndpointIdentity::new(*protocol, *address, u32::from(port), ipv6_scope)
                        .map_err(|error| error.to_string())?;
                let probe_request = ProbeRequest::new(
                    *protocol,
                    *address,
                    u32::from(port),
                    ipv6_scope,
                    ipv6_mode,
                    reuse_address,
                )
                .map_err(|error| error.to_string())?;
                endpoints.push(RequestedEndpoint {
                    identity,
                    probe_request,
                });
            }
        }
        Ok(Self {
            port,
            protocols,
            addresses,
            scope_id,
            ipv6_mode,
            reuse_address,
            endpoints,
            json: args.json,
            detailed: args.detailed,
        })
    }
}

fn endpoint_count(protocols: usize, addresses: usize) -> Result<usize, String> {
    let count = protocols
        .checked_mul(addresses)
        .ok_or_else(|| "endpoint matrix size overflowed".to_owned())?;
    if count == 0 || count > WHY_ENDPOINTS_MAX {
        return Err(format!(
            "endpoint matrix must contain 1..={WHY_ENDPOINTS_MAX} entries"
        ));
    }
    Ok(count)
}

fn parse_addresses(args: &WhyArgs) -> Result<Vec<IpAddr>, String> {
    if args.all_addresses {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]);
    }
    let Some(address) = args.address.as_deref() else {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]);
    };
    if address.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err("address exceeds the 64-byte limit".to_owned());
    }
    if address.contains('%') {
        return Err("address must not include a zone; use --scope-id".to_owned());
    }
    let address = address
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map_err(|_| "address must be one literal IP address".to_owned())?;
    Ok(vec![address])
}

fn aggregate_exit(verdicts: impl IntoIterator<Item = Verdict>) -> ExitReason {
    let mut aggregate = ExitReason::Success;
    for verdict in verdicts {
        let reason = match verdict {
            Verdict::BindableNow => ExitReason::Success,
            Verdict::ObservationRaced | Verdict::Indeterminate => ExitReason::Failure,
            Verdict::PermissionDenied => ExitReason::PermissionDenied,
            Verdict::Owned
            | Verdict::OwnerHidden
            | Verdict::KernelStateObserved
            | Verdict::AddressUnavailable
            | Verdict::ReservationOrPolicyUnknown
            | Verdict::Unsupported => ExitReason::NoMatch,
        };
        aggregate = match (aggregate, reason) {
            (ExitReason::Failure, _) | (_, ExitReason::Failure) => ExitReason::Failure,
            (ExitReason::PermissionDenied, _) | (_, ExitReason::PermissionDenied) => {
                ExitReason::PermissionDenied
            }
            (ExitReason::NoMatch, _) | (_, ExitReason::NoMatch) => ExitReason::NoMatch,
            _ => ExitReason::Success,
        };
    }
    aggregate
}

fn render_document(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
    aggregate: ExitReason,
) -> Result<(), PublicOutputError> {
    if options.json {
        render_json(output, options, snapshot, results, aggregate)
    } else if options.detailed {
        render_human(output, options, snapshot, results, aggregate)
    } else {
        render_summary(output, options, snapshot, results)
    }
}

fn render_json(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
    aggregate: ExitReason,
) -> Result<(), PublicOutputError> {
    let capture = CaptureDto::new(snapshot.capture_started_at, snapshot.capture_completed_at)?;
    let dto = WhyDto {
        schema: "kickoutchi.why",
        version: 1,
        query: QueryDto::from(options),
        capture,
        scope: ScopeDto::new(&snapshot.scope)?,
        completeness: snapshot_completeness_name(snapshot.completeness),
        owner_completeness: owner_completeness_name(&snapshot.owner_completeness),
        results: ResultSequence(results),
        aggregate_exit_code: aggregate as u8,
    };
    serde_json::to_writer_pretty(&mut *output, &dto)?;
    output.write_all(b"\n").map_err(PublicOutputError::from)
}

fn render_human(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
    aggregate: ExitReason,
) -> Result<(), PublicOutputError> {
    let capture = CaptureDto::new(snapshot.capture_started_at, snapshot.capture_completed_at)?;
    writeln!(
        &mut *output,
        "WHY port={} protocols={} addresses={} scope_id={} ipv6_mode={} reuse_address={} snapshot={} ownership={} capture_started_unix_ms={} capture_completed_unix_ms={}",
        options.port,
        options
            .protocols
            .iter()
            .map(|protocol| protocol.label())
            .collect::<Vec<_>>()
            .join(","),
        options
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        options
            .scope_id
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        ipv6_mode_name(options.ipv6_mode),
        options.reuse_address == ReuseAddressMode::Enabled,
        snapshot_completeness_name(snapshot.completeness),
        owner_completeness_name(&snapshot.owner_completeness),
        capture.started_unix_ms(),
        capture.completed_unix_ms(),
    )?;
    writeln!(
        &mut *output,
        "scope kind={} identifier={} limitations={}",
        scope_kind_name(snapshot.scope.kind),
        snapshot
            .scope
            .identifier
            .as_deref()
            .map_or_else(|| "-".to_owned(), sanitize),
        snapshot
            .scope
            .limitations
            .iter()
            .copied()
            .map(scope_limitation_name)
            .collect::<Vec<_>>()
            .join(","),
    )?;
    for result in results {
        render_human_result(output, result)?;
    }
    writeln!(output, "aggregate_exit_code={}", aggregate as u8)?;
    Ok(())
}

/// One line per endpoint: what holds it, or that it is free.
fn render_summary(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
) -> Result<(), PublicOutputError> {
    let endpoints = results
        .iter()
        .map(|result| summary_endpoint_text(&result.verdict.endpoint))
        .collect::<Vec<_>>();
    let width = endpoints
        .iter()
        .map(|text| text.chars().count())
        .max()
        .unwrap_or(0);
    for (result, endpoint) in results.iter().zip(&endpoints) {
        let label = result
            .verdict
            .label
            .as_deref()
            .map_or_else(String::new, |label| format!("  [{}]", sanitize(label)));
        writeln!(
            output,
            "{endpoint:<width$}  {}{label}",
            summary_verdict_text(result, options, snapshot)
        )?;
    }
    Ok(())
}

fn summary_endpoint_text(endpoint: &EndpointIdentity) -> String {
    format!(
        "{} {}",
        endpoint.protocol.label(),
        human_endpoint_text(endpoint.address, endpoint.port.get(), endpoint.ipv6_scope)
    )
}

fn summary_verdict_text(
    result: &CompletedResult,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
) -> String {
    match result.verdict.verdict {
        Verdict::BindableNow => "free".to_owned(),
        Verdict::Owned => {
            let owners = result
                .verdict
                .evidence
                .iter()
                .filter_map(Evidence::owner_label)
                .map(sanitize)
                .collect::<Vec<_>>();
            if owners.is_empty() {
                "in use".to_owned()
            } else {
                format!("in use by {}", owners.join(", "))
            }
        }
        Verdict::OwnerHidden => {
            "in use; the owner could not be read (usually another user's process; try sudo)"
                .to_owned()
        }
        Verdict::KernelStateObserved => {
            "busy: the kernel still holds a socket here (for example TIME_WAIT)".to_owned()
        }
        Verdict::PermissionDenied => {
            "not allowed: binding needs more privilege or is blocked by policy".to_owned()
        }
        Verdict::AddressUnavailable => "address is not available on this host".to_owned(),
        Verdict::ReservationOrPolicyUnknown => {
            let message = result.probe.result.os_error_message.as_deref().map_or_else(
                || "the bind failed".to_owned(),
                |message| sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES),
            );
            let blockers =
                dual_stack_blockers(&result.verdict.endpoint, options.ipv6_mode, snapshot);
            if blockers.is_empty() {
                format!("cannot bind ({message}); the cause is not visible, see --verbose")
            } else {
                format!(
                    "cannot bind ({message}); probably held through dual-stack by {}",
                    blockers.join(", ")
                )
            }
        }
        Verdict::ObservationRaced => "changed while checking; run it again".to_owned(),
        Verdict::Unsupported => "not supported on this host".to_owned(),
        Verdict::Indeterminate => "could not tell; rerun with --verbose for evidence".to_owned(),
    }
}

fn render_human_result(
    output: &mut impl Write,
    result: &CompletedResult,
) -> Result<(), PublicOutputError> {
    writeln!(
        output,
        "{} verdict={} certainty={} label={}",
        endpoint_text(&result.verdict.endpoint),
        result.verdict.verdict.name(),
        certainty_name(result.verdict.certainty),
        result
            .verdict
            .label
            .as_deref()
            .map_or_else(|| "-".to_owned(), sanitize),
    )?;
    let message = result.probe.result.os_error_message.as_deref().map_or_else(
        || "-".to_owned(),
        |message| sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES),
    );
    writeln!(
        output,
        "  probe={} started_unix_ms={} completed_unix_ms={} raw_os_error={} message={}",
        probe_outcome_name(result.probe.result.outcome),
        result.probe.capture.started_unix_ms(),
        result.probe.capture.completed_unix_ms(),
        result
            .probe
            .result
            .raw_os_error
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        message,
    )?;
    for item in &result.verdict.evidence {
        writeln!(
            output,
            "  evidence code={} source={} certainty={} message={}",
            evidence_code_name(item.code),
            evidence_source_name(item.source),
            certainty_name(item.certainty),
            sanitize_bounded(&item.message, PUBLIC_MESSAGE_MAX_BYTES),
        )?;
    }
    writeln!(
        output,
        "  omitted_evidence_count={}",
        result.verdict.omitted_evidence_count
    )?;
    for gap in &result.verdict.evidence_gaps {
        writeln!(
            output,
            "  gap code={} impact={} endpoint={} pid={} affected_pid_count={} message={}",
            evidence_gap_code_name(gap.code),
            evidence_impact_name(gap.impact),
            gap.endpoint
                .as_ref()
                .map_or_else(|| "-".to_owned(), endpoint_text),
            gap.pid
                .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
            gap.affected_pid_count()
                .map_or_else(|| "-".to_owned(), |count| count.to_string()),
            sanitize_bounded(gap.message(), PUBLIC_MESSAGE_MAX_BYTES),
        )?;
    }
    writeln!(
        output,
        "  omitted_evidence_gap_count={}",
        result.verdict.omitted_evidence_gap_count
    )?;
    Ok(())
}

#[derive(Serialize)]
struct WhyDto<'a> {
    schema: &'static str,
    version: u32,
    query: QueryDto,
    capture: CaptureDto,
    scope: ScopeDto<'a>,
    completeness: &'static str,
    owner_completeness: &'static str,
    results: ResultSequence<'a>,
    aggregate_exit_code: u8,
}

struct ResultSequence<'a>(&'a [CompletedResult]);

impl Serialize for ResultSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter().map(result_dto))
    }
}

#[derive(Serialize)]
struct QueryDto {
    port: u16,
    protocols: Vec<&'static str>,
    addresses: Vec<String>,
    scope_id: Option<u32>,
    ipv6_mode: &'static str,
    reuse_address: bool,
}

impl From<&WhyOptions> for QueryDto {
    fn from(options: &WhyOptions) -> Self {
        Self {
            port: options.port,
            protocols: options
                .protocols
                .iter()
                .copied()
                .map(protocol_name)
                .collect(),
            addresses: options.addresses.iter().map(ToString::to_string).collect(),
            scope_id: options.scope_id.map(NonZeroU32::get),
            ipv6_mode: ipv6_mode_name(options.ipv6_mode),
            reuse_address: options.reuse_address == ReuseAddressMode::Enabled,
        }
    }
}

#[derive(Serialize)]
struct ResultDto<'a> {
    endpoint: EndpointDto<'a>,
    label: Option<String>,
    verdict: &'static str,
    certainty: &'static str,
    probe: ProbeDto,
    evidence: Vec<EvidenceDto<'a>>,
    omitted_evidence_count: u64,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct ProbeDto {
    outcome: &'static str,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    raw_os_error: Option<i32>,
    message: Option<String>,
}

fn result_dto(result: &CompletedResult) -> ResultDto<'_> {
    ResultDto {
        endpoint: EndpointDto::from(&result.verdict.endpoint),
        label: result
            .verdict
            .label
            .as_deref()
            .map(|label| sanitize_bounded(label, PUBLIC_MESSAGE_MAX_BYTES)),
        verdict: result.verdict.verdict.name(),
        certainty: certainty_name(result.verdict.certainty),
        probe: ProbeDto {
            outcome: probe_outcome_name(result.probe.result.outcome),
            started_unix_ms: result.probe.capture.started_unix_ms(),
            completed_unix_ms: result.probe.capture.completed_unix_ms(),
            raw_os_error: result.probe.result.raw_os_error,
            message: result
                .probe
                .result
                .os_error_message
                .as_deref()
                .map(|message| sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES)),
        },
        evidence: result
            .verdict
            .evidence
            .iter()
            .map(EvidenceDto::from)
            .collect(),
        omitted_evidence_count: result.verdict.omitted_evidence_count,
        evidence_gaps: result
            .verdict
            .evidence_gaps
            .iter()
            .map(EvidenceGapDto::from)
            .collect(),
        omitted_evidence_gap_count: result.verdict.omitted_evidence_gap_count,
    }
}

fn endpoint_text(endpoint: &EndpointIdentity) -> String {
    format!(
        "{}://{}",
        protocol_name(endpoint.protocol),
        human_endpoint_text(endpoint.address, endpoint.port.get(), endpoint.ipv6_scope,)
    )
}

const fn probe_outcome_name(outcome: crate::probe::ProbeOutcome) -> &'static str {
    match outcome {
        crate::probe::ProbeOutcome::BindableNow => "bindable_now",
        crate::probe::ProbeOutcome::AddressInUse => "address_in_use",
        crate::probe::ProbeOutcome::PermissionDenied => "permission_denied",
        crate::probe::ProbeOutcome::AddressUnavailable => "address_unavailable",
        crate::probe::ProbeOutcome::Unsupported => "unsupported",
        crate::probe::ProbeOutcome::Other => "other",
    }
}

const fn ipv6_mode_name(mode: Ipv6Mode) -> &'static str {
    match mode {
        Ipv6Mode::SystemDefault => "system_default",
        Ipv6Mode::V6Only => "v6_only",
        Ipv6Mode::DualStack => "dual_stack",
    }
}

fn write_diagnostic(writer: &mut impl Write, message: &str) {
    let _ = writeln!(
        writer,
        "error: {}",
        sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES)
    );
    let _ = writer.flush();
}

#[cfg(test)]
mod tests;
