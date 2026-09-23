// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Live E2E harness for a real Greenbone Community container stack.

#![allow(clippy::print_stdout, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{self, Write};
use std::process::{Command, ExitCode};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gvm_client::{
    parse_version_text, CommandSupport, GmpClient, GvmError, WireTrace, WireTraceEvent,
};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::commands::credentials::{
    CreateCredentialRequest, DeleteCredentialRequest, GetCredentialRequest, GetCredentialsRequest,
};
use gvm_gmp::commands::feed::GetFeedsRequest;
use gvm_gmp::commands::filters::{CreateFilterRequest, DeleteFilterRequest, GetFilterRequest};
use gvm_gmp::commands::notes::{CreateNoteRequest, DeleteNoteRequest, GetNoteRequest};
use gvm_gmp::commands::nvts::GetNvtsRequest;
use gvm_gmp::commands::overrides::{
    CreateOverrideRequest, DeleteOverrideRequest, GetOverrideRequest,
};
use gvm_gmp::commands::port_lists::{
    CreatePortListRequest, DeletePortListRequest, GetPortListRequest, GetPortListsRequest,
    ModifyPortListRequest,
};
use gvm_gmp::commands::report_formats::GetReportFormatsRequest;
use gvm_gmp::commands::reports::{DeleteReportRequest, GetReportExportRequest, GetReportRequest};
use gvm_gmp::commands::scan_configs::GetScanConfigsRequest;
use gvm_gmp::commands::scanners::GetScannersRequest;
use gvm_gmp::commands::schedules::{
    CreateScheduleRequest, DeleteScheduleRequest, GetScheduleRequest,
};
use gvm_gmp::commands::secinfo::{
    GetCertBundAdvisoriesRequest, GetCpesRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest,
};
use gvm_gmp::commands::tags::{CreateTagRequest, DeleteTagRequest, GetTagRequest, TagResources};
use gvm_gmp::commands::targets::{
    CreateTargetRequest, DeleteTargetRequest, GetTargetRequest, GetTargetsRequest,
    ModifyTargetRequest,
};
use gvm_gmp::commands::tasks::{
    CreateTaskRequest, DeleteTaskRequest, GetTaskRequest, StartTaskRequest, StopTaskRequest,
};
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::enums::{CredentialType, EntityType, FilterType, PortRangeType};
use gvm_gmp::responses::ActionResponse;
use gvm_gmp::{
    EntityId, GmpRequest, GmpVersion, TargetHost, TargetHostError, TargetHosts, TargetHostsError,
    TargetPortSelection,
};
use serde_json::Value;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::{sleep, Instant};

const SMOKE_TARGET_PREFIX: &str = "e2e-679-smoke-target";
const SCAN_TARGET_PREFIX: &str = "e2e-679-scan-target";
const SCAN_TASK_PREFIX: &str = "e2e-679-scan-task";
const SECRET_SENTINEL: &str = "e2e-679-secret-sentinel-do-not-log";

fn main() -> ExitCode {
    match Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => match runtime.block_on(async_main()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log_line(&format!("E2E failure: {error}"));
                log_line(
                    "Capture container logs with: docker compose logs gvmd ospd-openvas openvasd > e2e-failure.log",
                );
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            log_line(&format!("failed to build Tokio runtime: {error}"));
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<(), AppError> {
    let mode = Mode::from_args(env::args().skip(1))?;
    let config = EnvConfig::from_env();

    match mode {
        Mode::WaitReady => {
            wait_ready(&config).await?;
            log_line("gvmd protocol and authenticated feed data are ready");
        }
        Mode::Smoke => run_mutating_suite(&config, MutatingSuite::Smoke).await?,
        Mode::Crud => run_mutating_suite(&config, MutatingSuite::Crud).await?,
        Mode::SecInfo => {
            run_secinfo_suite(&config).await?;
            log_line("E2E SecInfo suite passed");
        }
        Mode::Differential => run_mutating_suite(&config, MutatingSuite::Differential).await?,
        Mode::All => {
            run_mutating_suite(&config, MutatingSuite::Smoke).await?;
            run_mutating_suite(&config, MutatingSuite::Crud).await?;
            run_secinfo_suite(&config).await?;
            log_line("E2E SecInfo suite passed");
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MutatingSuite {
    Smoke,
    Crud,
    Differential,
}

async fn run_mutating_suite(config: &EnvConfig, suite: MutatingSuite) -> Result<(), AppError> {
    let mut tracker = CleanupTracker::new(config.clone());
    let label = match suite {
        MutatingSuite::Smoke => {
            run_smoke_suite(config, &mut tracker).await?;
            "smoke"
        }
        MutatingSuite::Crud => {
            run_crud_suite(config, &mut tracker).await?;
            "CRUD"
        }
        MutatingSuite::Differential => {
            run_differential_suite(config, &mut tracker).await?;
            "differential"
        }
    };
    tracker.cleanup_now().await?;
    log_line(&format!("E2E {label} suite passed"));
    Ok(())
}

#[derive(Clone, Debug)]
struct EnvConfig {
    task_progress_timeout_secs: u64,
    readiness_timeout_secs: u64,
    readiness_poll_interval_secs: u64,
    readiness_max_reconnects: usize,
    username: String,
    password: String,
    socket_path: String,
    run_scan: bool,
}

impl EnvConfig {
    fn from_env() -> Self {
        Self {
            task_progress_timeout_secs: env_u64("E2E_TASK_PROGRESS_TIMEOUT_SECS", 90),
            readiness_timeout_secs: env_u64("E2E_READINESS_TIMEOUT_SECS", 8400),
            readiness_poll_interval_secs: env_u64("E2E_READINESS_POLL_INTERVAL_SECS", 30),
            readiness_max_reconnects: env_usize("E2E_READINESS_MAX_RECONNECTS", 12),
            username: env::var("GVM_ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
            password: env::var("GVM_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string()),
            socket_path: env::var("GVM_SOCKET_PATH")
                .unwrap_or_else(|_| "/run/gvmd/gvmd.sock".to_string()),
            run_scan: matches!(
                env::var("E2E_RUN_SCAN")
                    .unwrap_or_else(|_| "0".to_string())
                    .as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES"
            ),
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Smoke,
    WaitReady,
    Crud,
    SecInfo,
    Differential,
    All,
}

impl Mode {
    fn from_args(args: impl Iterator<Item = String>) -> Result<Self, AppError> {
        let values: Vec<String> = args.collect();
        if values.is_empty() {
            return Ok(Self::Smoke);
        }
        if values.len() == 2 && values[0] == "--mode" {
            return match values[1].as_str() {
                "smoke" => Ok(Self::Smoke),
                "wait-ready" => Ok(Self::WaitReady),
                other => Err(AppError::Usage(format!(
                    "unsupported mode `{other}`; expected `smoke` or `wait-ready`"
                ))),
            };
        }
        if values.len() == 2 && values[0] == "--suite" {
            return match values[1].as_str() {
                "smoke" => Ok(Self::Smoke),
                "crud" => Ok(Self::Crud),
                "secinfo" => Ok(Self::SecInfo),
                "differential" => Ok(Self::Differential),
                "all" => Ok(Self::All),
                other => Err(AppError::Usage(format!(
                    "unsupported suite `{other}`; expected `smoke`, `crud`, `secinfo`, `differential`, or `all`"
                ))),
            };
        }
        Err(AppError::Usage(
            "usage: gvm-community-e2e [--mode <smoke|wait-ready> | --suite <smoke|crud|secinfo|differential|all>]"
                .to_string(),
        ))
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Assertion(String),
    #[error("{0}")]
    Usage(String),
    #[error("invalid entity id `{0}`")]
    InvalidEntityId(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Client(#[from] GvmError),
    #[error(transparent)]
    TargetHost(#[from] TargetHostError),
    #[error(transparent)]
    TargetHosts(#[from] TargetHostsError),
}

#[derive(Debug)]
struct CleanupTracker {
    config: EnvConfig,
    report_ids: Vec<EntityId>,
    task_ids: Vec<EntityId>,
    target_ids: Vec<EntityId>,
    port_list_ids: Vec<EntityId>,
    credential_ids: Vec<EntityId>,
    schedule_ids: Vec<EntityId>,
    filter_ids: Vec<EntityId>,
    note_ids: Vec<EntityId>,
    override_ids: Vec<EntityId>,
    tag_ids: Vec<EntityId>,
    armed: bool,
}

impl CleanupTracker {
    fn new(config: EnvConfig) -> Self {
        Self {
            config,
            report_ids: Vec::new(),
            task_ids: Vec::new(),
            target_ids: Vec::new(),
            port_list_ids: Vec::new(),
            credential_ids: Vec::new(),
            schedule_ids: Vec::new(),
            filter_ids: Vec::new(),
            note_ids: Vec::new(),
            override_ids: Vec::new(),
            tag_ids: Vec::new(),
            armed: true,
        }
    }

    fn is_empty(&self) -> bool {
        self.report_ids.is_empty()
            && self.task_ids.is_empty()
            && self.target_ids.is_empty()
            && self.port_list_ids.is_empty()
            && self.credential_ids.is_empty()
            && self.schedule_ids.is_empty()
            && self.filter_ids.is_empty()
            && self.note_ids.is_empty()
            && self.override_ids.is_empty()
            && self.tag_ids.is_empty()
    }

    fn track_report(&mut self, id: &EntityId) {
        self.report_ids.push(id.clone());
    }
    fn track_task(&mut self, id: &EntityId) {
        self.task_ids.push(id.clone());
    }
    fn track_target(&mut self, id: &EntityId) {
        self.target_ids.push(id.clone());
    }
    fn track_port_list(&mut self, id: &EntityId) {
        self.port_list_ids.push(id.clone());
    }
    fn track_credential(&mut self, id: &EntityId) {
        self.credential_ids.push(id.clone());
    }
    fn track_schedule(&mut self, id: &EntityId) {
        self.schedule_ids.push(id.clone());
    }
    fn track_filter(&mut self, id: &EntityId) {
        self.filter_ids.push(id.clone());
    }
    fn track_note(&mut self, id: &EntityId) {
        self.note_ids.push(id.clone());
    }
    fn track_override(&mut self, id: &EntityId) {
        self.override_ids.push(id.clone());
    }
    fn track_tag(&mut self, id: &EntityId) {
        self.tag_ids.push(id.clone());
    }

    fn untrack(ids: &mut Vec<EntityId>, id: &EntityId) {
        ids.retain(|value| value != id);
    }

    async fn cleanup_now(&mut self) -> Result<(), AppError> {
        let result = self.cleanup_inner().await;
        if self.is_empty() {
            self.armed = false;
        }
        result
    }

    async fn cleanup_inner(&mut self) -> Result<(), AppError> {
        if self.is_empty() {
            return Ok(());
        }
        let mut client = connect_authenticated(&self.config).await?;
        let mut errors = Vec::new();

        cleanup_ids(
            &mut client,
            "delete_report",
            &mut self.report_ids,
            DeleteReportRequest::new,
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_task",
            &mut self.task_ids,
            |id| DeleteTaskRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_target",
            &mut self.target_ids,
            |id| DeleteTargetRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_tag",
            &mut self.tag_ids,
            |id| DeleteTagRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_note",
            &mut self.note_ids,
            |id| DeleteNoteRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_override",
            &mut self.override_ids,
            |id| DeleteOverrideRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_filter",
            &mut self.filter_ids,
            |id| DeleteFilterRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_schedule",
            &mut self.schedule_ids,
            |id| DeleteScheduleRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_credential",
            &mut self.credential_ids,
            |id| DeleteCredentialRequest::new(id, true),
            &mut errors,
        )
        .await;
        cleanup_ids(
            &mut client,
            "delete_port_list",
            &mut self.port_list_ids,
            |id| DeletePortListRequest::new(id, true),
            &mut errors,
        )
        .await;

        if let Err(error) = client.disconnect().await {
            errors.push(format!("disconnect after cleanup: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::Assertion(format!(
                "cleanup incomplete; retained IDs for retry: {}",
                errors.join("; ")
            )))
        }
    }
}

async fn cleanup_ids<R, F>(
    client: &mut GmpClient<UnixSocketConnection>,
    action: &str,
    ids: &mut Vec<EntityId>,
    request: F,
    errors: &mut Vec<String>,
) where
    R: GmpRequest<Response = ActionResponse>,
    F: Fn(EntityId) -> R,
{
    let pending = std::mem::take(ids);
    let mut retained = Vec::new();
    for id in pending.into_iter().rev() {
        match client.execute(request(id.clone())).await {
            Ok(response) => {
                log_cleanup_result(action, &id, response.status);
            }
            Err(GvmError::Server { status: 404, .. }) => {
                log_cleanup_result(action, &id, 404);
            }
            Err(error) => {
                errors.push(format!("{action} {id}: {error}"));
                retained.push(id);
            }
        }
    }
    retained.reverse();
    *ids = retained;
}

impl Drop for CleanupTracker {
    fn drop(&mut self) {
        if !self.armed || self.is_empty() {
            return;
        }
        let config = self.config.clone();
        let mut retry = CleanupTracker {
            config,
            report_ids: self.report_ids.clone(),
            task_ids: self.task_ids.clone(),
            target_ids: self.target_ids.clone(),
            port_list_ids: self.port_list_ids.clone(),
            credential_ids: self.credential_ids.clone(),
            schedule_ids: self.schedule_ids.clone(),
            filter_ids: self.filter_ids.clone(),
            note_ids: self.note_ids.clone(),
            override_ids: self.override_ids.clone(),
            tag_ids: self.tag_ids.clone(),
            armed: false,
        };
        let cleanup = async move { retry.cleanup_inner().await };
        let result = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(cleanup))
        } else {
            match Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(cleanup),
                Err(error) => {
                    log_line(&format!("failed to build cleanup runtime: {error}"));
                    return;
                }
            }
        };
        if let Err(error) = result {
            log_line(&format!("cleanup after failure was incomplete: {error}"));
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ReadinessPolicy {
    timeout: Duration,
    poll_interval: Duration,
    max_reconnects: usize,
}

#[derive(Debug, Error)]
enum ReadinessFailure {
    #[error("connection dropped: {0}")]
    Dropped(String),
    #[error(transparent)]
    Fatal(#[from] AppError),
}

#[allow(async_fn_in_trait)]
trait FeedReadinessBackend {
    type Session;

    async fn connect(&mut self) -> Result<Self::Session, ReadinessFailure>;
    async fn authenticate(&mut self, session: &mut Self::Session) -> Result<(), ReadinessFailure>;
    async fn scan_config_count(
        &mut self,
        session: &mut Self::Session,
    ) -> Result<usize, ReadinessFailure>;
    async fn disconnect(&mut self, session: &mut Self::Session);
}

struct LiveReadinessBackend<'a> {
    config: &'a EnvConfig,
}

impl FeedReadinessBackend for LiveReadinessBackend<'_> {
    type Session = GmpClient<UnixSocketConnection>;

    async fn connect(&mut self) -> Result<Self::Session, ReadinessFailure> {
        connect_client(self.config)
            .await
            .map_err(classify_readiness_error)
    }

    async fn authenticate(&mut self, session: &mut Self::Session) -> Result<(), ReadinessFailure> {
        let response = session
            .authenticate(AuthenticateRequest::new(
                &self.config.username,
                &self.config.password,
            ))
            .await
            .map_err(classify_gvm_readiness_error)?;
        assert_typed_status(response.status, &response.status_text, 200, "authenticate")
            .map_err(ReadinessFailure::Fatal)
    }

    async fn scan_config_count(
        &mut self,
        session: &mut Self::Session,
    ) -> Result<usize, ReadinessFailure> {
        let response = session
            .get_scan_configs(GetScanConfigsRequest::new())
            .await
            .map_err(classify_gvm_readiness_error)?;
        assert_typed_status(
            response.status,
            &response.status_text,
            200,
            "get_scan_configs readiness",
        )
        .map_err(ReadinessFailure::Fatal)?;
        Ok(response.items.len())
    }

    async fn disconnect(&mut self, session: &mut Self::Session) {
        let _ = session.disconnect().await;
    }
}

fn classify_readiness_error(error: AppError) -> ReadinessFailure {
    match error {
        AppError::Client(client_error) => classify_gvm_readiness_error(client_error),
        other => ReadinessFailure::Fatal(other),
    }
}

fn classify_gvm_readiness_error(error: GvmError) -> ReadinessFailure {
    match error {
        GvmError::Connection(_) | GvmError::Timeout(_) => {
            ReadinessFailure::Dropped(error.to_string())
        }
        other => ReadinessFailure::Fatal(AppError::Client(other)),
    }
}

async fn wait_ready(config: &EnvConfig) -> Result<(), AppError> {
    let mut protocol_client = connect_client(config).await?;
    let version = protocol_client.version();
    protocol_client.disconnect().await?;
    log_line(&format!(
        "gvmd unauthenticated protocol readiness passed (GMP {version})"
    ));

    let policy = ReadinessPolicy {
        timeout: Duration::from_secs(config.readiness_timeout_secs),
        poll_interval: Duration::from_secs(config.readiness_poll_interval_secs),
        max_reconnects: config.readiness_max_reconnects,
    };
    let mut backend = LiveReadinessBackend { config };
    wait_for_feed(&mut backend, policy).await
}

async fn wait_for_feed<B: FeedReadinessBackend>(
    backend: &mut B,
    policy: ReadinessPolicy,
) -> Result<(), AppError> {
    let started = Instant::now();
    let deadline = started + policy.timeout;
    let mut reconnects = 0_usize;
    let mut polls = 0_usize;

    loop {
        if Instant::now() >= deadline {
            return Err(readiness_timeout(started, polls, reconnects));
        }
        let mut session = match backend.connect().await {
            Ok(session) => session,
            Err(ReadinessFailure::Dropped(message)) => {
                reconnects = register_reconnect(reconnects, policy.max_reconnects, &message)?;
                bounded_sleep(policy.poll_interval, deadline).await;
                continue;
            }
            Err(ReadinessFailure::Fatal(error)) => return Err(error),
        };

        match backend.authenticate(&mut session).await {
            Ok(()) => {}
            Err(ReadinessFailure::Dropped(message)) => {
                backend.disconnect(&mut session).await;
                reconnects = register_reconnect(reconnects, policy.max_reconnects, &message)?;
                bounded_sleep(policy.poll_interval, deadline).await;
                continue;
            }
            Err(ReadinessFailure::Fatal(error)) => {
                backend.disconnect(&mut session).await;
                return Err(error);
            }
        }

        loop {
            if Instant::now() >= deadline {
                backend.disconnect(&mut session).await;
                return Err(readiness_timeout(started, polls, reconnects));
            }
            polls += 1;
            match backend.scan_config_count(&mut session).await {
                Ok(count) if count > 0 => {
                    backend.disconnect(&mut session).await;
                    log_line(&format!(
                        "feed ready after {polls} poll(s) and {reconnects} reconnect(s): {count} scan config(s)"
                    ));
                    return Ok(());
                }
                Ok(_) => {
                    log_line(&format!(
                        "waiting for feed data: poll {polls} returned zero scan configs; authenticated session retained"
                    ));
                    bounded_sleep(policy.poll_interval, deadline).await;
                }
                Err(ReadinessFailure::Dropped(message)) => {
                    backend.disconnect(&mut session).await;
                    reconnects = register_reconnect(reconnects, policy.max_reconnects, &message)?;
                    bounded_sleep(policy.poll_interval, deadline).await;
                    break;
                }
                Err(ReadinessFailure::Fatal(error)) => {
                    backend.disconnect(&mut session).await;
                    return Err(error);
                }
            }
        }
    }
}

fn register_reconnect(current: usize, maximum: usize, diagnostic: &str) -> Result<usize, AppError> {
    let next = current + 1;
    if next > maximum {
        return Err(AppError::Assertion(format!(
            "feed readiness exceeded {maximum} reconnect attempt(s); last connection failure: {diagnostic}"
        )));
    }
    log_line(&format!(
        "feed readiness connection lost; reconnect {next}/{maximum}: {diagnostic}"
    ));
    Ok(next)
}

fn readiness_timeout(started: Instant, polls: usize, reconnects: usize) -> AppError {
    AppError::Assertion(format!(
        "feed readiness timed out after {}s ({polls} feed poll(s), {reconnects} reconnect(s)); gvmd authenticated successfully but no usable scan config became available",
        started.elapsed().as_secs()
    ))
}

async fn bounded_sleep(interval: Duration, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    sleep(interval.min(remaining)).await;
}

async fn run_smoke_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let suffix = run_suffix();
    let target_name = format!("{SMOKE_TARGET_PREFIX}-{suffix}");
    let mut client = connect_client(config).await?;

    let version_response = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        version_response.status,
        &version_response.status_text,
        200,
        "get_version",
    )?;
    let version = parse_version_text(&version_response.version)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("expected GMP version >= 22.4, got {version}"),
    )?;
    log_pass("01", &format!("typed version negotiation ({version})"));

    authenticate(&mut client, config).await?;
    log_pass("02", "typed authentication");

    ensure(
        client.command_support("export_scan_report") == CommandSupport::RequiresDiscovery,
        "export_scan_report should require explicit help discovery before classification",
    )?;
    let help = client.discover_commands().await?;
    assert_typed_status(help.status, &help.status_text, 200, "help discovery")?;
    let advertised = help
        .schema
        .as_ref()
        .map(|schema| schema.commands.len())
        .unwrap_or_default();
    ensure(
        advertised > 0,
        "help discovery returned no command inventory",
    )?;
    let export_support = client.command_support("export_scan_report");
    ensure(
        matches!(
            export_support,
            CommandSupport::Supported | CommandSupport::NotAdvertised
        ),
        &format!("unexpected post-discovery capability state: {export_support:?}"),
    )?;
    log_pass(
        "03",
        &format!(
            "help/capability discovery ({advertised} commands; export_scan_report={export_support:?})"
        ),
    );

    let configs = client
        .get_scan_configs(GetScanConfigsRequest::new())
        .await?;
    assert_typed_status(
        configs.status,
        &configs.status_text,
        200,
        "get_scan_configs",
    )?;
    ensure(
        !configs.items.is_empty(),
        "expected at least one scan config",
    )?;
    log_pass(
        "04",
        &format!("list scan configs ({})", configs.items.len()),
    );

    let scanners = client.get_scanners(GetScannersRequest::default()).await?;
    assert_typed_status(scanners.status, &scanners.status_text, 200, "get_scanners")?;
    ensure(!scanners.items.is_empty(), "expected at least one scanner")?;
    log_pass("05", &format!("list scanners ({})", scanners.items.len()));

    let formats = client
        .get_report_formats(GetReportFormatsRequest::new())
        .await?;
    assert_typed_status(
        formats.status,
        &formats.status_text,
        200,
        "get_report_formats",
    )?;
    ensure(
        !formats.items.is_empty(),
        "expected at least one report format",
    )?;
    log_pass(
        "06",
        &format!("list report formats ({})", formats.items.len()),
    );

    let port_lists = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    assert_typed_status(
        port_lists.status,
        &port_lists.status_text,
        200,
        "get_port_lists",
    )?;
    let port_list_id = first_meta_id(&port_lists.items, |item| &item.meta, "port list")?;
    log_pass(
        "07",
        &format!("list port lists ({})", port_lists.items.len()),
    );

    let targets_before = client.get_targets(GetTargetsRequest::default()).await?;
    assert_typed_status(
        targets_before.status,
        &targets_before.status_text,
        200,
        "get_targets",
    )?;
    log_pass(
        "08",
        &format!("list targets ({})", targets_before.items.len()),
    );

    let created = client
        .create_target(create_localhost_target(&target_name, port_list_id)?)
        .await?;
    assert_typed_status(created.status, &created.status_text, 201, "create_target")?;
    let target_id = created.id;
    tracker.track_target(&target_id);
    log_pass("09", &format!("create target ({target_id})"));

    let detail = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await?;
    assert_typed_status(detail.status, &detail.status_text, 200, "get_target")?;
    let target = only_item(&detail.items, "get_target")?;
    ensure(
        target.meta.name == target_name,
        "get_target returned an unexpected name",
    )?;
    log_pass("10", "typed target detail");

    let mut set_comment = ModifyTargetRequest::new(target_id.clone());
    set_comment.comment = Some("issue-679-set-clear".to_string());
    let modified = client.modify_target(set_comment).await?;
    assert_typed_status(
        modified.status,
        &modified.status_text,
        200,
        "modify_target set comment",
    )?;
    let set_detail = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await?;
    ensure(
        only_item(&set_detail.items, "get_target after set")?
            .meta
            .comment
            .as_deref()
            == Some("issue-679-set-clear"),
        "target comment was not set",
    )?;

    let mut clear_comment = ModifyTargetRequest::new(target_id.clone());
    clear_comment.comment = Some(String::new());
    let cleared = client.modify_target(clear_comment).await?;
    assert_typed_status(
        cleared.status,
        &cleared.status_text,
        200,
        "modify_target clear comment",
    )?;
    let cleared_detail = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await?;
    ensure(
        only_item(&cleared_detail.items, "get_target after clear")?
            .meta
            .comment
            .as_deref()
            .is_none_or(str::is_empty),
        "target comment was not cleared",
    )?;
    log_pass("11", "target set/clear mutation semantics");

    let deleted = client
        .delete_target(DeleteTargetRequest::new(target_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_target")?;
    CleanupTracker::untrack(&mut tracker.target_ids, &target_id);
    let absent = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await
        .expect_err("deleted target must return a server error");
    assert_server_error(absent, 404, &["find", "target"], "deleted target")?;
    log_pass("12", "delete target and exact typed server error");

    if config.run_scan {
        let xml_format = formats
            .items
            .iter()
            .find(|format| format.extension.as_deref() == Some("xml"))
            .or_else(|| {
                formats.items.iter().find(|format| {
                    format
                        .content_type
                        .as_deref()
                        .is_some_and(|value| value.contains("xml"))
                })
            })
            .ok_or_else(|| AppError::Assertion("no XML report format available".to_string()))?
            .meta
            .id
            .clone();
        run_scan_suite(
            &mut client,
            config,
            tracker,
            &suffix,
            &port_lists.items[0].meta.id,
            &configs.items[0].meta.id,
            &scanners.items[0].meta.id,
            &xml_format,
        )
        .await?;
    }

    client.disconnect().await?;
    let mut reconnected = connect_authenticated(config).await?;
    let after_reconnect = reconnected
        .get_targets(GetTargetsRequest::default())
        .await?;
    assert_typed_status(
        after_reconnect.status,
        &after_reconnect.status_text,
        200,
        "get_targets after reconnect",
    )?;
    reconnected.disconnect().await?;
    log_pass("13", "fresh reconnect with explicit re-authentication");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
    suffix: &str,
    port_list_id: &EntityId,
    scan_config_id: &EntityId,
    scanner_id: &EntityId,
    xml_format_id: &EntityId,
) -> Result<(), AppError> {
    log_line("Running extended typed scan flow because E2E_RUN_SCAN=1");
    let target_name = format!("{SCAN_TARGET_PREFIX}-{suffix}");
    let task_name = format!("{SCAN_TASK_PREFIX}-{suffix}");

    let target = client
        .create_target(create_localhost_target(&target_name, port_list_id.clone())?)
        .await?;
    assert_typed_status(
        target.status,
        &target.status_text,
        201,
        "create scan target",
    )?;
    let target_id = target.id;
    tracker.track_target(&target_id);

    let task = client
        .create_task(CreateTaskRequest::new(
            &task_name,
            scan_config_id.clone(),
            target_id.clone(),
            scanner_id.clone(),
        ))
        .await?;
    assert_typed_status(task.status, &task.status_text, 201, "create_task")?;
    let task_id = task.id;
    tracker.track_task(&task_id);

    let started = client
        .start_task(StartTaskRequest::new(task_id.clone()))
        .await?;
    assert_typed_status(started.status, &started.status_text, 202, "start_task")?;
    let report_id = started.report_id.ok_or_else(|| {
        AppError::Assertion("start_task response missing typed report_id".to_string())
    })?;
    tracker.track_report(&report_id);

    let status = poll_task_status(
        client,
        &task_id,
        Duration::from_secs(config.task_progress_timeout_secs),
    )
    .await?;
    if matches!(status.as_str(), "Running" | "Requested" | "Stop Requested") {
        let stopped = client
            .stop_task(StopTaskRequest::new(task_id.clone()))
            .await?;
        assert_typed_status(stopped.status, &stopped.status_text, 200, "stop_task")?;
    }

    let report = client
        .get_report(GetReportRequest::new(report_id.clone()))
        .await?;
    assert_typed_status(report.status, &report.status_text, 200, "get_report")?;
    ensure(
        report.items.iter().any(|item| item.meta.id == report_id),
        "typed get_report response omitted the requested report",
    )?;

    let export = client
        .get_report_export(GetReportExportRequest::new(
            report_id.clone(),
            xml_format_id.clone(),
        ))
        .await?;
    ensure(
        !export.bytes.is_empty(),
        "decoded XML report export was empty",
    )?;
    log_pass(
        "scan 01",
        &format!(
            "typed report/export decoding ({} bytes)",
            export.bytes.len()
        ),
    );

    let deleted_report = client
        .delete_report(DeleteReportRequest::new(report_id.clone()))
        .await?;
    assert_typed_status(
        deleted_report.status,
        &deleted_report.status_text,
        200,
        "delete_report",
    )?;
    CleanupTracker::untrack(&mut tracker.report_ids, &report_id);

    let deleted_task = client
        .delete_task(DeleteTaskRequest::new(task_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted_task.status,
        &deleted_task.status_text,
        200,
        "delete_task",
    )?;
    CleanupTracker::untrack(&mut tracker.task_ids, &task_id);

    let deleted_target = client
        .delete_target(DeleteTargetRequest::new(target_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted_target.status,
        &deleted_target.status_text,
        200,
        "delete_target",
    )?;
    CleanupTracker::untrack(&mut tracker.target_ids, &target_id);
    log_pass("scan 02", "task/report/target cleanup");
    Ok(())
}

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<WireTraceEvent>>>);

impl WireTrace for TraceCapture {
    fn trace(&self, event: WireTraceEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event);
        }
    }
}

impl TraceCapture {
    fn rendered(&self) -> String {
        self.0
            .lock()
            .map(|events| {
                events
                    .iter()
                    .map(|event| String::from_utf8_lossy(&event.bytes))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

async fn run_crud_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let suffix = run_suffix();
    let trace = TraceCapture::default();
    let connection = UnixSocketConnection::with_path(&config.socket_path);
    let mut client = GmpClient::connect_with_wire_trace(connection, trace.clone()).await?;
    authenticate(&mut client, config).await?;

    let mut port_list_request = CreatePortListRequest::new(format!("e2e-679-port-list-{suffix}"));
    port_list_request.port_range = Some("T:1-100".to_string());
    let port_list = client.create_port_list(port_list_request).await?;
    assert_typed_status(
        port_list.status,
        &port_list.status_text,
        201,
        "create_port_list",
    )?;
    let port_list_id = port_list.id;
    tracker.track_port_list(&port_list_id);
    let detail = client
        .get_port_list(GetPortListRequest::new(port_list_id.clone()))
        .await?;
    assert_one_id(
        &detail.items,
        |item| &item.meta.id,
        &port_list_id,
        "port list",
    )?;
    ensure(
        matches!(
            only_item(&detail.items, "created port list")?
                .port_ranges
                .as_slice(),
            [range]
                if range.start == 1
                    && range.end == 100
                    && range.range_type == PortRangeType::Tcp
                    && range.comment.is_empty()
        ),
        "created port list did not decode the expected structured TCP range",
    )?;
    let mut replace = ModifyPortListRequest::new(port_list_id.clone());
    replace.name = Some(format!("e2e-679-port-list-replaced-{suffix}"));
    replace.comment = Some("replacement preserves ranges".to_string());
    let replaced = client.modify_port_list(replace).await?;
    assert_typed_status(
        replaced.status,
        &replaced.status_text,
        200,
        "modify_port_list",
    )?;
    let replaced_detail = client
        .get_port_list(GetPortListRequest::new(port_list_id.clone()))
        .await?;
    ensure(
        matches!(
            only_item(&replaced_detail.items, "replaced port list")?
                .port_ranges
                .as_slice(),
            [range]
                if range.start == 1
                    && range.end == 100
                    && range.range_type == PortRangeType::Tcp
                    && range.comment.is_empty()
        ),
        "port-list metadata replacement unexpectedly discarded the port range",
    )?;
    delete_and_verify_port_list(&mut client, tracker, &port_list_id).await?;
    log_pass("crud 01", "port-list create/detail/replace-preserve/delete");

    let credentials_before = client.execute(GetCredentialsRequest::default()).await?;
    let ids_before = credentials_before
        .items
        .iter()
        .map(|item| item.meta.id.to_string())
        .collect::<BTreeSet<_>>();
    let mut invalid = CreateCredentialRequest::new(format!("e2e-679-invalid-{suffix}"));
    invalid.credential_type = Some(CredentialType::UsernamePassword);
    invalid.login = Some(String::new());
    invalid.password = Some(SECRET_SENTINEL.to_string());
    let validation_error = client
        .create_credential(invalid)
        .await
        .expect_err("empty login must fail before transport");
    ensure(
        matches!(validation_error, GvmError::Request(_)),
        "invalid credential did not fail as a request-validation error",
    )?;
    let credentials_after = client.execute(GetCredentialsRequest::default()).await?;
    let ids_after = credentials_after
        .items
        .iter()
        .map(|item| item.meta.id.to_string())
        .collect::<BTreeSet<_>>();
    ensure(
        ids_before == ids_after,
        "invalid credential validation changed live server state",
    )?;
    log_pass("crud 02", "invalid request rejected before mutation");

    let mut credential_request =
        CreateCredentialRequest::new(format!("e2e-679-credential-{suffix}"));
    credential_request.credential_type = Some(CredentialType::UsernamePassword);
    credential_request.login = Some("e2e-679-user".to_string());
    credential_request.password = Some(SECRET_SENTINEL.to_string());
    let credential = client.create_credential(credential_request).await?;
    assert_typed_status(
        credential.status,
        &credential.status_text,
        201,
        "create_credential",
    )?;
    let credential_id = credential.id;
    tracker.track_credential(&credential_id);
    let detail = client
        .execute(GetCredentialRequest::new(credential_id.clone()))
        .await?;
    assert_one_id(
        &detail.items,
        |item| &item.meta.id,
        &credential_id,
        "credential",
    )?;
    let deleted = client
        .delete_credential(DeleteCredentialRequest::new(credential_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "delete_credential",
    )?;
    CleanupTracker::untrack(&mut tracker.credential_ids, &credential_id);
    assert_missing_credential(&mut client, &credential_id).await?;
    let trace_text = trace.rendered();
    ensure(
        !trace_text.contains(SECRET_SENTINEL),
        "secret sentinel leaked through the live client wire trace",
    )?;
    ensure(
        trace_text.contains("redacted"),
        "wire trace did not contain a structural redaction marker",
    )?;
    log_pass(
        "crud 03",
        "credential lifecycle and live secret-sentinel redaction",
    );

    let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\nBEGIN:VEVENT\r\nDTSTART:20260401T060000Z\r\nDURATION:PT0S\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR";
    let mut schedule_request =
        CreateScheduleRequest::new(format!("e2e-679-schedule-{suffix}"), ical);
    schedule_request.timezone = Some("UTC".to_string());
    schedule_request.comment = Some("issue 679 canonical schedule".to_string());
    let schedule = client.create_schedule(schedule_request).await?;
    assert_typed_status(
        schedule.status,
        &schedule.status_text,
        201,
        "create_schedule",
    )?;
    let schedule_id = schedule.id;
    tracker.track_schedule(&schedule_id);
    let detail = client
        .get_schedule(GetScheduleRequest::new(schedule_id.clone()))
        .await?;
    assert_one_id(
        &detail.items,
        |item| &item.meta.id,
        &schedule_id,
        "schedule",
    )?;
    let deleted = client
        .delete_schedule(DeleteScheduleRequest::new(schedule_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_schedule")?;
    CleanupTracker::untrack(&mut tracker.schedule_ids, &schedule_id);
    assert_missing(
        client
            .get_schedule(GetScheduleRequest::new(schedule_id.clone()))
            .await,
        "schedule",
    )?;
    log_pass("crud 04", "schedule lifecycle");

    let mut filter_request = CreateFilterRequest::new(format!("e2e-679-filter-{suffix}"));
    filter_request.term = Some("name=test".to_string());
    filter_request.filter_type = Some(FilterType::Task);
    let filter = client.create_filter(filter_request).await?;
    assert_typed_status(filter.status, &filter.status_text, 201, "create_filter")?;
    let filter_id = filter.id;
    tracker.track_filter(&filter_id);
    let detail = client
        .get_filter(GetFilterRequest::new(filter_id.clone()))
        .await?;
    assert_one_id(&detail.items, |item| &item.meta.id, &filter_id, "filter")?;
    let deleted = client
        .delete_filter(DeleteFilterRequest::new(filter_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_filter")?;
    CleanupTracker::untrack(&mut tracker.filter_ids, &filter_id);
    assert_missing(
        client
            .get_filter(GetFilterRequest::new(filter_id.clone()))
            .await,
        "filter",
    )?;
    log_pass("crud 05", "filter lifecycle");

    run_task_crud(&mut client, tracker, &suffix).await?;
    run_note_override_tag_crud(&mut client, tracker, &suffix).await?;

    client.disconnect().await?;
    Ok(())
}

async fn run_task_crud(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    suffix: &str,
) -> Result<(), AppError> {
    let port_lists = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    let configs = client
        .get_scan_configs(GetScanConfigsRequest::new())
        .await?;
    let scanners = client.get_scanners(GetScannersRequest::default()).await?;
    let port_list_id = first_meta_id(&port_lists.items, |item| &item.meta, "port list")?;
    let config_id = first_meta_id(&configs.items, |item| &item.meta, "scan config")?;
    let scanner_id = first_meta_id(&scanners.items, |item| &item.meta, "scanner")?;

    let target = client
        .create_target(create_localhost_target(
            &format!("e2e-679-task-target-{suffix}"),
            port_list_id,
        )?)
        .await?;
    assert_typed_status(
        target.status,
        &target.status_text,
        201,
        "create task target",
    )?;
    let target_id = target.id;
    tracker.track_target(&target_id);

    let task = client
        .create_task(CreateTaskRequest::new(
            format!("e2e-679-task-{suffix}"),
            config_id,
            target_id.clone(),
            scanner_id,
        ))
        .await?;
    assert_typed_status(task.status, &task.status_text, 201, "create_task")?;
    let task_id = task.id;
    tracker.track_task(&task_id);
    let detail = client
        .get_task(GetTaskRequest::new(task_id.clone()))
        .await?;
    assert_one_id(&detail.items, |item| &item.meta.id, &task_id, "task")?;
    let deleted = client
        .delete_task(DeleteTaskRequest::new(task_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_task")?;
    CleanupTracker::untrack(&mut tracker.task_ids, &task_id);
    assert_missing(
        client.get_task(GetTaskRequest::new(task_id.clone())).await,
        "task",
    )?;
    let deleted_target = client
        .delete_target(DeleteTargetRequest::new(target_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted_target.status,
        &deleted_target.status_text,
        200,
        "delete task target",
    )?;
    CleanupTracker::untrack(&mut tracker.target_ids, &target_id);
    log_pass("crud 06", "task lifecycle with dependency-first cleanup");
    Ok(())
}

async fn run_note_override_tag_crud(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    suffix: &str,
) -> Result<(), AppError> {
    let nvts = client.get_nvts(GetNvtsRequest::default()).await?;
    assert_typed_status(nvts.status, &nvts.status_text, 200, "get_nvts")?;
    let nvt_oid = nvts
        .items
        .first()
        .ok_or_else(|| AppError::Assertion("no NVT available for note/override CRUD".to_string()))?
        .oid
        .clone();

    let note = client
        .create_note(CreateNoteRequest::new(&nvt_oid, "issue 679 canonical note"))
        .await?;
    assert_typed_status(note.status, &note.status_text, 201, "create_note")?;
    let note_id = note.id;
    tracker.track_note(&note_id);
    let detail = client
        .get_note(GetNoteRequest::new(note_id.clone()))
        .await?;
    assert_one_id(&detail.items, |item| &item.meta.id, &note_id, "note")?;
    let deleted = client
        .delete_note(DeleteNoteRequest::new(note_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_note")?;
    CleanupTracker::untrack(&mut tracker.note_ids, &note_id);
    assert_missing(
        client.get_note(GetNoteRequest::new(note_id.clone())).await,
        "note",
    )?;

    let override_response = client
        .create_override(CreateOverrideRequest::new(
            &nvt_oid,
            "issue 679 canonical override",
            -1.0,
        ))
        .await?;
    assert_typed_status(
        override_response.status,
        &override_response.status_text,
        201,
        "create_override",
    )?;
    let override_id = override_response.id;
    tracker.track_override(&override_id);
    let detail = client
        .get_override(GetOverrideRequest::new(override_id.clone()))
        .await?;
    assert_one_id(
        &detail.items,
        |item| &item.meta.id,
        &override_id,
        "override",
    )?;
    let deleted = client
        .delete_override(DeleteOverrideRequest::new(override_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_override")?;
    CleanupTracker::untrack(&mut tracker.override_ids, &override_id);
    assert_missing(
        client
            .get_override(GetOverrideRequest::new(override_id.clone()))
            .await,
        "override",
    )?;

    let resources = TagResources::new(EntityType::Task);
    let mut tag_request = CreateTagRequest::new(format!("e2e-679-tag-{suffix}"), resources);
    tag_request.value = Some("issue-679".to_string());
    tag_request.active = Some(true);
    let tag = client.create_tag(tag_request).await?;
    assert_typed_status(tag.status, &tag.status_text, 201, "create_tag")?;
    let tag_id = tag.id;
    tracker.track_tag(&tag_id);
    let detail = client.get_tag(GetTagRequest::new(tag_id.clone())).await?;
    assert_one_id(&detail.items, |item| &item.meta.id, &tag_id, "tag")?;
    let deleted = client
        .delete_tag(DeleteTagRequest::new(tag_id.clone(), true))
        .await?;
    assert_typed_status(deleted.status, &deleted.status_text, 200, "delete_tag")?;
    CleanupTracker::untrack(&mut tracker.tag_ids, &tag_id);
    assert_missing(
        client.get_tag(GetTagRequest::new(tag_id.clone())).await,
        "tag",
    )?;
    log_pass("crud 07", "note, override, and tag lifecycles");
    Ok(())
}

async fn run_secinfo_suite(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_authenticated(config).await?;
    let feeds = client.get_feeds(GetFeedsRequest::new()).await?;
    assert_typed_status(feeds.status, &feeds.status_text, 200, "get_feeds")?;
    ensure(!feeds.items.is_empty(), "expected at least one feed")?;
    log_pass("secinfo 01", &format!("get_feeds ({})", feeds.items.len()));

    let cves = client.get_cves(GetCvesRequest::default()).await?;
    assert_typed_status(cves.status, &cves.status_text, 200, "get_cves")?;
    log_pass("secinfo 02", &format!("get_cves ({})", cves.items.len()));

    let cpes = client.get_cpes(GetCpesRequest::default()).await?;
    assert_typed_status(cpes.status, &cpes.status_text, 200, "get_cpes")?;
    log_pass("secinfo 03", &format!("get_cpes ({})", cpes.items.len()));

    let cert = client
        .get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default())
        .await?;
    assert_typed_status(
        cert.status,
        &cert.status_text,
        200,
        "get_cert_bund_advisories",
    )?;
    log_pass(
        "secinfo 04",
        &format!("get_cert_bund_advisories ({})", cert.items.len()),
    );

    let dfn = client
        .get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default())
        .await?;
    assert_typed_status(dfn.status, &dfn.status_text, 200, "get_dfn_cert_advisories")?;
    log_pass(
        "secinfo 05",
        &format!("get_dfn_cert_advisories ({})", dfn.items.len()),
    );

    let nvts = client.get_nvts(GetNvtsRequest::default()).await?;
    assert_typed_status(nvts.status, &nvts.status_text, 200, "get_nvts")?;
    ensure(!nvts.items.is_empty(), "expected at least one NVT")?;
    log_pass("secinfo 06", &format!("get_nvts ({})", nvts.items.len()));
    client.disconnect().await?;
    Ok(())
}

#[derive(Clone, Debug)]
struct IdNameEntity {
    id: String,
    name: String,
}

#[derive(Clone, Debug)]
struct FeedEntity {
    feed_type: String,
    name: String,
    status: String,
    currently_syncing: bool,
}

#[derive(Clone, Debug)]
struct ReportFormatEntity {
    id: String,
    name: String,
    extension: String,
    content_type: String,
}

async fn run_differential_suite(
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    let mut client = connect_authenticated(config).await?;
    let mut warnings = Vec::new();

    let version = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(version.status, &version.status_text, 200, "get_version")?;
    compare_get_version(&version.version, &mut warnings)?;
    log_pass("diff 01", "get_version compared");

    let configs = client
        .get_scan_configs(GetScanConfigsRequest::new())
        .await?;
    let rust_configs = configs
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_scan_configs", &rust_configs, &mut warnings)?;
    log_pass("diff 02", "get_scan_configs compared");

    let scanners = client.get_scanners(GetScannersRequest::default()).await?;
    let rust_scanners = scanners
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_scanners", &rust_scanners, &mut warnings)?;
    log_pass("diff 03", "get_scanners compared");

    let port_lists = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    let rust_port_lists = port_lists
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_port_lists", &rust_port_lists, &mut warnings)?;
    log_pass("diff 04", "get_port_lists compared");

    let feeds = client.get_feeds(GetFeedsRequest::new()).await?;
    let rust_feeds = feeds
        .items
        .into_iter()
        .map(|entry| FeedEntity {
            feed_type: entry.type_,
            name: entry.name,
            status: entry.status.unwrap_or_default(),
            currently_syncing: entry.currently_syncing.as_deref().is_some_and(|value| {
                matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
            }),
        })
        .collect::<Vec<_>>();
    compare_get_feeds(&rust_feeds, &mut warnings)?;
    log_pass("diff 05", "get_feeds compared");

    let formats = client
        .get_report_formats(GetReportFormatsRequest::new())
        .await?;
    let rust_formats = formats
        .items
        .into_iter()
        .map(|entry| ReportFormatEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
            extension: entry.extension.unwrap_or_default(),
            content_type: entry.content_type.unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    compare_get_report_formats(&rust_formats, &mut warnings)?;
    log_pass("diff 06", "get_report_formats compared");

    run_target_differential(&mut client, tracker, &rust_port_lists, &mut warnings).await?;
    log_pass("diff 07", "cross-client target lifecycle");
    for warning in &warnings {
        log_line(&format!("[warn] {warning}"));
    }
    if warnings.is_empty() {
        log_line("[pass] differential comparison had no mismatches");
    }
    client.disconnect().await?;
    Ok(())
}

async fn run_target_differential(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    rust_port_lists: &[IdNameEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let port_list_id = rust_port_lists
        .first()
        .ok_or_else(|| AppError::Assertion("target differential requires a port list".to_string()))?
        .id
        .clone();
    let suffix = run_suffix();
    let rust_name = format!("e2e-679-diff-rust-{suffix}");
    let python_name = format!("e2e-679-diff-python-{suffix}");

    let created = client
        .create_target(create_localhost_target(
            &rust_name,
            parse_entity_id(&port_list_id)?,
        )?)
        .await?;
    let rust_id = created.id;
    tracker.track_target(&rust_id);

    let python_create = run_python_helper(
        "create_target",
        &[
            ("--name", python_name.as_str()),
            ("--hosts", "127.0.0.1"),
            ("--port-list-id", port_list_id.as_str()),
        ],
    )?;
    let python_id = parse_python_target_id(&python_create, "create_target", warnings);
    if let Some(id) = python_id.as_deref() {
        tracker.track_target(&parse_entity_id(id)?);
    }

    let targets = client.get_targets(GetTargetsRequest::default()).await?;
    let rust_targets = targets
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    let python_targets =
        parse_python_id_name_entities(&run_python_helper("get_targets", &[])?, "targets", warnings);
    compare_target_visibility(
        "rust target",
        rust_id.as_str(),
        &rust_name,
        &rust_targets,
        &python_targets,
        warnings,
    );
    if let Some(id) = python_id.as_deref() {
        compare_target_visibility(
            "python target",
            id,
            &python_name,
            &rust_targets,
            &python_targets,
            warnings,
        );
    }

    client
        .delete_target(DeleteTargetRequest::new(rust_id.clone(), true))
        .await?;
    CleanupTracker::untrack(&mut tracker.target_ids, &rust_id);
    if let Some(id) = python_id {
        let deleted = run_python_helper("delete_target", &[("--target-id", id.as_str())])?;
        if deleted.get("status").and_then(Value::as_str) != Some("ok") {
            warnings.push(format!(
                "delete_target python returned non-ok status: {deleted}"
            ));
        } else {
            let entity_id = parse_entity_id(&id)?;
            CleanupTracker::untrack(&mut tracker.target_ids, &entity_id);
        }
    }
    Ok(())
}

fn compare_target_visibility(
    label: &str,
    expected_id: &str,
    expected_name: &str,
    rust_targets: &[IdNameEntity],
    python_targets: &[IdNameEntity],
    warnings: &mut Vec<String>,
) {
    for (client, targets) in [("rust", rust_targets), ("python", python_targets)] {
        match targets.iter().find(|entry| entry.id == expected_id) {
            Some(entry) if entry.name == expected_name => {}
            Some(entry) => warnings.push(format!(
                "{label} mismatch in {client} get_targets: `{}` != `{expected_name}`",
                entry.name
            )),
            None => warnings.push(format!(
                "{label} missing in {client} get_targets: id `{expected_id}`"
            )),
        }
    }
}

fn compare_get_version(rust_version: &str, warnings: &mut Vec<String>) -> Result<(), AppError> {
    let payload = run_python_helper("get_version", &[])?;
    let python = payload
        .get("data")
        .and_then(|data| data.get("version"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if payload.get("status").and_then(Value::as_str) != Some("ok") {
        warnings.push(format!(
            "get_version python returned non-ok status: {payload}"
        ));
    } else if rust_version != python {
        warnings.push(format!(
            "get_version mismatch: rust `{rust_version}` vs python `{python}`"
        ));
    }
    Ok(())
}

fn compare_id_name_command(
    command: &str,
    rust: &[IdNameEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let payload = run_python_helper(command, &[])?;
    let python = parse_python_id_name_entities(&payload, list_key_for_command(command), warnings);
    compare_id_name_entities(command, rust, &python, warnings);
    Ok(())
}

fn compare_id_name_entities(
    label: &str,
    rust: &[IdNameEntity],
    python: &[IdNameEntity],
    warnings: &mut Vec<String>,
) {
    if rust.len() != python.len() {
        warnings.push(format!(
            "{label} count mismatch: rust {} vs python {}",
            rust.len(),
            python.len()
        ));
    }
    let rust_map = rust
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let python_map = python
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect::<BTreeMap<_, _>>();
    for id in rust_map
        .keys()
        .chain(python_map.keys())
        .collect::<BTreeSet<_>>()
    {
        match (rust_map.get(id), python_map.get(id)) {
            (Some(rust_name), Some(python_name)) if rust_name == python_name => {}
            (Some(rust_name), Some(python_name)) => warnings.push(format!(
                "{label} name mismatch for `{id}`: rust `{rust_name}` vs python `{python_name}`"
            )),
            (Some(_), None) => warnings.push(format!("{label} UUID missing in python: {id}")),
            (None, Some(_)) => warnings.push(format!("{label} UUID missing in rust: {id}")),
            (None, None) => {}
        }
    }
}

fn compare_get_feeds(rust: &[FeedEntity], warnings: &mut Vec<String>) -> Result<(), AppError> {
    let payload = run_python_helper("get_feeds", &[])?;
    let python = parse_python_feeds(&payload, warnings);
    let rust_map = rust
        .iter()
        .map(|entry| (entry.feed_type.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let python_map = python
        .iter()
        .map(|entry| (entry.feed_type.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    if rust_map.len() != python_map.len() {
        warnings.push(format!(
            "get_feeds count mismatch: rust {} vs python {}",
            rust_map.len(),
            python_map.len()
        ));
    }
    for (kind, rust_entry) in rust_map {
        match python_map.get(kind) {
            Some(python_entry)
                if rust_entry.name == python_entry.name
                    && rust_entry.status == python_entry.status
                    && rust_entry.currently_syncing == python_entry.currently_syncing => {}
            Some(python_entry) => warnings.push(format!(
                "get_feeds mismatch for `{kind}`: rust {rust_entry:?} vs python {python_entry:?}"
            )),
            None => warnings.push(format!("get_feeds type missing in python: {kind}")),
        }
    }
    Ok(())
}

fn compare_get_report_formats(
    rust: &[ReportFormatEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let payload = run_python_helper("get_report_formats", &[])?;
    let python = parse_python_report_formats(&payload, warnings);
    let rust_map = rust
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let python_map = python
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    for (id, rust_entry) in rust_map {
        match python_map.get(id) {
            Some(python_entry)
                if rust_entry.name == python_entry.name
                    && rust_entry.extension == python_entry.extension
                    && rust_entry.content_type == python_entry.content_type => {}
            Some(python_entry) => warnings.push(format!(
                "get_report_formats mismatch for `{id}`: rust {rust_entry:?} vs python {python_entry:?}"
            )),
            None => warnings.push(format!("get_report_formats UUID missing in python: {id}")),
        }
    }
    Ok(())
}

fn run_python_helper(command: &str, args: &[(&str, &str)]) -> Result<Value, AppError> {
    let helper_path = env::var("DIFFERENTIAL_HELPER_PATH")
        .unwrap_or_else(|_| "/workspace/docker/scripts/differential-helper.py".to_string());
    let mut helper = Command::new("python3");
    helper.arg(helper_path).arg(command);
    for (flag, value) in args {
        helper.arg(flag).arg(value);
    }
    let output = helper.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(AppError::Assertion(format!(
            "python helper `{command}` returned empty stdout: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(serde_json::from_str(&stdout)?)
}

fn list_key_for_command(command: &str) -> &str {
    match command {
        "get_scan_configs" => "scan_configs",
        "get_scanners" => "scanners",
        "get_port_lists" => "port_lists",
        "get_targets" => "targets",
        _ => "items",
    }
}

fn parse_python_id_name_entities(
    payload: &Value,
    key: &str,
    warnings: &mut Vec<String>,
) -> Vec<IdNameEntity> {
    if payload.get("status").and_then(Value::as_str) != Some("ok") {
        warnings.push(format!(
            "python helper returned non-ok status for `{key}`: {payload}"
        ));
        return Vec::new();
    }
    payload
        .get("data")
        .and_then(|data| data.get(key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(IdNameEntity {
                        id: item.get("id")?.as_str()?.to_string(),
                        name: item
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| {
            warnings.push(format!(
                "python helper payload missing data.{key}: {payload}"
            ));
            Vec::new()
        })
}

fn parse_python_feeds(payload: &Value, warnings: &mut Vec<String>) -> Vec<FeedEntity> {
    payload
        .get("data")
        .and_then(|data| data.get("feeds"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| FeedEntity {
                    feed_type: json_string(item, "type"),
                    name: json_string(item, "name"),
                    status: json_string(item, "status"),
                    currently_syncing: item
                        .get("currently_syncing")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_else(|| {
            warnings.push(format!(
                "python helper payload missing data.feeds: {payload}"
            ));
            Vec::new()
        })
}

fn parse_python_report_formats(
    payload: &Value,
    warnings: &mut Vec<String>,
) -> Vec<ReportFormatEntity> {
    payload
        .get("data")
        .and_then(|data| data.get("report_formats"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(ReportFormatEntity {
                        id: item.get("id")?.as_str()?.to_string(),
                        name: json_string(item, "name"),
                        extension: json_string(item, "extension"),
                        content_type: json_string(item, "content_type"),
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| {
            warnings.push(format!(
                "python helper payload missing data.report_formats: {payload}"
            ));
            Vec::new()
        })
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn parse_python_target_id(
    payload: &Value,
    command: &str,
    warnings: &mut Vec<String>,
) -> Option<String> {
    if payload.get("status").and_then(Value::as_str) != Some("ok") {
        warnings.push(format!(
            "{command} python helper returned non-ok status: {payload}"
        ));
        return None;
    }
    let id = payload
        .get("data")
        .and_then(|data| data.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if id.is_none() {
        warnings.push(format!(
            "{command} python helper payload missing data.id: {payload}"
        ));
    }
    id
}

async fn poll_task_status(
    client: &mut GmpClient<UnixSocketConnection>,
    task_id: &EntityId,
    timeout: Duration,
) -> Result<String, AppError> {
    let started = Instant::now();
    let mut last = "unknown".to_string();
    while started.elapsed() <= timeout {
        let response = client
            .get_task(GetTaskRequest::new(task_id.clone()))
            .await?;
        let task = only_item(&response.items, "get_task while polling")?;
        if let Some(status) = &task.status {
            last.clone_from(status);
            if status != "New" {
                return Ok(last);
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    Err(AppError::Assertion(format!(
        "task {task_id} did not progress within {} seconds; last status: {last}",
        timeout.as_secs()
    )))
}

async fn connect_client(config: &EnvConfig) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let connection = UnixSocketConnection::with_path(&config.socket_path);
    Ok(GmpClient::connect(connection).await?)
}

async fn connect_authenticated(
    config: &EnvConfig,
) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let mut client = connect_client(config).await?;
    authenticate(&mut client, config).await?;
    Ok(client)
}

async fn authenticate(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
) -> Result<(), AppError> {
    let response = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    assert_typed_status(response.status, &response.status_text, 200, "authenticate")
}

fn create_localhost_target(
    name: &str,
    port_list_id: EntityId,
) -> Result<CreateTargetRequest, AppError> {
    let localhost = TargetHost::from_str("127.0.0.1")?;
    let hosts = TargetHosts::new([localhost], [])?;
    Ok(CreateTargetRequest::new(
        name,
        hosts,
        TargetPortSelection::PortList(port_list_id),
    ))
}

fn parse_entity_id(value: &str) -> Result<EntityId, AppError> {
    EntityId::from_str(value).map_err(|_| AppError::InvalidEntityId(value.to_string()))
}

fn first_meta_id<T, F>(items: &[T], meta: F, label: &str) -> Result<EntityId, AppError>
where
    F: Fn(&T) -> &gvm_gmp::responses::EntityMeta,
{
    items
        .first()
        .map(|item| meta(item).id.clone())
        .ok_or_else(|| AppError::Assertion(format!("expected at least one {label}")))
}

fn only_item<'a, T>(items: &'a [T], label: &str) -> Result<&'a T, AppError> {
    ensure(
        items.len() == 1,
        &format!("{label} returned {} items, expected exactly 1", items.len()),
    )?;
    Ok(&items[0])
}

fn assert_one_id<T, F>(items: &[T], id: F, expected: &EntityId, label: &str) -> Result<(), AppError>
where
    F: Fn(&T) -> &EntityId,
{
    let item = only_item(items, label)?;
    ensure(
        id(item) == expected,
        &format!("{label} detail returned an unexpected ID"),
    )
}

fn assert_typed_status(
    actual: u16,
    status_text: &str,
    expected: u16,
    label: &str,
) -> Result<(), AppError> {
    ensure(
        actual == expected,
        &format!("{label} returned status {actual} ({status_text}), expected exactly {expected}"),
    )
}

fn assert_server_error(
    error: GvmError,
    expected_status: u16,
    message_terms: &[&str],
    label: &str,
) -> Result<(), AppError> {
    match error {
        GvmError::Server { status, message } => {
            ensure(
                status == expected_status,
                &format!("{label} returned server status {status}, expected {expected_status}"),
            )?;
            let lower = message.to_ascii_lowercase();
            for term in message_terms {
                ensure(
                    lower.contains(&term.to_ascii_lowercase()),
                    &format!("{label} server error `{message}` did not contain `{term}`"),
                )?;
            }
            Ok(())
        }
        other => Err(AppError::Assertion(format!(
            "{label} returned {other}, expected a typed server error"
        ))),
    }
}

fn assert_missing<T>(result: Result<T, GvmError>, resource: &str) -> Result<(), AppError> {
    match result {
        Ok(_) => Err(AppError::Assertion(format!(
            "deleted {resource} unexpectedly remained available"
        ))),
        Err(error) => assert_server_error(error, 404, &["find", resource], resource),
    }
}

async fn delete_and_verify_port_list(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    id: &EntityId,
) -> Result<(), AppError> {
    let deleted = client
        .delete_port_list(DeletePortListRequest::new(id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "delete_port_list",
    )?;
    CleanupTracker::untrack(&mut tracker.port_list_ids, id);
    assert_missing(
        client
            .get_port_list(GetPortListRequest::new(id.clone()))
            .await,
        "port_list",
    )
}

async fn assert_missing_credential(
    client: &mut GmpClient<UnixSocketConnection>,
    id: &EntityId,
) -> Result<(), AppError> {
    assert_missing(
        client.execute(GetCredentialRequest::new(id.clone())).await,
        "credential",
    )
}

fn run_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn ensure(condition: bool, message: &str) -> Result<(), AppError> {
    if condition {
        Ok(())
    } else {
        Err(AppError::Assertion(message.to_string()))
    }
}

fn log_pass(step: &str, label: &str) {
    log_line(&format!("[pass] {step} {label}"));
}

fn log_cleanup_result(action: &str, id: &EntityId, status: u16) {
    log_line(&format!("[cleanup] {action} {id} -> {status}"));
}

fn log_line(message: &str) {
    let _ = writeln!(io::stdout(), "{message}");
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use gvm_gmp::{GmpRequestCodec, GmpRequestError};

    #[derive(Debug)]
    struct FakeSession(usize);

    #[derive(Default)]
    struct FakeReadiness {
        plans: VecDeque<VecDeque<Result<usize, &'static str>>>,
        connects: usize,
        authentications: usize,
        disconnects: usize,
    }

    impl FeedReadinessBackend for FakeReadiness {
        type Session = FakeSession;

        async fn connect(&mut self) -> Result<Self::Session, ReadinessFailure> {
            let index = self.connects;
            self.connects += 1;
            Ok(FakeSession(index))
        }

        async fn authenticate(
            &mut self,
            _session: &mut Self::Session,
        ) -> Result<(), ReadinessFailure> {
            self.authentications += 1;
            Ok(())
        }

        async fn scan_config_count(
            &mut self,
            session: &mut Self::Session,
        ) -> Result<usize, ReadinessFailure> {
            self.plans
                .get_mut(session.0)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(1))
                .map_err(|message| ReadinessFailure::Dropped(message.to_string()))
        }

        async fn disconnect(&mut self, _session: &mut Self::Session) {
            self.disconnects += 1;
        }
    }

    fn test_policy() -> ReadinessPolicy {
        ReadinessPolicy {
            timeout: Duration::from_secs(1),
            poll_interval: Duration::ZERO,
            max_reconnects: 2,
        }
    }

    #[test]
    fn empty_feed_polls_authenticate_only_once_for_one_session() {
        let mut fake = FakeReadiness {
            plans: VecDeque::from([VecDeque::from([Ok(0), Ok(0), Ok(3)])]),
            ..FakeReadiness::default()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, test_policy()))
            .expect("feed becomes ready");
        assert_eq!(fake.connects, 1);
        assert_eq!(fake.authentications, 1);
        assert_eq!(fake.disconnects, 1);
    }

    #[test]
    fn dropped_feed_connection_reconnects_and_reauthenticates() {
        let mut fake = FakeReadiness {
            plans: VecDeque::from([
                VecDeque::from([Ok(0), Err("peer reset")]),
                VecDeque::from([Ok(2)]),
            ]),
            ..FakeReadiness::default()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, test_policy()))
            .expect("feed becomes ready after reconnect");
        assert_eq!(fake.connects, 2);
        assert_eq!(fake.authentications, 2);
        assert_eq!(fake.disconnects, 2);
    }

    #[test]
    fn canonical_target_request_uses_validated_hosts_and_port_list() -> Result<(), AppError> {
        let request = create_localhost_target("e2e-target", parse_entity_id("port-list")?)?;
        assert_eq!(
            request.encode(GmpVersion(22, 7)).expect("valid request"),
            b"<create_target><name>e2e-target</name><hosts>127.0.0.1</hosts><exclude_hosts></exclude_hosts><port_list id=\"port-list\"/></create_target>"
        );
        Ok(())
    }

    #[test]
    fn invalid_credential_is_rejected_without_exposing_secret() {
        let mut request = CreateCredentialRequest::new("invalid");
        request.credential_type = Some(CredentialType::UsernamePassword);
        request.login = Some(String::new());
        request.password = Some(SECRET_SENTINEL.to_string());
        let error = request
            .validate()
            .expect_err("empty credential login must be rejected");
        assert!(matches!(error, GmpRequestError::InvalidField { .. }));
        assert!(!format!("{request:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    fn username_password_credential_may_omit_password_for_gvmd_autogeneration() {
        let mut request = CreateCredentialRequest::new("generated-password");
        request.credential_type = Some(CredentialType::UsernamePassword);
        request.login = Some("generated-password-user".to_string());

        request
            .validate()
            .expect("gvmd accepts an omitted password and generates one");
    }
}
