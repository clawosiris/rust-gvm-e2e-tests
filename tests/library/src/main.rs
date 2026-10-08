// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Manual E2E harness for a real Greenbone Community container stack.

#![allow(clippy::print_stdout, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::process::Command;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use gvm_client::{parse_version_text, GmpClient, GvmError};
use gvm_connection::{
    ConnectionError, GvmConnection, SshAuth, SshConfig, SshConnection, TlsClientIdentity,
    TlsConfig, TlsConnection, UnixSocketConnection,
};
use gvm_gmp::commands::agent_groups::*;
use gvm_gmp::commands::agents::*;
use gvm_gmp::commands::aggregates::*;
use gvm_gmp::commands::alerts::*;
use gvm_gmp::commands::assets::*;
use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::commands::configs::*;
use gvm_gmp::commands::credentials::*;
use gvm_gmp::commands::feed::*;
use gvm_gmp::commands::filters::*;
use gvm_gmp::commands::groups::*;
use gvm_gmp::commands::help::{HelpMode, HelpRequest};
use gvm_gmp::commands::hosts::*;
use gvm_gmp::commands::notes::*;
use gvm_gmp::commands::nvts::*;
use gvm_gmp::commands::oci_image_targets::*;
use gvm_gmp::commands::operating_systems::*;
use gvm_gmp::commands::overrides::*;
use gvm_gmp::commands::permissions::*;
use gvm_gmp::commands::port_lists::*;
use gvm_gmp::commands::report_configs::*;
use gvm_gmp::commands::report_formats::*;
use gvm_gmp::commands::reports::*;
use gvm_gmp::commands::resource_names::*;
use gvm_gmp::commands::results::*;
use gvm_gmp::commands::roles::*;
use gvm_gmp::commands::scan_configs::*;
use gvm_gmp::commands::scanners::*;
use gvm_gmp::commands::schedules::*;
use gvm_gmp::commands::secinfo::*;
use gvm_gmp::commands::system::*;
use gvm_gmp::commands::system_reports::*;
use gvm_gmp::commands::tags::*;
use gvm_gmp::commands::targets::*;
use gvm_gmp::commands::tasks::*;
use gvm_gmp::commands::tls_certificates::*;
use gvm_gmp::commands::trashcan::*;
use gvm_gmp::commands::users::*;
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::enums::{
    AlertCondition, AlertEvent, AlertMethod, CredentialType, EntityType, FilterType, ResourceType,
    ScannerType,
};
use gvm_gmp::responses::permission::GetPermissionsResponse;
use gvm_gmp::responses::report::ReportExportInfo;
use gvm_gmp::responses::report_config::GetReportConfigsResponse;
use gvm_gmp::responses::report_format::{GetReportFormatsResponse, ReportFormat};
use gvm_gmp::responses::result::{GetResultsResponse, ScanResult};
use gvm_gmp::responses::scanner::GetScannersResponse;
use gvm_gmp::responses::task::{GetTasksResponse, Task};
use gvm_gmp::responses::ActionResponse;
use gvm_gmp::types::{CollectionUpdate, EntityId, GmpVersion};
#[cfg(test)]
use gvm_gmp::GmpRequestCodec;
use gvm_gmp::{
    GmpRequest, TargetHost, TargetHostError, TargetHosts, TargetHostsError, TargetPortSelection,
};
use gvm_protocol::{Response, XmlCommand};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::{sleep, Instant};

use gvm_community_e2e::capability::{
    build_plan, classify_live_help_commands, enforce_live_help_parity, parse_feature_evidence,
    CommandSupport, DeploymentCapabilities, DeploymentContract, Evidence, FeatureCatalog,
    FixtureDescriptor, PlanDecision, PlanEntryKind, PlanInput, ProbeResult, ProbeState, TestPlan,
    DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION,
};
use gvm_community_e2e::runtime::{self, FeatureState, Outcome};
use gvm_community_e2e::HELPER_MIGRATIONS;
use gvm_community_e2e::{Disposition, COMMAND_COVERAGE, HELPER_COVERAGE, LIVE_HELP_ALLOWLIST};

fn tls_certificate_data() -> Vec<u8> {
    include_bytes!("../../../fixtures/e2e-certificate.pem").to_vec()
}

fn main() -> ExitCode {
    match Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => match runtime.block_on(async_main()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                runtime::fail("lane", &error.to_string());
                if let Err(write_error) = runtime::write() {
                    log_line(&format!(
                        "failed to write structured result after failure: {write_error}"
                    ));
                }
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
    let config = EnvConfig::from_env()?;
    if mode != Mode::WaitReady {
        runtime::initialize(&config.run_id, mode.lane_name()).map_err(AppError::Assertion)?;
    }

    match mode {
        Mode::WaitReady => {
            wait_ready(&config).await?;
            log_line("gvmd is responsive");
        }
        Mode::Smoke => {
            let mut tracker = CleanupTracker::new(config.clone());
            run_smoke_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("E2E smoke suite passed");
        }
        Mode::Crud => {
            let mut tracker = CleanupTracker::new(config.clone());
            run_crud_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("E2E CRUD suite passed");
        }
        Mode::SecInfo => {
            run_secinfo_suite(&config).await?;
            log_line("E2E SecInfo suite passed");
        }
        Mode::Fast => {
            let mut tracker = CleanupTracker::new(config.clone());
            let plan = discover_deployment(&config, mode.lane_name()).await?;
            cleanup_previous_runs(&config).await?;
            run_dynamic_capability_scenarios(&config, &mut tracker, &plan).await?;
            run_typed_read_suite(&config).await?;
            run_config_scanner_lifecycles(&config, &mut tracker).await?;
            run_smoke_suite(&config, &mut tracker).await?;
            run_crud_suite(&config, &mut tracker).await?;
            run_secinfo_suite(&config).await?;
            tracker.cleanup_now().await?;
            reconcile_executed_plan(&plan)?;
            log_line("Deployment devel-fast lane passed");
        }
        Mode::Scan => {
            let mut tracker = CleanupTracker::new(config.clone());
            let plan = discover_deployment(&config, mode.lane_name()).await?;
            cleanup_previous_runs(&config).await?;
            let mut client = connect_client(&config).await?;
            run_scan_suite(&mut client, &config, &mut tracker, Some(&plan)).await?;
            client.disconnect().await?;
            tracker.cleanup_now().await?;
            reconcile_executed_plan(&plan)?;
            log_line("Deployment devel-scan lane passed");
        }
        Mode::Isolated => {
            let mut tracker = CleanupTracker::new(config.clone());
            let plan = discover_deployment(&config, mode.lane_name()).await?;
            cleanup_previous_runs(&config).await?;
            run_isolated_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            reconcile_executed_plan(&plan)?;
            log_line("Deployment devel-isolated lane passed");
        }
        Mode::Transport => {
            let plan = discover_deployment(&config, mode.lane_name()).await?;
            run_transport_suite(&config).await?;
            reconcile_executed_plan(&plan)?;
            log_line("Deployment devel-transport lane completed");
        }
        Mode::Differential => {
            let mut tracker = CleanupTracker::new(config.clone());
            let plan = discover_deployment(&config, mode.lane_name()).await?;
            cleanup_previous_runs(&config).await?;
            run_differential_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            reconcile_executed_plan(&plan)?;
            log_line("E2E differential suite completed");
        }
        Mode::All => {
            let mut tracker = CleanupTracker::new(config.clone());
            run_smoke_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("E2E smoke suite passed");

            let mut tracker = CleanupTracker::new(config.clone());
            run_crud_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("E2E CRUD suite passed");

            run_secinfo_suite(&config).await?;
            log_line("E2E SecInfo suite passed");
        }
    }

    if mode != Mode::WaitReady {
        let path = runtime::write().map_err(AppError::Assertion)?;
        log_line(&format!("structured result: {}", path.display()));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EnvConfig {
    task_progress_timeout_secs: u64,
    report_export_timeout_secs: u64,
    report_export_poll_interval_secs: u64,
    readiness_timeout_secs: u64,
    readiness_poll_interval_secs: u64,
    readiness_max_reconnects: usize,
    username: String,
    password: String,
    socket_path: String,
    run_scan: bool,
    run_id: String,
    namespace: String,
}

impl EnvConfig {
    fn from_env() -> Result<Self, AppError> {
        let task_progress_timeout_secs = env::var("E2E_TASK_PROGRESS_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(90);
        let report_export_timeout_secs = env_u64("E2E_REPORT_EXPORT_TIMEOUT_SECS", 300);
        let report_export_poll_interval_secs = env_u64("E2E_REPORT_EXPORT_POLL_INTERVAL_SECS", 1);
        ensure(
            report_export_timeout_secs > 0 && report_export_poll_interval_secs > 0,
            "report-export timeout and poll interval must both be positive",
        )?;
        let run_id = env::var("E2E_RUN_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(generated_run_id);
        let run_id = sanitize_run_id(&run_id)?;
        Ok(Self {
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
            task_progress_timeout_secs,
            report_export_timeout_secs,
            report_export_poll_interval_secs,
            readiness_timeout_secs: env_u64("E2E_READINESS_TIMEOUT_SECS", 21_000),
            readiness_poll_interval_secs: env_u64("E2E_READINESS_POLL_INTERVAL_SECS", 30),
            readiness_max_reconnects: env_usize("E2E_READINESS_MAX_RECONNECTS", 12),
            namespace: format!("rust-gvm-e2e-{run_id}-"),
            run_id,
        })
    }

    fn name(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.namespace)
    }
}

fn generated_run_id() -> String {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let github_run = env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string());
    let attempt = env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".to_string());
    format!("{github_run}-{attempt}-{}-{epoch}", std::process::id())
}

fn sanitize_run_id(value: &str) -> Result<String, AppError> {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('-').to_string();
    ensure(
        !sanitized.is_empty() && sanitized.len() <= 96,
        "E2E_RUN_ID must contain 1-96 alphanumeric/dash characters after sanitization",
    )?;
    Ok(sanitized)
}

fn fixture_uuid(run_id: &str, label: &str) -> String {
    let mut high = DefaultHasher::new();
    run_id.hash(&mut high);
    let mut low = DefaultHasher::new();
    label.hash(&mut low);
    run_id.hash(&mut low);
    let value = (u128::from(high.finish()) << 64) | u128::from(low.finish());
    let hex = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Smoke,
    WaitReady,
    Crud,
    SecInfo,
    Fast,
    Scan,
    Isolated,
    Transport,
    Differential,
    All,
}

impl Mode {
    fn from_args(args: impl Iterator<Item = String>) -> Result<Self, AppError> {
        let values: Vec<String> = args.collect();
        if values.is_empty() {
            return Ok(Self::Smoke);
        }

        if values.len() == 2 {
            if values[0] == "--mode" {
                return match values[1].as_str() {
                    "smoke" => Ok(Self::Smoke),
                    "wait-ready" => Ok(Self::WaitReady),
                    other => Err(AppError::Usage(format!(
                        "unsupported mode `{other}`; expected `smoke` or `wait-ready`"
                    ))),
                };
            }
            if values[0] == "--suite" {
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
            if values[0] == "--lane" {
                return match values[1].as_str() {
                    "devel-fast" | "fast" => Ok(Self::Fast),
                    "devel-scan" | "scan" => Ok(Self::Scan),
                    "devel-isolated" | "isolated" => Ok(Self::Isolated),
                    "devel-transport" | "transport" => Ok(Self::Transport),
                    "differential" => Ok(Self::Differential),
                    other => Err(AppError::Usage(format!(
                        "unsupported lane `{other}`; expected devel-fast, devel-scan, devel-isolated, devel-transport, or differential"
                    ))),
                };
            }
        }

        Err(AppError::Usage(
            "usage: gvm-community-e2e [--mode <smoke|wait-ready> | --suite <smoke|crud|secinfo|differential|all> | --lane <devel-fast|devel-scan|devel-isolated|devel-transport|differential>]"
                .to_string(),
        ))
    }

    const fn lane_name(self) -> &'static str {
        match self {
            Self::WaitReady => "readiness",
            Self::Fast | Self::Smoke | Self::Crud | Self::SecInfo | Self::All => "devel-fast",
            Self::Scan => "devel-scan",
            Self::Isolated => "devel-isolated",
            Self::Transport => "devel-transport",
            Self::Differential => "differential",
        }
    }
}

#[derive(Debug)]
struct CleanupTracker {
    config: EnvConfig,
    report_exports: Vec<TrackedReportExport>,
    report_export_reconciliation_required: bool,
    target_ids: Vec<String>,
    report_ids: Vec<String>,
    task_ids: Vec<String>,
    config_ids: Vec<String>,
    scanner_ids: Vec<String>,
    port_list_ids: Vec<String>,
    credential_ids: Vec<String>,
    schedule_ids: Vec<String>,
    filter_ids: Vec<String>,
    note_ids: Vec<String>,
    override_ids: Vec<String>,
    tag_ids: Vec<String>,
    alert_ids: Vec<String>,
    ticket_ids: Vec<String>,
    asset_ids: Vec<String>,
    group_ids: Vec<String>,
    agent_group_ids: Vec<String>,
    oci_image_target_ids: Vec<String>,
    permission_ids: Vec<String>,
    report_format_ids: Vec<String>,
    role_ids: Vec<String>,
    tls_certificate_ids: Vec<String>,
    user_ids: Vec<String>,
    armed: bool,
}

#[derive(Clone, Debug)]
struct TrackedReportExport {
    id: String,
    cancel_attempted: bool,
    download_attempted: bool,
}

#[derive(Debug, Default)]
struct ScanMutationGuard {
    started_task_ids: BTreeSet<String>,
}

impl ScanMutationGuard {
    fn claim_task_start(&mut self, task_id: &EntityId) -> Result<(), AppError> {
        if self.started_task_ids.insert(task_id.to_string()) {
            Ok(())
        } else {
            Err(AppError::DuplicateMutation {
                operation: "start_task",
                resource_id: task_id.to_string(),
            })
        }
    }
}

impl CleanupTracker {
    fn new(config: EnvConfig) -> Self {
        Self {
            config,
            report_exports: Vec::new(),
            report_export_reconciliation_required: false,
            target_ids: Vec::new(),
            report_ids: Vec::new(),
            task_ids: Vec::new(),
            config_ids: Vec::new(),
            scanner_ids: Vec::new(),
            port_list_ids: Vec::new(),
            credential_ids: Vec::new(),
            schedule_ids: Vec::new(),
            filter_ids: Vec::new(),
            note_ids: Vec::new(),
            override_ids: Vec::new(),
            tag_ids: Vec::new(),
            alert_ids: Vec::new(),
            ticket_ids: Vec::new(),
            asset_ids: Vec::new(),
            group_ids: Vec::new(),
            agent_group_ids: Vec::new(),
            oci_image_target_ids: Vec::new(),
            permission_ids: Vec::new(),
            report_format_ids: Vec::new(),
            role_ids: Vec::new(),
            tls_certificate_ids: Vec::new(),
            user_ids: Vec::new(),
            armed: true,
        }
    }

    fn is_empty(&self) -> bool {
        self.report_exports.is_empty()
            && !self.report_export_reconciliation_required
            && self.report_ids.is_empty()
            && self.task_ids.is_empty()
            && self.target_ids.is_empty()
            && self.config_ids.is_empty()
            && self.scanner_ids.is_empty()
            && self.port_list_ids.is_empty()
            && self.credential_ids.is_empty()
            && self.schedule_ids.is_empty()
            && self.filter_ids.is_empty()
            && self.note_ids.is_empty()
            && self.override_ids.is_empty()
            && self.tag_ids.is_empty()
            && self.alert_ids.is_empty()
            && self.ticket_ids.is_empty()
            && self.asset_ids.is_empty()
            && self.group_ids.is_empty()
            && self.agent_group_ids.is_empty()
            && self.oci_image_target_ids.is_empty()
            && self.permission_ids.is_empty()
            && self.report_format_ids.is_empty()
            && self.role_ids.is_empty()
            && self.tls_certificate_ids.is_empty()
            && self.user_ids.is_empty()
    }

    fn track_target(&mut self, id: &EntityId) {
        self.target_ids.push(id.to_string());
    }

    fn track_task(&mut self, id: &EntityId) {
        self.task_ids.push(id.to_string());
    }

    fn track_report(&mut self, id: &EntityId) {
        if id.as_str() != "0" && !self.report_ids.iter().any(|value| value == id.as_str()) {
            self.report_ids.push(id.to_string());
        }
    }

    fn arm_report_export_reconciliation(&mut self) {
        self.report_export_reconciliation_required = true;
    }

    fn track_report_export(&mut self, id: &EntityId) {
        if !self
            .report_exports
            .iter()
            .any(|tracked| tracked.id == id.as_str())
        {
            self.report_exports.push(TrackedReportExport {
                id: id.to_string(),
                cancel_attempted: false,
                download_attempted: false,
            });
        }
    }

    fn mark_report_export_cancel_attempted(&mut self, id: &EntityId) -> Result<(), AppError> {
        let tracked = self
            .report_exports
            .iter_mut()
            .find(|tracked| tracked.id == id.as_str())
            .ok_or_else(|| {
                AppError::Assertion(format!(
                    "cannot mark cancel attempt for untracked report export {id}"
                ))
            })?;
        ensure(
            !tracked.cancel_attempted,
            &format!("duplicate cancel_report_export blocked locally for {id}"),
        )?;
        tracked.cancel_attempted = true;
        Ok(())
    }

    fn mark_report_export_download_attempted(&mut self, id: &EntityId) -> Result<(), AppError> {
        let tracked = self
            .report_exports
            .iter_mut()
            .find(|tracked| tracked.id == id.as_str())
            .ok_or_else(|| {
                AppError::Assertion(format!(
                    "cannot mark download attempt for untracked report export {id}"
                ))
            })?;
        ensure(
            !tracked.download_attempted,
            &format!("duplicate download_report_export blocked locally for {id}"),
        )?;
        tracked.download_attempted = true;
        Ok(())
    }

    fn forget_report_export(&mut self, id: &EntityId) {
        self.report_exports
            .retain(|tracked| tracked.id != id.as_str());
    }

    fn track_config(&mut self, id: &EntityId) {
        self.config_ids.push(id.to_string());
    }

    fn track_scanner(&mut self, id: &EntityId) {
        self.scanner_ids.push(id.to_string());
    }

    fn track_port_list(&mut self, id: &EntityId) {
        self.port_list_ids.push(id.to_string());
    }

    fn track_credential(&mut self, id: &EntityId) {
        self.credential_ids.push(id.to_string());
    }

    fn track_schedule(&mut self, id: &EntityId) {
        self.schedule_ids.push(id.to_string());
    }

    fn track_filter(&mut self, id: &EntityId) {
        self.filter_ids.push(id.to_string());
    }

    fn track_note(&mut self, id: &EntityId) {
        self.note_ids.push(id.to_string());
    }

    fn track_override(&mut self, id: &EntityId) {
        self.override_ids.push(id.to_string());
    }

    fn track_tag(&mut self, id: &EntityId) {
        self.tag_ids.push(id.to_string());
    }

    fn track_alert(&mut self, id: &EntityId) {
        self.alert_ids.push(id.to_string());
    }

    fn track_asset(&mut self, id: &EntityId) {
        self.asset_ids.push(id.to_string());
    }

    fn track_group(&mut self, id: &EntityId) {
        self.group_ids.push(id.to_string());
    }

    fn track_agent_group(&mut self, id: &EntityId) {
        self.agent_group_ids.push(id.to_string());
    }

    fn track_oci_image_target(&mut self, id: &EntityId) {
        self.oci_image_target_ids.push(id.to_string());
    }

    fn track_permission(&mut self, id: &EntityId) {
        self.permission_ids.push(id.to_string());
    }

    fn track_report_format(&mut self, id: &EntityId) {
        self.report_format_ids.push(id.to_string());
    }

    fn track_role(&mut self, id: &EntityId) {
        self.role_ids.push(id.to_string());
    }

    fn track_tls_certificate(&mut self, id: &EntityId) {
        self.tls_certificate_ids.push(id.to_string());
    }

    fn track_user(&mut self, id: &EntityId) {
        self.user_ids.push(id.to_string());
    }

    async fn cleanup_now(&mut self) -> Result<(), AppError> {
        self.cleanup_inner().await?;
        self.armed = false;
        Ok(())
    }

    async fn cleanup_inner(&mut self) -> Result<(), AppError> {
        if self.is_empty() {
            return Ok(());
        }

        let mut client = connect_client(&self.config).await?;
        client
            .authenticate(AuthenticateRequest::new(
                &self.config.username,
                &self.config.password,
            ))
            .await?;

        if self.report_export_reconciliation_required || !self.report_exports.is_empty() {
            client.discover_commands().await?;
            reconcile_tracked_report_exports(&mut client, self).await?;
        }

        while let Some(ticket_id) = self.ticket_ids.last().cloned() {
            let entity_id = parse_entity_id(&ticket_id)?;
            let response = client
                .send(gvm_gmp::commands::tickets::delete_ticket(&entity_id, true))
                .await?;
            assert_cleanup_status(&response, &[200, 404], "final delete_ticket", &entity_id)?;
            log_cleanup_result("delete_ticket", &ticket_id, response.status_code())?;
            self.ticket_ids.pop();
        }

        while let Some(report_id) = self.report_ids.last().cloned() {
            let entity_id = parse_entity_id(&report_id)?;
            let status = match client.execute(DeleteReportRequest::new(entity_id)).await {
                Ok(response) => response.status,
                Err(GvmError::Server { status: 404, .. }) => 404,
                Err(error) => return Err(error.into()),
            };
            log_cleanup_result("delete_report", &report_id, Some(status))?;
            self.report_ids.pop();
        }

        while let Some(task_id) = self.task_ids.last().cloned() {
            let entity_id = parse_entity_id(&task_id)?;
            let response = client
                .execute(DeleteTaskRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_task", &task_id, Some(response.status))?;
            self.task_ids.pop();
        }

        while let Some(target_id) = self.target_ids.last().cloned() {
            let entity_id = parse_entity_id(&target_id)?;
            let response = client
                .execute(DeleteTargetRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_target", &target_id, Some(response.status))?;
            self.target_ids.pop();
        }

        while let Some(oci_target_id) = self.oci_image_target_ids.last().cloned() {
            let entity_id = parse_entity_id(&oci_target_id)?;
            let response = client
                .execute(DeleteOciImageTargetRequest::new(entity_id, true))
                .await?;
            log_cleanup_result(
                "delete_oci_image_target",
                &oci_target_id,
                Some(response.status),
            )?;
            self.oci_image_target_ids.pop();
        }

        while let Some(agent_group_id) = self.agent_group_ids.last().cloned() {
            let entity_id = parse_entity_id(&agent_group_id)?;
            let response = client
                .execute(DeleteAgentGroupRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_agent_group", &agent_group_id, Some(response.status))?;
            self.agent_group_ids.pop();
        }

        while let Some(config_id) = self.config_ids.last().cloned() {
            let entity_id = parse_entity_id(&config_id)?;
            let mut request = DeleteConfigRequest::new(entity_id);
            request.ultimate = Some(true);
            let response = client.delete_config(request).await?;
            log_cleanup_result("delete_config", &config_id, Some(response.status))?;
            self.config_ids.pop();
        }

        while let Some(scanner_id) = self.scanner_ids.last().cloned() {
            let entity_id = parse_entity_id(&scanner_id)?;
            let response = client
                .delete_scanner(DeleteScannerRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_scanner", &scanner_id, Some(response.status))?;
            self.scanner_ids.pop();
        }

        while let Some(permission_id) = self.permission_ids.last().cloned() {
            let entity_id = parse_entity_id(&permission_id)?;
            let response = client
                .execute(DeletePermissionRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_permission", &permission_id, Some(response.status))?;
            self.permission_ids.pop();
        }

        while let Some(group_id) = self.group_ids.last().cloned() {
            let entity_id = parse_entity_id(&group_id)?;
            let response = client
                .execute(DeleteGroupRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_group", &group_id, Some(response.status))?;
            self.group_ids.pop();
        }

        while let Some(role_id) = self.role_ids.last().cloned() {
            let entity_id = parse_entity_id(&role_id)?;
            let response = client
                .execute(DeleteRoleRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_role", &role_id, Some(response.status))?;
            self.role_ids.pop();
        }

        while let Some(user_id) = self.user_ids.last().cloned() {
            let entity_id = parse_entity_id(&user_id)?;
            let response = client.execute(DeleteUserRequest::new(entity_id)).await?;
            log_cleanup_result("delete_user", &user_id, Some(response.status))?;
            self.user_ids.pop();
        }

        while let Some(report_format_id) = self.report_format_ids.last().cloned() {
            let entity_id = parse_entity_id(&report_format_id)?;
            let mut request = DeleteReportFormatRequest::new(entity_id);
            request.ultimate = Some(true);
            let response = client.execute(request).await?;
            log_cleanup_result(
                "delete_report_format",
                &report_format_id,
                Some(response.status),
            )?;
            self.report_format_ids.pop();
        }

        while let Some(tls_certificate_id) = self.tls_certificate_ids.last().cloned() {
            let entity_id = parse_entity_id(&tls_certificate_id)?;
            let response = client
                .execute(DeleteTlsCertificateRequest::new(entity_id))
                .await?;
            log_cleanup_result(
                "delete_tls_certificate",
                &tls_certificate_id,
                Some(response.status),
            )?;
            self.tls_certificate_ids.pop();
        }

        while let Some(asset_id) = self.asset_ids.last().cloned() {
            let entity_id = parse_entity_id(&asset_id)?;
            let response = client.execute(DeleteAssetRequest::new(entity_id)).await?;
            log_cleanup_result("delete_asset", &asset_id, Some(response.status))?;
            self.asset_ids.pop();
        }

        while let Some(alert_id) = self.alert_ids.last().cloned() {
            let entity_id = parse_entity_id(&alert_id)?;
            let response = client
                .execute(DeleteAlertRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_alert", &alert_id, Some(response.status))?;
            self.alert_ids.pop();
        }

        while let Some(note_id) = self.note_ids.last().cloned() {
            let entity_id = parse_entity_id(&note_id)?;
            let response = client
                .execute(DeleteNoteRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_note", &note_id, Some(response.status))?;
            self.note_ids.pop();
        }

        while let Some(override_id) = self.override_ids.last().cloned() {
            let entity_id = parse_entity_id(&override_id)?;
            let response = client
                .execute(DeleteOverrideRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_override", &override_id, Some(response.status))?;
            self.override_ids.pop();
        }

        while let Some(tag_id) = self.tag_ids.last().cloned() {
            let entity_id = parse_entity_id(&tag_id)?;
            let response = client
                .execute(DeleteTagRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_tag", &tag_id, Some(response.status))?;
            self.tag_ids.pop();
        }

        while let Some(filter_id) = self.filter_ids.last().cloned() {
            let entity_id = parse_entity_id(&filter_id)?;
            let response = client
                .execute(DeleteFilterRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_filter", &filter_id, Some(response.status))?;
            self.filter_ids.pop();
        }

        while let Some(schedule_id) = self.schedule_ids.last().cloned() {
            let entity_id = parse_entity_id(&schedule_id)?;
            let response = client
                .execute(DeleteScheduleRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_schedule", &schedule_id, Some(response.status))?;
            self.schedule_ids.pop();
        }

        while let Some(credential_id) = self.credential_ids.last().cloned() {
            let entity_id = parse_entity_id(&credential_id)?;
            let response = client
                .execute(DeleteCredentialRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_credential", &credential_id, Some(response.status))?;
            self.credential_ids.pop();
        }

        while let Some(port_list_id) = self.port_list_ids.last().cloned() {
            let entity_id = parse_entity_id(&port_list_id)?;
            let response = client
                .execute(DeletePortListRequest::new(entity_id, true))
                .await?;
            log_cleanup_result("delete_port_list", &port_list_id, Some(response.status))?;
            self.port_list_ids.pop();
        }

        client.disconnect().await?;
        Ok(())
    }
}

impl Drop for CleanupTracker {
    fn drop(&mut self) {
        if !self.armed || self.is_empty() {
            return;
        }

        let config = self.config.clone();
        let report_exports = self.report_exports.clone();
        let report_export_reconciliation_required = self.report_export_reconciliation_required;
        let report_ids = self.report_ids.clone();
        let task_ids = self.task_ids.clone();
        let target_ids = self.target_ids.clone();
        let config_ids = self.config_ids.clone();
        let scanner_ids = self.scanner_ids.clone();
        let port_list_ids = self.port_list_ids.clone();
        let credential_ids = self.credential_ids.clone();
        let schedule_ids = self.schedule_ids.clone();
        let filter_ids = self.filter_ids.clone();
        let note_ids = self.note_ids.clone();
        let override_ids = self.override_ids.clone();
        let tag_ids = self.tag_ids.clone();
        let alert_ids = self.alert_ids.clone();
        let ticket_ids = self.ticket_ids.clone();
        let asset_ids = self.asset_ids.clone();
        let group_ids = self.group_ids.clone();
        let agent_group_ids = self.agent_group_ids.clone();
        let oci_image_target_ids = self.oci_image_target_ids.clone();
        let permission_ids = self.permission_ids.clone();
        let report_format_ids = self.report_format_ids.clone();
        let role_ids = self.role_ids.clone();
        let tls_certificate_ids = self.tls_certificate_ids.clone();
        let user_ids = self.user_ids.clone();

        let cleanup = async move {
            let mut tracker = CleanupTracker {
                config,
                report_exports,
                report_export_reconciliation_required,
                report_ids,
                task_ids,
                target_ids,
                config_ids,
                scanner_ids,
                port_list_ids,
                credential_ids,
                schedule_ids,
                filter_ids,
                note_ids,
                override_ids,
                tag_ids,
                alert_ids,
                ticket_ids,
                asset_ids,
                group_ids,
                agent_group_ids,
                oci_image_target_ids,
                permission_ids,
                report_format_ids,
                role_ids,
                tls_certificate_ids,
                user_ids,
                armed: false,
            };
            tracker.cleanup_inner().await
        };

        // If we're inside a tokio runtime, use block_in_place to avoid
        // the "Cannot start a runtime from within a runtime" panic.
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

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Assertion(String),
    #[error("{0}")]
    Usage(String),
    #[error("invalid entity id `{0}`")]
    InvalidEntityId(String),
    #[error("duplicate {operation} mutation blocked locally for {resource_id}")]
    DuplicateMutation {
        operation: &'static str,
        resource_id: String,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] gvm_protocol::error::ProtocolError),
    #[error(transparent)]
    Xml(#[from] quick_xml::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Parse(#[from] gvm_gmp::responses::ParseError),
    #[error(transparent)]
    Client(#[from] GvmError),
    #[error(transparent)]
    TargetHost(#[from] TargetHostError),
    #[error(transparent)]
    TargetHosts(#[from] TargetHostsError),
}

async fn cleanup_previous_runs(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    let mut removed = 0usize;

    let tickets = client
        .send(gvm_gmp::commands::tickets::get_tickets(Default::default()))
        .await?;
    assert_status(&tickets, 200, "preflight get_tickets")?;
    for id in e2e_entity_ids(tickets.as_str()?, "ticket")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::tickets::delete_ticket(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_ticket", &id)?;
        removed += 1;
    }

    macro_rules! cleanup_named_resources {
        ($get:expr, $get_label:literal, $delete_label:literal, |$item:ident| $meta:expr, |$id:ident| $delete:expr) => {{
            let response = client.execute($get).await?;
            assert_typed_cleanup_status(response.status, &[200], $get_label, None)?;
            for $item in response.items {
                let meta = $meta;
                if is_e2e_owned_value(&meta.name) {
                    let $id = meta.id.clone();
                    let response = client.execute($delete).await?;
                    assert_typed_cleanup_status(
                        response.status,
                        &[200, 404],
                        $delete_label,
                        Some(&$id),
                    )?;
                    removed += 1;
                }
            }
        }};
    }

    client.discover_commands().await?;
    let tasks = client
        .execute(GetTasksRequest {
            details: Some(true),
            ..Default::default()
        })
        .await?;
    assert_typed_cleanup_status(tasks.status, &[200], "preflight get_tasks", None)?;
    let owned_tasks = tasks
        .items
        .into_iter()
        .filter(|task| is_e2e_owned_value(&task.meta.name))
        .collect::<Vec<_>>();
    let stale_report_ids = owned_tasks
        .iter()
        .flat_map(|task| {
            [
                task.current_report
                    .as_ref()
                    .map(|report| report.id.to_string()),
                task.last_report
                    .as_ref()
                    .map(|report| report.id.to_string()),
            ]
            .into_iter()
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    if !stale_report_ids.is_empty()
        && matches!(
            client.command_support("export_scan_report"),
            gvm_client::CommandSupport::Supported
        )
    {
        for command in [
            "get_report_exports",
            "cancel_report_export",
            "download_report_export",
        ] {
            ensure(
                matches!(
                    client.command_support(command),
                    gvm_client::CommandSupport::Supported
                ),
                &format!(
                    "preflight found E2E-owned scan reports and export_scan_report is advertised, but cleanup command {command} is unavailable"
                ),
            )?;
        }
        let mut stale_tracker = CleanupTracker::new(config.clone());
        stale_tracker.armed = false;
        stale_tracker.report_ids = stale_report_ids.into_iter().collect();
        stale_tracker.arm_report_export_reconciliation();
        reconcile_tracked_report_exports(&mut client, &mut stale_tracker).await?;
    }

    for task in owned_tasks {
        let task_id = task.meta.id;
        let stop = client
            .execute(StopTaskRequest::new(task_id.clone()))
            .await?;
        assert_typed_cleanup_status(
            stop.status,
            &[200, 202, 400, 404],
            "preflight stop_task",
            Some(&task_id),
        )?;
        let delete = client
            .execute(DeleteTaskRequest::new(task_id.clone(), true))
            .await?;
        assert_typed_cleanup_status(
            delete.status,
            &[200, 404],
            "preflight delete_task",
            Some(&task_id),
        )?;
        removed += 1;
    }

    cleanup_named_resources!(
        GetTargetsRequest::default(),
        "preflight get_targets",
        "preflight delete_target",
        |item| &item.meta,
        |id| DeleteTargetRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetConfigsRequest::default(),
        "preflight get_configs",
        "preflight delete_config",
        |item| &item.meta,
        |id| {
            let mut request = DeleteConfigRequest::new(id.clone());
            request.ultimate = Some(true);
            request
        }
    );
    cleanup_named_resources!(
        GetScannersRequest::default(),
        "preflight get_scanners",
        "preflight delete_scanner",
        |item| &item.meta,
        |id| DeleteScannerRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetAlertsRequest::default(),
        "preflight get_alerts",
        "preflight delete_alert",
        |item| &item.meta,
        |id| DeleteAlertRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetNotesRequest::default(),
        "preflight get_notes",
        "preflight delete_note",
        |item| &item.meta,
        |id| DeleteNoteRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetOverridesRequest::default(),
        "preflight get_overrides",
        "preflight delete_override",
        |item| &item.meta,
        |id| DeleteOverrideRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetTagsRequest::default(),
        "preflight get_tags",
        "preflight delete_tag",
        |item| &item.meta,
        |id| DeleteTagRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetFiltersRequest::default(),
        "preflight get_filters",
        "preflight delete_filter",
        |item| &item.meta,
        |id| DeleteFilterRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetSchedulesRequest::default(),
        "preflight get_schedules",
        "preflight delete_schedule",
        |item| &item.meta,
        |id| DeleteScheduleRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetCredentialsRequest::default(),
        "preflight get_credentials",
        "preflight delete_credential",
        |item| &item.meta,
        |id| DeleteCredentialRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetPortListsRequest::default(),
        "preflight get_port_lists",
        "preflight delete_port_list",
        |item| &item.meta,
        |id| DeletePortListRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetPermissionsRequest::default(),
        "preflight get_permissions",
        "preflight delete_permission",
        |item| &item.meta,
        |id| DeletePermissionRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetGroupsRequest::default(),
        "preflight get_groups",
        "preflight delete_group",
        |item| &item.meta,
        |id| DeleteGroupRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetRolesRequest::default(),
        "preflight get_roles",
        "preflight delete_role",
        |item| &item.meta,
        |id| DeleteRoleRequest::new(id.clone(), true)
    );
    cleanup_named_resources!(
        GetUsersRequest::default(),
        "preflight get_users",
        "preflight delete_user",
        |item| &item.meta,
        |id| DeleteUserRequest::new(id.clone())
    );
    cleanup_named_resources!(
        GetReportFormatsRequest::default(),
        "preflight get_report_formats",
        "preflight delete_report_format",
        |item| &item.meta,
        |id| {
            let mut request = DeleteReportFormatRequest::new(id.clone());
            request.ultimate = Some(true);
            request
        }
    );
    cleanup_named_resources!(
        GetTlsCertificatesRequest::default(),
        "preflight get_tls_certificates",
        "preflight delete_tls_certificate",
        |item| &item.meta,
        |id| DeleteTlsCertificateRequest::new(id.clone())
    );

    let assets = client
        .execute(GetAssetsRequest::new(AssetType::Host))
        .await?;
    assert_typed_cleanup_status(assets.status, &[200], "preflight get_assets", None)?;
    for asset in assets.items {
        let meta = match &asset {
            gvm_gmp::responses::asset::Asset::Host(host) => &host.meta,
            gvm_gmp::responses::asset::Asset::OperatingSystem(asset) => &asset.meta,
            gvm_gmp::responses::asset::Asset::Generic(asset) => &asset.meta,
            _ => continue,
        };
        if is_e2e_owned_value(&meta.name) {
            let id = meta.id.clone();
            let response = client.execute(DeleteAssetRequest::new(id.clone())).await?;
            assert_typed_cleanup_status(
                response.status,
                &[200, 404],
                "preflight delete_asset",
                Some(&id),
            )?;
            removed += 1;
        }
    }

    client.disconnect().await?;
    log_pass(
        "preflight-cleanup",
        &format!("dependency-ordered cleanup removed {removed} stale resource(s)"),
    );
    Ok(())
}

fn assert_typed_cleanup_status(
    status: u16,
    accepted: &[u16],
    action: &str,
    id: Option<&EntityId>,
) -> Result<(), AppError> {
    ensure(
        accepted.contains(&status),
        &format!(
            "{action}{} expected status {accepted:?}, got {status}",
            id.map(|id| format!(" for {id}")).unwrap_or_default()
        ),
    )
}

fn assert_cleanup_status(
    response: &Response,
    accepted: &[u16],
    action: &str,
    id: &EntityId,
) -> Result<(), AppError> {
    let status = response.status_code().unwrap_or(0);
    ensure(
        accepted.contains(&status),
        &format!(
            "{action} for {id} returned {status}: {}",
            response.status_text().unwrap_or_default()
        ),
    )
}

fn read_json<T: serde::de::DeserializeOwned>(
    path_env: &str,
    fallback: &str,
) -> Result<T, AppError> {
    let contents = match env::var(path_env) {
        Ok(path) if !path.trim().is_empty() => fs::read_to_string(&path).map_err(|error| {
            AppError::Assertion(format!("failed to read {path_env} at {path}: {error}"))
        })?,
        _ => fallback.to_string(),
    };
    serde_json::from_str(&contents)
        .map_err(|error| AppError::Assertion(format!("invalid {path_env}: {error}")))
}

fn provider_probe(evidence: &gvm_community_e2e::capability::ProviderEvidence) -> ProbeResult {
    ProbeResult {
        state: evidence.state,
        evidence: Evidence {
            source: "deployment-provider".to_string(),
            value: format!("{:?}", evidence.state).to_ascii_lowercase(),
            detail: evidence.detail.clone(),
        },
    }
}

fn probe_wire_command(name: &str) -> Option<&'static str> {
    match name {
        "agents" => Some("get_agents"),
        "oci-image-targets" => Some("get_oci_image_targets"),
        "credential-stores" => Some("get_credential_stores"),
        "integration-configs" => Some("get_integration_configs"),
        "web-application-targets" => Some("get_web_application_targets"),
        "openvasd-scanner" => Some("get_scanners"),
        "vt-metadata" => Some("get_nvts"),
        "jwt-auth" => None,
        _ => None,
    }
}

fn helper_semantic_name(name: &str) -> &str {
    match name {
        "get_report_export_with_opts" => "get_report_export",
        _ => name,
    }
}

fn semantic_eligibility(
    kind: PlanEntryKind,
    name: &str,
    wire_command: Option<&str>,
    version: GmpVersion,
) -> (bool, String) {
    let semantic = match kind {
        PlanEntryKind::Command => name,
        PlanEntryKind::Helper => helper_semantic_name(name),
        PlanEntryKind::Scenario => {
            return (
                true,
                format!("scenario has no typed GMP version gate; negotiated GMP {version}"),
            );
        }
    };
    let minimum = gvm_gmp::capabilities::minimum_version_for_command(semantic)
        .or_else(|| wire_command.and_then(gvm_gmp::capabilities::minimum_version_for_command));
    match minimum {
        Some(minimum) if version < minimum => (
            false,
            format!(
                "typed semantic {semantic} requires GMP {minimum}; negotiated GMP {version}; no wire request is eligible"
            ),
        ),
        Some(minimum) => (
            true,
            format!("typed semantic {semantic} requires GMP {minimum}; negotiated GMP {version}"),
        ),
        None => (
            true,
            format!("typed semantic has no registry minimum; negotiated GMP {version}"),
        ),
    }
}

fn runtime_helper_path(name: &str) -> bool {
    matches!(
        name,
        "authenticate"
            | "clone_config"
            | "clone_report_format"
            | "clone_scanner"
            | "create_alert"
            | "create_asset"
            | "create_config"
            | "create_credential"
            | "create_filter"
            | "create_group"
            | "create_host"
            | "create_note"
            | "create_override"
            | "create_permission"
            | "create_port_list"
            | "create_port_range"
            | "create_role"
            | "create_scan_config"
            | "create_schedule"
            | "create_tag"
            | "create_target"
            | "create_task"
            | "create_tls_certificate"
            | "create_user"
            | "delete_asset"
            | "delete_config"
            | "delete_group"
            | "delete_permission"
            | "delete_port_range"
            | "delete_role"
            | "delete_scanner"
            | "delete_target"
            | "describe_auth"
            | "download_report_export"
            | "empty_trashcan"
            | "export_scan_report"
            | "get_aggregates"
            | "get_alert"
            | "get_alerts"
            | "get_asset"
            | "get_assets"
            | "get_cert_bund_advisories"
            | "get_cert_bund_advisory"
            | "get_config"
            | "get_configs"
            | "get_cpe"
            | "get_cpes"
            | "get_credentials"
            | "get_cve"
            | "get_cves"
            | "get_dfn_cert_advisories"
            | "get_dfn_cert_advisory"
            | "get_feed"
            | "get_feeds"
            | "get_filter"
            | "get_filters"
            | "get_groups"
            | "get_help"
            | "get_hosts"
            | "get_info_list"
            | "get_note"
            | "get_notes"
            | "get_nvt_families"
            | "get_nvts"
            | "get_operating_system_assets"
            | "get_override"
            | "get_overrides"
            | "get_permissions"
            | "get_policies"
            | "get_policy"
            | "get_port_list"
            | "get_port_lists"
            | "get_report"
            | "get_report_applications"
            | "get_report_closed_cves"
            | "get_report_configs"
            | "get_report_cves"
            | "get_report_errors"
            | "get_report_export"
            | "get_report_exports"
            | "get_report_formats"
            | "get_report_hosts"
            | "get_report_operating_systems"
            | "get_report_ports"
            | "get_report_tls_certificates"
            | "get_report_vulns"
            | "get_results"
            | "get_roles"
            | "get_scan_config"
            | "get_scan_config_nvt"
            | "get_scan_config_nvts"
            | "get_scan_configs"
            | "get_scan_report"
            | "get_scanner"
            | "get_scanners"
            | "get_schedule"
            | "get_schedules"
            | "get_settings"
            | "get_system_reports"
            | "get_tag"
            | "get_tags"
            | "get_target"
            | "get_targets"
            | "get_task"
            | "get_tasks"
            | "get_tls_certificates"
            | "get_users"
            | "get_version"
            | "get_vulnerabilities"
            | "get_vulnerability"
            | "import_report"
            | "modify_alert"
            | "modify_asset"
            | "modify_config"
            | "modify_credential"
            | "modify_filter"
            | "modify_group"
            | "modify_note"
            | "modify_override"
            | "modify_policy_set_comment"
            | "modify_policy_set_name"
            | "modify_port_list"
            | "modify_report_format"
            | "modify_role"
            | "modify_scan_config"
            | "modify_scan_config_set_comment"
            | "modify_scan_config_set_name"
            | "modify_scanner"
            | "modify_schedule"
            | "modify_tag"
            | "modify_target"
            | "modify_task"
            | "modify_tls_certificate"
            | "modify_user"
            | "restore"
            | "start_task"
            | "test_alert"
            | "verify_report_format"
            | "verify_scanner"
    )
}

fn direct_command_runtime_path(name: &str) -> bool {
    matches!(
        name,
        "get_features"
            | "get_preferences"
            | "get_resource_names"
            | "create_agent_group"
            | "delete_agent_group"
            | "get_agent_groups"
            | "get_agents"
            | "get_credential_stores"
            | "get_integration_configs"
            | "get_web_application_targets"
            | "modify_agent_group"
            | "create_oci_image_target"
            | "delete_oci_image_target"
            | "get_oci_image_targets"
            | "modify_oci_image_target"
            | "delete_user"
            | "delete_alert"
            | "delete_credential"
            | "delete_filter"
            | "delete_note"
            | "delete_override"
            | "delete_schedule"
            | "delete_tag"
    )
}

fn runtime_command_path(name: &str) -> bool {
    direct_command_runtime_path(name)
        || HELPER_COVERAGE
            .iter()
            .any(|entry| entry.wire_command == name && runtime_helper_path(entry.name))
}

fn plan_inputs(catalog: &FeatureCatalog, version: GmpVersion) -> Vec<PlanInput> {
    let command_inputs = COMMAND_COVERAGE.iter().map(|entry| {
        let (semantic_eligible, semantic_evidence) = semantic_eligibility(
            PlanEntryKind::Command,
            entry.name,
            Some(entry.wire_command),
            version,
        );
        PlanInput {
            kind: PlanEntryKind::Command,
            name: entry.name.to_string(),
            lane: entry.lane.to_string(),
            feature: entry.requires.first().map(|value| (*value).to_string()),
            wire_command: Some(entry.wire_command.to_string()),
            command_optional: entry.disposition == Disposition::ConditionalAvailability,
            implemented: entry.implemented && runtime_command_path(entry.name),
            semantic_eligible,
            semantic_evidence,
        }
    });
    let helper_inputs = HELPER_COVERAGE.iter().map(|entry| {
        let (semantic_eligible, semantic_evidence) = semantic_eligibility(
            PlanEntryKind::Helper,
            entry.name,
            Some(entry.wire_command),
            version,
        );
        PlanInput {
            kind: PlanEntryKind::Helper,
            name: entry.name.to_string(),
            lane: entry.lane.to_string(),
            feature: entry.requires.first().map(|value| (*value).to_string()),
            wire_command: Some(entry.wire_command.to_string()),
            command_optional: entry.disposition == Disposition::ConditionalAvailability,
            implemented: entry.implemented && runtime_helper_path(entry.name),
            semantic_eligible,
            semantic_evidence,
        }
    });
    let migrated_helper_inputs = HELPER_MIGRATIONS.iter().filter_map(|migration| {
        let command = COMMAND_COVERAGE
            .iter()
            .find(|entry| entry.name == migration.wire_command)?;
        let (semantic_eligible, semantic_evidence) = semantic_eligibility(
            PlanEntryKind::Helper,
            migration.name,
            Some(migration.wire_command),
            version,
        );
        Some(PlanInput {
            kind: PlanEntryKind::Helper,
            name: migration.name.to_string(),
            lane: command.lane.to_string(),
            feature: None,
            wire_command: Some(migration.wire_command.to_string()),
            command_optional: command.disposition == Disposition::ConditionalAvailability,
            implemented: false,
            semantic_eligible,
            semantic_evidence,
        })
    });
    let scenario_inputs = catalog.features.iter().flat_map(|(feature, mapping)| {
        mapping
            .scenarios
            .iter()
            .map(|(scenario, requirement)| PlanInput {
                kind: PlanEntryKind::Scenario,
                name: scenario.clone(),
                lane: requirement.lane.clone(),
                feature: Some(feature.clone()),
                wire_command: None,
                command_optional: false,
                implemented: requirement.implemented,
                semantic_eligible: true,
                semantic_evidence: format!(
                    "scenario has no typed GMP version gate; negotiated GMP {version}"
                ),
            })
    });
    command_inputs
        .chain(helper_inputs)
        .chain(migrated_helper_inputs)
        .chain(scenario_inputs)
        .collect()
}

fn validate_selected_inputs(plan: &TestPlan) -> Result<(), String> {
    let oci_selected = plan.entries.iter().any(|entry| {
        entry.kind == PlanEntryKind::Scenario
            && entry.name == "oci-target-lifecycle"
            && entry.decision == PlanDecision::Selected
    });
    if oci_selected
        && env::var("E2E_OCI_IMAGE_REFERENCE")
            .ok()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(
            "selected OCI scenario requires non-secret E2E_OCI_IMAGE_REFERENCE before mutation"
                .to_string(),
        );
    }
    Ok(())
}

async fn discover_deployment(config: &EnvConfig, lane: &str) -> Result<TestPlan, AppError> {
    runtime::validate_runtime_images().map_err(AppError::Assertion)?;
    let contract: DeploymentContract = read_json(
        "E2E_DEPLOYMENT_CONTRACT_PATH",
        include_str!("../../../contracts/community-stable.json"),
    )?;
    let catalog: FeatureCatalog =
        serde_json::from_str(include_str!("../../../coverage/feature-catalog.json"))
            .map_err(|error| AppError::Assertion(format!("invalid feature catalog: {error}")))?;
    let descriptor: FixtureDescriptor = read_json(
        "E2E_FIXTURE_DESCRIPTOR_PATH",
        include_str!("../../../fixtures/community-provider.json"),
    )?;
    let deployment_id =
        env::var("E2E_DEPLOYMENT_ID").unwrap_or_else(|_| "community-stable".to_string());
    ensure(
        contract.deployment_id == deployment_id && descriptor.deployment_id == deployment_id,
        "deployment ID, contract, and fixture descriptor must match",
    )?;

    let mut client = connect_client(config).await?;
    let version_response = client.get_version(GetVersionRequest::new()).await?;
    let version = parse_version_text(&version_response.version)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("unsupported deployment GMP version {version}"),
    )?;

    let auth = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    ensure(
        auth.status == 200,
        "typed authentication did not return 200",
    )?;

    let text_help = client.get_help(HelpRequest::default()).await?;
    ensure(
        text_help.status == 200 && !text_help.help_text.trim().is_empty(),
        "typed text help did not return a nonempty 200 response",
    )?;

    let feature_response = client.send(XmlCommand::new("get_features")).await?;
    ensure(
        feature_response.status_code() == Some(200),
        "raw get_features did not return 200",
    )?;
    let observed_features =
        parse_feature_evidence(feature_response.data()).map_err(AppError::Assertion)?;
    let features: BTreeMap<String, FeatureState> = observed_features
        .iter()
        .filter_map(|(name, feature)| {
            Some((
                name.clone(),
                FeatureState {
                    compiled_in: feature.compiled_in?,
                    enabled: feature.enabled?,
                },
            ))
        })
        .collect();

    let help = client
        .get_help(HelpRequest::new(HelpMode::BriefXml))
        .await?;
    ensure(
        help.status == 200,
        "typed brief XML help did not return 200",
    )?;
    let help_commands: BTreeSet<String> = help
        .schema
        .ok_or_else(|| {
            AppError::Assertion("brief XML help response did not contain a schema".to_string())
        })?
        .commands
        .into_iter()
        .map(|command| canonical_help_command(&command.name))
        .collect();
    let modeled_commands = COMMAND_COVERAGE
        .iter()
        .map(|entry| entry.wire_command.to_string())
        .collect::<BTreeSet<_>>();
    let live_help_parity =
        classify_live_help_commands(&help_commands, &modeled_commands, LIVE_HELP_ALLOWLIST)
            .map_err(AppError::Assertion)?;
    let commands = COMMAND_COVERAGE
        .iter()
        .map(|entry| {
            let advertised =
                entry.name == "get_features" || help_commands.contains(entry.wire_command);
            (
                entry.name.to_string(),
                CommandSupport {
                    advertised,
                    evidence: Evidence {
                        source: "authenticated-help".to_string(),
                        value: advertised.to_string(),
                        detail: format!("wire command {}", entry.wire_command),
                    },
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    runtime::discovery(
        &version_response.version,
        features.clone(),
        help_commands.iter().cloned().collect(),
        live_help_parity.clone(),
    );
    ensure(
        !help_commands.is_empty(),
        "authenticated brief XML help advertised no commands",
    )?;
    let schema_help = client
        .get_help(HelpRequest::new(HelpMode::Schema(
            gvm_gmp::enums::HelpFormat::Xml,
        )))
        .await?;
    ensure(
        schema_help.status == 200
            && schema_help
                .schema
                .as_ref()
                .is_some_and(|schema| !schema.commands.is_empty()),
        "typed full XML help did not return a command schema",
    )?;
    runtime::observe(
        "typed-help-modes",
        Outcome::Pass,
        &format!(
            "text, brief XML, and full XML parsed; {} authenticated command(s) advertised; negotiation commands are validated directly",
            help_commands.len()
        ),
    );
    log_line(&format!(
        "authenticated brief XML help commands: {}",
        help_commands.iter().cloned().collect::<Vec<_>>().join(",")
    ));

    let mut provider_probes = descriptor
        .probes
        .iter()
        .map(|(name, evidence)| (name.clone(), provider_probe(evidence)))
        .collect::<BTreeMap<_, _>>();
    let epss_deployment_evidence = if lane == "devel-scan" {
        provider_probes.insert(
            "gvmd-epss-result-filter-sort-policy".to_string(),
            epss_regression_capability_probe()?,
        );
        Some(EpssDeploymentEvidence::from_env()?)
    } else {
        None
    };
    let fixtures = descriptor
        .fixtures
        .iter()
        .map(|(name, evidence)| (name.clone(), provider_probe(evidence)))
        .collect::<BTreeMap<_, _>>();
    if let Err(error) = enforce_live_help_parity(&live_help_parity) {
        let capabilities = DeploymentCapabilities {
            schema_version: DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION,
            deployment_id,
            gmp_version: Some(version_response.version.clone()),
            gvmd_version: epss_deployment_evidence
                .as_ref()
                .map(|evidence| evidence.gvmd_version.clone()),
            gvmd_source_revision: epss_deployment_evidence
                .as_ref()
                .and_then(|evidence| evidence.gvmd_source_revision.clone()),
            gvmd_image_digest: epss_deployment_evidence
                .as_ref()
                .map(|evidence| evidence.gvmd_image_digest.clone()),
            live_help_parity,
            features: observed_features,
            commands,
            probes: provider_probes,
            fixtures,
        };
        runtime::observe("live-help-reverse-parity", Outcome::Fail, &error);
        runtime::publish_discovery_failure(&capabilities, &contract, lane, &error)
            .map_err(AppError::Assertion)?;
        return Err(AppError::Assertion(error));
    }
    runtime::observe(
        "live-help-reverse-parity",
        Outcome::Pass,
        &format!(
            "classified all {} advertised commands: {} modeled, {} exact-name allowlisted, 0 unknown",
            live_help_parity.advertised_commands.len(),
            live_help_parity.modeled_commands.len(),
            live_help_parity.allowlisted_commands.len()
        ),
    );

    let mut conditional_commands = BTreeMap::new();
    let mut registry_version_gates = BTreeMap::new();
    for entry in COMMAND_COVERAGE
        .iter()
        .filter(|entry| entry.disposition == Disposition::ConditionalAvailability)
    {
        let version_available = gvm_gmp::capabilities::command_capability(entry.name)
            .is_some_and(|capability| capability.available_in(version));
        let advertised = help_commands.contains(entry.name);
        let available = live_help_supports(&help_commands, entry.name);
        conditional_commands.insert(entry.name.to_string(), available);
        registry_version_gates.insert(entry.name.to_string(), version_available);
        runtime::observe(
            &format!("conditional-command:{}", entry.name),
            if available {
                Outcome::ConditionalAvailable
            } else {
                Outcome::ConditionalUnavailable
            },
            &format!(
                "GMP {version}; help advertised={advertised}; registry version gate={version_available}"
            ),
        );
    }

    runtime::conditional_discovery(conditional_commands.clone(), registry_version_gates.clone());
    let mut probes = provider_probes;
    for (feature_name, mapping) in &catalog.features {
        let Some(probe_name) = mapping.probe.as_deref() else {
            continue;
        };
        // A provider may supply out-of-band evidence for probes that cannot be
        // expressed safely over GMP.  Where a read-only GMP probe exists, run
        // it directly so caller-supplied metadata cannot outrank observation.
        if probes.contains_key(probe_name) && probe_wire_command(probe_name).is_none() {
            continue;
        }
        let enabled = observed_features
            .get(feature_name)
            .and_then(|feature| feature.enabled)
            .unwrap_or(false);
        let result = if !enabled {
            ProbeResult {
                state: ProbeState::Unavailable,
                evidence: Evidence {
                    source: "get_features".into(),
                    value: "disabled".into(),
                    detail: format!("{feature_name} is not enabled"),
                },
            }
        } else if let Some(command) = probe_wire_command(probe_name) {
            match client.send(XmlCommand::new(command)).await {
                Ok(response) if response.status_code() == Some(200) => ProbeResult {
                    state: ProbeState::Ready,
                    evidence: Evidence {
                        source: "safe-gmp-probe".into(),
                        value: "ready".into(),
                        detail: format!("{command} returned 200"),
                    },
                },
                Ok(response) => ProbeResult {
                    state: ProbeState::Unhealthy,
                    evidence: Evidence {
                        source: "safe-gmp-probe".into(),
                        value: "unhealthy".into(),
                        detail: format!("{command} returned {:?}", response.status_code()),
                    },
                },
                Err(error) => ProbeResult {
                    state: ProbeState::Unhealthy,
                    evidence: Evidence {
                        source: "safe-gmp-probe".into(),
                        value: "unhealthy".into(),
                        detail: error.to_string(),
                    },
                },
            }
        } else {
            ProbeResult {
                state: ProbeState::Unknown,
                evidence: Evidence {
                    source: "deployment-provider".into(),
                    value: "missing".into(),
                    detail: format!("provider supplied no {probe_name} evidence"),
                },
            }
        };
        probes.insert(probe_name.to_string(), result);
    }
    let capabilities = DeploymentCapabilities {
        schema_version: DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION,
        deployment_id,
        gmp_version: Some(version_response.version.clone()),
        gvmd_version: epss_deployment_evidence
            .as_ref()
            .map(|evidence| evidence.gvmd_version.clone()),
        gvmd_source_revision: epss_deployment_evidence
            .as_ref()
            .and_then(|evidence| evidence.gvmd_source_revision.clone()),
        gvmd_image_digest: epss_deployment_evidence
            .as_ref()
            .map(|evidence| evidence.gvmd_image_digest.clone()),
        live_help_parity,
        features: observed_features,
        commands,
        probes,
        fixtures,
    };
    let plan = match build_plan(
        &contract,
        &catalog,
        &capabilities,
        lane,
        plan_inputs(&catalog, version),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            runtime::publish_planning_failure(&capabilities, &contract, lane, &error)
                .map_err(AppError::Assertion)?;
            return Err(AppError::Assertion(error));
        }
    };
    if let Err(error) = validate_selected_inputs(&plan) {
        runtime::publish_planning_failure(&capabilities, &contract, lane, &error)
            .map_err(AppError::Assertion)?;
        return Err(AppError::Assertion(error));
    }
    runtime::publish_plan(&capabilities, &contract, &plan).map_err(AppError::Assertion)?;

    record_helper_executions(
        &["get_version", "authenticate", "get_help"],
        "deployment discovery executed the typed helper successfully",
    )?;
    record_command_execution(
        "get_features",
        "deployment discovery executed raw get_features successfully",
    )?;
    for (scenario, command) in [
        ("credential-store-read", "get_credential_stores"),
        ("integration-read", "get_integration_configs"),
        ("web-target-read", "get_web_application_targets"),
    ] {
        if selected_scenario(&plan, scenario) {
            record_command_execution(command, "selected safe GMP readiness probe returned 200")?;
            record_scenario_execution(scenario, "selected safe GMP readiness probe returned 200");
        }
    }
    for scenario in ["openvasd-discovery", "vt-metadata-read"] {
        if selected_scenario(&plan, scenario) {
            record_scenario_execution(scenario, "selected safe GMP readiness probe returned 200");
        }
    }

    log_pass(
        "discovery",
        &format!(
            "typed GMP {}, {} feature(s), {} advertised command(s)",
            version_response.version,
            features.len(),
            help_commands.len()
        ),
    );
    client.disconnect().await?;
    Ok(plan)
}

fn current_lane() -> Option<String> {
    runtime::snapshot().map(|report| report.lane)
}

fn record_command_execution(name: &str, evidence: &str) -> Result<(), AppError> {
    let entry = COMMAND_COVERAGE
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| AppError::Assertion(format!("unknown executed command {name}")))?;
    if runtime_command_path(name) && current_lane().as_deref() == Some(entry.lane) {
        runtime::record_execution(PlanEntryKind::Command, name, evidence);
    }
    Ok(())
}

fn record_helper_execution(name: &str, evidence: &str) -> Result<(), AppError> {
    let entry = HELPER_COVERAGE
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| AppError::Assertion(format!("unknown executed helper {name}")))?;
    if runtime_helper_path(name) && current_lane().as_deref() == Some(entry.lane) {
        runtime::record_execution(PlanEntryKind::Helper, name, evidence);
    }
    record_command_execution(entry.wire_command, evidence)
}

fn record_helper_executions(names: &[&str], evidence: &str) -> Result<(), AppError> {
    for name in names {
        record_helper_execution(name, evidence)?;
    }
    Ok(())
}

fn record_scenario_execution(name: &str, evidence: &str) {
    runtime::record_execution(PlanEntryKind::Scenario, name, evidence);
}

fn reconcile_executed_plan(plan: &TestPlan) -> Result<(), AppError> {
    runtime::reconcile_plan(plan).map_err(AppError::Assertion)
}

fn selected_scenario(plan: &TestPlan, name: &str) -> bool {
    plan.entries.iter().any(|entry| {
        entry.kind == PlanEntryKind::Scenario
            && entry.name == name
            && entry.decision == PlanDecision::Selected
    })
}

async fn run_dynamic_capability_scenarios(
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
    plan: &TestPlan,
) -> Result<(), AppError> {
    let agents =
        selected_scenario(plan, "agent-read") || selected_scenario(plan, "agent-group-lifecycle");
    let oci = selected_scenario(plan, "oci-target-lifecycle");
    if !agents && !oci {
        return Ok(());
    }
    let mut client = connect_client(config).await?;
    let auth = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    ensure(
        auth.status == 200,
        "capability scenario authentication failed",
    )?;

    if agents {
        let existing = client.execute(GetAgentGroupsRequest::default()).await?;
        ensure(existing.status == 200, "agent-group preflight read failed")?;
        for group in existing.items {
            if is_e2e_owned_value(&group.meta.name) {
                let deleted = client
                    .execute(DeleteAgentGroupRequest::new(group.meta.id.clone(), true))
                    .await?;
                ensure(
                    matches!(deleted.status, 200 | 404),
                    "stale agent-group cleanup failed",
                )?;
            }
        }
        let response = client.execute(GetAgentsRequest::default()).await?;
        ensure(response.status == 200, "agent readiness read failed")?;
        log_pass(
            "agent-read",
            &format!(
                "typed get_agents returned {} agent(s)",
                response.items.len()
            ),
        );
        let agent_ids = response
            .items
            .iter()
            .take(1)
            .map(|agent| agent.meta.id.clone())
            .collect();
        let mut create =
            CreateAgentGroupRequest::new(config.name("agent-group"), agent_ids, "0 */6 * * *");
        create.comment = Some("rust-gvm dynamic capability E2E".to_string());
        let created = client.execute(create).await?;
        ensure(
            created.status == 201,
            "create_agent_group did not return 201",
        )?;
        tracker.track_agent_group(&created.id);
        let detail = client
            .execute(GetAgentGroupRequest::new(created.id.clone()))
            .await?;
        ensure(
            detail.status == 200 && detail.items.iter().any(|item| item.meta.id == created.id),
            "created agent group was not readable",
        )?;
        let mut modify = ModifyAgentGroupRequest::new(created.id.clone(), "0 */12 * * *");
        modify.comment = Some("rust-gvm dynamic capability E2E modified".to_string());
        let modified = client.execute(modify).await?;
        ensure(
            modified.status == 200,
            "modify_agent_group did not return 200",
        )?;
        let deleted = client
            .execute(DeleteAgentGroupRequest::new(created.id.clone(), true))
            .await?;
        ensure(
            deleted.status == 200,
            "delete_agent_group did not return 200",
        )?;
        tracker.agent_group_ids.pop();
        log_pass(
            "agent-group-lifecycle",
            "create/read/modify/delete completed exactly once",
        );
        for command in [
            "get_agent_groups",
            "get_agents",
            "create_agent_group",
            "modify_agent_group",
            "delete_agent_group",
        ] {
            record_command_execution(command, "agent capability runtime path executed")?;
        }
        record_scenario_execution("agent-read", "typed agent read executed successfully");
        record_scenario_execution(
            "agent-group-lifecycle",
            "agent-group create/read/modify/delete runtime path executed",
        );
    }

    if oci {
        let image_reference = env::var("E2E_OCI_IMAGE_REFERENCE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::Assertion(
                    "selected OCI scenario requires non-secret E2E_OCI_IMAGE_REFERENCE".to_string(),
                )
            })?;
        let existing = client.execute(GetOciImageTargetsRequest::default()).await?;
        ensure(existing.status == 200, "OCI target preflight read failed")?;
        for target in existing.items {
            if is_e2e_owned_value(&target.meta.name) {
                let deleted = client
                    .execute(DeleteOciImageTargetRequest::new(
                        target.meta.id.clone(),
                        true,
                    ))
                    .await?;
                ensure(
                    matches!(deleted.status, 200 | 404),
                    "stale OCI target cleanup failed",
                )?;
            }
        }
        let mut create = CreateOciImageTargetRequest::new(
            config.name("oci-target"),
            vec![image_reference.clone()],
        );
        create.comment = Some("rust-gvm dynamic capability E2E".to_string());
        let created = client.execute(create).await?;
        ensure(
            created.status == 201,
            "create_oci_image_target did not return 201",
        )?;
        tracker.track_oci_image_target(&created.id);
        let detail = client
            .execute(GetOciImageTargetRequest::new(created.id.clone()))
            .await?;
        ensure(
            detail.status == 200 && detail.items.iter().any(|item| item.meta.id == created.id),
            "created OCI target was not readable",
        )?;
        let mut modify = ModifyOciImageTargetRequest::new(created.id.clone());
        modify.comment = Some("rust-gvm dynamic capability E2E modified".to_string());
        modify.image_references = vec![image_reference];
        let modified = client.execute(modify).await?;
        ensure(
            modified.status == 200,
            "modify_oci_image_target did not return 200",
        )?;
        let deleted = client
            .execute(DeleteOciImageTargetRequest::new(created.id.clone(), true))
            .await?;
        ensure(
            deleted.status == 200,
            "delete_oci_image_target did not return 200",
        )?;
        tracker.oci_image_target_ids.pop();
        log_pass(
            "oci-target-lifecycle",
            "create/read/modify/delete completed exactly once",
        );
        for command in [
            "get_oci_image_targets",
            "create_oci_image_target",
            "modify_oci_image_target",
            "delete_oci_image_target",
        ] {
            record_command_execution(command, "OCI target runtime path executed")?;
        }
        record_scenario_execution(
            "oci-target-lifecycle",
            "OCI target create/read/modify/delete runtime path executed",
        );
    }
    client.disconnect().await?;
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).unwrap_or_default().as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES"
    )
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

#[derive(Clone, Copy, Debug)]
struct ReadinessPolicy {
    timeout: Duration,
    poll_interval: Duration,
    max_reconnects: usize,
}

#[derive(Clone, Copy, Debug)]
struct FeedReadinessState {
    scan_config_count: usize,
    syncing_feed_count: usize,
    scap_ready: bool,
    cpe_ready: bool,
    cert_ready: bool,
}

impl FeedReadinessState {
    fn is_ready(self) -> bool {
        self.scan_config_count > 0
            && self.syncing_feed_count == 0
            && self.scap_ready
            && self.cpe_ready
            && self.cert_ready
    }
}

#[derive(Debug, Error)]
enum ReadinessFailure {
    #[error("connection dropped: {0}")]
    Dropped(String),
    #[error("feed database unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Fatal(#[from] AppError),
}

#[allow(async_fn_in_trait)]
trait FeedReadinessBackend {
    type Session;

    async fn connect(&mut self) -> Result<Self::Session, ReadinessFailure>;
    async fn authenticate(&mut self, session: &mut Self::Session) -> Result<(), ReadinessFailure>;
    async fn feed_state(
        &mut self,
        session: &mut Self::Session,
    ) -> Result<FeedReadinessState, ReadinessFailure>;
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

    async fn feed_state(
        &mut self,
        session: &mut Self::Session,
    ) -> Result<FeedReadinessState, ReadinessFailure> {
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
        let scan_config_count = response.items.len();
        if scan_config_count == 0 {
            return Ok(FeedReadinessState {
                scan_config_count,
                syncing_feed_count: 0,
                scap_ready: false,
                cpe_ready: false,
                cert_ready: false,
            });
        }

        let feeds = session
            .get_feeds(GetFeedsRequest::new())
            .await
            .map_err(classify_gvm_readiness_error)?;
        assert_typed_status(feeds.status, &feeds.status_text, 200, "get_feeds readiness")
            .map_err(ReadinessFailure::Fatal)?;
        let syncing_feed_count = feeds
            .items
            .iter()
            .filter(|feed| feed.currently_syncing.is_some())
            .count();
        if syncing_feed_count > 0 {
            return Ok(FeedReadinessState {
                scan_config_count,
                syncing_feed_count,
                scap_ready: false,
                cpe_ready: false,
                cert_ready: false,
            });
        }

        let cve_probe = GetCvesRequest {
            filter_string: Some("rows=1".to_string()),
            ..GetCvesRequest::default()
        };
        let scap_ready = match session.get_cves(cve_probe).await {
            Ok(response) => {
                assert_typed_status(
                    response.status,
                    &response.status_text,
                    200,
                    "get_cves readiness",
                )
                .map_err(ReadinessFailure::Fatal)?;
                true
            }
            Err(error) => return Err(classify_gvm_readiness_error(error)),
        };
        let cpe_probe = GetCpesRequest {
            filter_string: Some("rows=1".to_string()),
            ..GetCpesRequest::default()
        };
        let cpe_ready = match session.get_cpes(cpe_probe).await {
            Ok(response) => {
                assert_typed_status(
                    response.status,
                    &response.status_text,
                    200,
                    "get_cpes readiness",
                )
                .map_err(ReadinessFailure::Fatal)?;
                true
            }
            Err(error) => return Err(classify_gvm_readiness_error(error)),
        };
        let cert_probe = GetCertBundAdvisoriesRequest {
            filter_string: Some("rows=1".to_string()),
            ..GetCertBundAdvisoriesRequest::default()
        };
        let cert_ready = match session.get_cert_bund_advisories(cert_probe).await {
            Ok(response) => {
                assert_typed_status(
                    response.status,
                    &response.status_text,
                    200,
                    "get_cert_bund_advisories readiness",
                )
                .map_err(ReadinessFailure::Fatal)?;
                true
            }
            Err(error) => return Err(classify_gvm_readiness_error(error)),
        };

        Ok(FeedReadinessState {
            scan_config_count,
            syncing_feed_count,
            scap_ready,
            cpe_ready,
            cert_ready,
        })
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
    if feed_database_unavailable(&error, "SCAP") || feed_database_unavailable(&error, "CERT") {
        return ReadinessFailure::Unavailable(error.to_string());
    }
    match error {
        GvmError::Connection(_) | GvmError::Timeout(_) => {
            ReadinessFailure::Dropped(error.to_string())
        }
        other => ReadinessFailure::Fatal(AppError::Client(other)),
    }
}

fn feed_database_unavailable(error: &GvmError, database: &str) -> bool {
    matches!(
        error,
        GvmError::Server { message, .. }
            if message.eq_ignore_ascii_case(&format!("The {database} database is required"))
    )
}

fn missing_observed_vulnerability(error: &GvmError) -> bool {
    matches!(
        error,
        GvmError::Server {
            status: 404,
            message,
        } if message.starts_with("Failed to find vuln '") && message.ends_with('\'')
    )
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
            Err(ReadinessFailure::Unavailable(message)) => {
                log_readiness_unavailable("connect", &message);
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
            Err(ReadinessFailure::Unavailable(message)) => {
                backend.disconnect(&mut session).await;
                log_readiness_unavailable("authenticate", &message);
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
            match backend.feed_state(&mut session).await {
                Ok(state) if state.is_ready() => {
                    backend.disconnect(&mut session).await;
                    log_line(&format!(
                        "feed ready after {polls} poll(s) and {reconnects} reconnect(s): {} scan config(s), no feed synchronization active, and SCAP/CPE/CERT queries available",
                        state.scan_config_count
                    ));
                    return Ok(());
                }
                Ok(state) => {
                    log_line(&format!(
                        "waiting for feed data: poll {polls}: {} scan config(s), {} feed synchronization(s) active, SCAP {}, CPE {}, CERT {}; authenticated session retained",
                        state.scan_config_count,
                        state.syncing_feed_count,
                        readiness_label(state.scap_ready),
                        readiness_label(state.cpe_ready),
                        readiness_label(state.cert_ready),
                    ));
                    bounded_sleep(policy.poll_interval, deadline).await;
                }
                Err(ReadinessFailure::Dropped(message)) => {
                    backend.disconnect(&mut session).await;
                    reconnects = register_reconnect(reconnects, policy.max_reconnects, &message)?;
                    bounded_sleep(policy.poll_interval, deadline).await;
                    break;
                }
                Err(ReadinessFailure::Unavailable(message)) => {
                    backend.disconnect(&mut session).await;
                    log_readiness_unavailable("feed probe", &message);
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

fn log_readiness_unavailable(phase: &str, diagnostic: &str) {
    log_line(&format!(
        "feed readiness prerequisite unavailable during {phase}; opening a fresh session after the poll interval: {diagnostic}"
    ));
}

fn readiness_label(ready: bool) -> &'static str {
    if ready {
        "ready"
    } else {
        "not ready"
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
        "feed readiness timed out after {}s ({polls} feed poll(s), {reconnects} reconnect(s)); gvmd protocol responded but authenticated scan-config, SCAP, and CERT readiness was not reached",
        started.elapsed().as_secs()
    ))
}

async fn bounded_sleep(interval: Duration, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    sleep(interval.min(remaining)).await;
}

fn resource_names_request() -> GetResourceNamesRequest {
    GetResourceNamesRequest::new(ResourceType::Target)
}

const E2E_SCHEDULE_ICALENDAR: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\nBEGIN:VEVENT\r\nDTSTART:20260401T060000Z\r\nDURATION:PT0S\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR";
const E2E_SCHEDULE_TIMEZONE: &str = "UTC";

fn e2e_create_schedule_request(name: String, comment: String) -> CreateScheduleRequest {
    let mut request = CreateScheduleRequest::new(name, E2E_SCHEDULE_ICALENDAR);
    request.comment = Some(comment);
    request.timezone = Some(E2E_SCHEDULE_TIMEZONE.into());
    request
}

fn e2e_modify_schedule_request(
    schedule_id: EntityId,
    comment: String,
    name: Option<String>,
) -> ModifyScheduleRequest {
    let mut request = ModifyScheduleRequest::new(schedule_id, E2E_SCHEDULE_ICALENDAR);
    request.comment = Some(comment);
    request.timezone = Some(E2E_SCHEDULE_TIMEZONE.into());
    request.name = name;
    request
}

fn create_port_range_request(
    port_list_id: &EntityId,
    start: u16,
    end: u16,
) -> CreatePortRangeRequest {
    CreatePortRangeRequest::new(
        port_list_id.clone(),
        gvm_gmp::PortRangeType::Tcp,
        start,
        end,
    )
}

fn modify_setting_request(setting_id: &EntityId, value: &str) -> ModifySettingRequest {
    ModifySettingRequest::new(setting_id.clone(), value)
}

fn delete_user_directly_request(user_id: &EntityId) -> DeleteUserRequest {
    // gvmd deletes users directly; unlike ordinary resources, users are not
    // restorable from the trashcan.
    DeleteUserRequest::new(user_id.clone())
}

async fn run_typed_read_suite(config: &EnvConfig) -> Result<(), AppError> {
    let mut rejected_client = connect_client(config).await?;
    let rejected = rejected_client
        .authenticate(AuthenticateRequest::new(
            &config.username,
            "rust-gvm-e2e-intentionally-wrong",
        ))
        .await;
    ensure(
        matches!(rejected, Err(GvmError::Server { .. })),
        "typed authentication failure did not preserve the server error",
    )?;
    rejected_client.disconnect().await?;
    log_pass("typed authentication failure", "non-2xx server error");

    let mut client = connect_client(config).await?;
    let rejected = client
        .authenticate(AuthenticateRequest::new(&config.username, ""))
        .await;
    ensure(
        matches!(
            rejected,
            Err(GvmError::Request(gvm_gmp::GmpRequestError::InvalidField {
                field: "password",
                ..
            }))
        ),
        "empty-password authentication did not return the typed password validation error",
    )?;
    let mut empty_password = XmlCommand::new("authenticate");
    let credentials = empty_password.add_element("credentials");
    credentials.add_child_with_text("username", &config.username);
    credentials.add_child_with_text("password", "");
    match client.call(empty_password).await {
        Err(GvmError::Server {
            status: 400,
            message,
        }) if message == "Authentication failed" => {}
        Err(error) => {
            return Err(AppError::Assertion(format!(
                "empty-password authentication returned unexpected server error: {error}"
            )));
        }
        Ok(_) => {
            return Err(AppError::Assertion(
                "empty-password authentication unexpectedly succeeded".to_string(),
            ));
        }
    }
    let pre_auth_version = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        pre_auth_version.status,
        &pre_auth_version.status_text,
        200,
        "get_version after empty-password authentication rejection",
    )?;
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    let post_auth_version = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        post_auth_version.status,
        &post_auth_version.status_text,
        200,
        "get_version after empty-password authentication rejection",
    )?;
    log_pass(
        "typed empty-password authentication",
        "local validation plus live GMP 400 Authentication failed, same-connection get_version, and valid authentication",
    );

    macro_rules! typed_read {
        ($name:literal, $future:expr) => {{
            let response = $future.await?;
            ensure(
                response.status == 200,
                concat!("typed ", $name, " did not return status 200"),
            )?;
            log_pass(concat!("typed ", $name), "real-gvmd response parsed");
            response
        }};
    }

    let targets = typed_read!(
        "get_targets",
        client.get_targets(GetTargetsRequest::default())
    );
    let filtered_targets = typed_read!(
        "get_targets(filter/pagination)",
        client.get_targets(GetTargetsRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    ensure(
        filtered_targets.items.len() <= 1,
        "get_targets rows=1 returned more than one typed item",
    )?;

    let configs = typed_read!(
        "get_scan_configs",
        client.get_scan_configs(GetScanConfigsRequest {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    ensure(
        !configs.items.is_empty(),
        "warm-volume baseline requires at least one typed scan config",
    )?;
    typed_read!(
        "get_scan_config(single)",
        client.get_scan_config(GetScanConfigRequest::new(configs.items[0].meta.id.clone(),))
    );
    typed_read!(
        "get_policies",
        client.get_policies(GetPoliciesRequest {
            filter_string: Some("rows=2".to_string()),
            ..Default::default()
        })
    );
    let generic_configs = typed_read!(
        "get_configs(generic)",
        client.get_configs(GetConfigsRequest {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(generic_config) = generic_configs.items.first() {
        typed_read!(
            "get_config(generic single)",
            client.get_config({
                let mut request = GetConfigRequest::new(generic_config.meta.id.clone());
                request.details = Some(true);
                request
            })
        );
        record_helper_execution("get_config", "typed generic config detail executed")?;
    }
    let policies = typed_read!(
        "get_policies(single prerequisite)",
        client.get_policies(GetPoliciesRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(policy) = policies.items.first() {
        typed_read!(
            "get_policy(single)",
            client.get_policy(GetPolicyRequest::new(policy.meta.id.clone()))
        );
        record_helper_execution("get_policy", "typed policy detail executed")?;
    }

    let scanners = typed_read!(
        "get_scanners",
        client.get_scanners(GetScannersRequest::default())
    );
    ensure(
        !scanners.items.is_empty(),
        "warm-volume baseline requires at least one typed scanner",
    )?;
    typed_read!(
        "get_scanner(single)",
        client.get_scanner(GetScannerRequest::new(scanners.items[0].meta.id.clone()))
    );

    let port_lists = typed_read!(
        "get_port_lists",
        client.get_port_lists(GetPortListsRequest {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    ensure(
        !port_lists.items.is_empty(),
        "warm-volume baseline requires at least one typed port list",
    )?;
    typed_read!("get_tasks", client.get_tasks(GetTasksRequest::default()));

    let feeds = typed_read!("get_feeds", client.get_feeds(GetFeedsRequest));
    ensure(
        !feeds.items.is_empty(),
        "warm-volume baseline requires typed feed metadata",
    )?;
    typed_read!(
        "get_feed(single)",
        client.get_feed(GetFeedRequest {
            feed_type: gvm_gmp::FeedType::Nvt,
        })
    );

    let nvts = typed_read!("get_nvts", client.get_nvts(GetNvtsRequest::default()));
    ensure(
        !nvts.items.is_empty(),
        "warm-volume baseline requires at least one typed NVT",
    )?;
    let nvt_oid = nvts.items[0].oid.clone();
    let mut oid_filtered_nvt_request = GetInfoListRequest::new(GenericInfoType::Nvt);
    oid_filtered_nvt_request.filter_string = Some(format!("oid={nvt_oid}"));
    let oid_filtered_nvts = typed_read!(
        "get_info(NVT oid filter)",
        client.get_info_list(oid_filtered_nvt_request)
    );
    ensure(
        oid_filtered_nvts.items.len() == 1
            && oid_filtered_nvts.items[0].id == nvt_oid
            && oid_filtered_nvts.items[0].info_type == "NVT",
        "get_info NVT OID filtering did not return exactly the requested NVT identity",
    )?;
    typed_read!(
        "get_scan_config_nvt(single preferences/count)",
        client.get_scan_config_nvt(GetScanConfigNvtRequest::new(nvts.items[0].oid.clone()))
    );
    let nvt_families = typed_read!(
        "get_nvt_families",
        client.get_nvt_families(GetNvtFamiliesRequest::new())
    );
    ensure(
        !nvt_families.items.is_empty(),
        "warm-volume baseline requires at least one typed NVT family",
    )?;
    typed_read!(
        "get_scan_config_nvts(public helper)",
        client.get_scan_config_nvts(GetScanConfigNvtsRequest::new(
            configs.items[0].meta.id.clone(),
            &nvt_families.items[0].name,
        ))
    );
    record_helper_execution(
        "get_scan_config_nvts",
        "typed scan-config NVT family read executed",
    )?;

    let cves = typed_read!(
        "get_cves",
        client.get_cves(GetCvesRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(cve) = cves.items.first() {
        typed_read!(
            "get_cve(single)",
            client.get_cve(GetCveRequest::new(&cve.id))
        );
        record_helper_execution("get_cve", "typed CVE detail executed")?;
    }
    let cpes = typed_read!(
        "get_cpes",
        client.get_cpes(GetCpesRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(cpe) = cpes.items.first() {
        typed_read!(
            "get_cpe(single)",
            client.get_cpe(GetCpeRequest::new(&cpe.id))
        );
        record_helper_execution("get_cpe", "typed CPE detail executed")?;
    }
    let cert = typed_read!(
        "get_cert_bund_advisories",
        client.get_cert_bund_advisories(GetCertBundAdvisoriesRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(advisory) = cert.items.first() {
        typed_read!(
            "get_cert_bund_advisory(single)",
            client.get_cert_bund_advisory(GetCertBundAdvisoryRequest::new(&advisory.id))
        );
        record_helper_execution(
            "get_cert_bund_advisory",
            "typed CERT-Bund advisory detail executed",
        )?;
    }
    let dfn = typed_read!(
        "get_dfn_cert_advisories",
        client.get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(advisory) = dfn.items.first() {
        typed_read!(
            "get_dfn_cert_advisory(single)",
            client.get_dfn_cert_advisory(GetDfnCertAdvisoryRequest::new(&advisory.id))
        );
        record_helper_execution(
            "get_dfn_cert_advisory",
            "typed DFN-CERT advisory detail executed",
        )?;
    }
    typed_read!(
        "get_vulnerabilities",
        client.get_vulnerabilities(GetVulnsRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    match client
        .get_vulnerability(GetVulnerabilityRequest::new(&nvts.items[0].oid))
        .await
    {
        Ok(response) => {
            ensure(
                response.status == 200,
                "typed get_vulnerability(single NVT) did not return status 200",
            )?;
            log_pass(
                "typed get_vulnerability(single NVT)",
                "real-gvmd response parsed",
            );
        }
        Err(error) if missing_observed_vulnerability(&error) => log_pass(
            "typed get_vulnerability(single NVT)",
            "exact missing observed-vulnerability rejection preserved",
        ),
        Err(error) => return Err(error.into()),
    }
    record_helper_execution("get_vulnerability", "typed vulnerability detail executed")?;

    typed_read!(
        "get_alerts",
        client.get_alerts(GetAlertsRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_credentials",
        client.get_credentials(GetCredentialsRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_filters",
        client.get_filters(GetFiltersRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_notes",
        client.get_notes(GetNotesRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_overrides",
        client.get_overrides(GetOverridesRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_schedules",
        client.get_schedules(GetSchedulesRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_tags",
        client.get_tags(GetTagsRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_report_formats",
        client.get_report_formats(GetReportFormatsRequest {
            filter_string: Some("rows=2".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_settings",
        client.get_settings(GetSettingsRequest::new())
    );
    let invalid_sort = client
        .get_settings(GetSettingsRequest {
            sort_field: Some("rust-gvm-e2e-invalid-sort-field".to_string()),
            ..GetSettingsRequest::new()
        })
        .await?;
    assert_typed_status(
        invalid_sort.status,
        &invalid_sort.status_text,
        200,
        "get_settings with an invalid sort field",
    )?;
    let settings_health = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        settings_health.status,
        &settings_health.status_text,
        200,
        "get_version after invalid get_settings sort field",
    )?;
    log_pass(
        "typed get_settings invalid sort field",
        "validated fallback returned GMP 200 followed by same-session get_version",
    );
    typed_read!(
        "get_system_reports",
        client.get_system_reports(GetSystemReportsRequest {
            brief: Some(true),
            ..Default::default()
        })
    );
    typed_read!(
        "get_aggregates",
        client.get_aggregates({
            let mut request = GetAggregatesRequest::new("task");
            request.max_groups = Some(1);
            request
        })
    );
    typed_read!(
        "describe_auth",
        client.describe_auth(DescribeAuthRequest::new())
    );

    let preferences = client
        .send(XmlCommand::new("get_preferences").attribute("filter", "rows=2"))
        .await?;
    assert_status(&preferences, 200, "get_preferences")?;
    log_pass("raw diagnostic get_preferences", "status and framing");
    let resource_names = client.execute(resource_names_request()).await?;
    ensure(
        resource_names.status == 200,
        "typed get_resource_names did not return status 200",
    )?;
    log_pass("typed get_resource_names", "real-gvmd response parsed");

    ensure(
        targets.status == 200,
        "typed target collection status changed unexpectedly",
    )?;
    record_helper_executions(
        &[
            "authenticate",
            "describe_auth",
            "get_aggregates",
            "get_alerts",
            "get_cert_bund_advisories",
            "get_configs",
            "get_cpes",
            "get_credentials",
            "get_cves",
            "get_dfn_cert_advisories",
            "get_feed",
            "get_feeds",
            "get_filters",
            "get_notes",
            "get_info_list",
            "get_nvt_families",
            "get_nvts",
            "get_overrides",
            "get_policies",
            "get_port_lists",
            "get_report_formats",
            "get_scan_config",
            "get_scan_config_nvt",
            "get_scan_configs",
            "get_scanner",
            "get_scanners",
            "get_schedules",
            "get_settings",
            "get_system_reports",
            "get_tags",
            "get_targets",
            "get_tasks",
            "get_vulnerabilities",
        ],
        "typed read suite runtime path executed",
    )?;
    record_command_execution("get_preferences", "raw preference read executed")?;
    record_command_execution(
        "get_resource_names",
        "canonical resource-name request executed",
    )?;
    client.disconnect().await?;
    Ok(())
}

async fn run_transport_suite(config: &EnvConfig) -> Result<(), AppError> {
    let mut selected = 0usize;

    if let Some(host) = optional_env("E2E_TLS_HOST") {
        selected += 1;
        let mut tls = TlsConfig::new(host);
        if let Some(port) = env_u16("E2E_TLS_PORT")? {
            tls = tls.with_port(port);
        }
        if let Some(server_name) = optional_env("E2E_TLS_SERVER_NAME") {
            tls = tls.with_server_name(server_name);
        }
        if let Some(ca_path) = optional_env("E2E_TLS_CA_PATH") {
            tls = tls
                .with_native_roots(false)
                .with_root_certificate_file(ca_path)?;
        }
        validate_transport(
            "tls",
            GmpClient::connect(TlsConnection::new(tls)).await?,
            config,
        )
        .await?;
    } else {
        runtime::observe(
            "transport:tls",
            Outcome::ConditionalUnavailable,
            "E2E_TLS_HOST is not provisioned",
        );
    }

    if let Some(host) = optional_env("E2E_MTLS_HOST") {
        selected += 1;
        let certificate = required_env("E2E_MTLS_CERT_PATH")?;
        let private_key = required_env("E2E_MTLS_KEY_PATH")?;
        let identity = TlsClientIdentity::from_files(certificate, private_key)?;
        let mut tls = TlsConfig::new(host).with_client_identity(identity);
        if let Some(port) = env_u16("E2E_MTLS_PORT")? {
            tls = tls.with_port(port);
        }
        if let Some(server_name) = optional_env("E2E_MTLS_SERVER_NAME") {
            tls = tls.with_server_name(server_name);
        }
        if let Some(ca_path) = optional_env("E2E_MTLS_CA_PATH") {
            tls = tls
                .with_native_roots(false)
                .with_root_certificate_file(ca_path)?;
        }
        validate_transport(
            "mtls",
            GmpClient::connect(TlsConnection::new(tls)).await?,
            config,
        )
        .await?;
    } else {
        runtime::observe(
            "transport:mtls",
            Outcome::ConditionalUnavailable,
            "E2E_MTLS_HOST is not provisioned",
        );
    }

    if let Some(host) = optional_env("E2E_SSH_HOST") {
        selected += 1;
        let username = required_env("E2E_SSH_USER")?;
        let auth = if let Some(key_path) = optional_env("E2E_SSH_KEY_PATH") {
            SshAuth::PrivateKey {
                key_path: key_path.into(),
                passphrase: optional_env("E2E_SSH_KEY_PASSPHRASE"),
            }
        } else if let Some(password) = optional_env("E2E_SSH_PASSWORD") {
            SshAuth::Password(password)
        } else {
            SshAuth::Agent
        };
        let mut ssh = SshConfig::new(host, username, auth);
        if let Some(port) = env_u16("E2E_SSH_PORT")? {
            ssh = ssh.with_port(port);
        }
        if let Some(socket) = optional_env("E2E_SSH_SOCKET_PATH") {
            ssh = ssh.with_remote_socket(socket);
        }
        validate_transport(
            "ssh",
            GmpClient::connect(SshConnection::new(ssh)).await?,
            config,
        )
        .await?;
    } else {
        runtime::observe(
            "transport:ssh",
            Outcome::ConditionalUnavailable,
            "E2E_SSH_HOST is not provisioned",
        );
    }

    if selected == 0 {
        log_line("transport lane selected correctly; no TLS, mTLS, or SSH endpoint is provisioned");
    }
    Ok(())
}

async fn run_config_scanner_lifecycles(
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;

    let configs = client
        .get_configs(GetConfigsRequest {
            filter_string: Some("rows=1".to_string()),
            usage_type: Some(ConfigUsageType::Scan),
            ..Default::default()
        })
        .await?;
    let base = configs.items.first().ok_or_else(|| {
        AppError::Assertion("config lifecycle requires a warm scan config".to_string())
    })?;
    let mut create_scan =
        CreateScanConfigRequest::new(config.name("scan-config"), base.meta.id.clone());
    create_scan.comment = Some(config.name("scan-config-comment"));
    create_scan.usage_type = Some(ConfigUsageType::Scan);
    let scan_config = client.create_scan_config(create_scan).await?;
    ensure(scan_config.status == 201, "typed create_scan_config failed")?;
    tracker.track_config(&scan_config.id);
    let mut modify_scan = ModifyScanConfigRequest::new(scan_config.id.clone());
    modify_scan.comment = Some(config.name("scan-config-comment-modified"));
    ensure(
        client.modify_scan_config(modify_scan).await?.status == 200,
        "typed modify_scan_config failed",
    )?;
    ensure(
        client
            .modify_scan_config_set_name(ModifyScanConfigSetNameRequest::new(
                scan_config.id.clone(),
                config.name("scan-config-renamed"),
            ))
            .await?
            .status
            == 200,
        "typed scan-config name modification failed",
    )?;
    ensure(
        client
            .modify_scan_config_set_comment(ModifyScanConfigSetCommentRequest::new(
                scan_config.id.clone(),
                Some(config.name("scan-config-comment-final")),
            ))
            .await?
            .status
            == 200,
        "typed scan-config comment modification failed",
    )?;
    let mut create_config = CreateConfigRequest::new(config.name("config"), base.meta.id.clone());
    create_config.comment = Some(config.name("config-comment"));
    create_config.usage_type = Some(ConfigUsageType::Scan);
    let created = client.create_config(create_config).await?;
    ensure(created.status == 201, "typed create_config failed")?;
    tracker.track_config(&created.id);
    let mut modify_config = ModifyConfigRequest::new(created.id.clone());
    modify_config.name = Some(config.name("config-modified"));
    modify_config.comment = Some(config.name("config-comment-modified"));
    let modified = client.modify_config(modify_config).await?;
    ensure(modified.status == 200, "typed modify_config failed")?;
    let mut get_config = GetConfigRequest::new(created.id.clone());
    get_config.details = Some(true);
    get_config.families = Some(true);
    get_config.preferences = Some(true);
    get_config.tasks = Some(true);
    get_config.usage_type = Some(ConfigUsageType::Scan);
    let singular = client.get_config(get_config).await?;
    ensure(
        singular.items.iter().any(|item| item.meta.id == created.id),
        "typed generic config did not round-trip",
    )?;
    let mut clone_config = CloneConfigRequest::new(created.id.clone());
    clone_config.name = Some(config.name("config-clone"));
    let cloned = client.clone_config(clone_config).await?;
    ensure(cloned.status == 201, "typed clone_config failed")?;
    tracker.track_config(&cloned.id);
    let mut invalid_request = CreateConfigRequest::new(
        config.name("config-invalid-reference"),
        parse_entity_id("00000000-0000-0000-0000-000000000118")?,
    );
    invalid_request.usage_type = Some(ConfigUsageType::Scan);
    let invalid_config = client.create_config(invalid_request).await;
    ensure(
        matches!(invalid_config, Err(GvmError::Server { .. })),
        "invalid config base reference did not return a typed server error",
    )?;

    let policies = client
        .get_policies(GetPoliciesRequest {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
        .await?;
    let policy = policies.items.first().ok_or_else(|| {
        AppError::Assertion("policy import lifecycle requires a warm policy".to_string())
    })?;
    let mut clone_policy = ClonePolicyRequest::new(policy.meta.id.clone());
    clone_policy.name = Some(config.name("policy-clone"));
    let cloned_policy = client.execute(clone_policy).await?;
    ensure(cloned_policy.status == 201, "typed clone_policy failed")?;
    tracker.track_config(&cloned_policy.id);
    ensure(
        client
            .modify_policy_set_name(ModifyPolicySetNameRequest::new(
                cloned_policy.id.clone(),
                config.name("policy-clone-renamed"),
            ))
            .await?
            .status
            == 200,
        "typed policy name modification failed",
    )?;
    ensure(
        client
            .modify_policy_set_comment(ModifyPolicySetCommentRequest::new(
                cloned_policy.id.clone(),
                Some(config.name("policy-comment")),
            ))
            .await?
            .status
            == 200,
        "typed policy comment modification failed",
    )?;
    let mut get_policy = GetPolicyRequest::new(cloned_policy.id.clone());
    get_policy.audits = Some(true);
    let imported_policy_read = client.get_policy(get_policy).await?;
    ensure(
        imported_policy_read
            .items
            .iter()
            .any(|item| item.meta.id == cloned_policy.id),
        "typed cloned policy did not round-trip",
    )?;
    for id in [cloned.id, created.id, scan_config.id, cloned_policy.id] {
        let mut trash_request = DeleteConfigRequest::new(id.clone());
        trash_request.ultimate = Some(false);
        let trashed = client.delete_config(trash_request).await?;
        ensure(trashed.status == 200, "typed config trash failed")?;
        let restored = client.restore(RestoreRequest::new(id.clone())).await?;
        ensure(restored.status == 200, "typed config restore failed")?;
        let mut delete_request = DeleteConfigRequest::new(id.clone());
        delete_request.ultimate = Some(true);
        let deleted = client.delete_config(delete_request).await?;
        ensure(deleted.status == 200, "typed config ultimate delete failed")?;
        tracker.config_ids.retain(|tracked| tracked != id.as_str());
    }
    log_pass(
        "config lifecycle",
        "typed create/clone/get/modify/trash/restore/delete/failure; import remains fixture-gated",
    );

    let scanners = client.get_scanners(GetScannersRequest::default()).await?;
    let base_scanner = select_cloneable_scanner(&scanners)?;
    let scanner = client
        .clone_scanner(CloneScannerRequest::new(base_scanner.meta.id.clone()))
        .await?;
    ensure(scanner.status == 201, "typed clone_scanner failed")?;
    tracker.track_scanner(&scanner.id);
    let mut modify_scanner = ModifyScannerRequest::new(scanner.id.clone());
    modify_scanner.comment = Some(config.name("scanner-comment-modified"));
    let modified = client.modify_scanner(modify_scanner).await?;
    ensure(modified.status == 200, "typed modify_scanner failed")?;
    let listed = client
        .get_scanner(GetScannerRequest::new(scanner.id.clone()))
        .await?;
    ensure(
        listed.items.iter().any(|item| item.meta.id == scanner.id),
        "typed scanner did not round-trip",
    )?;
    let verified = client
        .verify_scanner(VerifyScannerRequest::new(scanner.id.clone()))
        .await?;
    ensure(
        matches!(verified.status, 200 | 202),
        "typed verify_scanner returned an unexpected status",
    )?;
    let invalid = client
        .verify_scanner(VerifyScannerRequest::new(parse_entity_id(
            "00000000-0000-0000-0000-000000000118",
        )?))
        .await;
    ensure(
        matches!(invalid, Err(GvmError::Server { .. })),
        "invalid scanner reference did not return a typed server error",
    )?;
    let trashed = client
        .delete_scanner(DeleteScannerRequest::new(scanner.id.clone(), false))
        .await?;
    ensure(trashed.status == 200, "typed scanner trash failed")?;
    let restored = client
        .restore(RestoreRequest::new(scanner.id.clone()))
        .await?;
    ensure(restored.status == 200, "typed scanner restore failed")?;
    let deleted = client
        .delete_scanner(DeleteScannerRequest::new(scanner.id.clone(), true))
        .await?;
    ensure(
        deleted.status == 200,
        "typed scanner ultimate delete failed",
    )?;
    tracker
        .scanner_ids
        .retain(|tracked| tracked != scanner.id.as_str());
    log_pass(
        "scanner lifecycle",
        "typed clone/get/modify/verify/trash/restore/delete/failure",
    );

    record_helper_executions(
        &[
            "authenticate",
            "clone_config",
            "clone_scanner",
            "create_config",
            "create_scan_config",
            "delete_config",
            "delete_scanner",
            "get_config",
            "get_configs",
            "get_policies",
            "get_policy",
            "get_scanner",
            "get_scanners",
            "modify_config",
            "modify_policy_set_comment",
            "modify_policy_set_name",
            "modify_scan_config",
            "modify_scan_config_set_comment",
            "modify_scan_config_set_name",
            "modify_scanner",
            "restore",
            "verify_scanner",
        ],
        "config/scanner lifecycle runtime path executed",
    )?;

    client.disconnect().await?;
    Ok(())
}

fn select_cloneable_scanner(
    scanners: &GetScannersResponse,
) -> Result<&gvm_gmp::responses::scanner::Scanner, AppError> {
    scanners
        .items
        .iter()
        .find(|scanner| {
            scanner
                .scanner_type
                .as_deref()
                .and_then(|kind| ScannerType::from_str(kind).ok())
                .is_some_and(|kind| kind != ScannerType::CveScannerType)
        })
        .ok_or_else(|| {
            let types = scanners
                .items
                .iter()
                .map(|scanner| scanner.scanner_type.as_deref().unwrap_or("<missing>"))
                .collect::<Vec<_>>();
            AppError::Assertion(format!(
                "scanner lifecycle requires a cloneable non-CVE scanner; get_scanners returned types [{}]",
                types.join(", ")
            ))
        })
}

fn select_scan_scanner(
    scanners: &GetScannersResponse,
) -> Result<&gvm_gmp::responses::scanner::Scanner, AppError> {
    scanners
        .items
        .iter()
        .find(|scanner| {
            scanner
                .scanner_type
                .as_deref()
                .and_then(|kind| ScannerType::from_str(kind).ok())
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        ScannerType::OpenVasScanner | ScannerType::OpenVasdScannerType
                    )
                })
        })
        .ok_or_else(|| {
            AppError::Assertion("scan lane requires an OpenVAS/openvasd scanner".to_string())
        })
}

async fn run_isolated_suite(
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    ensure(
        env_flag("E2E_ISOLATED"),
        "devel-isolated requires E2E_ISOLATED=1 and a dedicated database/volume namespace",
    )?;
    let mut client = connect_client(config).await?;
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;

    let report_configs = client
        .get_report_configs(GetReportConfigsRequest::default())
        .await?;
    assert_typed_status(
        report_configs.status,
        &report_configs.status_text,
        200,
        "get_report_configs",
    )?;
    log_pass(
        "isolated report config list",
        "safe typed list read; report-config mutations are recorded as greenbone/gvmd#3165 and are not executed",
    );
    match select_deterministic_report_config_id(&report_configs) {
        Some(report_config_id) => {
            let mut request = GetReportConfigRequest::new(report_config_id.clone());
            request.details = Some(true);
            let singular = client.get_report_config(request).await?;
            assert_typed_status(
                singular.status,
                &singular.status_text,
                200,
                "get_report_config",
            )?;
            ensure(
                singular.items.len() == 1 && singular.items[0].meta.id == report_config_id,
                &format!(
                    "typed get_report_config for {report_config_id} returned {} item(s) without the selected identity",
                    singular.items.len()
                ),
            )?;
            log_pass(
                "isolated report config singular read",
                &format!(
                    "safe typed get_report_config for deterministically selected existing report config {report_config_id}; report-config mutations remain quarantined"
                ),
            );
            record_helper_execution(
                "get_report_config",
                "deterministically selected report-config detail executed",
            )?;
        }
        None => runtime::observe(
            "isolated report config singular read",
            Outcome::ConditionalUnavailable,
            "typed get_report_configs returned no existing report configs; get_report_config was not invoked because creation is quarantined by greenbone/gvmd#3165",
        ),
    }

    let predefined_roles = client
        .get_roles(GetRolesRequest {
            filter_string: Some("name=User".to_string()),
            ..Default::default()
        })
        .await?;
    let user_role_id = predefined_roles
        .items
        .iter()
        .find(|entry| entry.meta.name == "User")
        .map(|entry| entry.meta.id.clone())
        .ok_or_else(|| {
            AppError::Assertion(
                "isolated access-control suite requires the predefined User role".to_string(),
            )
        })?;

    let user_name = config.name("user");
    let user_password = format!("{}-password", config.run_id);
    let mut create_user = CreateUserRequest::new(user_name.clone());
    create_user.password = Some(user_password.clone());
    create_user.comment = Some(config.name("user-comment"));
    create_user.role_ids = vec![user_role_id.clone()];
    let user = client.create_user(create_user).await?;
    tracker.track_user(&user.id);
    log_pass("isolated user create", &user.id.to_string());

    let mut duplicate_request = CreateUserRequest::new(user_name.clone());
    duplicate_request.password = Some("not-used".to_string());
    let duplicate = client.create_user(duplicate_request).await;
    ensure(
        matches!(duplicate, Err(GvmError::Server { .. })),
        "duplicate user creation did not produce a typed server error",
    )?;
    log_pass("isolated user duplicate", "typed conflict error");

    let group_name = config.name("group");
    let mut create_group = CreateGroupRequest::new(group_name.clone());
    create_group.users = vec![user_name.clone()];
    create_group.comment = Some(config.name("group-comment"));
    let group = client.create_group(create_group).await?;
    tracker.track_group(&group.id);
    let role_name = config.name("role");
    let mut create_role = CreateRoleRequest::new(role_name.clone());
    create_role.users = vec![user_name.clone()];
    create_role.comment = Some(config.name("role-comment"));
    let role = client.create_role(create_role).await?;
    tracker.track_role(&role.id);
    let permission_id = create_role_permission(
        &mut client,
        "get_tasks",
        &config.name("permission-comment"),
        &role.id,
    )
    .await?;
    tracker.track_permission(&permission_id);

    let users = client
        .get_users(GetUsersRequest {
            filter_string: Some(format!("uuid={}", user.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        users.items.iter().any(|entry| entry.meta.id == user.id),
        "typed get_users did not round-trip the created user",
    )?;
    let mut user_role_ids = users
        .items
        .iter()
        .find(|entry| entry.meta.id == user.id)
        .map(|entry| {
            entry
                .roles
                .iter()
                .map(|role| role.id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ensure(
        user_role_ids.contains(&user_role_id),
        "typed get_users did not preserve the predefined User role",
    )?;
    if !user_role_ids.contains(&role.id) {
        user_role_ids.push(role.id.clone());
    }
    let groups = client
        .get_groups(GetGroupsRequest {
            filter_string: Some(format!("uuid={}", group.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        groups.items.iter().any(|entry| entry.meta.id == group.id),
        "typed get_groups did not round-trip the created group",
    )?;
    let roles = client
        .get_roles(GetRolesRequest {
            filter_string: Some(format!("uuid={}", role.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        roles.items.iter().any(|entry| entry.meta.id == role.id),
        "typed get_roles did not round-trip the created role",
    )?;
    let permissions = client
        .get_permissions(GetPermissionsRequest {
            filter_string: Some(format!("uuid={permission_id}")),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        permissions
            .items
            .iter()
            .any(|entry| entry.meta.id == permission_id),
        "typed get_permissions did not round-trip the created permission",
    )?;
    log_pass(
        "isolated access-control reads",
        "typed users/groups/roles/permissions",
    );

    modify_role_permission_reconciled(
        &mut client,
        config,
        &permission_id,
        &role.id,
        &config.name("permission-modified"),
    )
    .await?;

    let modify_group = client
        .modify_group(ModifyGroupRequest::new(
            group.id.clone(),
            group_name,
            config.name("group-modified"),
            vec![user_name.clone()],
        ))
        .await?;
    assert_typed_status(
        modify_group.status,
        &modify_group.status_text,
        200,
        "modify_group",
    )?;
    let modify_role = client
        .modify_role(ModifyRoleRequest::new(
            role.id.clone(),
            role_name,
            config.name("role-modified"),
            vec![user_name.clone()],
        ))
        .await?;
    assert_typed_status(
        modify_role.status,
        &modify_role.status_text,
        200,
        "modify_role",
    )?;
    let mut modify_user =
        ModifyUserRequest::new(user.id.clone(), UserHostAccess::allow(String::new()));
    modify_user.password = Some(user_password.clone());
    modify_user.comment = Some(config.name("user-modified"));
    modify_user.role_ids = CollectionUpdate::Replace(user_role_ids);
    let modify_user = client.modify_user(modify_user).await?;
    assert_typed_status(
        modify_user.status,
        &modify_user.status_text,
        200,
        "modify_user",
    )?;
    log_pass(
        "isolated access-control modify",
        "permission/group/role/user",
    );

    let mut restricted =
        GmpClient::connect(UnixSocketConnection::with_path(config.socket_path.clone())).await?;
    restricted
        .authenticate(AuthenticateRequest::new(&user_name, &user_password))
        .await?;
    let denied = restricted
        .create_user(CreateUserRequest::new("rust-gvm-e2e-permission-denied"))
        .await;
    ensure(
        matches!(denied, Err(GvmError::Server { .. })),
        "restricted user unexpectedly created an administrative user",
    )?;
    restricted.disconnect().await?;
    log_pass("isolated permission denied", "typed server error");

    let mut create_host = CreateHostRequest::new("192.0.2.118");
    create_host.comment = Some(config.name("host"));
    let host = client.create_host(create_host).await?;
    tracker.track_asset(&host.id);
    let hosts = client
        .get_hosts(GetHostsRequest {
            filter_string: Some(format!("uuid={}", host.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        hosts.items.iter().any(|entry| entry.meta.id == host.id),
        "typed host asset did not round-trip",
    )?;
    let mut get_assets = GetAssetsRequest::new(AssetType::Host);
    get_assets.filter_string = Some(format!("uuid={}", host.id));
    get_assets.details = Some(true);
    let assets = client.get_assets(get_assets).await?;
    ensure(
        assets.items.iter().any(|entry| match entry {
            gvm_gmp::responses::Asset::Host(value) => value.meta.id == host.id,
            gvm_gmp::responses::Asset::OperatingSystem(value) => value.meta.id == host.id,
            gvm_gmp::responses::Asset::Generic(value) => value.meta.id == host.id,
            _ => false,
        }),
        "typed generic asset list did not round-trip the host",
    )?;
    let asset = client
        .get_asset(GetAssetRequest::new(host.id.clone(), AssetType::Host))
        .await?;
    ensure(
        asset.items.iter().any(|entry| match entry {
            gvm_gmp::responses::Asset::Host(value) => value.meta.id == host.id,
            gvm_gmp::responses::Asset::OperatingSystem(value) => value.meta.id == host.id,
            gvm_gmp::responses::Asset::Generic(value) => value.meta.id == host.id,
            _ => false,
        }),
        "typed singular asset did not round-trip",
    )?;
    let operating_systems = client
        .get_operating_system_assets(GetOperatingSystemAssetsRequest {
            filter_string: Some("rows=1".to_string()),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    if let Some(operating_system) = operating_systems.items.first() {
        let single = client
            .get_operating_system_asset({
                let mut request =
                    GetOperatingSystemAssetRequest::new(operating_system.meta.id.clone());
                request.details = Some(true);
                request
            })
            .await?;
        ensure(
            single
                .items
                .iter()
                .any(|entry| entry.meta.id == operating_system.meta.id),
            "typed singular operating-system asset did not round-trip",
        )?;
        record_helper_execution(
            "get_operating_system_asset",
            "typed operating-system asset detail executed",
        )?;
    }
    let modify_host = client
        .modify_asset(ModifyAssetRequest::new(
            host.id.clone(),
            config.name("host-modified"),
        ))
        .await?;
    ensure(modify_host.status == 200, "typed modify_asset failed")?;
    let invalid_host = client
        .create_host(CreateHostRequest::new("not-an-ip"))
        .await;
    ensure(
        matches!(invalid_host, Err(GvmError::Request(_))),
        "invalid host asset did not produce a typed request error",
    )?;
    let mut create_asset = CreateAssetRequest::new("192.0.2.119");
    create_asset.comment = Some(config.name("generic-asset"));
    let generic_asset = client.create_asset(create_asset).await?;
    ensure(
        generic_asset.status == 201,
        "typed generic create_asset failed",
    )?;
    let generic_asset_id = generic_asset.id.ok_or_else(|| {
        AppError::Assertion("typed generic create_asset omitted its id".to_string())
    })?;
    tracker.track_asset(&generic_asset_id);
    let deleted_generic_asset = client
        .delete_asset(DeleteAssetRequest::new(generic_asset_id.clone()))
        .await?;
    ensure(
        deleted_generic_asset.status == 200,
        "typed generic delete_asset failed",
    )?;
    tracker
        .asset_ids
        .retain(|id| id != generic_asset_id.as_str());
    log_pass(
        "isolated host asset",
        "typed create/get/modify/local-validation failure",
    );

    let report_formats = client
        .get_report_formats(GetReportFormatsRequest::default())
        .await?;
    assert_typed_status(
        report_formats.status,
        &report_formats.status_text,
        200,
        "get_report_formats for isolated lifecycles",
    )?;
    let ordinary_report_format_id = report_formats
        .items
        .iter()
        .min_by(|left, right| left.meta.id.as_str().cmp(right.meta.id.as_str()))
        .map(|format| format.meta.id.clone())
        .ok_or_else(|| AppError::Assertion("no report format is available to clone".to_string()))?;
    let cloned_format = client
        .clone_report_format(CloneReportFormatRequest::new(
            ordinary_report_format_id.clone(),
        ))
        .await?;
    tracker.track_report_format(&cloned_format.id);
    let mut modify_format = ModifyReportFormatRequest::new(cloned_format.id.clone());
    modify_format.name = Some(config.name("report-format-clone"));
    let modify_format = client.modify_report_format(modify_format).await?;
    assert_typed_status(
        modify_format.status,
        &modify_format.status_text,
        200,
        "modify_report_format",
    )?;
    let verified = client
        .verify_report_format(VerifyReportFormatRequest::new(cloned_format.id.clone()))
        .await?;
    assert_typed_status(
        verified.status,
        &verified.status_text,
        200,
        "verify_report_format",
    )?;

    log_pass(
        "isolated report format lifecycle",
        "canonical clone/modify/verify; cleanup is tracked",
    );
    runtime::observe(
        "isolated report format import",
        Outcome::ConditionalUnavailable,
        "the pinned typed report-format projection does not expose the export envelope required to construct a canonical import request",
    );
    runtime::observe(
        "sync_config surfaces",
        Outcome::ConditionalUnavailable,
        "rust-gvm v0.7 removes sync_config and sync_scan_config because gvmd does not dispatch that schema name",
    );

    let mut create_alert = CreateAlertRequest::new(
        config.name("test-alert"),
        AlertEvent::TaskRunStatusChanged,
        AlertCondition::Always,
        AlertMethod::SysLog,
    );
    create_alert.comment = Some(config.name("test-alert-comment"));
    let test_alert = client.create_alert(create_alert).await?;
    tracker.track_alert(&test_alert.id);
    let tested = client
        .test_alert(TestAlertRequest::new(test_alert.id.clone()))
        .await?;
    assert_typed_status(tested.status, &tested.status_text, 200, "test_alert")?;
    log_pass("isolated alert test", "syslog alert test request");

    let mut create_tls = CreateTlsCertificateRequest::new(tls_certificate_data());
    create_tls.name = Some(config.name("tls-certificate"));
    create_tls.comment = Some(config.name("tls-certificate-comment"));
    let tls = client.create_tls_certificate(create_tls).await?;
    tracker.track_tls_certificate(&tls.id);
    let get_certificates = GetTlsCertificatesRequest {
        filter_string: Some(format!("uuid={}", tls.id)),
        details: Some(true),
        ..Default::default()
    };
    let certificates = client.get_tls_certificates(get_certificates).await?;
    ensure(
        certificates
            .items
            .iter()
            .any(|entry| entry.meta.id == tls.id),
        "typed TLS certificate did not round-trip",
    )?;
    let mut modify_tls_request = ModifyTlsCertificateRequest::new(tls.id.clone());
    modify_tls_request.comment = Some(config.name("tls-certificate-modified"));
    let modify_tls = client.modify_tls_certificate(modify_tls_request).await?;
    assert_typed_status(
        modify_tls.status,
        &modify_tls.status_text,
        200,
        "modify_tls_certificate",
    )?;
    log_pass("isolated tls certificate", "canonical create/get/modify");

    let settings = client.get_settings(GetSettingsRequest::default()).await?;
    let mut restored_setting = None;
    for setting in settings
        .items
        .iter()
        .filter(|setting| setting.value.is_some())
    {
        let original = setting.value.as_deref().unwrap_or_default();
        let write_same_value = match client
            .execute(modify_setting_request(&setting.id, original))
            .await
        {
            Ok(response) => response,
            Err(GvmError::Server {
                status: 400,
                message,
            }) if message.contains("Failed to find setting") => continue,
            Err(error) => return Err(error.into()),
        };
        assert_typed_status(
            write_same_value.status,
            &write_same_value.status_text,
            200,
            "modify_setting snapshot",
        )?;
        let restore = client
            .execute(modify_setting_request(&setting.id, original))
            .await?;
        assert_typed_status(
            restore.status,
            &restore.status_text,
            200,
            "modify_setting restore",
        )?;
        restored_setting = Some(setting.name.clone());
        break;
    }
    if let Some(setting_name) = restored_setting {
        log_pass(
            "isolated setting",
            &format!("snapshot and restore exact value for {setting_name}"),
        );
        record_command_execution(
            "modify_setting",
            "setting write and exact-value restore both executed",
        )?;
    } else {
        runtime::observe(
            "isolated setting",
            Outcome::ConditionalUnavailable,
            "stable gvmd exposed no value-bearing setting accepted by modify_setting",
        );
    }

    let trashed = client
        .delete_permission(DeletePermissionRequest::new(permission_id.clone(), false))
        .await?;
    assert_typed_status(
        trashed.status,
        &trashed.status_text,
        200,
        "trash permission",
    )?;
    let restored = client
        .restore(RestoreRequest::new(permission_id.clone()))
        .await?;
    assert_typed_status(
        restored.status,
        &restored.status_text,
        200,
        "restore permission",
    )?;
    let deleted = client
        .delete_permission(DeletePermissionRequest::new(permission_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "ultimate delete permission",
    )?;
    tracker
        .permission_ids
        .retain(|id| id != permission_id.as_str());
    let trashed = client
        .delete_group(DeleteGroupRequest::new(group.id.clone(), false))
        .await?;
    assert_typed_status(trashed.status, &trashed.status_text, 200, "trash group")?;
    let restored = client
        .restore(RestoreRequest::new(group.id.clone()))
        .await?;
    assert_typed_status(restored.status, &restored.status_text, 200, "restore group")?;
    let deleted = client
        .delete_group(DeleteGroupRequest::new(group.id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "ultimate delete group",
    )?;
    tracker.group_ids.retain(|id| id != group.id.as_str());
    let trashed = client
        .delete_role(DeleteRoleRequest::new(role.id.clone(), false))
        .await?;
    assert_typed_status(trashed.status, &trashed.status_text, 200, "trash role")?;
    let restored = client.restore(RestoreRequest::new(role.id.clone())).await?;
    assert_typed_status(restored.status, &restored.status_text, 200, "restore role")?;
    let deleted = client
        .delete_role(DeleteRoleRequest::new(role.id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "ultimate delete role",
    )?;
    tracker.role_ids.retain(|id| id != role.id.as_str());
    let deleted_user = client
        .execute(delete_user_directly_request(&user.id))
        .await?;
    assert_typed_status(
        deleted_user.status,
        &deleted_user.status_text,
        200,
        "delete user directly",
    )?;
    tracker.user_ids.retain(|id| id != user.id.as_str());

    tracker.cleanup_inner().await?;
    let empty = client.empty_trashcan(EmptyTrashcanRequest).await?;
    ensure(empty.status == 200, "isolated empty_trashcan failed")?;
    log_pass(
        "isolated trash",
        "typed restore lifecycles and dedicated empty_trashcan",
    );

    record_helper_executions(
        &[
            "clone_report_format",
            "create_asset",
            "create_group",
            "create_host",
            "create_role",
            "create_tls_certificate",
            "create_user",
            "delete_asset",
            "delete_group",
            "delete_permission",
            "delete_role",
            "empty_trashcan",
            "get_asset",
            "get_assets",
            "get_groups",
            "get_hosts",
            "get_operating_system_assets",
            "get_permissions",
            "get_report_configs",
            "get_roles",
            "get_tls_certificates",
            "get_users",
            "modify_asset",
            "modify_group",
            "modify_report_format",
            "modify_role",
            "modify_tls_certificate",
            "modify_user",
            "restore",
            "test_alert",
            "verify_report_format",
        ],
        "isolated runtime path executed",
    )?;
    record_command_execution("delete_user", "direct user deletion executed")?;

    client.disconnect().await?;
    Ok(())
}

async fn trash_restore_then_delete<R, F>(
    client: &mut GmpClient<UnixSocketConnection>,
    label: &str,
    id: &EntityId,
    delete: F,
) -> Result<(), AppError>
where
    R: GmpRequest<Response = ActionResponse>,
    F: Fn(&EntityId, bool) -> R,
{
    let trashed = client.execute(delete(id, false)).await?;
    assert_typed_status(
        trashed.status,
        &trashed.status_text,
        200,
        &format!("trash {label}"),
    )?;
    let restored = client.restore(RestoreRequest::new(id.clone())).await?;
    assert_typed_status(
        restored.status,
        &restored.status_text,
        200,
        &format!("restore {label}"),
    )?;
    let deleted = client.execute(delete(id, true)).await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        &format!("ultimate delete {label}"),
    )?;
    Ok(())
}

async fn validate_transport<C>(
    label: &str,
    mut client: GmpClient<C>,
    config: &EnvConfig,
) -> Result<(), AppError>
where
    C: GvmConnection + Send,
{
    let version = client.get_version(GetVersionRequest::new()).await?;
    ensure(version.status == 200, "transport get_version failed")?;
    let auth = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    ensure(auth.status == 200, "transport authentication failed")?;
    runtime::observe(
        &format!("transport:{label}"),
        Outcome::Pass,
        &format!(
            "typed get_version/authenticate succeeded with GMP {}",
            version.version
        ),
    );
    client.disconnect().await?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, AppError> {
    optional_env(name).ok_or_else(|| {
        AppError::Assertion(format!("{name} is required for the selected transport"))
    })
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn canonical_help_command(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn live_help_supports(help_commands: &BTreeSet<String>, command: &str) -> bool {
    help_commands.contains(command)
}

fn env_u16(name: &str) -> Result<Option<u16>, AppError> {
    optional_env(name)
        .map(|value| {
            value
                .parse()
                .map_err(|_| AppError::Assertion(format!("{name} must be a valid u16 port")))
        })
        .transpose()
}

async fn run_smoke_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    let smoke_target_name = config.name("smoke-target");

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
    log_pass("01", &format!("version negotiation ({version})"));

    let auth_response = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    assert_typed_status(
        auth_response.status,
        &auth_response.status_text,
        200,
        "authenticate",
    )?;
    log_pass("02", "authentication");

    let configs_response = client
        .get_scan_configs(GetScanConfigsRequest::default())
        .await?;
    assert_typed_status(
        configs_response.status,
        &configs_response.status_text,
        200,
        "get_scan_configs",
    )?;
    let config_count = configs_response.items.len();
    ensure(config_count >= 1, "expected at least one scan config")?;
    log_pass("03", &format!("list scan configs ({config_count})"));

    let scanners_response = client.get_scanners(GetScannersRequest::default()).await?;
    assert_typed_status(
        scanners_response.status,
        &scanners_response.status_text,
        200,
        "get_scanners",
    )?;
    let scanner_count = scanners_response.items.len();
    ensure(scanner_count >= 1, "expected at least one scanner")?;
    log_pass("04", &format!("list scanners ({scanner_count})"));

    let report_formats_response = client
        .get_report_formats(GetReportFormatsRequest::default())
        .await?;
    assert_typed_status(
        report_formats_response.status,
        &report_formats_response.status_text,
        200,
        "get_report_formats",
    )?;
    log_pass(
        "05",
        &format!(
            "list report formats ({})",
            report_formats_response.items.len()
        ),
    );

    let port_lists_response = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    assert_typed_status(
        port_lists_response.status,
        &port_lists_response.status_text,
        200,
        "get_port_lists",
    )?;
    let port_list_count = port_lists_response.items.len();
    ensure(port_list_count >= 1, "expected at least one port list")?;
    log_pass("06", &format!("list port lists ({port_list_count})"));

    // Pick the first port list for target creation (GMP requires PORT_LIST or PORT_RANGE)
    let port_list_id = port_lists_response
        .items
        .first()
        .map(|port_list| port_list.meta.id.clone())
        .ok_or_else(|| AppError::Assertion("expected at least one port list".to_string()))?;

    let target_response = client
        .create_target(create_localhost_target(&smoke_target_name, port_list_id)?)
        .await?;
    assert_typed_status(
        target_response.status,
        &target_response.status_text,
        201,
        "create_target",
    )?;
    let target_id = target_response.id;
    tracker.track_target(&target_id);
    log_pass("07", &format!("create target ({target_id})"));

    let get_target_response = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await?;
    assert_typed_status(
        get_target_response.status,
        &get_target_response.status_text,
        200,
        "get_target",
    )?;
    ensure(
        get_target_response
            .items
            .iter()
            .any(|target| target.meta.name == smoke_target_name),
        "expected created target name in get_target response",
    )?;
    log_pass("08", "get target by UUID");

    let mut modify_request = ModifyTargetRequest::new(target_id.clone());
    modify_request.name = Some(config.name("smoke-target-modified"));
    modify_request.comment = Some(config.name("smoke-target-comment"));
    let modify_target = client.modify_target(modify_request).await?;
    assert_typed_status(
        modify_target.status,
        &modify_target.status_text,
        200,
        "modify_target",
    )?;
    let trashed = client
        .delete_target(DeleteTargetRequest::new(target_id.clone(), false))
        .await?;
    assert_typed_status(trashed.status, &trashed.status_text, 200, "trash target")?;
    let restored = client
        .restore(RestoreRequest::new(target_id.clone()))
        .await?;
    assert_typed_status(
        restored.status,
        &restored.status_text,
        200,
        "restore target",
    )?;
    let deleted = client
        .delete_target(DeleteTargetRequest::new(target_id.clone(), true))
        .await?;
    assert_typed_status(
        deleted.status,
        &deleted.status_text,
        200,
        "ultimate delete target",
    )?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());
    log_pass("09", "modify/trash/restore/ultimate-delete target");

    let verify_delete_response = client
        .get_target(GetTargetRequest::new(target_id.clone()))
        .await;
    ensure(
        matches!(
            verify_delete_response,
            Err(GvmError::Server { status: 404, .. })
        ),
        "verify target deletion did not return typed 404",
    )?;
    log_pass("10", "verify deletion");

    if config.run_scan {
        run_scan_suite(&mut client, config, tracker, None).await?;
    }

    record_helper_executions(
        &[
            "authenticate",
            "create_target",
            "delete_target",
            "get_port_lists",
            "get_report_formats",
            "get_scan_configs",
            "get_scanners",
            "get_target",
            "get_version",
            "modify_target",
            "restore",
        ],
        "smoke runtime path executed",
    )?;

    client.disconnect().await?;
    Ok(())
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

fn select_scan_report_id(
    started_report_id: &EntityId,
    current_report_id: Option<&EntityId>,
    last_report_id: Option<&EntityId>,
) -> Option<EntityId> {
    if started_report_id.as_str() != "0" {
        return Some(started_report_id.clone());
    }

    current_report_id
        .filter(|id| id.as_str() != "0")
        .or_else(|| last_report_id.filter(|id| id.as_str() != "0"))
        .cloned()
}

fn task_links_report(task: &Task, report_id: &EntityId) -> bool {
    task.current_report
        .as_ref()
        .is_some_and(|report| report.id == *report_id)
        || task
            .last_report
            .as_ref()
            .is_some_and(|report| report.id == *report_id)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct EpssRegressionFixture {
    schema_version: u32,
    upstream_pull_request: String,
    fixed_source_revision: String,
    known_affected_release: String,
    probes: Vec<EpssFieldProbe>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct EpssFieldProbe {
    field: String,
    filter_expression: String,
    sort_expression: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpssExpectedDisposition {
    KnownAffectedBaseline,
    FixedSourceMustPass,
    UnclassifiedMustPass,
}

impl EpssExpectedDisposition {
    const fn label(self) -> &'static str {
        match self {
            Self::KnownAffectedBaseline => "known-affected-baseline",
            Self::FixedSourceMustPass => "fixed-source-must-pass",
            Self::UnclassifiedMustPass => "unclassified-must-pass",
        }
    }

    const fn accepts_connection_abort(self) -> bool {
        matches!(self, Self::KnownAffectedBaseline)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EpssDeploymentEvidence {
    gvmd_version: String,
    gvmd_source_revision: Option<String>,
    gvmd_image_digest: String,
    source_specific_image: bool,
}

impl EpssDeploymentEvidence {
    fn from_env() -> Result<Self, AppError> {
        let gvmd_version = env::var("E2E_GVMD_VERSION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::Assertion(
                    "E2E_GVMD_VERSION is required for EPSS regression provenance".to_string(),
                )
            })?;
        ensure(
            parse_release_triplet(&gvmd_version).is_some(),
            "E2E_GVMD_VERSION must be an exact numeric release triplet",
        )?;
        let gvmd_source_revision = env::var("E2E_GVMD_SOURCE_REVISION")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if let Some(revision) = &gvmd_source_revision {
            ensure(
                revision.len() == 40
                    && revision
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "E2E_GVMD_SOURCE_REVISION must be an exact lowercase commit SHA",
            )?;
        }
        let gvmd_image_digest = env::var("E2E_GVMD_IMAGE_DIGEST")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::Assertion(
                    "E2E_GVMD_IMAGE_DIGEST is required for EPSS regression provenance".to_string(),
                )
            })?;
        let source_specific_image = match env::var("E2E_GVMD_SOURCE_SPECIFIC_IMAGE").ok().as_deref()
        {
            Some("0") => false,
            Some("1") => true,
            _ => {
                return Err(AppError::Assertion(
                    "E2E_GVMD_SOURCE_SPECIFIC_IMAGE must be 0 or 1 for EPSS regression provenance"
                        .to_string(),
                ));
            }
        };
        Ok(Self {
            gvmd_version,
            gvmd_source_revision,
            gvmd_image_digest,
            source_specific_image,
        })
    }

    fn detail(&self, fixture: &EpssRegressionFixture) -> String {
        format!(
            "gvmd release {}; source revision {}; image digest {}; source-specific image {}; upstream {}; fixed source {}",
            self.gvmd_version,
            self.gvmd_source_revision
                .as_deref()
                .unwrap_or("unavailable"),
            self.gvmd_image_digest,
            self.source_specific_image,
            fixture.upstream_pull_request,
            fixture.fixed_source_revision
        )
    }
}

fn parse_release_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let triplet = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(triplet)
}

fn epss_regression_fixture() -> Result<EpssRegressionFixture, AppError> {
    let fixture: EpssRegressionFixture = serde_json::from_str(include_str!(
        "../../../fixtures/epss-result-regression.json"
    ))?;
    ensure(
        fixture.schema_version == 1,
        "unsupported EPSS regression fixture schema",
    )?;
    ensure(
        fixture.probes.len() == 4,
        "EPSS regression fixture must define exactly four fields",
    )?;
    Ok(fixture)
}

fn epss_expected_disposition(
    fixture: &EpssRegressionFixture,
    evidence: &EpssDeploymentEvidence,
) -> EpssExpectedDisposition {
    if evidence.gvmd_source_revision.as_deref() == Some(fixture.fixed_source_revision.as_str()) {
        EpssExpectedDisposition::FixedSourceMustPass
    } else if evidence.gvmd_version == fixture.known_affected_release
        && !evidence.source_specific_image
    {
        EpssExpectedDisposition::KnownAffectedBaseline
    } else {
        EpssExpectedDisposition::UnclassifiedMustPass
    }
}

fn epss_regression_capability_probe() -> Result<ProbeResult, AppError> {
    let fixture = epss_regression_fixture()?;
    let evidence = EpssDeploymentEvidence::from_env()?;
    let disposition = epss_expected_disposition(&fixture, &evidence);
    let state = match disposition {
        EpssExpectedDisposition::KnownAffectedBaseline => ProbeState::Unavailable,
        EpssExpectedDisposition::FixedSourceMustPass => ProbeState::Ready,
        EpssExpectedDisposition::UnclassifiedMustPass => ProbeState::Unknown,
    };
    Ok(ProbeResult {
        state,
        evidence: Evidence {
            source: "gvmd-release-source-image".to_string(),
            value: disposition.label().to_string(),
            detail: format!(
                "four fields [{}], each filtered and sorted through get_results; {}; expected outcome: {}",
                fixture
                    .probes
                    .iter()
                    .map(|probe| probe.field.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                evidence.detail(&fixture),
                if disposition.accepts_connection_abort() {
                    "an exact server-abort is recorded as known-upstream-bug, never pass"
                } else {
                    "every request must return GMP 200 and preserve the same authenticated connection"
                }
            ),
        },
    })
}

fn epss_results_request(report_id: &EntityId, expression: &str) -> GetResultsRequest {
    GetResultsRequest {
        filter_string: Some(format!("report_id={report_id} {expression} rows=-1")),
        details: Some(false),
        get_counts: Some(true),
        ..Default::default()
    }
}

fn epss_error_is_connection_abort(error: &GvmError) -> bool {
    matches!(
        error,
        GvmError::Connection(ConnectionError::ReadFailed(error))
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
            )
    )
}

fn epss_health_confirms_lost_connection(error: &GvmError) -> bool {
    matches!(error, GvmError::Connection(ConnectionError::NotConnected))
}

async fn run_epss_result_regression(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    report_id: &EntityId,
) -> Result<(), AppError> {
    let fixture = epss_regression_fixture()?;
    let evidence = EpssDeploymentEvidence::from_env()?;
    let disposition = epss_expected_disposition(&fixture, &evidence);
    let deployment_detail = evidence.detail(&fixture);

    for probe in &fixture.probes {
        for (operation, expression) in [
            ("filter", probe.filter_expression.as_str()),
            ("sort", probe.sort_expression.as_str()),
        ] {
            let observation = format!("epss:get_results:{}:{operation}", probe.field);
            let request_result = client
                .get_results(epss_results_request(report_id, expression))
                .await;
            let health_result = client.get_version(GetVersionRequest::new()).await;
            let request_connection_abort = request_result
                .as_ref()
                .is_err_and(epss_error_is_connection_abort);
            let health_confirms_lost_connection = health_result
                .as_ref()
                .is_err_and(epss_health_confirms_lost_connection);
            let connection_abort_proved =
                request_connection_abort && health_confirms_lost_connection;

            match (&request_result, &health_result) {
                (Ok(response), Ok(version)) => {
                    assert_typed_status(response.status, &response.status_text, 200, &observation)?;
                    ensure(
                        version.version == client.version().to_string(),
                        &format!(
                            "{observation} connection-health probe changed GMP version from {} to {}",
                            client.version(), version.version
                        ),
                    )?;
                    runtime::observe(
                        &observation,
                        Outcome::Pass,
                        &format!(
                            "normal GMP 200 with {} result(s); same authenticated connection returned get_version {}; expression `{expression}`; policy {}; {deployment_detail}",
                            response.items.len(),
                            version.version,
                            disposition.label()
                        ),
                    );
                    log_line(&format!(
                        "[pass] {observation} normal response and same-connection health probe"
                    ));
                    continue;
                }
                _ if disposition.accepts_connection_abort() && connection_abort_proved => {
                    let request_evidence = request_result
                        .as_ref()
                        .map(|response| format!("GMP status {}", response.status))
                        .unwrap_or_else(|error| error.to_string());
                    let health_evidence = health_result
                        .as_ref()
                        .map(|version| format!("unexpectedly returned GMP {}", version.version))
                        .unwrap_or_else(|error| error.to_string());
                    runtime::observe(
                        &observation,
                        Outcome::KnownUpstreamBug,
                        &format!(
                            "greenbone/gvmd#3163 pre-fix server-abort reproduced; request outcome: {request_evidence}; same-connection get_version outcome: {health_evidence}; expression `{expression}`; policy {}; {deployment_detail}",
                            disposition.label()
                        ),
                    );
                    log_line(&format!(
                        "[known-upstream-bug] {observation} connection aborted; reconnecting for the next independent probe"
                    ));
                    *client = reconnect_authenticated(
                        config,
                        Duration::from_secs(config.task_progress_timeout_secs),
                    )
                    .await?;
                    client.discover_commands().await?;
                }
                _ => {
                    let request_evidence = request_result
                        .as_ref()
                        .map(|response| format!("GMP status {}", response.status))
                        .unwrap_or_else(|error| error.to_string());
                    let health_evidence = health_result
                        .as_ref()
                        .map(|version| format!("GMP {}", version.version))
                        .unwrap_or_else(|error| error.to_string());
                    return Err(AppError::Assertion(format!(
                        "{observation} violated EPSS regression policy {}: request outcome: {request_evidence}; same-connection get_version outcome: {health_evidence}; expression `{expression}`; {deployment_detail}",
                        disposition.label()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn scan_report_results_request(report_id: &EntityId) -> GetResultsRequest {
    GetResultsRequest {
        filter_string: Some(format!("report_id={report_id} rows=-1")),
        details: Some(false),
        get_counts: Some(true),
        ..Default::default()
    }
}

fn select_deterministic_scan_result(results: &GetResultsResponse) -> Option<&ScanResult> {
    results
        .items
        .iter()
        .min_by(|left, right| left.meta.id.as_str().cmp(right.meta.id.as_str()))
}

fn select_deterministic_report_config_id(
    report_configs: &GetReportConfigsResponse,
) -> Option<EntityId> {
    report_configs
        .items
        .iter()
        .map(|item| item.meta.id.clone())
        .min_by(|left, right| left.as_str().cmp(right.as_str()))
}

fn select_usable_report_format(
    response: &GetReportFormatsResponse,
) -> Result<&ReportFormat, AppError> {
    response
        .items
        .iter()
        .filter(|format| {
            format.active
                && format
                    .content_type
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                && format
                    .extension
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
        })
        .min_by(|left, right| left.meta.id.as_str().cmp(right.meta.id.as_str()))
        .ok_or_else(|| {
            AppError::Assertion(
                "typed report-format selection requires an active format with content type and extension"
                    .to_string(),
            )
        })
}

fn report_export_status_is_active(status: &str) -> bool {
    matches!(status, "pending" | "running" | "cancel_requested")
}

fn report_export_status_is_terminal(status: &str) -> bool {
    matches!(status, "done" | "error" | "canceled" | "expired")
}

fn validate_report_export_state(
    export: &ReportExportInfo,
    export_id: &EntityId,
    report_id: Option<&EntityId>,
    report_format_id: Option<&EntityId>,
) -> Result<(), AppError> {
    ensure(
        export.meta.id == *export_id,
        &format!(
            "get_report_exports returned {} for requested export {export_id}",
            export.meta.id
        ),
    )?;
    ensure(
        report_export_status_is_active(&export.status)
            || report_export_status_is_terminal(&export.status),
        &format!(
            "report export {export_id} returned unknown state {:?}",
            export.status
        ),
    )?;
    if let Some(report_id) = report_id {
        ensure(
            export.report_id.as_ref() == Some(report_id),
            &format!("report export {export_id} did not preserve report identity {report_id}"),
        )?;
        ensure(
            export.export_type == "scan",
            &format!(
                "scan report export {export_id} returned type {:?}",
                export.export_type
            ),
        )?;
    }
    if let Some(report_format_id) = report_format_id {
        ensure(
            export.report_format_id.as_ref() == Some(report_format_id),
            &format!("report export {export_id} did not preserve report format {report_format_id}"),
        )?;
    }
    Ok(())
}

async fn get_report_export_once(
    client: &mut GmpClient<UnixSocketConnection>,
    export_id: &EntityId,
) -> Result<Option<ReportExportInfo>, AppError> {
    match client
        .get_report_exports(GetReportExportsRequest::new(export_id.clone()))
        .await
    {
        Ok(response) => {
            assert_typed_status(
                response.status,
                &response.status_text,
                200,
                "get_report_exports by id",
            )?;
            ensure(
                response.items.len() <= 1,
                &format!(
                    "get_report_exports returned {} rows for exact ID {export_id}",
                    response.items.len()
                ),
            )?;
            Ok(response.items.into_iter().next())
        }
        Err(GvmError::Server { status: 404, .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn poll_report_export_terminal(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    export_id: &EntityId,
    report_id: Option<&EntityId>,
    report_format_id: Option<&EntityId>,
    phase: &str,
) -> Result<ReportExportInfo, AppError> {
    let timeout = Duration::from_secs(config.report_export_timeout_secs);
    let started = Instant::now();
    let mut observed = Vec::new();
    loop {
        let export = get_report_export_once(client, export_id)
            .await?
            .ok_or_else(|| {
                AppError::Assertion(format!(
                    "report export {export_id} disappeared during {phase} before download"
                ))
            })?;
        validate_report_export_state(&export, export_id, report_id, report_format_id)?;
        let state = format!("{}:{}", export.status, export.progress);
        if observed.last() != Some(&state) {
            log_line(&format!(
                "report export {export_id} {phase} state={:?} progress={:?}",
                export.status, export.progress
            ));
            observed.push(state);
        }
        if report_export_status_is_terminal(&export.status) {
            log_pass(
                &format!("report export {phase}"),
                &format!("{export_id} observed states [{}]", observed.join(" -> ")),
            );
            return Ok(export);
        }
        ensure(
            started.elapsed() < timeout,
            &format!(
                "report export {export_id} did not reach a terminal state within {} seconds; observed [{}]",
                timeout.as_secs(),
                observed.join(" -> ")
            ),
        )?;
        sleep(Duration::from_secs(config.report_export_poll_interval_secs)).await;
    }
}

async fn prove_report_export_consumed(
    client: &mut GmpClient<UnixSocketConnection>,
    export_id: &EntityId,
) -> Result<(), AppError> {
    match client
        .get_report_exports(GetReportExportsRequest::new(export_id.clone()))
        .await
    {
        Err(GvmError::Server { status: 404, .. }) => {}
        Ok(response) => {
            return Err(AppError::Assertion(format!(
                "downloaded report export {export_id} remained queryable with status {} and {} row(s)",
                response.status,
                response.items.len()
            )));
        }
        Err(error) => return Err(error.into()),
    }
    log_pass(
        "report export consumption",
        &format!("get_report_exports returned exact 404 absence for {export_id}"),
    );
    Ok(())
}

async fn download_completed_report_export(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    export_id: &EntityId,
    report_id: &EntityId,
    report_format_id: &EntityId,
    expected_content_type: Option<&str>,
    expected_extension: Option<&str>,
) -> Result<usize, AppError> {
    tracker.mark_report_export_download_attempted(export_id)?;
    let response = client
        .download_report_export(DownloadReportExportRequest::new(export_id.clone()))
        .await?;
    assert_typed_status(
        response.status,
        &response.status_text,
        200,
        "download_report_export",
    )?;
    let export = response.report_export;
    ensure(
        export.id == *export_id,
        "download changed report-export identity",
    )?;
    ensure(
        export.export_type == "scan" && export.status == "done" && export.progress == "completed",
        &format!(
            "downloaded export {export_id} metadata was type={:?} status={:?} progress={:?}",
            export.export_type, export.status, export.progress
        ),
    )?;
    ensure(
        export.report_id.as_ref() == Some(report_id)
            && export.report_format_id.as_ref() == Some(report_format_id)
            && export.delta_report_id.is_none()
            && export.report_config_id.is_none(),
        &format!("downloaded export {export_id} relationship metadata did not match request"),
    )?;
    ensure(
        !export.bytes.is_empty()
            && export.file_size > 0
            && export.file_size == export.bytes.len() as u64,
        &format!(
            "downloaded export {export_id} contained {} bytes with declared file_size {}",
            export.bytes.len(),
            export.file_size
        ),
    )?;
    if let Some(expected) = expected_content_type {
        ensure(
            export.content_type.as_deref() == Some(expected),
            &format!(
                "downloaded export {export_id} content type {:?} did not match selected format {expected:?}",
                export.content_type
            ),
        )?;
    }
    if let Some(expected) = expected_extension {
        ensure(
            export.extension.as_deref() == Some(expected),
            &format!(
                "downloaded export {export_id} extension {:?} did not match selected format {expected:?}",
                export.extension
            ),
        )?;
    }
    let byte_count = export.bytes.len();
    prove_report_export_consumed(client, export_id).await?;
    tracker.forget_report_export(export_id);
    Ok(byte_count)
}

async fn reconcile_tracked_report_exports(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    let report_ids = tracker.report_ids.iter().cloned().collect::<BTreeSet<_>>();
    let listed = client
        .get_report_exports(GetReportExportsRequest::default())
        .await?;
    assert_typed_status(
        listed.status,
        &listed.status_text,
        200,
        "cleanup get_report_exports",
    )?;
    for export in listed.items {
        if export
            .report_id
            .as_ref()
            .is_some_and(|id| report_ids.contains(id.as_str()))
        {
            tracker.track_report_export(&export.meta.id);
        }
    }

    let tracked = tracker.report_exports.clone();
    for tracked_export in tracked {
        let export_id = parse_entity_id(&tracked_export.id)?;
        let Some(mut export) = get_report_export_once(client, &export_id).await? else {
            tracker.forget_report_export(&export_id);
            continue;
        };
        validate_report_export_state(&export, &export_id, None, None)?;
        if matches!(export.status.as_str(), "pending" | "running") {
            if tracked_export.cancel_attempted {
                log_line(&format!(
                    "report export {export_id} remains active after an ambiguous prior cancellation; polling without replay"
                ));
            } else {
                tracker.mark_report_export_cancel_attempted(&export_id)?;
                match client
                    .cancel_report_export(CancelReportExportRequest::new(export_id.clone()))
                    .await
                {
                    Ok(response) => assert_typed_status(
                        response.status,
                        &response.status_text,
                        200,
                        "cleanup cancel_report_export",
                    )?,
                    Err(error) => log_line(&format!(
                        "ambiguous cleanup cancellation for report export {export_id}: {error}; reconciling by read without replay"
                    )),
                }
            }
            export = poll_report_export_terminal(
                client,
                &tracker.config,
                &export_id,
                None,
                None,
                "cleanup cancellation",
            )
            .await?;
        } else if export.status == "cancel_requested" {
            export = poll_report_export_terminal(
                client,
                &tracker.config,
                &export_id,
                None,
                None,
                "cleanup cancellation",
            )
            .await?;
        }

        if export.status == "done" {
            if tracked_export.download_attempted {
                log_line(&format!(
                    "report export {export_id} is done after an ambiguous prior download; not replaying the consuming mutation"
                ));
            } else {
                tracker.mark_report_export_download_attempted(&export_id)?;
                match client
                    .download_report_export(DownloadReportExportRequest::new(export_id.clone()))
                    .await
                {
                    Ok(response) => {
                        assert_typed_status(
                            response.status,
                            &response.status_text,
                            200,
                            "cleanup download_report_export",
                        )?;
                        ensure(
                            !response.report_export.bytes.is_empty(),
                            &format!("cleanup download for report export {export_id} was empty"),
                        )?;
                        prove_report_export_consumed(client, &export_id).await?;
                    }
                    Err(error) => {
                        let reconciled = get_report_export_once(client, &export_id).await?;
                        log_line(&format!(
                            "ambiguous cleanup download for report export {export_id}: {error}; post-read state={}",
                            reconciled
                                .as_ref()
                                .map_or("absent".to_string(), |value| value.status.clone())
                        ));
                    }
                }
            }
        }
        ensure(
            report_export_status_is_terminal(&export.status),
            &format!(
                "cleanup left report export {export_id} active in {}",
                export.status
            ),
        )?;
        tracker.forget_report_export(&export_id);
    }

    let final_exports = client
        .get_report_exports(GetReportExportsRequest::default())
        .await?;
    assert_typed_status(
        final_exports.status,
        &final_exports.status_text,
        200,
        "final cleanup get_report_exports",
    )?;
    let active = final_exports
        .items
        .iter()
        .filter(|export| {
            export
                .report_id
                .as_ref()
                .is_some_and(|id| report_ids.contains(id.as_str()))
                && report_export_status_is_active(&export.status)
        })
        .map(|export| format!("{}:{}", export.meta.id, export.status))
        .collect::<Vec<_>>();
    ensure(
        active.is_empty(),
        &format!(
            "E2E-owned reports retained active report exports after cleanup: {}",
            active.join(", ")
        ),
    )?;
    tracker.report_export_reconciliation_required = false;
    log_pass(
        "report export cleanup",
        "all tracked and report-linked exports reconciled; no active E2E-owned export remains",
    );
    Ok(())
}

fn report_export_fixture_disposition(
    advertised_commands: &BTreeSet<String>,
    descriptor: &FixtureDescriptor,
    command: &str,
    fixture: &str,
) -> Result<(), AppError> {
    if !advertised_commands.contains(command) {
        runtime::observe(
            &format!("report export variant {command}"),
            Outcome::ConditionalUnavailable,
            &format!("authenticated help did not advertise {command}; no mutation was sent"),
        );
        return Ok(());
    }
    let evidence = descriptor.fixtures.get(fixture).ok_or_else(|| {
        AppError::Assertion(format!(
            "fixture descriptor omitted report-export fixture {fixture} for {command}"
        ))
    })?;
    ensure(
        evidence.state == ProbeState::Unavailable,
        &format!(
            "{command} is advertised and fixture {fixture} is {:?}; this lane requires an implemented lifecycle when the fixture is not explicitly unavailable",
            evidence.state
        ),
    )?;
    runtime::observe(
        &format!("report export variant {command}"),
        Outcome::ConditionalUnavailable,
        &format!(
            "authenticated help advertised {command}; provider fixture {fixture}=unavailable: {}; no mutation was sent",
            evidence.detail
        ),
    );
    Ok(())
}

#[derive(Debug)]
struct ScanReportExportFixture {
    advertised_commands: BTreeSet<String>,
    report_id: EntityId,
    report_format_id: EntityId,
    content_type: Option<String>,
    extension: Option<String>,
}

async fn run_async_report_export_lifecycle(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
    fixture: &ScanReportExportFixture,
) -> Result<(), AppError> {
    let advertised_commands = &fixture.advertised_commands;
    let report_id = &fixture.report_id;
    let report_format_id = &fixture.report_format_id;
    let expected_content_type = fixture.content_type.as_deref();
    let expected_extension = fixture.extension.as_deref();
    let required = [
        "export_scan_report",
        "get_report_exports",
        "download_report_export",
    ];
    let advertised = required
        .iter()
        .filter(|command| advertised_commands.contains(**command))
        .copied()
        .collect::<Vec<_>>();
    if advertised.is_empty() {
        runtime::observe(
            "scan report asynchronous export lifecycle",
            Outcome::ConditionalUnavailable,
            "authenticated help advertised none of export_scan_report, get_report_exports, or download_report_export; no mutation was sent",
        );
        return Ok(());
    }
    ensure(
        advertised.len() == required.len(),
        &format!(
            "cleanup-safe asynchronous export requires all commands {:?}; help advertised only {:?}; no mutation was sent",
            required, advertised
        ),
    )?;
    for command in required {
        ensure(
            matches!(
                client.command_support(command),
                gvm_client::CommandSupport::Supported
            ),
            &format!("typed client did not classify advertised {command} as supported"),
        )?;
    }

    tracker.arm_report_export_reconciliation();
    let mut request = ExportScanReportRequest::new(report_id.clone());
    request.report_format_id = Some(report_format_id.clone());
    let created = client.export_scan_report(request).await?;
    tracker.track_report_export(&created.id);
    ensure(
        matches!(created.status, 200 | 201),
        &format!(
            "export_scan_report returned unexpected status {} ({})",
            created.status, created.status_text
        ),
    )?;
    let export_id = created.id;
    let terminal = poll_report_export_terminal(
        client,
        config,
        &export_id,
        Some(report_id),
        Some(report_format_id),
        "completion",
    )
    .await?;
    ensure(
        terminal.status == "done" && terminal.progress == "completed",
        &format!(
            "primary report export {export_id} terminated as {}:{} (error={:?})",
            terminal.status, terminal.progress, terminal.error_message
        ),
    )?;
    let bytes = download_completed_report_export(
        client,
        tracker,
        &export_id,
        report_id,
        report_format_id,
        expected_content_type,
        expected_extension,
    )
    .await?;
    log_pass(
        "scan report asynchronous export lifecycle",
        &format!(
            "created {export_id}, observed exact terminal done/completed, downloaded {bytes} bytes, and proved server-side consumption"
        ),
    );
    record_helper_executions(
        &[
            "export_scan_report",
            "get_report_exports",
            "download_report_export",
        ],
        "help-gated asynchronous scan export completed, downloaded, and reconciled",
    )?;

    if !advertised_commands.contains("cancel_report_export") {
        runtime::observe(
            "scan report export cancellation",
            Outcome::ConditionalUnavailable,
            "authenticated help did not advertise cancel_report_export; no second export was created",
        );
        reconcile_tracked_report_exports(client, tracker).await?;
        return Ok(());
    }
    ensure(
        matches!(
            client.command_support("cancel_report_export"),
            gvm_client::CommandSupport::Supported
        ),
        "typed client did not classify advertised cancel_report_export as supported",
    )?;

    let mut cancel_request = ExportScanReportRequest::new(report_id.clone());
    cancel_request.report_format_id = Some(report_format_id.clone());
    cancel_request.lean = Some(true);
    let cancel_candidate = client.export_scan_report(cancel_request).await?;
    tracker.track_report_export(&cancel_candidate.id);
    ensure(
        matches!(cancel_candidate.status, 200 | 201),
        "cancellation candidate export did not return 200 or 201",
    )?;
    let cancel_id = cancel_candidate.id;
    let initial = get_report_export_once(client, &cancel_id)
        .await?
        .ok_or_else(|| {
            AppError::Assertion(format!(
                "cancellation candidate report export {cancel_id} disappeared before observation"
            ))
        })?;
    validate_report_export_state(
        &initial,
        &cancel_id,
        Some(report_id),
        Some(report_format_id),
    )?;
    match initial.status.as_str() {
        "pending" | "running" => {
            tracker.mark_report_export_cancel_attempted(&cancel_id)?;
            let canceled = client
                .cancel_report_export(CancelReportExportRequest::new(cancel_id.clone()))
                .await?;
            assert_typed_status(
                canceled.status,
                &canceled.status_text,
                200,
                "cancel_report_export",
            )?;
            let terminal = poll_report_export_terminal(
                client,
                config,
                &cancel_id,
                Some(report_id),
                Some(report_format_id),
                "cancellation",
            )
            .await?;
            ensure(
                terminal.status == "canceled",
                &format!(
                    "cancel_report_export for {cancel_id} settled as {}:{} instead of canceled",
                    terminal.status, terminal.progress
                ),
            )?;
            tracker.forget_report_export(&cancel_id);
            runtime::observe(
                "scan report export cancellation",
                Outcome::Pass,
                &format!(
                    "separate export {cancel_id} was observed {}, cancel_report_export returned 200, and get_report_exports reconciled canceled",
                    initial.status
                ),
            );
        }
        "done" => {
            let bytes = download_completed_report_export(
                client,
                tracker,
                &cancel_id,
                report_id,
                report_format_id,
                expected_content_type,
                expected_extension,
            )
            .await?;
            runtime::observe(
                "scan report export cancellation",
                Outcome::ConditionalUnavailable,
                &format!(
                    "separate export {cancel_id} was already done/completed at the first get_report_exports observation; downloaded {bytes} bytes and proved consumption; no deterministic pending/running cancellation window existed"
                ),
            );
        }
        status if report_export_status_is_terminal(status) => {
            tracker.forget_report_export(&cancel_id);
            runtime::observe(
                "scan report export cancellation",
                Outcome::ConditionalUnavailable,
                &format!(
                    "separate export {cancel_id} was already terminal at first observation: status={:?}, progress={:?}, error={:?}; no cancellation mutation was sent",
                    initial.status, initial.progress, initial.error_message
                ),
            );
        }
        "cancel_requested" => {
            let terminal = poll_report_export_terminal(
                client,
                config,
                &cancel_id,
                Some(report_id),
                Some(report_format_id),
                "pre-existing cancellation",
            )
            .await?;
            tracker.forget_report_export(&cancel_id);
            runtime::observe(
                "scan report export cancellation",
                Outcome::ConditionalUnavailable,
                &format!(
                    "separate export {cancel_id} was already cancel_requested before this lane sent cancellation and reconciled as {}; no mutation was replayed",
                    terminal.status
                ),
            );
        }
        _ => unreachable!("state validation rejects unknown report-export status"),
    }

    reconcile_tracked_report_exports(client, tracker).await?;
    Ok(())
}

fn assert_gmp_22_8_rejection<T>(
    result: Result<T, GvmError>,
    command: &str,
    negotiated_version: GmpVersion,
) -> Result<(), AppError> {
    ensure(
        matches!(
            result,
            Err(GvmError::UnsupportedCommand {
                command: rejected_command,
                version,
                required: "22.8",
            }) if rejected_command == command && version == negotiated_version
        ),
        &format!(
            "{command} on GMP {negotiated_version} did not return the exact typed GMP 22.8 capability rejection"
        ),
    )
}

fn gmp_22_8_rejection_evidence(
    surface: &str,
    advertised_wire_command: &str,
    negotiated_version: GmpVersion,
) -> String {
    format!(
        "live help advertised {advertised_wire_command}; canonical typed {surface} was rejected locally because GMP {negotiated_version} is below required 22.8; no wire request was sent"
    )
}

async fn resolve_scan_report_id(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    task_id: &EntityId,
    started_report_id: &EntityId,
) -> Result<EntityId, AppError> {
    if let Some(report_id) = select_scan_report_id(started_report_id, None, None) {
        return Ok(report_id);
    }

    let timeout = Duration::from_secs(config.task_progress_timeout_secs);
    let started = tokio::time::Instant::now();

    while started.elapsed() <= timeout {
        let response = get_tasks_with_reconnect(
            client,
            config,
            GetTasksRequest {
                filter_string: Some(format!("uuid={task_id}")),
                details: Some(true),
                ..Default::default()
            },
            timeout.saturating_sub(started.elapsed()),
            "resolve scan report",
        )
        .await?;
        let task = response
            .items
            .iter()
            .find(|task| task.meta.id == *task_id)
            .ok_or_else(|| {
                AppError::Assertion(format!(
                    "typed get_tasks did not return scan task {task_id} while resolving its report"
                ))
            })?;

        if let Some(report_id) = select_scan_report_id(
            started_report_id,
            task.current_report.as_ref().map(|report| &report.id),
            task.last_report.as_ref().map(|report| &report.id),
        ) {
            return Ok(report_id);
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "task {task_id} retained provisional report id {started_report_id} without exposing a current or last report within {} seconds",
        timeout.as_secs()
    )))
}

async fn start_scan_task_once(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
    mutations: &mut ScanMutationGuard,
    task_id: &EntityId,
) -> Result<EntityId, AppError> {
    mutations.claim_task_start(task_id)?;
    let started = client
        .start_task(StartTaskRequest::new(task_id.clone()))
        .await?;
    ensure(started.status == 202, "typed start_task did not return 202")?;
    let report_id = started.report_id.ok_or_else(|| {
        AppError::Assertion("typed start_task response omitted report_id".to_string())
    })?;
    tracker.track_report(&report_id);
    record_helper_execution("start_task", "scan start mutation executed exactly once")?;
    Ok(report_id)
}

async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
    plan: Option<&TestPlan>,
) -> Result<(), AppError> {
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    let help = client.discover_commands().await?;
    let advertised_commands = help
        .schema
        .ok_or_else(|| {
            AppError::Assertion(
                "scan-lane XML help discovery did not contain a command schema".to_string(),
            )
        })?
        .commands
        .into_iter()
        .map(|command| canonical_help_command(&command.name))
        .collect::<BTreeSet<_>>();
    log_line("Running deterministic host/network scan flow");
    let scan_target_name = config.name("scan-target");
    let scan_task_name = config.name("scan-task");
    let scan_host = env::var("E2E_SCAN_TARGET_HOST").unwrap_or_else(|_| "scan-fixture".to_string());

    let mut create_port_list = CreatePortListRequest::new(config.name("scan-port-list"));
    create_port_list.port_range = Some("T:80".to_string());
    create_port_list.comment = Some(config.name("scan-port-list-comment"));
    let port_list = client.create_port_list(create_port_list).await?;
    ensure(
        port_list.status == 201,
        "typed scan port-list create failed",
    )?;
    tracker.track_port_list(&port_list.id);
    let scan_host = TargetHost::from_str(&scan_host)?;
    let hosts = TargetHosts::new([scan_host], [])?;
    let scan_target = client
        .create_target(CreateTargetRequest::new(
            scan_target_name,
            hosts,
            TargetPortSelection::PortList(port_list.id.clone()),
        ))
        .await?;
    ensure(scan_target.status == 201, "typed scan target create failed")?;
    tracker.track_target(&scan_target.id);

    let configs = client
        .get_scan_configs(GetScanConfigsRequest::default())
        .await?;
    let preferred_config = env::var("E2E_SCAN_CONFIG_NAME").ok();
    let scan_config = preferred_config
        .as_deref()
        .and_then(|name| configs.items.iter().find(|item| item.meta.name == name))
        .or_else(|| {
            configs
                .items
                .iter()
                .find(|item| item.meta.name.to_ascii_lowercase().contains("discovery"))
        })
        .or_else(|| configs.items.first())
        .ok_or_else(|| AppError::Assertion("scan lane requires a warm scan config".to_string()))?;
    let scanners = client.get_scanners(GetScannersRequest::default()).await?;
    let scanner = select_scan_scanner(&scanners)?;

    let task = client
        .create_task(CreateTaskRequest::new(
            scan_task_name,
            scan_config.meta.id.clone(),
            scan_target.id.clone(),
            scanner.meta.id.clone(),
        ))
        .await?;
    ensure(task.status == 201, "typed scan task create failed")?;
    tracker.track_task(&task.id);
    let listed = client
        .get_tasks(GetTasksRequest {
            filter_string: Some(format!("uuid={}", task.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        listed.items.iter().any(|item| item.meta.id == task.id),
        "typed task list/filter did not return the scan task",
    )?;

    let no_match_results = client
        .get_results(GetResultsRequest {
            filter_string: Some("uuid=00000000-0000-0000-0000-000000000000 rows=1".to_string()),
            details: Some(false),
            ..Default::default()
        })
        .await?;
    ensure(
        no_match_results.status == 200,
        "typed get_results did not return 200",
    )?;
    ensure(
        no_match_results.items.is_empty(),
        "typed no-match get_results unexpectedly returned a result",
    )?;

    let mut mutations = ScanMutationGuard::default();
    let started_report_id = start_scan_task_once(client, tracker, &mut mutations, &task.id).await?;
    match start_scan_task_once(client, tracker, &mut mutations, &task.id).await {
        Err(AppError::DuplicateMutation {
            operation: "start_task",
            resource_id,
        }) if resource_id == task.id.as_str() => {
            log_pass(
                "local duplicate start_task",
                "exactly-once guard suppressed a second wire mutation",
            );
        }
        Ok(second_report_id) => {
            return Err(AppError::Assertion(format!(
                "local exactly-once guard allowed a second start_task for task {} and report {second_report_id}",
                task.id
            )));
        }
        Err(error) => return Err(error),
    }

    wait_task_state(
        client,
        config,
        &task.id,
        Duration::from_secs(config.task_progress_timeout_secs),
        task_state_has_started,
    )
    .await?;
    let report_id = resolve_scan_report_id(client, config, &task.id, &started_report_id).await?;
    tracker.track_report(&report_id);
    // The deterministic fixture can finish just after the first Running
    // snapshot. Give that terminal transition a short grace period before the
    // stop mutation so a completed task is not moved back into a permanent
    // Stop Requested state.
    let task_status = settle_task_state_before_stop(
        client,
        config,
        &task.id,
        Duration::from_secs(config.task_progress_timeout_secs),
        Duration::from_secs(5),
    )
    .await?;
    let final_task_status = if task_state_is_stoppable(&task_status) {
        let stop_response = client
            .stop_task(StopTaskRequest::new(task.id.clone()))
            .await?;
        assert_typed_status(
            stop_response.status,
            &stop_response.status_text,
            200,
            "stop_task",
        )?;
        record_helper_execution("stop_task", "scan stop mutation executed")?;
        let stopped = wait_task_state(
            client,
            config,
            &task.id,
            Duration::from_secs(config.task_progress_timeout_secs),
            task_state_is_terminal_after_stop,
        )
        .await?;
        ensure(
            task_state_is_terminal_after_stop(&stopped),
            "synchronous stop did not settle in Stopped or raced terminal Done",
        )?;
        stopped
    } else {
        task_status
    };
    ensure(
        task_state_is_terminal_after_stop(&final_task_status),
        &format!(
            "scan task {} reached unsupported terminal state {final_task_status}; report assertions require Stopped or Done",
            task.id
        ),
    )?;

    let linked_tasks = get_tasks_with_reconnect(
        client,
        config,
        GetTasksRequest {
            filter_string: Some(format!("uuid={}", task.id)),
            details: Some(true),
            ..Default::default()
        },
        Duration::from_secs(config.task_progress_timeout_secs),
        "verify scan task/report linkage",
    )
    .await?;
    ensure(
        linked_tasks.items.len() == 1 && linked_tasks.items[0].meta.id == task.id,
        &format!(
            "typed get_tasks did not return exactly scan task {} while verifying report linkage",
            task.id
        ),
    )?;
    ensure(
        task_links_report(&linked_tasks.items[0], &report_id),
        &format!(
            "typed scan task {} did not expose resolved report {report_id} as current or last report",
            task.id
        ),
    )?;

    let report = client
        .get_report(GetReportRequest::new(report_id.clone()))
        .await?;
    assert_typed_status(
        report.status,
        &report.status_text,
        200,
        "get scan-linked report",
    )?;
    ensure(
        report.items.len() == 1,
        &format!(
            "typed get_report for {report_id} returned {} reports instead of exactly one",
            report.items.len()
        ),
    )?;
    let report_item = &report.items[0];
    ensure(
        report_item.meta.id == report_id,
        &format!(
            "typed get_report returned report {} for requested report {report_id}",
            report_item.meta.id
        ),
    )?;
    ensure(
        report_item
            .task
            .as_ref()
            .is_some_and(|linked_task| linked_task.id == task.id),
        &format!(
            "typed report {report_id} did not link back to scan task {}",
            task.id
        ),
    )?;
    log_pass(
        "scan report read/linkage",
        &format!("typed report {report_id} links to task {}", task.id),
    );

    let missing_report_id = parse_entity_id(&fixture_uuid(&config.run_id, "missing-report"))?;
    let missing_report = client
        .get_report(GetReportRequest::new(missing_report_id))
        .await;
    ensure(
        matches!(missing_report, Err(GvmError::Server { status: 404, .. })),
        "typed missing report lookup did not preserve the exact 404 server error",
    )?;
    log_pass("scan report missing", "typed 404 server error");

    let scan_results = client
        .get_results(scan_report_results_request(&report_id))
        .await?;
    assert_typed_status(
        scan_results.status,
        &scan_results.status_text,
        200,
        "get scan-linked results",
    )?;
    for result in &scan_results.items {
        ensure(
            result
                .report
                .as_ref()
                .is_none_or(|linked_report| linked_report.id == report_id),
            &format!(
                "result {} from report-scoped listing linked to a different report",
                result.meta.id
            ),
        )?;
    }
    let scan_result_count = scan_results.items.len();
    log_pass(
        "scan report results",
        &format!("typed report_id filter returned {scan_result_count} scan-linked result(s)"),
    );

    run_epss_result_regression(client, config, &report_id).await?;

    if let Some(selected_result) = select_deterministic_scan_result(&scan_results) {
        let selected_result_id = selected_result.meta.id.clone();
        let mut request = GetResultRequest::new(selected_result_id.clone());
        request.task_id = Some(task.id.clone());
        let result_detail = client.get_result(request).await?;
        assert_typed_status(
            result_detail.status,
            &result_detail.status_text,
            200,
            "get deterministic scan result",
        )?;
        ensure(
            result_detail.items.len() == 1 && result_detail.items[0].meta.id == selected_result_id,
            &format!(
                "typed get_result did not return exactly selected result {selected_result_id}"
            ),
        )?;
        let detailed_result = &result_detail.items[0];
        ensure(
            detailed_result
                .report
                .as_ref()
                .is_none_or(|linked_report| linked_report.id == report_id),
            &format!("typed result detail {selected_result_id} linked to a different report"),
        )?;
        log_pass(
            "scan result detail",
            &format!("typed deterministic result {selected_result_id}"),
        );
        record_helper_execution("get_result", "deterministic scan-result detail executed")?;
    } else {
        runtime::observe(
            "scan result detail",
            Outcome::ConditionalUnavailable,
            &format!(
                "typed report-scoped get_results for report {report_id} returned zero results; no result ID existed for canonical get_result"
            ),
        );
    }

    let negotiated_version = client.version();
    macro_rules! report_drilldown {
        ($command:literal, $future:expr) => {{
            ensure(
                advertised_commands.contains($command),
                concat!(
                    "live XML help did not advertise expected report drill-down ",
                    $command
                ),
            )?;
            let result = $future.await;
            if negotiated_version >= GmpVersion(22, 8) {
                let response = result?;
                assert_typed_status(
                    response.status,
                    &response.status_text,
                    200,
                    concat!("scan report drill-down ", $command),
                )?;
                log_pass(
                    concat!("scan report drill-down ", $command),
                    "canonical typed response",
                );
                record_helper_execution($command, concat!("typed ", $command, " executed"))?;
            } else {
                assert_gmp_22_8_rejection(result, $command, negotiated_version)?;
                runtime::observe(
                    concat!("scan report drill-down ", $command),
                    Outcome::ConditionalUnavailable,
                    &gmp_22_8_rejection_evidence($command, $command, negotiated_version),
                );
            }
        }};
    }

    report_drilldown!(
        "get_scan_report",
        client.get_scan_report(GetScanReportRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_vulns",
        client.get_report_vulns(GetReportVulnsRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_tls_certificates",
        client.get_report_tls_certificates(GetReportTlsCertificatesRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_hosts",
        client.get_report_hosts(GetReportHostsRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_ports",
        client.get_report_ports(GetReportPortsRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_applications",
        client.get_report_applications(GetReportApplicationsRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_operating_systems",
        client.get_report_operating_systems(GetReportOperatingSystemsRequest::new(
            report_id.clone(),
        ))
    );
    report_drilldown!(
        "get_report_cves",
        client.get_report_cves(GetReportCvesRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_errors",
        client.get_report_errors(GetReportErrorsRequest::new(report_id.clone()))
    );
    report_drilldown!(
        "get_report_closed_cves",
        client.get_report_closed_cves(GetReportClosedCvesRequest::new(report_id.clone()))
    );

    let report_formats = client
        .get_report_formats(GetReportFormatsRequest::default())
        .await?;
    assert_typed_status(
        report_formats.status,
        &report_formats.status_text,
        200,
        "get report formats for scan export",
    )?;
    let selected_format = select_usable_report_format(&report_formats)?;
    let selected_format_id = selected_format.meta.id.clone();
    let selected_content_type = selected_format.content_type.clone();
    let selected_extension = selected_format.extension.clone();
    let selected_format_read = client
        .get_report_format(GetReportFormatRequest::new(selected_format_id.clone()))
        .await?;
    assert_typed_status(
        selected_format_read.status,
        &selected_format_read.status_text,
        200,
        "get selected report format",
    )?;
    ensure(
        selected_format_read.items.len() == 1
            && selected_format_read.items[0].meta.id == selected_format_id,
        &format!(
            "typed singular report-format lookup did not preserve selected identity {selected_format_id}"
        ),
    )?;
    log_pass(
        "scan report format selection",
        &format!(
            "active format {selected_format_id} ({}/{}) round-tripped by identity",
            selected_content_type.as_deref().unwrap_or("<missing>"),
            selected_extension.as_deref().unwrap_or("<missing>")
        ),
    );

    run_async_report_export_lifecycle(
        client,
        config,
        tracker,
        &ScanReportExportFixture {
            advertised_commands: advertised_commands.clone(),
            report_id: report_id.clone(),
            report_format_id: selected_format_id.clone(),
            content_type: selected_content_type.clone(),
            extension: selected_extension.clone(),
        },
    )
    .await?;

    let fixture_descriptor: FixtureDescriptor = read_json(
        "E2E_FIXTURE_DESCRIPTOR_PATH",
        include_str!("../../../fixtures/community-provider.json"),
    )?;
    for (command, fixture) in [
        ("export_audit_report", "audit_report"),
        ("export_delta_audit_report", "audit_report_pair"),
        ("export_delta_scan_report", "delta_scan_report_pair"),
    ] {
        report_export_fixture_disposition(
            &advertised_commands,
            &fixture_descriptor,
            command,
            fixture,
        )?;
    }

    ensure(
        advertised_commands.contains("get_reports"),
        "live XML help did not advertise get_reports for synchronous report export",
    )?;
    let synchronous_export = client
        .get_report_export(GetReportExportRequest::new(
            report_id.clone(),
            selected_format_id.clone(),
        ))
        .await;
    if negotiated_version >= GmpVersion(22, 8) {
        let export = synchronous_export?;
        ensure(
            !export.bytes.is_empty(),
            "typed synchronous report export returned an empty payload",
        )?;
        log_pass(
            "scan report synchronous export",
            &format!(
                "canonical typed export decoded {} byte(s)",
                export.bytes.len()
            ),
        );
        record_helper_execution(
            "get_report_export",
            "typed synchronous report export executed and decoded bytes",
        )?;
    } else {
        assert_gmp_22_8_rejection(synchronous_export, "get_report_export", negotiated_version)?;
        runtime::observe(
            "scan report synchronous export",
            Outcome::ConditionalUnavailable,
            &gmp_22_8_rejection_evidence("get_report_export", "get_reports", negotiated_version),
        );
    }

    let mut import_task_request = CreateImportTaskRequest::new(config.name("import-task"));
    import_task_request.comment = Some(config.name("sanitized-report-import"));
    let import_task = client.create_import_task(import_task_request).await?;
    ensure(import_task.status == 201, "typed create_import_task failed")?;
    tracker.track_task(&import_task.id);
    let import_xml = include_str!("../../../fixtures/import-report.xml")
        .replace("{{RUN_NAME}}", &config.name("imported-report"))
        .replace(
            "{{REPORT_ID}}",
            &fixture_uuid(&config.run_id, "rust-gvm-e2e-report"),
        );
    let mut import_request =
        ImportReportRequest::new(import_task.id.clone(), import_xml.as_bytes());
    import_request.in_assets = Some(false);
    let imported = client.import_report(import_request).await?;
    ensure(imported.status == 201, "typed import_report failed")?;
    tracker.track_report(&imported.id);
    log_pass(
        "report import",
        "sanitized fixture create_import_task/import_report; report and parent-task cleanup tracked",
    );

    let delete_report = client
        .delete_report(DeleteReportRequest::new(report_id.clone()))
        .await?;
    assert_typed_status(
        delete_report.status,
        &delete_report.status_text,
        200,
        "delete scan report",
    )?;
    tracker
        .report_ids
        .retain(|value| value != report_id.as_str());
    let absent_report = client
        .get_report(GetReportRequest::new(report_id.clone()))
        .await;
    ensure(
        matches!(absent_report, Err(GvmError::Server { status: 404, .. })),
        "verify report cleanup did not return typed 404",
    )?;
    let delete_task_response = client
        .delete_task(DeleteTaskRequest::new(task.id.clone(), true))
        .await?;
    assert_typed_status(
        delete_task_response.status,
        &delete_task_response.status_text,
        200,
        "delete_task",
    )?;
    tracker.task_ids.retain(|value| value != task.id.as_str());

    let delete_target_response = client
        .delete_target(DeleteTargetRequest::new(scan_target.id.clone(), true))
        .await?;
    assert_typed_status(
        delete_target_response.status,
        &delete_target_response.status_text,
        200,
        "delete_target",
    )?;
    tracker
        .target_ids
        .retain(|value| value != scan_target.id.as_str());
    let delete_port_list_response = client
        .delete_port_list(DeletePortListRequest::new(port_list.id.clone(), true))
        .await?;
    assert_typed_status(
        delete_port_list_response.status,
        &delete_port_list_response.status_text,
        200,
        "delete scan port list",
    )?;
    tracker
        .port_list_ids
        .retain(|value| value != port_list.id.as_str());

    log_pass(
        "scan",
        &format!(
            "task states, report {}, {} typed result(s), report coverage, cleanup",
            report_id, scan_result_count
        ),
    );
    record_helper_executions(
        &["get_report", "get_results", "import_report"],
        "scan/report runtime path executed",
    )?;
    if plan.is_some_and(|plan| selected_scenario(plan, "openvasd-network-scan")) {
        record_scenario_execution(
            "openvasd-network-scan",
            "deterministic network scan runtime path executed",
        );
    }
    Ok(())
}

#[cfg(test)]
fn conditional_surface_wire_command(surface_name: &str) -> Result<&'static str, AppError> {
    if let Some(helper) = HELPER_COVERAGE
        .iter()
        .find(|entry| entry.name == surface_name)
    {
        ensure(
            helper.disposition == Disposition::ConditionalAvailability,
            &format!("helper {surface_name} must be conditional in the coverage manifest"),
        )?;
        return Ok(helper.wire_command);
    }

    let migration = HELPER_MIGRATIONS
        .iter()
        .find(|entry| entry.name == surface_name)
        .ok_or_else(|| {
            AppError::Assertion(format!(
                "missing current-helper or migration evidence for surface {surface_name}"
            ))
        })?;
    ensure(
        migration.status == gvm_community_e2e::SurfaceStatus::Replaced,
        &format!("surface {surface_name} was removed without a replacement"),
    )?;
    Ok(migration.wire_command)
}

#[cfg(test)]
fn conditional_helper_minimum_version(helper_name: &str) -> Result<GmpVersion, AppError> {
    let wire_command = conditional_surface_wire_command(helper_name)?;
    gvm_gmp::capabilities::minimum_version_for_command(helper_semantic_name(helper_name))
        .or_else(|| gvm_gmp::capabilities::minimum_version_for_command(wire_command))
        .ok_or_else(|| {
            AppError::Assertion(format!(
                "conditional helper {helper_name} has no semantic capability version gate"
            ))
        })
}

#[cfg(test)]
fn conditional_helper_available(helper_name: &str, version: GmpVersion) -> Result<bool, AppError> {
    let minimum = conditional_helper_minimum_version(helper_name)?;
    Ok(version >= minimum)
}

#[cfg(test)]
fn conditional_helper_call_allowed(
    helper_name: &str,
    advertised: bool,
    version: GmpVersion,
) -> Result<bool, AppError> {
    let version_eligible = conditional_helper_available(helper_name, version)?;
    Ok(advertised && version_eligible)
}

#[cfg(test)]
fn conditional_report_drilldown_call_allowed(
    helper_name: &str,
    available_commands: &BTreeSet<String>,
    version: GmpVersion,
) -> Result<bool, AppError> {
    let wire_command = conditional_surface_wire_command(helper_name)?;
    conditional_helper_call_allowed(
        helper_name,
        available_commands.contains(wire_command),
        version,
    )
}

#[cfg(test)]
const CONDITIONAL_REPORT_DRILLDOWN_HELPERS: &[&str] = &[
    "get_scan_report",
    "get_report_vulns",
    "get_report_tls_certificates",
    "get_report_hosts",
    "get_report_ports",
    "get_report_applications",
    "get_report_operating_systems",
    "get_report_cves",
    "get_report_errors",
    "get_report_closed_cves",
];

async fn run_crud_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;

    let auth_response = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    assert_typed_status(
        auth_response.status,
        &auth_response.status_text,
        200,
        "authenticate",
    )?;

    // --- port_list CRUD ---
    let mut create_port_list = CreatePortListRequest::new(config.name("port-list"));
    create_port_list.port_range = Some("T:1-100".into());
    let pl_resp = client.create_port_list(create_port_list).await?;
    assert_typed_status(
        pl_resp.status,
        &pl_resp.status_text,
        201,
        "create_port_list",
    )?;
    let pl_id = pl_resp.id;
    tracker.track_port_list(&pl_id);
    log_pass("crud 01", &format!("create port_list ({pl_id})"));

    let get_pl_resp = client
        .get_port_list(GetPortListRequest::new(pl_id.clone()))
        .await?;
    assert_typed_status(
        get_pl_resp.status,
        &get_pl_resp.status_text,
        200,
        "get_port_list",
    )?;
    log_pass("crud 02", "get port_list");

    let range = client
        .create_port_range(create_port_range_request(&pl_id, 101, 102))
        .await?;
    assert_typed_status(range.status, &range.status_text, 201, "create_port_range")?;
    let ranges = client
        .get_port_list(GetPortListRequest::new(pl_id.clone()))
        .await?;
    let range_id = ranges
        .items
        .iter()
        .flat_map(|port_list| &port_list.port_ranges)
        .find(|range| range.start == 101 && range.end == 102)
        .map(|range| range.id.clone())
        .ok_or_else(|| {
            AppError::Assertion("created port range did not round-trip with an id".to_string())
        })?;
    let delete_range = client
        .delete_port_range(DeletePortRangeRequest::new(range_id))
        .await?;
    assert_typed_status(
        delete_range.status,
        &delete_range.status_text,
        200,
        "delete_port_range",
    )?;
    let mut modify_port_list = ModifyPortListRequest::new(pl_id.clone());
    modify_port_list.comment = Some(config.name("port-list-modified"));
    let modified = client.modify_port_list(modify_port_list).await?;
    assert_typed_status(
        modified.status,
        &modified.status_text,
        200,
        "modify_port_list",
    )?;
    trash_restore_then_delete(&mut client, "port_list", &pl_id, |id, ultimate| {
        DeletePortListRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.port_list_ids.retain(|v| v != pl_id.as_str());
    log_pass("crud 03", "modify/trash/restore/delete port_list");

    let verify_pl_resp = client
        .get_port_list(GetPortListRequest::new(pl_id.clone()))
        .await;
    ensure(
        matches!(verify_pl_resp, Err(GvmError::Server { status: 404, .. })),
        "verify port_list absent did not return typed 404",
    )?;
    log_pass("crud 04", "verify port_list absent");

    // --- credential CRUD ---
    let mut create_credential = CreateCredentialRequest::new(config.name("credential"));
    create_credential.credential_type = Some(CredentialType::UsernamePassword);
    create_credential.login = Some("testuser".into());
    create_credential.password = Some("testpass".into());
    let cred_resp = client.create_credential(create_credential).await?;
    assert_typed_status(
        cred_resp.status,
        &cred_resp.status_text,
        201,
        "create_credential",
    )?;
    let cred_id = cred_resp.id;
    tracker.track_credential(&cred_id);
    log_pass("crud 05", &format!("create credential ({cred_id})"));

    let get_cred_resp = client
        .execute(GetCredentialRequest::new(cred_id.clone()))
        .await?;
    assert_typed_status(
        get_cred_resp.status,
        &get_cred_resp.status_text,
        200,
        "get_credential",
    )?;
    log_pass("crud 06", "get credential");

    let mut modify_credential = ModifyCredentialRequest::new(cred_id.clone());
    modify_credential.comment = Some(config.name("credential-modified"));
    let modified = client.modify_credential(modify_credential).await?;
    assert_typed_status(
        modified.status,
        &modified.status_text,
        200,
        "modify_credential",
    )?;
    trash_restore_then_delete(&mut client, "credential", &cred_id, |id, ultimate| {
        DeleteCredentialRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.credential_ids.retain(|v| v != cred_id.as_str());
    log_pass("crud 07", "modify/trash/restore/delete credential");

    let verify_cred_resp = client
        .execute(GetCredentialRequest::new(cred_id.clone()))
        .await;
    ensure(
        matches!(verify_cred_resp, Err(GvmError::Server { status: 404, .. })),
        "verify credential absent did not return typed 404",
    )?;
    log_pass("crud 08", "verify credential absent");

    // --- schedule CRUD ---
    let sched_resp = client
        .create_schedule(e2e_create_schedule_request(
            config.name("schedule"),
            "e2e test schedule".into(),
        ))
        .await?;
    assert_typed_status(
        sched_resp.status,
        &sched_resp.status_text,
        201,
        "create_schedule",
    )?;
    let sched_id = sched_resp.id;
    tracker.track_schedule(&sched_id);
    log_pass("crud 09", &format!("create schedule ({sched_id})"));

    let get_sched_resp = client
        .get_schedule(GetScheduleRequest::new(sched_id.clone()))
        .await?;
    assert_typed_status(
        get_sched_resp.status,
        &get_sched_resp.status_text,
        200,
        "get_schedule",
    )?;
    log_pass("crud 10", "get schedule");

    let modified = client
        .modify_schedule(e2e_modify_schedule_request(
            sched_id.clone(),
            config.name("schedule-modified"),
            Some(config.name("schedule-renamed")),
        ))
        .await?;
    assert_typed_status(
        modified.status,
        &modified.status_text,
        200,
        "modify_schedule",
    )?;
    trash_restore_then_delete(&mut client, "schedule", &sched_id, |id, ultimate| {
        DeleteScheduleRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.schedule_ids.retain(|v| v != sched_id.as_str());
    log_pass("crud 11", "modify/trash/restore/delete schedule");

    let verify_sched_resp = client
        .get_schedule(GetScheduleRequest::new(sched_id.clone()))
        .await;
    ensure(
        matches!(verify_sched_resp, Err(GvmError::Server { status: 404, .. })),
        "verify schedule absent did not return typed 404",
    )?;
    log_pass("crud 12", "verify schedule absent");

    // --- filter CRUD ---
    let mut create_filter = CreateFilterRequest::new(config.name("filter"));
    create_filter.term = Some("name=test".into());
    create_filter.filter_type = Some(FilterType::Task);
    let filter_resp = client.create_filter(create_filter).await?;
    assert_typed_status(
        filter_resp.status,
        &filter_resp.status_text,
        201,
        "create_filter",
    )?;
    let filter_id = filter_resp.id;
    tracker.track_filter(&filter_id);
    log_pass("crud 13", &format!("create filter ({filter_id})"));

    let get_filter_resp = client
        .get_filter(GetFilterRequest::new(filter_id.clone()))
        .await?;
    assert_typed_status(
        get_filter_resp.status,
        &get_filter_resp.status_text,
        200,
        "get_filter",
    )?;
    log_pass("crud 14", "get filter");

    let mut modify_filter = ModifyFilterRequest::new(filter_id.clone());
    modify_filter.comment = Some(config.name("filter-modified"));
    modify_filter.term = Some("name~rust-gvm-e2e".to_string());
    modify_filter.filter_type = Some(FilterType::Task);
    let modified = client.modify_filter(modify_filter).await?;
    assert_typed_status(modified.status, &modified.status_text, 200, "modify_filter")?;
    trash_restore_then_delete(&mut client, "filter", &filter_id, |id, ultimate| {
        DeleteFilterRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.filter_ids.retain(|v| v != filter_id.as_str());
    log_pass("crud 15", "modify/trash/restore/delete filter");

    let verify_filter_resp = client
        .get_filter(GetFilterRequest::new(filter_id.clone()))
        .await;
    ensure(
        matches!(
            verify_filter_resp,
            Err(GvmError::Server { status: 404, .. })
        ),
        "verify filter absent did not return typed 404",
    )?;
    log_pass("crud 16", "verify filter absent");

    // --- task CRUD (requires target, scan_config, scanner) ---
    let pl_list_resp = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    assert_typed_status(
        pl_list_resp.status,
        &pl_list_resp.status_text,
        200,
        "get_port_lists for task prereq",
    )?;
    let task_port_list_id = pl_list_resp
        .items
        .first()
        .map(|item| item.meta.id.clone())
        .ok_or_else(|| AppError::Assertion("task CRUD requires a port list".to_string()))?;

    let task_target_resp = client
        .create_target(create_localhost_target(
            &config.name("task-target"),
            task_port_list_id,
        )?)
        .await?;
    assert_typed_status(
        task_target_resp.status,
        &task_target_resp.status_text,
        201,
        "create task target",
    )?;
    let task_target_id = task_target_resp.id;
    tracker.track_target(&task_target_id);

    let scan_configs_resp = client
        .get_scan_configs(GetScanConfigsRequest::default())
        .await?;
    let scan_config_id = scan_configs_resp
        .items
        .first()
        .map(|item| item.meta.id.clone())
        .ok_or_else(|| AppError::Assertion("task CRUD requires a scan config".to_string()))?;

    let scanners_resp = client.get_scanners(GetScannersRequest::default()).await?;
    let scanner_id = scanners_resp
        .items
        .first()
        .map(|item| item.meta.id.clone())
        .ok_or_else(|| AppError::Assertion("task CRUD requires a scanner".to_string()))?;

    let task_resp = client
        .create_task(CreateTaskRequest::new(
            config.name("task"),
            scan_config_id,
            task_target_id.clone(),
            scanner_id,
        ))
        .await?;
    assert_typed_status(task_resp.status, &task_resp.status_text, 201, "create_task")?;
    let task_id = task_resp.id;
    tracker.track_task(&task_id);
    log_pass("crud 17", &format!("create task ({task_id})"));

    let get_task_resp = client
        .get_task(GetTaskRequest::new(task_id.clone()))
        .await?;
    assert_typed_status(
        get_task_resp.status,
        &get_task_resp.status_text,
        200,
        "get_task",
    )?;
    log_pass("crud 18", "get task");

    let mut modify_task = ModifyTaskRequest::new(task_id.clone());
    modify_task.name = Some(config.name("task-modified"));
    modify_task.comment = Some(config.name("task-comment-modified"));
    let modified = client.modify_task(modify_task).await?;
    assert_typed_status(modified.status, &modified.status_text, 200, "modify_task")?;
    trash_restore_then_delete(&mut client, "task", &task_id, |id, ultimate| {
        DeleteTaskRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.task_ids.retain(|v| v != task_id.as_str());
    log_pass("crud 19", "modify/trash/restore/delete task");

    trash_restore_then_delete(
        &mut client,
        "task target",
        &task_target_id,
        |id, ultimate| DeleteTargetRequest::new(id.clone(), ultimate),
    )
    .await?;
    tracker.target_ids.retain(|v| v != task_target_id.as_str());
    log_pass("crud 20", "trash/restore/delete task target");

    // --- notes and overrides (require an NVT OID) ---
    let nvts_resp = client.get_nvts(GetNvtsRequest::default()).await?;
    assert_typed_status(
        nvts_resp.status,
        &nvts_resp.status_text,
        200,
        "get_nvts for note prereq",
    )?;
    let nvt_oid = nvts_resp
        .items
        .first()
        .map(|nvt| nvt.oid.clone())
        .ok_or_else(|| AppError::Assertion("note CRUD requires an NVT".to_string()))?;

    // --- note CRUD ---
    let note_resp = client
        .create_note(CreateNoteRequest::new(&nvt_oid, config.name("note")))
        .await?;
    assert_typed_status(note_resp.status, &note_resp.status_text, 201, "create_note")?;
    let note_id = note_resp.id;
    tracker.track_note(&note_id);
    log_pass("crud 21", &format!("create note ({note_id})"));

    let mut invalid_create_note = XmlCommand::new("create_note");
    invalid_create_note
        .add_element("nvt")
        .set_attribute("oid", &nvt_oid);
    invalid_create_note.add_element_with_text("text", &config.name("invalid-note-severity"));
    invalid_create_note.add_element_with_text("severity", "not-a-severity");
    match client.call(invalid_create_note).await {
        Err(GvmError::Server {
            status: 400,
            message,
        }) if message == "Error in severity specification" => {}
        Ok(response) => {
            let id = response.id().ok_or_else(|| {
                AppError::Assertion(
                    "invalid create_note severity unexpectedly succeeded without an ID".to_string(),
                )
            })?;
            let id = EntityId::new(id).map_err(|error| {
                AppError::Assertion(format!(
                    "invalid create_note severity unexpectedly succeeded with invalid ID: {error}"
                ))
            })?;
            tracker.track_note(&id);
            return Err(AppError::Assertion(format!(
                "invalid create_note severity unexpectedly created note {id}"
            )));
        }
        Err(error) => return Err(error.into()),
    }

    let invalid_modify_note = XmlCommand::new("modify_note")
        .attribute("note_id", note_id.as_str())
        .child_with_text("text", &config.name("invalid-note-active"))
        .child_with_text("active", "not-an-active-value");
    let invalid_modify_note = client.call(invalid_modify_note).await;
    match invalid_modify_note {
        Err(GvmError::Server {
            status: 400,
            message,
        }) if message == "Error in active specification" => {}
        Err(error) => {
            return Err(AppError::Assertion(format!(
                "invalid modify_note active value returned unexpected server error: {error}"
            )));
        }
        Ok(_) => {
            return Err(AppError::Assertion(
                "invalid modify_note active value unexpectedly succeeded".to_string(),
            ));
        }
    }
    let note_error_health = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        note_error_health.status,
        &note_error_health.status_text,
        200,
        "get_version after invalid note requests",
    )?;
    log_pass(
        "crud note validation errors",
        "typed GMP 400 Error in severity specification and Error in active specification followed by same-session get_version",
    );

    let get_note_resp = client
        .get_note(GetNoteRequest::new(note_id.clone()))
        .await?;
    assert_typed_status(
        get_note_resp.status,
        &get_note_resp.status_text,
        200,
        "get_note",
    )?;
    log_pass("crud 22", "get note");

    let modified = client
        .modify_note(ModifyNoteRequest::new(
            note_id.clone(),
            config.name("note-modified"),
        ))
        .await?;
    assert_typed_status(modified.status, &modified.status_text, 200, "modify_note")?;
    trash_restore_then_delete(&mut client, "note", &note_id, |id, ultimate| {
        DeleteNoteRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.note_ids.retain(|v| v != note_id.as_str());
    log_pass("crud 23", "modify/trash/restore/delete note");

    let verify_note_resp = client.get_note(GetNoteRequest::new(note_id.clone())).await;
    ensure(
        matches!(verify_note_resp, Err(GvmError::Server { status: 404, .. })),
        "verify note absent did not return typed 404",
    )?;
    log_pass("crud 24", "verify note absent");

    // --- override CRUD ---
    let override_resp = client
        .create_override(CreateOverrideRequest::new(
            &nvt_oid,
            config.name("override"),
            -1.0,
        ))
        .await?;
    assert_typed_status(
        override_resp.status,
        &override_resp.status_text,
        201,
        "create_override",
    )?;
    let override_id = override_resp.id;
    tracker.track_override(&override_id);
    log_pass("crud 25", &format!("create override ({override_id})"));

    let get_override_resp = client
        .get_override(GetOverrideRequest::new(override_id.clone()))
        .await?;
    assert_typed_status(
        get_override_resp.status,
        &get_override_resp.status_text,
        200,
        "get_override",
    )?;
    log_pass("crud 26", "get override");

    let modified = client
        .modify_override(ModifyOverrideRequest::new(
            override_id.clone(),
            config.name("override-modified"),
            0.0,
        ))
        .await?;
    assert_typed_status(
        modified.status,
        &modified.status_text,
        200,
        "modify_override",
    )?;
    trash_restore_then_delete(&mut client, "override", &override_id, |id, ultimate| {
        DeleteOverrideRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.override_ids.retain(|v| v != override_id.as_str());
    log_pass("crud 27", "modify/trash/restore/delete override");

    let verify_override_resp = client
        .get_override(GetOverrideRequest::new(override_id.clone()))
        .await;
    ensure(
        matches!(
            verify_override_resp,
            Err(GvmError::Server { status: 404, .. })
        ),
        "verify override absent did not return typed 404",
    )?;
    log_pass("crud 28", "verify override absent");

    // --- tag CRUD ---
    let mut create_tag =
        CreateTagRequest::new(config.name("tag"), TagResources::new(EntityType::Task));
    create_tag.value = Some("e2e-value".into());
    create_tag.comment = Some("e2e test tag".into());
    create_tag.active = Some(true);
    let tag_resp = client.create_tag(create_tag).await?;
    assert_typed_status(tag_resp.status, &tag_resp.status_text, 201, "create_tag")?;
    let tag_id = tag_resp.id;
    tracker.track_tag(&tag_id);
    log_pass("crud 29", &format!("create tag ({tag_id})"));

    let get_tag_resp = client.get_tag(GetTagRequest::new(tag_id.clone())).await?;
    assert_typed_status(
        get_tag_resp.status,
        &get_tag_resp.status_text,
        200,
        "get_tag",
    )?;
    log_pass("crud 30", "get tag");

    let mut modify_tag = ModifyTagRequest::new(tag_id.clone());
    modify_tag.comment = Some(config.name("tag-modified"));
    modify_tag.value = Some(config.name("tag-value-modified"));
    modify_tag.active = Some(true);
    let modified = client.modify_tag(modify_tag).await?;
    assert_typed_status(modified.status, &modified.status_text, 200, "modify_tag")?;
    trash_restore_then_delete(&mut client, "tag", &tag_id, |id, ultimate| {
        DeleteTagRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.tag_ids.retain(|v| v != tag_id.as_str());
    log_pass("crud 31", "modify/trash/restore/delete tag");

    let verify_tag_resp = client.get_tag(GetTagRequest::new(tag_id.clone())).await;
    ensure(
        matches!(verify_tag_resp, Err(GvmError::Server { status: 404, .. })),
        "verify tag absent did not return typed 404",
    )?;
    log_pass("crud 32", "verify tag absent");

    // --- alert CRUD ---
    let mut create_alert = CreateAlertRequest::new(
        config.name("alert"),
        AlertEvent::TaskRunStatusChanged,
        AlertCondition::Always,
        AlertMethod::SysLog,
    );
    create_alert.comment = Some(config.name("alert-comment"));
    let alert = client.create_alert(create_alert).await?;
    tracker.track_alert(&alert.id);
    log_pass("crud 33", &format!("typed create alert ({})", alert.id));
    let alerts = client
        .get_alerts(GetAlertsRequest {
            filter_string: Some(format!("uuid={}", alert.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        alerts.items.iter().any(|item| item.meta.id == alert.id),
        "typed get_alerts did not return the created alert",
    )?;
    log_pass("crud 34", "typed get alert");
    let mut modify_alert = ModifyAlertRequest::new(alert.id.clone());
    modify_alert.comment = Some(config.name("alert-modified"));
    modify_alert.event = Some(AlertEvent::TaskRunStatusChanged);
    modify_alert.condition = Some(AlertCondition::Always);
    modify_alert.method = Some(AlertMethod::SysLog);
    let modified = client.modify_alert(modify_alert).await?;
    assert_typed_status(modified.status, &modified.status_text, 200, "modify_alert")?;
    trash_restore_then_delete(&mut client, "alert", &alert.id, |id, ultimate| {
        DeleteAlertRequest::new(id.clone(), ultimate)
    })
    .await?;
    tracker.alert_ids.retain(|id| id != alert.id.as_str());
    let absent = client
        .get_alert(GetAlertRequest::new(alert.id.clone()))
        .await;
    ensure(
        matches!(absent, Err(GvmError::Server { status: 404, .. })),
        "verify alert absent did not return typed 404",
    )?;
    log_pass(
        "crud 35-36",
        "modify/trash/restore/delete alert and verify absent",
    );

    record_helper_executions(
        &[
            "authenticate",
            "create_alert",
            "create_credential",
            "create_filter",
            "create_note",
            "create_override",
            "create_port_list",
            "create_port_range",
            "create_schedule",
            "create_tag",
            "create_target",
            "create_task",
            "delete_port_range",
            "get_alert",
            "get_alerts",
            "get_filter",
            "get_note",
            "get_nvts",
            "get_override",
            "get_port_list",
            "get_port_lists",
            "get_scan_configs",
            "get_scanners",
            "get_schedule",
            "get_tag",
            "get_task",
            "modify_alert",
            "modify_credential",
            "modify_filter",
            "modify_note",
            "modify_override",
            "modify_port_list",
            "modify_schedule",
            "modify_tag",
            "modify_task",
            "restore",
        ],
        "CRUD runtime path executed",
    )?;
    for command in [
        "delete_alert",
        "delete_credential",
        "delete_filter",
        "delete_note",
        "delete_override",
        "delete_schedule",
        "delete_tag",
    ] {
        record_command_execution(command, "CRUD delete runtime path executed")?;
    }

    client.disconnect().await?;
    Ok(())
}

async fn run_secinfo_suite(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    let auth_response = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    assert_typed_status(
        auth_response.status,
        &auth_response.status_text,
        200,
        "authenticate",
    )?;

    let feeds_resp = client.get_feeds(GetFeedsRequest::new()).await?;
    assert_typed_status(feeds_resp.status, &feeds_resp.status_text, 200, "get_feeds")?;
    let feed_count = feeds_resp.items.len();
    ensure(feed_count >= 1, "expected at least one feed")?;
    log_pass("secinfo 01", &format!("get_feeds ({feed_count} feeds)"));

    let cves_resp = client.get_cves(GetCvesRequest::default()).await?;
    assert_typed_status(cves_resp.status, &cves_resp.status_text, 200, "get_cves")?;
    let cve_count = cves_resp.items.len();
    if cve_count == 0 {
        log_line("[info] secinfo 02 get_cves returned a valid empty warm-feed collection");
    }
    log_pass("secinfo 02", &format!("get_cves ({cve_count} entries)"));

    let cpes_resp = client.get_cpes(GetCpesRequest::default()).await?;
    assert_typed_status(cpes_resp.status, &cpes_resp.status_text, 200, "get_cpes")?;
    let cpe_count = cpes_resp.items.len();
    if cpe_count == 0 {
        log_line("[info] secinfo 03 get_cpes returned a valid empty warm-feed collection");
    }
    log_pass("secinfo 03", &format!("get_cpes ({cpe_count} entries)"));

    let cert_resp = client
        .get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default())
        .await?;
    assert_typed_status(
        cert_resp.status,
        &cert_resp.status_text,
        200,
        "get_cert_bund_advisories",
    )?;
    let cert_count = cert_resp.items.len();
    if cert_count == 0 {
        log_line("[info] secinfo 04 get_cert_bund_advisories returned a valid empty collection");
    }
    log_pass(
        "secinfo 04",
        &format!("get_cert_bund_advisories ({cert_count} entries)"),
    );

    let dfn_resp = client
        .get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default())
        .await?;
    assert_typed_status(
        dfn_resp.status,
        &dfn_resp.status_text,
        200,
        "get_dfn_cert_advisories",
    )?;
    let dfn_count = dfn_resp.items.len();
    if dfn_count == 0 {
        log_line("[info] secinfo 05 get_dfn_cert_advisories returned a valid empty collection");
    }
    log_pass(
        "secinfo 05",
        &format!("get_dfn_cert_advisories ({dfn_count} entries)"),
    );

    let nvts_resp = client.get_nvts(GetNvtsRequest::default()).await?;
    assert_typed_status(nvts_resp.status, &nvts_resp.status_text, 200, "get_nvts")?;
    let nvt_count = nvts_resp.items.len();
    ensure(
        nvt_count >= 1,
        "expected at least one NVT; VT feed may not be loaded",
    )?;
    log_pass("secinfo 06", &format!("get_nvts ({nvt_count} entries)"));

    record_helper_executions(
        &[
            "authenticate",
            "get_cert_bund_advisories",
            "get_cpes",
            "get_cves",
            "get_dfn_cert_advisories",
            "get_feeds",
            "get_nvts",
        ],
        "SecInfo runtime path executed",
    )?;

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
    let mut client = connect_client(config).await?;
    let auth_response = client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
    assert_typed_status(
        auth_response.status,
        &auth_response.status_text,
        200,
        "authenticate",
    )?;

    let mut warnings: Vec<String> = Vec::new();

    // 01: get_version
    let rust_version_response = client.get_version(GetVersionRequest::new()).await?;
    assert_typed_status(
        rust_version_response.status,
        &rust_version_response.status_text,
        200,
        "get_version",
    )?;
    let rust_version = rust_version_response.version;
    compare_get_version(&rust_version, &mut warnings)?;
    log_pass("diff 01", "get_version compared");

    // 02: compare identical, unbounded usage_type=scan queries. The ergonomic
    // rust-gvm get_scan_configs wrapper currently omits usage_type, unlike
    // python-gvm, so the generic typed helper makes the wire semantics explicit.
    let rust_scan_configs = client
        .get_configs(GetConfigsRequest {
            filter_string: Some("rows=-1".to_string()),
            usage_type: Some(ConfigUsageType::Scan),
            ..Default::default()
        })
        .await?
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_scan_configs", &rust_scan_configs, &mut warnings)?;
    log_pass("diff 02", "get_scan_configs compared");

    // 03: get_scanners
    let rust_scanners_response = client.get_scanners(GetScannersRequest::default()).await?;
    assert_typed_status(
        rust_scanners_response.status,
        &rust_scanners_response.status_text,
        200,
        "get_scanners",
    )?;
    let rust_scanners = rust_scanners_response
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_scanners", &rust_scanners, &mut warnings)?;
    log_pass("diff 03", "get_scanners compared");

    // 04: get_port_lists
    let rust_port_lists_response = client
        .get_port_lists(GetPortListsRequest::default())
        .await?;
    assert_typed_status(
        rust_port_lists_response.status,
        &rust_port_lists_response.status_text,
        200,
        "get_port_lists",
    )?;
    let rust_port_lists = rust_port_lists_response
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();
    compare_id_name_command("get_port_lists", &rust_port_lists, &mut warnings)?;
    log_pass("diff 04", "get_port_lists compared");

    // 05: get_feeds
    let rust_feeds_response = client.get_feeds(GetFeedsRequest::new()).await?;
    assert_typed_status(
        rust_feeds_response.status,
        &rust_feeds_response.status_text,
        200,
        "get_feeds",
    )?;
    let rust_feeds = rust_feeds_response
        .items
        .into_iter()
        .map(|entry| FeedEntity {
            feed_type: entry.type_,
            name: entry.name,
            status: entry.status.unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    compare_get_feeds(&rust_feeds, &mut warnings)?;
    log_pass("diff 05", "get_feeds compared");

    // 06: get_report_formats
    let rust_report_formats_response = client
        .get_report_formats(GetReportFormatsRequest::default())
        .await?;
    assert_typed_status(
        rust_report_formats_response.status,
        &rust_report_formats_response.status_text,
        200,
        "get_report_formats",
    )?;
    let rust_report_formats = rust_report_formats_response
        .items
        .into_iter()
        .map(|entry| ReportFormatEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
            extension: entry.extension.unwrap_or_default(),
            content_type: entry.content_type.unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    compare_get_report_formats(&rust_report_formats, &mut warnings)?;
    log_pass("diff 06", "get_report_formats compared");

    macro_rules! compare_deterministic_list {
        ($command:literal, $request:expr) => {{
            let response = client.execute($request).await?;
            assert_typed_status(response.status, &response.status_text, 200, $command)?;
            let entities = response
                .items
                .into_iter()
                .map(|entry| IdNameEntity {
                    id: entry.meta.id.to_string(),
                    name: entry.meta.name,
                })
                .collect::<Vec<_>>();
            compare_id_name_command($command, &entities, &mut warnings)?;
            log_pass(
                concat!("diff ", $command),
                "semantic UUID/name set compared",
            );
        }};
    }
    compare_deterministic_list!("get_alerts", GetAlertsRequest::default());
    compare_deterministic_list!("get_credentials", GetCredentialsRequest::default());
    compare_deterministic_list!("get_filters", GetFiltersRequest::default());
    compare_deterministic_list!("get_schedules", GetSchedulesRequest::default());
    compare_deterministic_list!("get_tags", GetTagsRequest::default());
    compare_deterministic_list!("get_tasks", GetTasksRequest::default());

    // Reversible target lifecycle through both clients and cross-visibility.
    run_target_differential(&mut client, tracker, &rust_port_lists, &mut warnings).await?;
    log_pass("diff lifecycle", "cross-client target lifecycle");

    ensure(
        warnings.is_empty(),
        &format!(
            "differential comparison found {} semantic mismatch(es): {}",
            warnings.len(),
            warnings.join("; ")
        ),
    )?;
    log_pass(
        "differential",
        "all semantic fields and entity identities matched",
    );

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
        .map(|entry| entry.id.clone())
        .ok_or_else(|| {
            AppError::Assertion("target differential requires a warm-volume port list".to_string())
        })?;

    let rust_target_name = tracker.config.name("diff-rust-target");
    let python_target_name = tracker.config.name("diff-python-target");

    let rust_target_response = client
        .create_target(create_localhost_target(
            &rust_target_name,
            parse_entity_id(&port_list_id)?,
        )?)
        .await?;
    assert_typed_status(
        rust_target_response.status,
        &rust_target_response.status_text,
        201,
        "differential create_target rust",
    )?;
    let rust_target_id = rust_target_response.id;
    tracker.track_target(&rust_target_id);

    let python_create = run_python_helper(
        "create_target",
        &[
            ("--name", python_target_name.as_str()),
            ("--hosts", "127.0.0.1"),
            ("--port-list-id", port_list_id.as_str()),
        ],
    )?;
    let python_target_id = parse_python_target_id(&python_create, "create_target", warnings);
    if let Some(id) = python_target_id.as_deref() {
        if let Ok(entity_id) = parse_entity_id(id) {
            tracker.track_target(&entity_id);
        } else {
            warnings.push(format!("create_target python returned invalid UUID `{id}`"));
        }
    }

    let rust_targets_response = client.get_targets(GetTargetsRequest::default()).await?;
    assert_typed_status(
        rust_targets_response.status,
        &rust_targets_response.status_text,
        200,
        "get_targets rust",
    )?;
    let rust_targets = rust_targets_response
        .items
        .into_iter()
        .map(|entry| IdNameEntity {
            id: entry.meta.id.to_string(),
            name: entry.meta.name,
        })
        .collect::<Vec<_>>();

    let python_targets_json = run_python_helper("get_targets", &[])?;
    let python_targets = parse_python_id_name_entities(&python_targets_json, "targets", warnings);

    compare_target_visibility(
        "rust target",
        rust_target_id.as_str(),
        &rust_target_name,
        &rust_targets,
        &python_targets,
        warnings,
    );
    if let Some(id) = python_target_id.as_deref() {
        compare_target_visibility(
            "python target",
            id,
            &python_target_name,
            &rust_targets,
            &python_targets,
            warnings,
        );
    }

    let rust_delete_response = client
        .delete_target(DeleteTargetRequest::new(rust_target_id.clone(), true))
        .await?;
    assert_typed_status(
        rust_delete_response.status,
        &rust_delete_response.status_text,
        200,
        "differential delete_target rust",
    )?;
    tracker
        .target_ids
        .retain(|value| value != rust_target_id.as_str());

    if let Some(id) = python_target_id {
        let python_delete = run_python_helper("delete_target", &[("--target-id", id.as_str())])?;
        if python_delete
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            != "ok"
        {
            warnings.push(format!(
                "delete_target python returned non-ok status: {}",
                python_delete
            ));
        }
        tracker.target_ids.retain(|value| value != id.as_str());
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
    let rust_map: BTreeMap<&str, &str> = rust_targets
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect();
    let python_map: BTreeMap<&str, &str> = python_targets
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect();

    match rust_map.get(expected_id) {
        Some(name) if *name == expected_name => {}
        Some(name) => warnings.push(format!(
            "{label} mismatch in rust get_targets: id `{expected_id}` has name `{name}`, expected `{expected_name}`"
        )),
        None => warnings.push(format!(
            "{label} missing in rust get_targets: id `{expected_id}`"
        )),
    }
    match python_map.get(expected_id) {
        Some(name) if *name == expected_name => {}
        Some(name) => warnings.push(format!(
            "{label} mismatch in python get_targets: id `{expected_id}` has name `{name}`, expected `{expected_name}`"
        )),
        None => warnings.push(format!(
            "{label} missing in python get_targets: id `{expected_id}`"
        )),
    }
}

fn compare_get_version(rust_version: &str, warnings: &mut Vec<String>) -> Result<(), AppError> {
    let python_json = run_python_helper("get_version", &[])?;
    let python_status = python_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if python_status != "ok" {
        warnings.push(format!(
            "get_version python helper returned non-ok status: {python_json}"
        ));
        return Ok(());
    }

    let python_version = python_json
        .get("data")
        .and_then(|data| data.get("version"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if rust_version != python_version {
        warnings.push(format!(
            "get_version mismatch: rust `{rust_version}` vs python `{python_version}`"
        ));
    }

    Ok(())
}

fn compare_id_name_command(
    command: &str,
    rust_entities: &[IdNameEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let python_json = run_python_helper(command, &[])?;
    let python_entities =
        parse_python_id_name_entities(&python_json, list_key_for_command(command), warnings);
    compare_id_name_entities(command, rust_entities, &python_entities, warnings);
    Ok(())
}

fn compare_id_name_entities(
    label: &str,
    rust_entities: &[IdNameEntity],
    python_entities: &[IdNameEntity],
    warnings: &mut Vec<String>,
) {
    if rust_entities.len() != python_entities.len() {
        warnings.push(format!(
            "{label} count mismatch: rust {} vs python {}",
            rust_entities.len(),
            python_entities.len()
        ));
    }

    let rust_ids: BTreeSet<&str> = rust_entities
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    let python_ids: BTreeSet<&str> = python_entities
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();

    for missing in rust_ids.difference(&python_ids) {
        warnings.push(format!("{label} UUID missing in python: {missing}"));
    }
    for missing in python_ids.difference(&rust_ids) {
        warnings.push(format!("{label} UUID missing in rust: {missing}"));
    }

    let rust_map: BTreeMap<&str, &str> = rust_entities
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect();
    let python_map: BTreeMap<&str, &str> = python_entities
        .iter()
        .map(|entry| (entry.id.as_str(), entry.name.as_str()))
        .collect();

    for id in rust_ids.intersection(&python_ids) {
        let rust_name = rust_map.get(id).copied().unwrap_or_default();
        let python_name = python_map.get(id).copied().unwrap_or_default();
        if rust_name != python_name {
            warnings.push(format!(
                "{label} name mismatch for UUID `{id}`: rust `{rust_name}` vs python `{python_name}`"
            ));
        }
    }
}

fn compare_get_feeds(
    rust_feeds: &[FeedEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let python_json = run_python_helper("get_feeds", &[])?;
    let python_status = python_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if python_status != "ok" {
        warnings.push(format!(
            "get_feeds python helper returned non-ok status: {python_json}"
        ));
        return Ok(());
    }

    let python_feeds = parse_python_feeds(&python_json, warnings);
    if rust_feeds.len() != python_feeds.len() {
        warnings.push(format!(
            "get_feeds count mismatch: rust {} vs python {}",
            rust_feeds.len(),
            python_feeds.len()
        ));
    }

    let rust_types: BTreeSet<&str> = rust_feeds
        .iter()
        .map(|entry| entry.feed_type.as_str())
        .collect();
    let python_types: BTreeSet<&str> = python_feeds
        .iter()
        .map(|entry| entry.feed_type.as_str())
        .collect();
    for missing in rust_types.difference(&python_types) {
        warnings.push(format!("get_feeds type missing in python: {missing}"));
    }
    for missing in python_types.difference(&rust_types) {
        warnings.push(format!("get_feeds type missing in rust: {missing}"));
    }

    let rust_map: BTreeMap<&str, &FeedEntity> = rust_feeds
        .iter()
        .map(|entry| (entry.feed_type.as_str(), entry))
        .collect();
    let python_map: BTreeMap<&str, &FeedEntity> = python_feeds
        .iter()
        .map(|entry| (entry.feed_type.as_str(), entry))
        .collect();
    for key in rust_types.intersection(&python_types) {
        let Some(rust_entry) = rust_map.get(key).copied() else {
            continue;
        };
        let Some(python_entry) = python_map.get(key).copied() else {
            continue;
        };
        if rust_entry.name != python_entry.name {
            warnings.push(format!(
                "get_feeds name mismatch for type `{key}`: rust `{}` vs python `{}`",
                rust_entry.name, python_entry.name
            ));
        }
        if rust_entry.status != python_entry.status {
            warnings.push(format!(
                "get_feeds status mismatch for type `{key}`: rust `{}` vs python `{}`",
                rust_entry.status, python_entry.status
            ));
        }
    }

    Ok(())
}

fn compare_get_report_formats(
    rust_formats: &[ReportFormatEntity],
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    let python_json = run_python_helper("get_report_formats", &[])?;
    let python_status = python_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if python_status != "ok" {
        warnings.push(format!(
            "get_report_formats python helper returned non-ok status: {python_json}"
        ));
        return Ok(());
    }

    let python_formats = parse_python_report_formats(&python_json, warnings);
    if rust_formats.len() != python_formats.len() {
        warnings.push(format!(
            "get_report_formats count mismatch: rust {} vs python {}",
            rust_formats.len(),
            python_formats.len()
        ));
    }

    let rust_ids: BTreeSet<&str> = rust_formats.iter().map(|entry| entry.id.as_str()).collect();
    let python_ids: BTreeSet<&str> = python_formats
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    for missing in rust_ids.difference(&python_ids) {
        warnings.push(format!(
            "get_report_formats UUID missing in python: {missing}"
        ));
    }
    for missing in python_ids.difference(&rust_ids) {
        warnings.push(format!(
            "get_report_formats UUID missing in rust: {missing}"
        ));
    }

    let rust_map: BTreeMap<&str, &ReportFormatEntity> = rust_formats
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let python_map: BTreeMap<&str, &ReportFormatEntity> = python_formats
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    for id in rust_ids.intersection(&python_ids) {
        let Some(rust_entry) = rust_map.get(id).copied() else {
            continue;
        };
        let Some(python_entry) = python_map.get(id).copied() else {
            continue;
        };
        if rust_entry.name != python_entry.name {
            warnings.push(format!(
                "get_report_formats name mismatch for `{id}`: rust `{}` vs python `{}`",
                rust_entry.name, python_entry.name
            ));
        }
        if rust_entry.extension != python_entry.extension {
            warnings.push(format!(
                "get_report_formats extension mismatch for `{id}`: rust `{}` vs python `{}`",
                rust_entry.extension, python_entry.extension
            ));
        }
        if rust_entry.content_type != python_entry.content_type {
            warnings.push(format!(
                "get_report_formats content_type mismatch for `{id}`: rust `{}` vs python `{}`",
                rust_entry.content_type, python_entry.content_type
            ));
        }
    }

    Ok(())
}

fn run_python_helper(command: &str, args: &[(&str, &str)]) -> Result<Value, AppError> {
    let helper_path = env::var("DIFFERENTIAL_HELPER_PATH")
        .unwrap_or_else(|_| "/workspace/docker/scripts/differential-helper.py".to_string());
    let mut helper_command = Command::new("python3");
    helper_command.arg(helper_path).arg(command);
    for (flag, value) in args {
        helper_command.arg(flag).arg(value);
    }

    let output = helper_command.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let rendered = if !stderr.is_empty() {
            stderr
        } else {
            "no output".to_string()
        };
        return Err(AppError::Assertion(format!(
            "python helper `{command}` returned empty stdout: {rendered}"
        )));
    }

    Ok(serde_json::from_str(&stdout)?)
}

fn list_key_for_command(command: &str) -> &str {
    match command {
        "get_alerts" => "alerts",
        "get_credentials" => "credentials",
        "get_filters" => "filters",
        "get_schedules" => "schedules",
        "get_scan_configs" => "scan_configs",
        "get_scanners" => "scanners",
        "get_port_lists" => "port_lists",
        "get_tags" => "tags",
        "get_targets" => "targets",
        "get_tasks" => "tasks",
        _ => "items",
    }
}

fn parse_python_id_name_entities(
    payload: &Value,
    list_key: &str,
    warnings: &mut Vec<String>,
) -> Vec<IdNameEntity> {
    let status = payload.get("status").and_then(Value::as_str).unwrap_or("");
    if status != "ok" {
        warnings.push(format!(
            "python helper returned non-ok status for `{list_key}`: {payload}"
        ));
        return Vec::new();
    }

    let Some(items) = payload
        .get("data")
        .and_then(|data| data.get(list_key))
        .and_then(Value::as_array)
    else {
        warnings.push(format!(
            "python helper payload missing data.{list_key}: {payload}"
        ));
        return Vec::new();
    };

    let mut entities = Vec::new();
    for item in items {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            entities.push(IdNameEntity {
                id: id.to_string(),
                name,
            });
        }
    }
    entities
}

fn parse_python_feeds(payload: &Value, warnings: &mut Vec<String>) -> Vec<FeedEntity> {
    let Some(items) = payload
        .get("data")
        .and_then(|data| data.get("feeds"))
        .and_then(Value::as_array)
    else {
        warnings.push(format!(
            "python helper payload missing data.feeds: {payload}"
        ));
        return Vec::new();
    };

    let mut feeds = Vec::new();
    for item in items {
        feeds.push(FeedEntity {
            feed_type: item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            name: item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            status: item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    feeds
}

fn parse_python_report_formats(
    payload: &Value,
    warnings: &mut Vec<String>,
) -> Vec<ReportFormatEntity> {
    let Some(items) = payload
        .get("data")
        .and_then(|data| data.get("report_formats"))
        .and_then(Value::as_array)
    else {
        warnings.push(format!(
            "python helper payload missing data.report_formats: {payload}"
        ));
        return Vec::new();
    };

    let mut formats = Vec::new();
    for item in items {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            formats.push(ReportFormatEntity {
                id: id.to_string(),
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                extension: item
                    .get("extension")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                content_type: item
                    .get("content_type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }
    formats
}

fn parse_python_target_id(
    payload: &Value,
    command: &str,
    warnings: &mut Vec<String>,
) -> Option<String> {
    let status = payload.get("status").and_then(Value::as_str).unwrap_or("");
    if status != "ok" {
        warnings.push(format!(
            "{command} python helper returned non-ok status: {payload}"
        ));
        return None;
    }

    let Some(id) = payload
        .get("data")
        .and_then(|data| data.get("id"))
        .and_then(Value::as_str)
    else {
        warnings.push(format!(
            "{command} python helper payload missing data.id: {payload}"
        ));
        return None;
    };
    Some(id.to_string())
}

async fn get_tasks_with_reconnect(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    request: GetTasksRequest,
    timeout: Duration,
    label: &str,
) -> Result<GetTasksResponse, AppError> {
    let started = Instant::now();
    let mut last_error = String::from("no request attempt completed");
    while started.elapsed() <= timeout {
        match client.get_tasks(request.clone()).await {
            Ok(response) => return Ok(response),
            Err(GvmError::Connection(error)) => {
                last_error = error.to_string();
                log_line(&format!(
                    "{label} connection failed ({error}); renewing authenticated session"
                ));
            }
            Err(error) => return Err(error.into()),
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        *client = reconnect_authenticated(config, remaining).await?;
    }
    Err(AppError::Assertion(format!(
        "{label} did not complete within {} seconds; last connection error: {last_error}",
        timeout.as_secs()
    )))
}

async fn read_task_status(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    task_id: &EntityId,
    timeout: Duration,
    label: &str,
) -> Result<String, AppError> {
    let response = get_tasks_with_reconnect(
        client,
        config,
        GetTasksRequest {
            filter_string: Some(format!("uuid={task_id}")),
            details: Some(true),
            ..Default::default()
        },
        timeout,
        label,
    )
    .await?;
    response
        .items
        .iter()
        .find(|task| task.meta.id == *task_id)
        .ok_or_else(|| {
            AppError::Assertion(format!(
                "typed get_tasks did not return task {task_id} for {label}"
            ))
        })?
        .status
        .clone()
        .ok_or_else(|| AppError::Assertion(format!("task {task_id} omitted status for {label}")))
}

async fn settle_task_state_before_stop(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    task_id: &EntityId,
    read_timeout: Duration,
    grace_period: Duration,
) -> Result<String, AppError> {
    let started = tokio::time::Instant::now();

    loop {
        let status =
            read_task_status(client, config, task_id, read_timeout, "pre-stop task state").await?;
        let elapsed = started.elapsed();
        if task_state_is_terminal_after_stop(&status)
            || (task_state_is_stoppable(&status) && elapsed >= grace_period)
            || (!task_state_is_stoppable(&status) && !task_state_is_finishing(&status))
            || elapsed >= read_timeout
        {
            return Ok(status);
        }

        let remaining = if task_state_is_finishing(&status) {
            read_timeout.saturating_sub(elapsed)
        } else {
            grace_period.saturating_sub(elapsed)
        };
        sleep(Duration::from_secs(1).min(remaining)).await;
    }
}

async fn get_permissions_with_reconnect(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    request: GetPermissionsRequest,
    timeout: Duration,
    label: &str,
) -> Result<GetPermissionsResponse, AppError> {
    let started = Instant::now();
    let mut last_error = String::from("no request attempt completed");
    while started.elapsed() <= timeout {
        match client.get_permissions(request.clone()).await {
            Ok(response) => return Ok(response),
            Err(GvmError::Connection(error)) => {
                last_error = error.to_string();
                log_line(&format!(
                    "{label} connection failed ({error}); renewing authenticated session"
                ));
            }
            Err(error) => return Err(error.into()),
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        *client = reconnect_authenticated(config, remaining).await?;
    }
    Err(AppError::Assertion(format!(
        "{label} did not complete within {} seconds; last connection error: {last_error}",
        timeout.as_secs()
    )))
}

async fn wait_task_state(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    task_id: &EntityId,
    timeout: Duration,
    accept: impl Fn(&str) -> bool,
) -> Result<String, AppError> {
    let started = tokio::time::Instant::now();
    let mut last_status = String::from("unknown");

    while started.elapsed() <= timeout {
        last_status = read_task_status(
            client,
            config,
            task_id,
            timeout.saturating_sub(started.elapsed()),
            "task status poll",
        )
        .await?;
        if accept(&last_status) {
            return Ok(last_status);
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "task {task_id} did not reach the required state within {} seconds; last status: {last_status}",
        timeout.as_secs()
    )))
}

#[derive(Debug)]
enum PermissionModifyDelivery {
    Confirmed,
    KnownSubjectRejection,
    ConnectionLost(String),
}

async fn modify_role_permission_reconciled(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    permission_id: &EntityId,
    role_id: &EntityId,
    desired_comment: &str,
) -> Result<(), AppError> {
    let mut request = ModifyPermissionRequest::new(permission_id.clone());
    request.comment = Some(desired_comment.to_string());
    request.subject_type = Some(gvm_gmp::PermissionSubjectType::Role);
    request.subject_id = Some(role_id.clone());
    let delivery = match client.modify_permission(request).await {
        Ok(response) => {
            assert_typed_status(
                response.status,
                &response.status_text,
                200,
                "modify_permission",
            )?;
            PermissionModifyDelivery::Confirmed
        }
        Err(GvmError::Server {
            status: 400,
            message,
        }) if message == "Error in SUBJECT" => PermissionModifyDelivery::KnownSubjectRejection,
        Err(GvmError::Connection(error)) => {
            PermissionModifyDelivery::ConnectionLost(error.to_string())
        }
        Err(error) => return Err(error.into()),
    };

    renew_authenticated_after_response(
        client,
        config,
        Duration::from_secs(config.task_progress_timeout_secs),
        "modify_permission outcome",
    )
    .await?;
    let permissions = get_permissions_with_reconnect(
        client,
        config,
        GetPermissionsRequest {
            filter_string: Some(format!("uuid={permission_id}")),
            details: Some(true),
            ..Default::default()
        },
        Duration::from_secs(config.task_progress_timeout_secs),
        "reconcile modify_permission",
    )
    .await?;
    let permission = permissions
        .items
        .iter()
        .find(|entry| entry.meta.id == *permission_id)
        .ok_or_else(|| {
            AppError::Assertion(format!(
                "permission {permission_id} disappeared while reconciling modify_permission"
            ))
        })?;
    let desired_state_observed = permission.meta.comment.as_deref() == Some(desired_comment)
        && permission
            .subject
            .as_ref()
            .is_some_and(|subject| subject.id == *role_id);

    match delivery {
        PermissionModifyDelivery::Confirmed if desired_state_observed => {
            log_pass(
                "typed permission modify",
                "response and read-after-write reconciliation confirmed the desired state",
            );
            record_helper_execution(
                "modify_permission",
                "permission modification and read-after-write reconciliation executed",
            )?;
        }
        PermissionModifyDelivery::Confirmed => {
            return Err(AppError::Assertion(format!(
                "modify_permission returned success but permission {permission_id} did not expose the desired comment and role subject"
            )));
        }
        PermissionModifyDelivery::KnownSubjectRejection if desired_state_observed => {
            return Err(AppError::Assertion(format!(
                "modify_permission returned Error in SUBJECT but permission {permission_id} exposed the rejected state"
            )));
        }
        PermissionModifyDelivery::KnownSubjectRejection => {
            runtime::observe(
                "typed permission modify",
                Outcome::KnownUpstreamBug,
                "rust-gvm#405 reproduced: flat subject elements were rejected by gvmd",
            );
        }
        PermissionModifyDelivery::ConnectionLost(error) if desired_state_observed => {
            log_pass(
                "typed permission modify",
                &format!(
                    "read-after-write reconciliation confirmed the desired state after response loss ({error})"
                ),
            );
            record_helper_execution(
                "modify_permission",
                "permission response-loss reconciliation proved the executed mutation",
            )?;
        }
        PermissionModifyDelivery::ConnectionLost(error) => {
            runtime::observe(
                "canonical permission modify",
                Outcome::KnownUpstreamBug,
                &format!(
                    "stable gvmd closed the connection without applying the requested permission state ({error})"
                ),
            );
        }
    }
    Ok(())
}

async fn create_role_permission(
    client: &mut GmpClient<UnixSocketConnection>,
    name: &str,
    comment: &str,
    role_id: &EntityId,
) -> Result<EntityId, AppError> {
    let subject = PermissionSubject::new(role_id.clone(), gvm_gmp::PermissionSubjectType::Role);
    let mut request = CreatePermissionRequest::new(name, subject);
    request.comment = Some(comment.to_string());
    let permission = client.create_permission(request).await?;
    assert_typed_status(
        permission.status,
        &permission.status_text,
        201,
        "create_permission",
    )?;
    log_pass(
        "typed permission create",
        "canonical nested subject accepted",
    );
    record_helper_execution(
        "create_permission",
        "canonical permission creation executed",
    )?;
    Ok(permission.id)
}

async fn connect_client(config: &EnvConfig) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let connection = UnixSocketConnection::with_path(&config.socket_path);
    Ok(GmpClient::connect(connection).await?)
}

async fn renew_authenticated_after_response(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    timeout: Duration,
    label: &str,
) -> Result<(), AppError> {
    log_line(&format!(
        "{label} completed at a connection-closing boundary; renewing authenticated session"
    ));
    *client = reconnect_authenticated(config, timeout).await?;
    Ok(())
}

async fn reconnect_authenticated(
    config: &EnvConfig,
    timeout: Duration,
) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let started = tokio::time::Instant::now();
    let mut last_error = String::from("no connection attempt completed");

    while started.elapsed() <= timeout {
        match connect_client(config).await {
            Ok(mut client) => {
                match client
                    .authenticate(AuthenticateRequest::new(&config.username, &config.password))
                    .await
                {
                    Ok(_) => return Ok(client),
                    Err(GvmError::Connection(error)) => {
                        last_error = format!("authentication connection failed: {error}");
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => {
                last_error = format!("connection failed: {error}");
            }
        }
        log_line(&format!(
            "authenticated reconnect unavailable ({last_error}); retrying"
        ));
        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "authenticated reconnect did not succeed within {} seconds; last error: {last_error}",
        timeout.as_secs()
    )))
}

fn assert_status(response: &Response, expected: u16, label: &str) -> Result<(), AppError> {
    let actual = response.status_code().unwrap_or_default();
    ensure(
        actual == expected,
        &format!(
            "{label} returned status {actual}, expected {expected}. Response: {}",
            response_summary(response)?
        ),
    )
}

fn assert_typed_status(
    status: u16,
    status_text: &str,
    expected: u16,
    label: &str,
) -> Result<(), AppError> {
    ensure(
        status == expected,
        &format!("{label}: expected status {expected}, got {status} ({status_text})"),
    )
}

#[cfg(test)]
fn stop_task_status_is_success(status: u16) -> bool {
    status == 200
}

fn task_state_is_stoppable(status: &str) -> bool {
    status == "Running"
}

fn task_state_is_finishing(status: &str) -> bool {
    status == "Processing"
}

fn task_state_has_started(status: &str) -> bool {
    !matches!(status, "New" | "Requested" | "Queued")
}

fn task_state_is_terminal_after_stop(status: &str) -> bool {
    matches!(status, "Stopped" | "Done")
}

fn parse_entity_id(value: &str) -> Result<EntityId, AppError> {
    EntityId::from_str(value).map_err(|_| AppError::InvalidEntityId(value.to_string()))
}

fn response_summary(response: &Response) -> Result<String, AppError> {
    let xml = response.as_str()?;
    Ok(xml.chars().take(240).collect())
}

/// Find resources owned by this harness without touching non-E2E names.
fn e2e_entity_ids(xml: &str, element_name: &str) -> Result<Vec<String>, AppError> {
    let mut reader = Reader::from_str(xml);
    let mut ids = Vec::new();
    let mut current_id: Option<String> = None;
    let mut inside_element = false;
    let mut inside_identity_field = false;
    let mut matched = false;

    loop {
        match reader.read_event()? {
            Event::Start(ref e) if e.name().as_ref() == element_name => {
                inside_element = true;
                current_id = None;
                matched = false;
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == "id" {
                        current_id = Some(
                            attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)?
                                .into_owned(),
                        );
                    }
                }
            }
            Event::End(ref e) if e.name().as_ref() == element_name => {
                if matched {
                    if let Some(id) = current_id.take() {
                        ids.push(id);
                    }
                }
                inside_element = false;
                current_id = None;
                matched = false;
            }
            Event::Start(ref e)
                if inside_element
                    && matches!(e.name().as_ref(), "name" | "comment" | "text" | "value") =>
            {
                inside_identity_field = true;
            }
            Event::End(ref e)
                if matches!(e.name().as_ref(), "name" | "comment" | "text" | "value") =>
            {
                inside_identity_field = false;
            }
            Event::Text(ref e) if inside_element && inside_identity_field => {
                let value = e.as_ref().to_string();
                matched |= is_e2e_owned_value(&value);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(ids)
}

fn is_e2e_owned_value(value: &str) -> bool {
    value.starts_with("rust-gvm-e2e-")
        || matches!(
            value,
            "e2e-target"
                | "e2e-test-target"
                | "e2e-scan-target"
                | "e2e-scan-task"
                | "e2e-port-list"
                | "e2e-cred"
                | "e2e-schedule"
                | "e2e-filter"
                | "e2e-task-target"
                | "e2e-task"
                | "e2e:test-tag"
                | "e2e test note"
                | "e2e test override"
        )
        || value.starts_with("e2e-diff-rust-")
        || value.starts_with("e2e-diff-python-")
}

fn ensure(condition: bool, message: &str) -> Result<(), AppError> {
    if condition {
        Ok(())
    } else {
        Err(AppError::Assertion(message.to_string()))
    }
}

fn log_pass(step: &str, label: &str) {
    runtime::pass(step, label);
    log_line(&format!("[pass] {step} {label}"));
}

fn log_cleanup_result(action: &str, id: &str, status: Option<u16>) -> Result<(), AppError> {
    ensure(
        matches!(status, Some(200 | 202 | 404)),
        &format!("final cleanup {action} {id} returned unexpected status {status:?}"),
    )?;
    let rendered_status = status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    log_line(&format!("[cleanup] {action} {id} -> {rendered_status}"));
    Ok(())
}

fn log_line(message: &str) {
    let _ = writeln!(io::stdout(), "{message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 7))
                .expect("canonical request should encode"),
        )
        .expect("canonical request should be UTF-8")
    }

    #[derive(Debug)]
    struct FakeSession(usize);

    #[derive(Default)]
    struct FakeReadiness {
        plans: VecDeque<VecDeque<Result<FeedReadinessState, &'static str>>>,
        connects: usize,
        authentications: usize,
        unavailable_authentications: usize,
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
            if self.unavailable_authentications > 0 {
                self.unavailable_authentications -= 1;
                return Err(ReadinessFailure::Unavailable(
                    "server error (status 400): The SCAP database is required".to_string(),
                ));
            }
            Ok(())
        }

        async fn feed_state(
            &mut self,
            session: &mut Self::Session,
        ) -> Result<FeedReadinessState, ReadinessFailure> {
            self.plans
                .get_mut(session.0)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(ready_feed(1)))
                .map_err(|message| ReadinessFailure::Dropped(message.to_string()))
        }

        async fn disconnect(&mut self, _session: &mut Self::Session) {
            self.disconnects += 1;
        }
    }

    fn feed_state(
        scan_config_count: usize,
        syncing_feed_count: usize,
        scap_ready: bool,
        cpe_ready: bool,
        cert_ready: bool,
    ) -> FeedReadinessState {
        FeedReadinessState {
            scan_config_count,
            syncing_feed_count,
            scap_ready,
            cpe_ready,
            cert_ready,
        }
    }

    fn ready_feed(scan_config_count: usize) -> FeedReadinessState {
        feed_state(scan_config_count, 0, true, true, true)
    }

    fn readiness_test_policy() -> ReadinessPolicy {
        ReadinessPolicy {
            timeout: Duration::from_secs(1),
            poll_interval: Duration::ZERO,
            max_reconnects: 2,
        }
    }

    const VERSION_RESPONSE: &str = concat!(
        r#"<get_version_response status="200" status_text="OK">"#,
        "<version>22.7</version></get_version_response>"
    );
    const AUTH_RESPONSE: &str = r#"<authenticate_response status="200" status_text="OK"/>"#;
    const EMPTY_PASSWORD_AUTH_RESPONSE: &str =
        r#"<authenticate_response status="400" status_text="Authentication failed"/>"#;
    const RUNNING_TASK_RESPONSE: &str = concat!(
        r#"<get_tasks_response status="200" status_text="OK">"#,
        r#"<task id="task-id"><name>Task</name><status>Running</status></task>"#,
        "<task_count>1<filtered>1</filtered><page>1</page></task_count>",
        "</get_tasks_response>"
    );
    const PROCESSING_TASK_RESPONSE: &str = concat!(
        r#"<get_tasks_response status="200" status_text="OK">"#,
        r#"<task id="task-id"><name>Task</name><status>Processing</status></task>"#,
        "<task_count>1<filtered>1</filtered><page>1</page></task_count>",
        "</get_tasks_response>"
    );
    const DONE_TASK_RESPONSE: &str = concat!(
        r#"<get_tasks_response status="200" status_text="OK">"#,
        r#"<task id="task-id"><name>Task</name><status>Done</status></task>"#,
        "<task_count>1<filtered>1</filtered><page>1</page></task_count>",
        "</get_tasks_response>"
    );
    const START_TASK_RESPONSE: &str = concat!(
        r#"<start_task_response status="202" status_text="OK, request submitted">"#,
        "<report_id>report-id</report_id></start_task_response>"
    );
    const MISSING_REPORT_RESPONSE: &str =
        r#"<delete_report_response status="404" status_text="Failed to find report"/>"#;
    const STOP_TASK_BAD_REQUEST_RESPONSE: &str =
        r#"<stop_task_response status="400" status_text="Internal error stopping task"/>"#;
    const MODIFIED_PERMISSION_RESPONSE: &str = concat!(
        r#"<get_permissions_response status="200" status_text="OK">"#,
        r#"<permission id="permission-id"><name>get_tasks</name>"#,
        "<comment>permission-modified</comment><writable>1</writable><in_use>0</in_use>",
        r#"<subject id="role-id"><name>Role</name><type>role</type></subject>"#,
        "</permission>",
        "<permission_count>1<filtered>1</filtered><page>1</page></permission_count>",
        "</get_permissions_response>"
    );

    type ServerStep = (&'static str, Option<&'static str>);

    fn socket_test_config(path: &Path) -> EnvConfig {
        EnvConfig {
            task_progress_timeout_secs: 3,
            report_export_timeout_secs: 3,
            report_export_poll_interval_secs: 1,
            readiness_timeout_secs: 3,
            readiness_poll_interval_secs: 1,
            readiness_max_reconnects: 2,
            username: "admin".to_string(),
            password: "admin".to_string(),
            socket_path: path.display().to_string(),
            run_scan: false,
            run_id: "socket-policy-test".to_string(),
            namespace: "rust-gvm-e2e-socket-policy-test-".to_string(),
        }
    }

    fn socket_test_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "gce-{}-{}-{nonce:x}.sock",
            std::process::id(),
            &label[..label.len().min(3)]
        ))
    }

    async fn read_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut reader = gvm_protocol::XmlReader::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = stream.read(&mut buffer).await.expect("read request");
            assert_ne!(
                count, 0,
                "client closed before sending the scripted request"
            );
            reader
                .feed(&buffer[..count])
                .expect("scripted request must be valid XML");
            if let Some(frame) = reader.take_frame().expect("extract scripted request") {
                return frame;
            }
        }
    }

    fn request_root(request: &[u8]) -> String {
        let text = std::str::from_utf8(request).expect("request must be UTF-8");
        text.trim_start()
            .strip_prefix('<')
            .expect("request must start with an element")
            .split([' ', '/', '>'])
            .next()
            .expect("request root element")
            .to_string()
    }

    async fn serve_script(listener: UnixListener, sessions: Vec<Vec<ServerStep>>) -> Vec<String> {
        let mut commands = Vec::new();
        for session in sessions {
            let (mut stream, _) = listener.accept().await.expect("accept scripted client");
            for (expected_root, response) in session {
                let request = read_request(&mut stream).await;
                let root = request_root(&request);
                assert_eq!(root, expected_root);
                commands.push(root);
                let Some(response) = response else {
                    break;
                };
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write scripted response");
            }
        }
        commands
    }

    async fn connect_and_authenticate(config: &EnvConfig) -> GmpClient<UnixSocketConnection> {
        let mut client = connect_client(config).await.expect("connect test client");
        client
            .authenticate(AuthenticateRequest::new(&config.username, &config.password))
            .await
            .expect("authenticate test client");
        client
    }

    #[test]
    fn empty_feed_polls_authenticate_only_once_for_one_session() {
        let mut fake = FakeReadiness {
            plans: VecDeque::from([VecDeque::from([
                Ok(feed_state(0, 0, false, false, false)),
                Ok(feed_state(0, 0, false, false, false)),
                Ok(ready_feed(3)),
            ])]),
            ..FakeReadiness::default()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, readiness_test_policy()))
            .expect("feed becomes ready");
        assert_eq!(fake.connects, 1);
        assert_eq!(fake.authentications, 1);
        assert_eq!(fake.disconnects, 1);
    }

    #[test]
    fn dropped_feed_connection_reconnects_and_reauthenticates() {
        let mut fake = FakeReadiness {
            plans: VecDeque::from([
                VecDeque::from([Ok(feed_state(0, 0, false, false, false)), Err("peer reset")]),
                VecDeque::from([Ok(ready_feed(2))]),
            ]),
            ..FakeReadiness::default()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, readiness_test_policy()))
            .expect("feed becomes ready after reconnect");
        assert_eq!(fake.connects, 2);
        assert_eq!(fake.authentications, 2);
        assert_eq!(fake.disconnects, 2);
    }

    #[test]
    fn feed_waits_for_sync_and_all_required_databases() {
        let mut fake = FakeReadiness {
            plans: VecDeque::from([VecDeque::from([
                Ok(feed_state(3, 1, false, false, false)),
                Ok(feed_state(3, 0, false, false, true)),
                Ok(feed_state(3, 0, true, false, true)),
                Ok(feed_state(3, 0, true, true, false)),
                Ok(ready_feed(3)),
            ])]),
            ..FakeReadiness::default()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, readiness_test_policy()))
            .expect("feed databases become ready");
        assert_eq!(fake.connects, 1);
        assert_eq!(fake.authentications, 1);
        assert_eq!(fake.disconnects, 1);
    }

    #[test]
    fn unavailable_authentication_uses_a_fresh_session_without_reconnect_budget() {
        let mut fake = FakeReadiness {
            unavailable_authentications: 1,
            ..FakeReadiness::default()
        };
        let policy = ReadinessPolicy {
            max_reconnects: 0,
            ..readiness_test_policy()
        };
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(wait_for_feed(&mut fake, policy))
            .expect("expected database startup state is retryable");
        assert_eq!(fake.connects, 2);
        assert_eq!(fake.authentications, 2);
        assert_eq!(fake.disconnects, 2);
    }

    #[test]
    fn database_required_errors_are_retryable_only_for_scap_or_cert() {
        let scap = GvmError::Server {
            status: 400,
            message: "The SCAP database is required".to_string(),
        };
        let other = GvmError::Server {
            status: 400,
            message: "The task database is required".to_string(),
        };

        assert!(feed_database_unavailable(&scap, "SCAP"));
        assert!(!feed_database_unavailable(&scap, "CERT"));
        assert!(!feed_database_unavailable(&other, "SCAP"));
        assert!(matches!(
            classify_gvm_readiness_error(scap),
            ReadinessFailure::Unavailable(_)
        ));
        assert!(matches!(
            classify_gvm_readiness_error(other),
            ReadinessFailure::Fatal(_)
        ));
    }

    #[test]
    fn missing_observed_vulnerability_requires_the_exact_typed_rejection() {
        let missing = GvmError::Server {
            status: 404,
            message: "Failed to find vuln '1.3.6.1.4.1.25623.1.0.117946'".to_string(),
        };
        let wrong_status = GvmError::Server {
            status: 400,
            message: "Failed to find vuln '1.3.6.1.4.1.25623.1.0.117946'".to_string(),
        };
        let unrelated = GvmError::Server {
            status: 404,
            message: "Failed to find task 'task-id'".to_string(),
        };

        assert!(missing_observed_vulnerability(&missing));
        assert!(!missing_observed_vulnerability(&wrong_status));
        assert!(!missing_observed_vulnerability(&unrelated));
    }

    #[test]
    fn scan_start_guard_sends_once_and_tracks_the_owned_report() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("scan-start-once");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("start_task", Some(START_TASK_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let task_id = EntityId::new("task-id").expect("valid task ID");
                let mut tracker = CleanupTracker::new(config);
                let mut mutations = ScanMutationGuard::default();

                let report_id =
                    start_scan_task_once(&mut client, &mut tracker, &mut mutations, &task_id)
                        .await
                        .expect("first start_task should be delivered");
                let duplicate =
                    start_scan_task_once(&mut client, &mut tracker, &mut mutations, &task_id)
                        .await
                        .expect_err("second start_task should be blocked locally");

                assert_eq!(report_id.as_str(), "report-id");
                assert!(matches!(
                    duplicate,
                    AppError::DuplicateMutation {
                        operation: "start_task",
                        resource_id,
                    } if resource_id == "task-id"
                ));
                assert_eq!(tracker.report_ids, ["report-id"]);
                tracker.armed = false;

                let commands = server.await.expect("scripted server");
                assert_eq!(commands, ["get_version", "authenticate", "start_task"]);
                assert_eq!(
                    commands
                        .iter()
                        .filter(|command| command.as_str() == "start_task")
                        .count(),
                    1,
                    "the scan flow must never deliver start_task twice"
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn issue_715_help_discovery_normalizes_report_export_command_names() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("report-export-help-normalization");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        (
                            "help",
                            Some(
                                r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name> EXPORT_SCAN_REPORT </name></command></schema></help_response>"#,
                            ),
                        ),
                        (
                            "export_scan_report",
                            Some(
                                r#"<export_scan_report_response status="201" status_text="OK, resource created" id="export-id"/>"#,
                            ),
                        ),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;

                client
                    .discover_commands()
                    .await
                    .expect("help discovery should parse");
                assert_eq!(
                    client.command_support("export_scan_report"),
                    gvm_client::CommandSupport::Supported
                );
                let response = client
                    .export_scan_report(ExportScanReportRequest::new(
                        EntityId::new("report-id").expect("valid report ID"),
                    ))
                    .await
                    .expect("normalized discovery should permit the typed export");
                assert_eq!(response.status, 201);

                let commands = server.await.expect("scripted server");
                assert_eq!(
                    commands,
                    [
                        "get_version",
                        "authenticate",
                        "help",
                        "export_scan_report"
                    ]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn issue_715_nvt_oid_filter_selects_the_executed_info_list_helper() {
        assert!(runtime_helper_path("get_info_list"));
        assert!(!runtime_helper_path("get_nvt"));
    }

    #[test]
    fn empty_password_authentication_server_error_keeps_the_connection_usable() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("empty-password-server-error");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(EMPTY_PASSWORD_AUTH_RESPONSE)),
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("get_version", Some(VERSION_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_client(&config).await.expect("connect test client");
                let mut empty_password = XmlCommand::new("authenticate");
                let credentials = empty_password.add_element("credentials");
                credentials.add_child_with_text("username", &config.username);
                credentials.add_child_with_text("password", "");
                assert_eq!(
                    gvm_protocol::Request::to_bytes(&empty_password),
                    b"<authenticate><credentials><username>admin</username><password></password></credentials></authenticate>"
                );

                let rejected = client.call(empty_password).await;
                assert!(matches!(
                    rejected,
                    Err(GvmError::Server {
                        status: 400,
                        message,
                    }) if message == "Authentication failed"
                ));

                let health_before_authentication = client
                    .get_version(GetVersionRequest::new())
                    .await
                    .expect("same connection remains usable after empty-password GMP error");
                assert_eq!(health_before_authentication.status, 200);
                let authenticated = client
                    .authenticate(AuthenticateRequest::new(&config.username, &config.password))
                    .await
                    .expect("valid authentication succeeds on the same connection");
                assert_eq!(authenticated.status, 200);
                let health_after_authentication = client
                    .get_version(GetVersionRequest::new())
                    .await
                    .expect("authenticated same connection remains usable");
                assert_eq!(health_after_authentication.status, 200);
                client.disconnect().await.expect("disconnect test client");

                assert_eq!(
                    server.await.expect("scripted server"),
                    [
                        "get_version",
                        "authenticate",
                        "get_version",
                        "authenticate",
                        "get_version",
                    ]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn stop_task_server_error_is_typed_and_session_remains_usable() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("stop-task-server-error");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("stop_task", Some(STOP_TASK_BAD_REQUEST_RESPONSE)),
                        ("get_version", Some(VERSION_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let task_id = EntityId::new("task-id").expect("valid task ID");
                let request = StopTaskRequest::new(task_id);
                assert_eq!(request_xml(&request), "<stop_task task_id=\"task-id\"/>");

                let stop = client.stop_task(request).await;
                assert!(matches!(
                    stop,
                    Err(GvmError::Server {
                        status: 400,
                        message,
                    }) if message == "Internal error stopping task"
                ));

                let health = client
                    .get_version(GetVersionRequest::new())
                    .await
                    .expect("same session remains usable after stop_task GMP error");
                assert_eq!(health.status, 200);
                assert_eq!(health.version, "22.7");
                client.disconnect().await.expect("disconnect test client");

                assert_eq!(
                    server.await.expect("scripted server"),
                    ["get_version", "authenticate", "stop_task", "get_version"]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn provisional_report_ids_are_not_cleanup_ownership() {
        let config = socket_test_config(Path::new("/tmp/not-used.sock"));
        let mut tracker = CleanupTracker::new(config);
        let provisional = EntityId::new("0").expect("valid provisional report ID");
        let concrete = EntityId::new("report-id").expect("valid concrete report ID");

        tracker.track_report(&provisional);
        tracker.track_report(&concrete);
        tracker.track_report(&concrete);

        assert_eq!(tracker.report_ids, ["report-id"]);
        tracker.armed = false;
    }

    #[test]
    fn cleanup_treats_an_already_absent_report_as_complete() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("missing-report-cleanup");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("delete_report", Some(MISSING_REPORT_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut tracker = CleanupTracker::new(config);
                let report_id = EntityId::new("report-id").expect("valid report ID");
                tracker.track_report(&report_id);

                tracker
                    .cleanup_now()
                    .await
                    .expect("an already-absent report is cleaned up");

                assert!(tracker.report_ids.is_empty());
                assert!(!tracker.armed);
                assert_eq!(
                    server.await.expect("scripted server"),
                    ["get_version", "authenticate", "delete_report"]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn known_closing_response_renews_before_the_next_command() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("response-boundary");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("start_task", Some(START_TASK_RESPONSE)),
                        ],
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("get_tasks", Some(RUNNING_TASK_RESPONSE)),
                        ],
                    ],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let task_id = EntityId::new("task-id").expect("valid task ID");

                let started = client
                    .start_task(StartTaskRequest::new(task_id.clone()))
                    .await
                    .expect("start task");
                assert_eq!(started.status, 202);
                renew_authenticated_after_response(
                    &mut client,
                    &config,
                    Duration::from_secs(2),
                    "known closing response",
                )
                .await
                .expect("renew after known closing response");
                let tasks = get_tasks_with_reconnect(
                    &mut client,
                    &config,
                    GetTasksRequest {
                        filter_string: Some("uuid=task-id".to_string()),
                        details: Some(true),
                        ..Default::default()
                    },
                    Duration::from_secs(2),
                    "post-start task read",
                )
                .await
                .expect("read task on replacement session");

                assert_eq!(tasks.items[0].status.as_deref(), Some("Running"));
                assert_eq!(
                    server.await.expect("scripted server"),
                    [
                        "get_version",
                        "authenticate",
                        "start_task",
                        "get_version",
                        "authenticate",
                        "get_tasks",
                    ]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn idempotent_task_read_retries_after_disconnect() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("idempotent-read");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("get_tasks", None),
                        ],
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("get_tasks", Some(RUNNING_TASK_RESPONSE)),
                        ],
                    ],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;

                let tasks = get_tasks_with_reconnect(
                    &mut client,
                    &config,
                    GetTasksRequest {
                        filter_string: Some("uuid=task-id".to_string()),
                        details: Some(true),
                        ..Default::default()
                    },
                    Duration::from_secs(2),
                    "retry test task read",
                )
                .await
                .expect("idempotent read should recover");

                assert_eq!(tasks.items[0].status.as_deref(), Some("Running"));
                assert_eq!(
                    server.await.expect("scripted server"),
                    [
                        "get_version",
                        "authenticate",
                        "get_tasks",
                        "get_version",
                        "authenticate",
                        "get_tasks",
                    ]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn pre_stop_grace_observes_a_terminal_scan_transition() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("pre-stop-grace");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("get_tasks", Some(RUNNING_TASK_RESPONSE)),
                        ("get_tasks", Some(DONE_TASK_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let task_id = EntityId::new("task-id").expect("valid task ID");

                let status = settle_task_state_before_stop(
                    &mut client,
                    &config,
                    &task_id,
                    Duration::from_secs(2),
                    Duration::from_secs(2),
                )
                .await
                .expect("terminal transition during grace period");

                assert_eq!(status, "Done");
                assert_eq!(
                    server.await.expect("scripted server"),
                    ["get_version", "authenticate", "get_tasks", "get_tasks",]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn pre_stop_wait_observes_processing_to_done_transition() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("pre-stop-processing");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![vec![
                        ("get_version", Some(VERSION_RESPONSE)),
                        ("authenticate", Some(AUTH_RESPONSE)),
                        ("get_tasks", Some(PROCESSING_TASK_RESPONSE)),
                        ("get_tasks", Some(DONE_TASK_RESPONSE)),
                    ]],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let task_id = EntityId::new("task-id").expect("valid task ID");

                let status = settle_task_state_before_stop(
                    &mut client,
                    &config,
                    &task_id,
                    Duration::from_secs(2),
                    Duration::from_millis(100),
                )
                .await
                .expect("processing transition should settle as Done");

                assert_eq!(status, "Done");
                assert_eq!(
                    server.await.expect("scripted server"),
                    ["get_version", "authenticate", "get_tasks", "get_tasks",]
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn mutation_response_loss_is_reconciled_without_retrying_mutation() {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime")
            .block_on(async {
                let path = socket_test_path("mutation-reconcile");
                let listener = UnixListener::bind(&path).expect("bind scripted socket");
                let server = tokio::spawn(serve_script(
                    listener,
                    vec![
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("modify_permission", None),
                        ],
                        vec![
                            ("get_version", Some(VERSION_RESPONSE)),
                            ("authenticate", Some(AUTH_RESPONSE)),
                            ("get_permissions", Some(MODIFIED_PERMISSION_RESPONSE)),
                        ],
                    ],
                ));
                let config = socket_test_config(&path);
                let mut client = connect_and_authenticate(&config).await;
                let permission_id = EntityId::new("permission-id").expect("valid permission ID");
                let role_id = EntityId::new("role-id").expect("valid role ID");

                modify_role_permission_reconciled(
                    &mut client,
                    &config,
                    &permission_id,
                    &role_id,
                    "permission-modified",
                )
                .await
                .expect("ambiguous mutation should reconcile");

                let commands = server.await.expect("scripted server");
                assert_eq!(
                    commands,
                    [
                        "get_version",
                        "authenticate",
                        "modify_permission",
                        "get_version",
                        "authenticate",
                        "get_permissions",
                    ]
                );
                assert_eq!(
                    commands
                        .iter()
                        .filter(|command| command.as_str() == "modify_permission")
                        .count(),
                    1,
                    "a mutation with an ambiguous response must never be retried"
                );
                std::fs::remove_file(&path).expect("remove scripted socket");
            });
    }

    #[test]
    fn tls_certificate_create_request_uses_base64_encoded_pem() {
        let certificate = tls_certificate_data();
        let mut request = CreateTlsCertificateRequest::new(certificate.clone());
        request.name = Some("tls-certificate".to_string());
        let xml = request_xml(&request);

        assert!(xml.contains("<certificate>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"));
        assert!(!xml.contains("BEGIN CERTIFICATE"));
        assert!(certificate.starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn stop_task_accepts_only_synchronous_success() {
        assert!(stop_task_status_is_success(200));

        for status in [0, 201, 202, 204, 400, 404, 500] {
            assert!(
                !stop_task_status_is_success(status),
                "unexpectedly accepted stop_task status {status}"
            );
        }
    }

    #[test]
    fn completed_scan_is_not_stopped_from_a_stale_running_snapshot() {
        assert!(task_state_is_stoppable("Running"));

        for status in [
            "Stop Requested",
            "Done",
            "Stopped",
            "Interrupted",
            "Internal Error",
        ] {
            assert!(
                !task_state_is_stoppable(status),
                "completed scan state {status} must not be sent stop_task"
            );
        }
    }

    #[test]
    fn processing_scan_is_allowed_to_finish_without_a_stop_mutation() {
        assert!(task_state_is_finishing("Processing"));
        assert!(!task_state_is_stoppable("Processing"));

        for status in ["Running", "Done", "Stopped", "Interrupted"] {
            assert!(
                !task_state_is_finishing(status),
                "non-processing scan state {status} must not use the finishing wait path"
            );
        }
    }

    #[test]
    fn scan_selects_openvas_instead_of_the_first_cve_scanner() {
        let scanners = GetScannersResponse::from_response(&Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="cve"><name>CVE</name><type>CVE</type></scanner>
                <scanner id="openvas"><name>OpenVAS</name><type>OpenVAS</type></scanner>
                <scanner_count>2<filtered>2</filtered></scanner_count>
            </get_scanners_response>"#,
        ))
        .expect("typed scanner response should parse");

        assert_eq!(
            select_scan_scanner(&scanners)
                .expect("OpenVAS scanner should be selected")
                .meta
                .id
                .as_str(),
            "openvas"
        );
    }

    #[test]
    fn scan_selects_numeric_openvasd_instead_of_numeric_cve() {
        let scanners = GetScannersResponse::from_response(&Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="cve"><name>CVE</name><type>3</type></scanner>
                <scanner id="openvasd"><name>OpenVASD</name><type>6</type></scanner>
                <scanner_count>2<filtered>2</filtered></scanner_count>
            </get_scanners_response>"#,
        ))
        .expect("typed scanner response should parse");

        assert_eq!(
            select_scan_scanner(&scanners)
                .expect("OpenVASD scanner should be selected")
                .meta
                .id
                .as_str(),
            "openvasd"
        );
    }

    #[test]
    fn scan_waits_through_queued_and_only_accepts_stopped_or_done_after_stop() {
        for status in ["New", "Requested", "Queued"] {
            assert!(!task_state_has_started(status));
        }
        assert!(task_state_has_started("Running"));
        assert!(task_state_is_terminal_after_stop("Stopped"));
        assert!(task_state_is_terminal_after_stop("Done"));
        assert!(!task_state_is_terminal_after_stop("Running"));
        assert!(!task_state_is_terminal_after_stop("Interrupted"));
    }

    #[test]
    fn run_id_is_sanitized_and_bounded() {
        assert_eq!(
            sanitize_run_id("Run_118 / Attempt.2").expect("valid"),
            "run-118---attempt-2"
        );
        assert!(sanitize_run_id("___").is_err());
        assert!(sanitize_run_id(&"a".repeat(97)).is_err());
    }

    #[test]
    fn cleanup_selection_never_matches_unowned_resources() {
        let xml = r#"
          <get_targets_response status="200">
            <target id="00000000-0000-0000-0000-000000000001">
              <name>production-target</name>
              <comment>must survive</comment>
            </target>
            <target id="00000000-0000-0000-0000-000000000002">
              <name>rust-gvm-e2e-run-118-target</name>
            </target>
          </get_targets_response>
        "#;
        assert_eq!(
            e2e_entity_ids(xml, "target").expect("parse"),
            vec!["00000000-0000-0000-0000-000000000002"]
        );
    }

    #[test]
    fn cleanup_selection_recognizes_issue_seven_legacy_names_only() {
        let xml = r#"
          <get_targets_response status="200">
            <target id="00000000-0000-0000-0000-000000000003">
              <name>e2e-test-target</name>
            </target>
            <target id="00000000-0000-0000-0000-000000000004">
              <name>e2e-test-target-but-not-owned</name>
            </target>
            <target id="00000000-0000-0000-0000-000000000005">
              <name>e2e-target</name>
            </target>
            <target id="00000000-0000-0000-0000-000000000006">
              <name>e2e-target-production</name>
            </target>
          </get_targets_response>
        "#;
        assert_eq!(
            e2e_entity_ids(xml, "target").expect("parse"),
            vec![
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000005"
            ]
        );
    }

    #[test]
    fn help_command_names_match_registry_case() {
        assert_eq!(canonical_help_command(" GET_TASKS "), "get_tasks");
    }

    #[test]
    fn live_help_is_authoritative_over_registry_version_metadata() {
        let help_commands = BTreeSet::from(["get_report_hosts".to_string()]);
        let registry_gate = false;
        assert!(live_help_supports(&help_commands, "get_report_hosts"));
        assert!(!registry_gate);
    }

    #[test]
    fn resource_names_request_includes_mandatory_resource_type() {
        let request = resource_names_request();
        let xml = request_xml(&request);

        assert_eq!(xml, r#"<get_resource_names type="TARGET"/>"#);
    }

    #[test]
    fn schedule_modification_preserves_the_created_icalendar_contract() {
        let create_opts =
            e2e_create_schedule_request("schedule-created".into(), "schedule comment".into());
        let modify_opts = e2e_modify_schedule_request(
            EntityId::new("schedule-id").expect("valid id"),
            "schedule-modified".into(),
            Some("schedule-renamed".into()),
        );

        assert_eq!(create_opts.icalendar, modify_opts.icalendar);
        assert_eq!(create_opts.timezone, modify_opts.timezone);
        assert_eq!(modify_opts.comment.as_deref(), Some("schedule-modified"));
        assert_eq!(modify_opts.name.as_deref(), Some("schedule-renamed"));
    }

    #[test]
    fn typed_schedule_modify_request_uses_live_id_and_icalendar_contract() {
        let schedule_id = EntityId::new("created-schedule").expect("valid id");
        let request = e2e_modify_schedule_request(
            schedule_id,
            "schedule-modified".into(),
            Some("schedule-renamed".into()),
        );
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            format!(
                "<modify_schedule schedule_id=\"created-schedule\"><name>schedule-renamed</name><comment>schedule-modified</comment><icalendar>{E2E_SCHEDULE_ICALENDAR}</icalendar><timezone>{E2E_SCHEDULE_TIMEZONE}</timezone></modify_schedule>"
            )
        );
    }

    #[test]
    fn port_range_request_references_the_live_port_list_with_gmp_child_elements() {
        let port_list_id = EntityId::new("created-port-list").expect("valid id");
        let request = create_port_range_request(&port_list_id, 101, 102);
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            concat!(
                "<create_port_range><port_list id=\"created-port-list\"/>",
                "<start>101</start><end>102</end><type>TCP</type></create_port_range>"
            )
        );
    }

    #[test]
    fn scan_result_listing_uses_the_canonical_report_filter_without_pagination() {
        let report_id = EntityId::new("scan-report-id").expect("valid report id");
        let request = scan_report_results_request(&report_id);
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            r#"<get_results details="0" filter="report_id=scan-report-id rows=-1" get_counts="1"/>"#
        );
    }

    #[test]
    fn epss_regression_fixture_routes_all_four_fields_through_filter_and_sort() {
        let fixture = epss_regression_fixture().expect("EPSS regression fixture parses");
        assert_eq!(
            fixture
                .probes
                .iter()
                .map(|probe| probe.field.as_str())
                .collect::<Vec<_>>(),
            [
                "epss_score",
                "epss_percentile",
                "max_epss_score",
                "max_epss_percentile",
            ]
        );
        let report_id = EntityId::new("epss-report-id").expect("valid report id");
        for probe in &fixture.probes {
            let filter_xml =
                request_xml(&epss_results_request(&report_id, &probe.filter_expression));
            assert_eq!(
                filter_xml,
                format!(
                    r#"<get_results details="0" filter="report_id=epss-report-id {}&gt;0 rows=-1" get_counts="1"/>"#,
                    probe.field
                )
            );
            let sort_xml = request_xml(&epss_results_request(&report_id, &probe.sort_expression));
            assert_eq!(
                sort_xml,
                format!(
                    r#"<get_results details="0" filter="report_id=epss-report-id sort={} rows=-1" get_counts="1"/>"#,
                    probe.field
                )
            );
        }
    }

    #[test]
    fn epss_disposition_accepts_abort_only_for_exact_known_affected_release() {
        let fixture = epss_regression_fixture().expect("EPSS regression fixture parses");
        let evidence = |version: &str, revision: Option<&str>| EpssDeploymentEvidence {
            gvmd_version: version.to_string(),
            gvmd_source_revision: revision.map(ToString::to_string),
            gvmd_image_digest: "registry.example/gvmd@sha256:exact".to_string(),
            source_specific_image: false,
        };

        let affected = epss_expected_disposition(&fixture, &evidence("26.40.2", None));
        assert_eq!(affected, EpssExpectedDisposition::KnownAffectedBaseline);
        assert!(affected.accepts_connection_abort());

        let fixed = epss_expected_disposition(
            &fixture,
            &evidence("26.40.2", Some(&fixture.fixed_source_revision)),
        );
        assert_eq!(fixed, EpssExpectedDisposition::FixedSourceMustPass);
        assert!(!fixed.accepts_connection_abort());

        let source_specific_unknown = EpssDeploymentEvidence {
            source_specific_image: true,
            ..evidence("26.40.2", Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        };
        assert_eq!(
            epss_expected_disposition(&fixture, &source_specific_unknown),
            EpssExpectedDisposition::UnclassifiedMustPass
        );

        let unclassified = epss_expected_disposition(&fixture, &evidence("26.40.3", None));
        assert_eq!(unclassified, EpssExpectedDisposition::UnclassifiedMustPass);
        assert!(!unclassified.accepts_connection_abort());
    }

    #[test]
    fn epss_known_bug_requires_a_read_side_server_abort_and_dead_same_session() {
        let eof = GvmError::Connection(ConnectionError::ReadFailed(io::Error::from(
            io::ErrorKind::UnexpectedEof,
        )));
        let reset = GvmError::Connection(ConnectionError::ReadFailed(io::Error::from(
            io::ErrorKind::ConnectionReset,
        )));
        let timeout = GvmError::Timeout(Duration::from_secs(1));
        let not_connected = GvmError::Connection(ConnectionError::NotConnected);

        assert!(epss_error_is_connection_abort(&eof));
        assert!(epss_error_is_connection_abort(&reset));
        assert!(!epss_error_is_connection_abort(&timeout));
        assert!(epss_health_confirms_lost_connection(&not_connected));
        assert!(!epss_health_confirms_lost_connection(&eof));
    }

    #[test]
    fn epss_release_parser_rejects_tags_and_partial_versions() {
        assert_eq!(parse_release_triplet("26.40.2"), Some((26, 40, 2)));
        for invalid in ["stable", "v26.40.2", "26.40", "26.40.2-dev", "26.40.2.1"] {
            assert_eq!(parse_release_triplet(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn scan_result_detail_selection_is_stable_by_result_id_and_allows_empty_reports() {
        let response = GetResultsResponse::from_response(&Response::from(
            r#"<get_results_response status="200" status_text="OK">
                <result id="result-z"><name>Last from server</name></result>
                <result id="result-a"><name>First by identity</name></result>
            </get_results_response>"#,
        ))
        .expect("typed results parse");

        assert_eq!(
            select_deterministic_scan_result(&response)
                .expect("a result is selected")
                .meta
                .id
                .as_str(),
            "result-a"
        );

        let empty = GetResultsResponse::from_response(&Response::from(
            r#"<get_results_response status="200" status_text="OK"/>"#,
        ))
        .expect("empty typed results parse");
        assert!(select_deterministic_scan_result(&empty).is_none());
    }

    #[test]
    fn report_config_singular_read_selection_is_stable_and_allows_empty_lists() {
        let response = GetReportConfigsResponse::from_response(&Response::from(
            r#"<get_report_configs_response status="200" status_text="OK">
                <report_config id="config-z"><name>Zed</name></report_config>
                <report_config id="config-a"><name>Alpha</name></report_config>
            </get_report_configs_response>"#,
        ))
        .expect("typed report configs parse");
        assert_eq!(
            select_deterministic_report_config_id(&response)
                .expect("a report config is selected")
                .as_str(),
            "config-a"
        );

        let empty = GetReportConfigsResponse::from_response(&Response::from(
            r#"<get_report_configs_response status="200" status_text="OK"/>"#,
        ))
        .expect("empty typed report configs parse");
        assert!(select_deterministic_report_config_id(&empty).is_none());
    }

    #[test]
    fn scan_export_format_selection_is_usable_and_deterministic() {
        let response = GetReportFormatsResponse::from_response(&Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="inactive"><name>Inactive</name><active>0</active><content_type>text/plain</content_type><extension>txt</extension></report_format>
                <report_format id="missing-extension"><name>Incomplete</name><active>1</active><content_type>text/plain</content_type></report_format>
                <report_format id="format-z"><name>Z</name><active>1</active><content_type>application/pdf</content_type><extension>pdf</extension></report_format>
                <report_format id="format-a"><name>A</name><active>1</active><content_type>text/xml</content_type><extension>xml</extension></report_format>
            </get_report_formats_response>"#,
        ))
        .expect("typed report formats parse");

        let selected = select_usable_report_format(&response).expect("usable format");

        assert_eq!(selected.meta.id.as_str(), "format-a");
        assert!(selected.active);
        assert_eq!(selected.content_type.as_deref(), Some("text/xml"));
        assert_eq!(selected.extension.as_deref(), Some("xml"));
    }

    #[test]
    fn scan_export_format_selection_rejects_inactive_or_incomplete_formats() {
        let response = GetReportFormatsResponse::from_response(&Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="inactive"><name>Inactive</name><active>0</active><content_type>text/plain</content_type><extension>txt</extension></report_format>
                <report_format id="incomplete"><name>Incomplete</name><active>1</active><content_type>text/plain</content_type></report_format>
            </get_report_formats_response>"#,
        ))
        .expect("typed report formats parse");

        let error = select_usable_report_format(&response)
            .expect_err("no format satisfies the export contract");

        assert_eq!(
            error.to_string(),
            "typed report-format selection requires an active format with content type and extension"
        );
    }

    #[test]
    fn gmp_22_8_gate_requires_the_exact_typed_rejection() {
        let exact = Err::<(), _>(GvmError::UnsupportedCommand {
            command: "get_report_export".to_string(),
            version: GmpVersion(22, 7),
            required: "22.8",
        });
        assert!(assert_gmp_22_8_rejection(exact, "get_report_export", GmpVersion(22, 7)).is_ok());

        for rejection in [
            GvmError::UnsupportedCommand {
                command: "get_reports".to_string(),
                version: GmpVersion(22, 7),
                required: "22.8",
            },
            GvmError::UnsupportedCommand {
                command: "get_report_export".to_string(),
                version: GmpVersion(22, 6),
                required: "22.8",
            },
            GvmError::UnsupportedCommand {
                command: "get_report_export".to_string(),
                version: GmpVersion(22, 7),
                required: "22.7",
            },
        ] {
            assert!(assert_gmp_22_8_rejection(
                Err::<(), _>(rejection),
                "get_report_export",
                GmpVersion(22, 7),
            )
            .is_err());
        }
    }

    #[test]
    fn gmp_22_8_observation_evidence_names_help_gate_and_no_wire_call() {
        assert_eq!(
            gmp_22_8_rejection_evidence(
                "get_report_export",
                "get_reports",
                GmpVersion(22, 7),
            ),
            "live help advertised get_reports; canonical typed get_report_export was rejected locally because GMP 22.7 is below required 22.8; no wire request was sent"
        );
    }

    #[test]
    fn gmp_22_7_plan_marks_both_report_export_helpers_semantically_ineligible() {
        let catalog: FeatureCatalog =
            serde_json::from_str(include_str!("../../../coverage/feature-catalog.json"))
                .expect("feature catalog parses");
        let inputs = plan_inputs(&catalog, GmpVersion(22, 7));

        for helper in ["get_report_export", "get_report_export_with_opts"] {
            let input = inputs
                .iter()
                .find(|input| input.kind == PlanEntryKind::Helper && input.name == helper)
                .expect("report-export helper is planned");
            assert!(!input.semantic_eligible);
            assert!(input.semantic_evidence.contains("requires GMP 22.8"));
            assert!(input.semantic_evidence.contains("negotiated GMP 22.7"));
            assert!(input
                .semantic_evidence
                .contains("no wire request is eligible"));
        }
    }

    #[test]
    fn setting_modify_request_base64_encodes_the_value_required_by_gmp() {
        let setting_id = EntityId::new("setting-id").expect("valid setting id");
        let request = modify_setting_request(&setting_id, "Europe/Berlin");
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            r#"<modify_setting setting_id="setting-id"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"#
        );
    }

    #[test]
    fn isolated_user_cleanup_uses_one_direct_delete_request() {
        let user_id = EntityId::new("user-id").expect("valid user id");
        let request = delete_user_directly_request(&user_id);
        let xml = request_xml(&request);

        assert_eq!(xml, r#"<delete_user user_id="user-id"/>"#);
    }

    #[test]
    fn import_report_fixture_builds_as_embedded_command_xml() {
        let task_id = EntityId::new("import-task").expect("valid task id");
        let report_xml = include_str!("../../../fixtures/import-report.xml")
            .replace("{{RUN_NAME}}", "imported-report")
            .replace("{{REPORT_ID}}", "89245cdb-8f0a-4ae9-8505-d60713578915");
        let mut request = ImportReportRequest::new(task_id, report_xml.as_bytes());
        request.in_assets = Some(false);
        let xml = request_xml(&request);

        assert!(xml.starts_with(r#"<create_report><report "#));
        assert!(!xml.contains("<?xml"));
        assert!(!xml.contains("<!DOCTYPE"));
        assert!(xml.ends_with(
            "</report>\n<task id=\"import-task\"/><in_assets>0</in_assets></create_report>"
        ));
    }

    #[test]
    fn scanner_clone_request_preserves_the_live_scanner_endpoint() {
        let scanner_id = EntityId::new("socket-backed-scanner").expect("valid scanner id");
        let request = CloneScannerRequest::new(scanner_id);
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            "<create_scanner><copy>socket-backed-scanner</copy></create_scanner>"
        );
        assert!(!xml.contains("<host>"));
    }

    #[test]
    fn scanner_lifecycle_selects_a_cloneable_type_after_cve() {
        let scanners = GetScannersResponse::from_response(&Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="cve"><name>CVE Scanner</name><type>CVE</type></scanner>
                <scanner id="openvas"><name>OpenVAS Scanner</name><type>OpenVAS</type></scanner>
            </get_scanners_response>"#,
        ))
        .expect("typed scanner response should parse");

        let selected = select_cloneable_scanner(&scanners).expect("OpenVAS scanner is cloneable");

        assert_eq!(selected.meta.id.as_str(), "openvas");
        assert_eq!(selected.scanner_type.as_deref(), Some("OpenVAS"));
    }

    #[test]
    fn scanner_lifecycle_reports_no_cloneable_scanner_types() {
        let scanners = GetScannersResponse::from_response(&Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="cve"><name>CVE Scanner</name><type>CVE</type></scanner>
                <scanner id="unknown"><name>Unknown Scanner</name><type>99</type></scanner>
                <scanner id="missing"><name>Missing Type</name></scanner>
            </get_scanners_response>"#,
        ))
        .expect("typed scanner response should parse");

        let error = select_cloneable_scanner(&scanners)
            .expect_err("CVE, unknown, and missing types are not cloneable");

        assert_eq!(
            error.to_string(),
            "scanner lifecycle requires a cloneable non-CVE scanner; get_scanners returned types [CVE, 99, <missing>]"
        );
    }

    #[test]
    fn report_export_helpers_follow_the_semantic_version_gate() {
        assert!(
            !conditional_helper_available("get_report_export", GmpVersion(22, 7))
                .expect("export helper has conditional coverage")
        );
        assert!(
            !conditional_helper_available("get_report_export_with_opts", GmpVersion(22, 7))
                .expect("export-with-options helper has conditional coverage")
        );
        assert!(
            conditional_helper_available("get_report_export", GmpVersion(22, 8))
                .expect("export helper has conditional coverage")
        );
    }

    #[test]
    fn asynchronous_report_export_states_have_exact_active_and_terminal_sets() {
        for state in ["pending", "running", "cancel_requested"] {
            assert!(report_export_status_is_active(state), "{state}");
            assert!(!report_export_status_is_terminal(state), "{state}");
        }
        for state in ["done", "error", "canceled", "expired"] {
            assert!(!report_export_status_is_active(state), "{state}");
            assert!(report_export_status_is_terminal(state), "{state}");
        }
        for state in ["", "complete", "cancelled", "queued"] {
            assert!(!report_export_status_is_active(state), "{state}");
            assert!(!report_export_status_is_terminal(state), "{state}");
        }
    }

    #[test]
    fn report_export_tracker_blocks_cancel_and_download_replay() {
        let mut tracker = CleanupTracker::new(socket_test_config(Path::new(
            "/tmp/rust-gvm-e2e-report-export-test.sock",
        )));
        tracker.armed = false;
        let export_id = EntityId::new("report-export-id").expect("valid export id");

        tracker.track_report_export(&export_id);
        tracker.track_report_export(&export_id);
        assert_eq!(tracker.report_exports.len(), 1);
        tracker
            .mark_report_export_cancel_attempted(&export_id)
            .expect("first cancellation attempt is owned");
        assert!(tracker
            .mark_report_export_cancel_attempted(&export_id)
            .expect_err("cancellation replay must be blocked")
            .to_string()
            .contains("duplicate cancel_report_export"));
        tracker
            .mark_report_export_download_attempted(&export_id)
            .expect("first download attempt is owned");
        assert!(tracker
            .mark_report_export_download_attempted(&export_id)
            .expect_err("download replay must be blocked")
            .to_string()
            .contains("duplicate download_report_export"));
    }

    #[test]
    fn community_report_export_variant_fixtures_are_explicitly_unavailable() {
        let descriptor: FixtureDescriptor =
            serde_json::from_str(include_str!("../../../fixtures/community-provider.json"))
                .expect("fixture descriptor parses");
        for fixture in [
            "audit_report",
            "audit_report_pair",
            "delta_scan_report_pair",
            "report_export_cancellation_window",
        ] {
            let evidence = descriptor
                .fixtures
                .get(fixture)
                .expect("report-export fixture remains inventory-visible");
            assert_eq!(evidence.state, ProbeState::Unavailable, "{fixture}");
            assert!(!evidence.detail.trim().is_empty(), "{fixture}");
        }
    }

    #[test]
    fn only_cleanup_safe_scan_export_helpers_are_deterministic_runtime_paths() {
        for helper in [
            "export_scan_report",
            "get_report_exports",
            "download_report_export",
        ] {
            assert!(runtime_helper_path(helper), "{helper}");
        }
        for helper in [
            "cancel_report_export",
            "export_audit_report",
            "export_delta_audit_report",
            "export_delta_scan_report",
        ] {
            assert!(!runtime_helper_path(helper), "{helper}");
        }
    }

    #[test]
    fn scan_report_helper_call_path_requires_advertisement_and_semantic_version() {
        assert!(
            !conditional_helper_call_allowed("get_scan_report", true, GmpVersion(22, 7))
                .expect("scan report helper has conditional coverage")
        );
        assert!(
            conditional_helper_call_allowed("get_scan_report", true, GmpVersion(22, 8))
                .expect("scan report helper has conditional coverage")
        );
        assert!(
            !conditional_helper_call_allowed("get_scan_report", false, GmpVersion(22, 8))
                .expect("unadvertised scan report helper must not be called")
        );
    }

    #[test]
    fn report_drilldowns_skip_advertised_but_ineligible_helpers_without_invoking_them() {
        let advertised: BTreeSet<String> = CONDITIONAL_REPORT_DRILLDOWN_HELPERS
            .iter()
            .map(|helper_name| {
                conditional_surface_wire_command(helper_name)
                    .expect("report drilldown surface has current or migration evidence")
                    .to_string()
            })
            .collect();

        for helper_name in CONDITIONAL_REPORT_DRILLDOWN_HELPERS {
            let mut invoked = false;
            if conditional_report_drilldown_call_allowed(
                helper_name,
                &advertised,
                GmpVersion(22, 7),
            )
            .expect("report drilldown helper has a semantic capability gate")
            {
                invoked = true;
            }
            assert!(
                !invoked,
                "GMP 22.7 must not invoke ineligible advertised helper {helper_name}"
            );
        }
    }

    #[test]
    fn report_drilldowns_allow_advertised_helpers_at_their_semantic_minimum() {
        let advertised: BTreeSet<String> = CONDITIONAL_REPORT_DRILLDOWN_HELPERS
            .iter()
            .map(|helper_name| {
                conditional_surface_wire_command(helper_name)
                    .expect("report drilldown surface has current or migration evidence")
                    .to_string()
            })
            .collect();

        for helper_name in CONDITIONAL_REPORT_DRILLDOWN_HELPERS {
            let mut invoked = false;
            if conditional_report_drilldown_call_allowed(
                helper_name,
                &advertised,
                GmpVersion(22, 8),
            )
            .expect("report drilldown helper has a semantic capability gate")
            {
                invoked = true;
            }
            assert!(
                invoked,
                "GMP 22.8 must invoke advertised helper {helper_name}"
            );
        }

        assert_eq!(
            conditional_surface_wire_command("get_report_vulnerabilities")
                .expect("removed alias has explicit replacement evidence"),
            "get_report_vulns"
        );
    }

    #[test]
    fn provisional_start_report_id_resolves_from_task_linkage() {
        let provisional = EntityId::new("0").expect("valid provisional id");
        let current = EntityId::new("current-report").expect("valid current report id");
        let last = EntityId::new("last-report").expect("valid last report id");

        assert_eq!(
            select_scan_report_id(&provisional, Some(&current), Some(&last)),
            Some(current.clone())
        );
        assert_eq!(
            select_scan_report_id(&provisional, None, Some(&last)),
            Some(last)
        );
    }

    #[test]
    fn task_report_linkage_accepts_current_or_last_report_only_by_exact_id() {
        let response = GetTasksResponse::from_response(&Response::from(
            r#"<get_tasks_response status="200" status_text="OK">
                <task id="task-current"><name>Current</name><current_report><report id="report-current"/></current_report></task>
                <task id="task-last"><name>Last</name><last_report><report id="report-last"/></last_report></task>
            </get_tasks_response>"#,
        ))
        .expect("typed task response parses");
        let current = EntityId::new("report-current").expect("valid current report id");
        let last = EntityId::new("report-last").expect("valid last report id");
        let other = EntityId::new("report-other").expect("valid other report id");

        assert!(task_links_report(&response.items[0], &current));
        assert!(task_links_report(&response.items[1], &last));
        assert!(!task_links_report(&response.items[0], &last));
        assert!(!task_links_report(&response.items[1], &other));
    }

    #[test]
    fn concrete_start_report_id_is_preserved() {
        let started = EntityId::new("started-report").expect("valid started report id");
        let stale = EntityId::new("older-report").expect("valid stale report id");

        assert_eq!(
            select_scan_report_id(&started, Some(&stale), None),
            Some(started)
        );
    }
}
