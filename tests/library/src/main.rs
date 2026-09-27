// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Manual E2E harness for a real Greenbone Community container stack.

#![allow(clippy::print_stdout, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::process::Command;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use gvm_client::{parse_version_text, GmpClient, GvmError};
use gvm_connection::{
    GvmConnection, SshAuth, SshConfig, SshConnection, TlsClientIdentity, TlsConfig, TlsConnection,
    UnixSocketConnection,
};
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
use gvm_gmp::responses::scanner::GetScannersResponse;
use gvm_gmp::responses::task::GetTasksResponse;
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
use serde_json::Value;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::{sleep, Instant};

use gvm_community_e2e::runtime::{self, FeatureState, Outcome};
use gvm_community_e2e::{Disposition, COMMAND_COVERAGE};
#[cfg(test)]
use gvm_community_e2e::{HELPER_COVERAGE, HELPER_MIGRATIONS};

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
            cleanup_previous_runs(&config).await?;
            discover_community(&config).await?;
            run_typed_read_suite(&config).await?;
            run_config_scanner_lifecycles(&config, &mut tracker).await?;
            run_smoke_suite(&config, &mut tracker).await?;
            run_crud_suite(&config, &mut tracker).await?;
            run_secinfo_suite(&config).await?;
            tracker.cleanup_now().await?;
            log_line("Community devel-fast lane passed");
        }
        Mode::Scan => {
            let mut tracker = CleanupTracker::new(config.clone());
            cleanup_previous_runs(&config).await?;
            discover_community(&config).await?;
            let mut client = connect_client(&config).await?;
            run_scan_suite(&mut client, &config, &mut tracker).await?;
            client.disconnect().await?;
            tracker.cleanup_now().await?;
            log_line("Community devel-scan lane passed");
        }
        Mode::Isolated => {
            let mut tracker = CleanupTracker::new(config.clone());
            cleanup_previous_runs(&config).await?;
            discover_community(&config).await?;
            run_isolated_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("Community devel-isolated lane passed");
        }
        Mode::Transport => {
            run_transport_suite(&config).await?;
            log_line("Community devel-transport lane completed");
        }
        Mode::Differential => {
            let mut tracker = CleanupTracker::new(config.clone());
            cleanup_previous_runs(&config).await?;
            discover_community(&config).await?;
            run_differential_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
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
    permission_ids: Vec<String>,
    report_config_ids: Vec<String>,
    report_format_ids: Vec<String>,
    role_ids: Vec<String>,
    tls_certificate_ids: Vec<String>,
    user_ids: Vec<String>,
    armed: bool,
}

impl CleanupTracker {
    fn new(config: EnvConfig) -> Self {
        Self {
            config,
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
            permission_ids: Vec::new(),
            report_config_ids: Vec::new(),
            report_format_ids: Vec::new(),
            role_ids: Vec::new(),
            tls_certificate_ids: Vec::new(),
            user_ids: Vec::new(),
            armed: true,
        }
    }

    fn is_empty(&self) -> bool {
        self.report_ids.is_empty()
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
            && self.permission_ids.is_empty()
            && self.report_config_ids.is_empty()
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
        self.report_ids.push(id.to_string());
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
            let response = client.execute(DeleteReportRequest::new(entity_id)).await?;
            log_cleanup_result("delete_report", &report_id, Some(response.status))?;
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

        while let Some(report_config_id) = self.report_config_ids.last().cloned() {
            let mut request = DeleteReportConfigRequest::new(parse_entity_id(&report_config_id)?);
            request.ultimate = Some(true);
            let response = client.execute(request).await?;
            log_cleanup_result(
                "delete_report_config",
                &report_config_id,
                Some(response.status),
            )?;
            self.report_config_ids.pop();
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
        let permission_ids = self.permission_ids.clone();
        let report_config_ids = self.report_config_ids.clone();
        let report_format_ids = self.report_format_ids.clone();
        let role_ids = self.role_ids.clone();
        let tls_certificate_ids = self.tls_certificate_ids.clone();
        let user_ids = self.user_ids.clone();

        let cleanup = async move {
            let mut tracker = CleanupTracker {
                config,
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
                permission_ids,
                report_config_ids,
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

    let tasks = client.execute(GetTasksRequest::default()).await?;
    assert_typed_cleanup_status(tasks.status, &[200], "preflight get_tasks", None)?;
    for task in tasks.items {
        if !is_e2e_owned_value(&task.meta.name) {
            continue;
        }
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
        GetReportConfigsRequest::default(),
        "preflight get_report_configs",
        "preflight delete_report_config",
        |item| &item.meta,
        |id| {
            let mut request = DeleteReportConfigRequest::new(id.clone());
            request.ultimate = Some(true);
            request
        }
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

async fn discover_community(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    let version_response = client.get_version(GetVersionRequest::new()).await?;
    let version = parse_version_text(&version_response.version)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("unsupported Community GMP version {version}"),
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

    let feature_response = client
        .execute(gvm_gmp::commands::features::GetFeaturesRequest)
        .await?;
    ensure(
        feature_response.status == 200,
        "typed get_features did not return 200",
    )?;
    let features: BTreeMap<String, FeatureState> = feature_response
        .features
        .into_iter()
        .map(|feature| {
            (
                feature.name,
                FeatureState {
                    compiled_in: feature.compiled_in,
                    enabled: feature.enabled,
                },
            )
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
    runtime::discovery(
        &version_response.version,
        features.clone(),
        help_commands.iter().cloned().collect(),
    );
    ensure(
        !help_commands.is_empty(),
        "authenticated brief XML help advertised no commands",
    )?;
    let required_authenticated_commands = ["get_reports", "get_targets", "get_tasks"];
    let missing_authenticated_commands = required_authenticated_commands
        .iter()
        .filter(|command| !help_commands.contains(**command))
        .copied()
        .collect::<Vec<_>>();
    ensure(
        missing_authenticated_commands.is_empty(),
        &format!(
            "authenticated brief XML help omitted expected Community commands: {}",
            missing_authenticated_commands.join(", ")
        ),
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

    let mut conditional_commands = BTreeMap::new();
    let mut registry_version_gates = BTreeMap::new();
    for entry in COMMAND_COVERAGE
        .iter()
        .filter(|entry| entry.disposition == Disposition::ConditionalCommunity)
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
    if env_flag("E2E_RECORD_BASELINE") {
        let path = runtime::write_baseline_candidate(
            &version_response.version,
            &features,
            &help_commands.iter().cloned().collect::<Vec<_>>(),
            &conditional_commands,
            &registry_version_gates,
        )
        .map_err(AppError::Assertion)?;
        log_line(&format!("recorded baseline candidate: {}", path.display()));
    } else {
        runtime::validate_baseline(
            &version_response.version,
            &features,
            &help_commands.iter().cloned().collect::<Vec<_>>(),
            &conditional_commands,
            &registry_version_gates,
        )
        .map_err(AppError::Assertion)?;
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

#[cfg(test)]
fn create_report_config_request(
    name: &str,
    report_format_id: &EntityId,
    comment: &str,
) -> CreateReportConfigRequest {
    let mut request = CreateReportConfigRequest::new(name, report_format_id.clone());
    request.comment = Some(comment.into());
    request
}

fn get_report_formats_with_params_request() -> GetReportFormatsRequest {
    GetReportFormatsRequest {
        params: Some(true),
        ..Default::default()
    }
}

fn modify_setting_request(setting_id: &EntityId, value: &str) -> ModifySettingRequest {
    ModifySettingRequest::new(setting_id.clone(), value)
}

fn delete_user_directly_request(user_id: &EntityId) -> DeleteUserRequest {
    // gvmd deletes users directly; unlike ordinary resources, users are not
    // restorable from the trashcan.
    DeleteUserRequest::new(user_id.clone())
}

#[cfg(test)]
#[derive(Debug)]
struct ReportFormatParamEvidence {
    id: Option<String>,
    name: String,
    parameter_count: usize,
    depth: usize,
    name_depth: Option<usize>,
}

#[cfg(test)]
fn parse_report_format_params(
    response: &Response,
) -> Result<Vec<ReportFormatParamEvidence>, AppError> {
    let mut reader = Reader::from_str(response.as_str()?);
    let mut formats = Vec::new();
    let mut current: Option<ReportFormatParamEvidence> = None;

    loop {
        match reader.read_event()? {
            Event::Start(ref event) if event.name().as_ref() == "report_format" => {
                if current.is_none() {
                    let id = event
                        .attributes()
                        .flatten()
                        .find(|attribute| attribute.key.as_ref() == "id")
                        .map(|attribute| {
                            attribute
                                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map(|value| value.into_owned())
                        })
                        .transpose()?;
                    current = Some(ReportFormatParamEvidence {
                        id,
                        name: String::new(),
                        parameter_count: 0,
                        depth: 1,
                        name_depth: None,
                    });
                } else if let Some(format) = current.as_mut() {
                    format.depth += 1;
                }
            }
            Event::Start(ref event) => {
                if let Some(format) = current.as_mut() {
                    if format.depth == 1 && event.name().as_ref() == "param" {
                        format.parameter_count += 1;
                    }
                    if format.depth == 1 && event.name().as_ref() == "name" {
                        format.name_depth = Some(format.depth + 1);
                    }
                    format.depth += 1;
                }
            }
            Event::Empty(ref event)
                if event.name().as_ref() == "report_format" && current.is_none() =>
            {
                let id = event
                    .attributes()
                    .flatten()
                    .find(|attribute| attribute.key.as_ref() == "id")
                    .map(|attribute| {
                        attribute
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(|value| value.into_owned())
                    })
                    .transpose()?;
                formats.push(ReportFormatParamEvidence {
                    id,
                    name: String::new(),
                    parameter_count: 0,
                    depth: 0,
                    name_depth: None,
                });
            }
            Event::Empty(ref event) => {
                if let Some(format) = current.as_mut() {
                    if format.depth == 1 && event.name().as_ref() == "param" {
                        format.parameter_count += 1;
                    }
                }
            }
            Event::Text(ref event) => {
                if let Some(format) = current.as_mut() {
                    if format.name_depth == Some(format.depth) {
                        format.name.push_str(event.as_ref());
                    }
                }
            }
            Event::End(ref event) => {
                let closes_format = current.as_ref().is_some_and(|format| {
                    format.depth == 1 && event.name().as_ref() == "report_format"
                });
                if closes_format {
                    formats.push(current.take().expect("report format is active"));
                } else if let Some(format) = current.as_mut() {
                    if format.name_depth == Some(format.depth) && event.name().as_ref() == "name" {
                        format.name_depth = None;
                    }
                    format.depth = format.depth.saturating_sub(1);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if current.is_some() {
        return Err(AppError::Assertion(
            "get_report_formats params=1 response ended before report_format closed".to_string(),
        ));
    }
    if formats.is_empty() {
        return Err(AppError::Assertion(
            "get_report_formats params=1 returned no report formats".to_string(),
        ));
    }
    for format in &formats {
        let id = format.id.as_deref().ok_or_else(|| {
            AppError::Assertion(
                "get_report_formats params=1 returned a report format without an id".to_string(),
            )
        })?;
        parse_entity_id(id)?;
    }

    Ok(formats)
}

#[cfg(test)]
fn select_ordinary_report_format(
    formats: &[ReportFormatParamEvidence],
) -> Result<EntityId, AppError> {
    formats
        .iter()
        .find_map(|format| format.id.as_deref())
        .map(parse_entity_id)
        .transpose()?
        .ok_or_else(|| {
            AppError::Assertion(
                "get_report_formats params=1 returned no usable report formats".to_string(),
            )
        })
}

#[cfg(test)]
fn select_configurable_report_format(formats: &[ReportFormatParamEvidence]) -> Option<EntityId> {
    formats
        .iter()
        .find(|format| format.parameter_count > 0)
        .and_then(|format| format.id.as_deref())
        .map(|id| parse_entity_id(id).expect("report-format ids were validated during parsing"))
}

#[cfg(test)]
fn report_format_parameter_evidence(formats: &[ReportFormatParamEvidence]) -> String {
    formats
        .iter()
        .map(|format| {
            format!(
                "{} ({}, {} parameter(s))",
                format.id.as_deref().unwrap_or("<missing id>"),
                if format.name.is_empty() {
                    "<unnamed>"
                } else {
                    &format.name
                },
                format.parameter_count
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
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
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;

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
    typed_read!(
        "get_scan_config_nvt(single preferences/count)",
        client.get_scan_config_nvt(GetScanConfigNvtRequest::new(nvts.items[0].oid.clone()))
    );
    if let Some(family) = nvts.items[0].family.as_deref() {
        typed_read!(
            "get_scan_config_nvts(public helper)",
            client.get_scan_config_nvts(GetScanConfigNvtsRequest::new(
                configs.items[0].meta.id.clone(),
                family,
            ))
        );
    }
    typed_read!(
        "get_nvt_families",
        client.get_nvt_families(GetNvtFamiliesRequest::new())
    );

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
    }
    let vulnerabilities = typed_read!(
        "get_vulnerabilities",
        client.get_vulnerabilities(GetVulnsRequest {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(vulnerability) = vulnerabilities.items.first() {
        typed_read!(
            "get_vulnerability(single)",
            client.get_vulnerability(GetVulnerabilityRequest::new(&vulnerability.id))
        );
    }

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
        matches!(invalid_host, Err(GvmError::Server { .. })),
        "invalid host asset did not produce a typed server error",
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
    log_pass("isolated host asset", "typed create/get/modify/failure");

    let report_formats = client
        .get_report_formats(get_report_formats_with_params_request())
        .await?;
    assert_typed_status(
        report_formats.status,
        &report_formats.status_text,
        200,
        "get_report_formats with params",
    )?;
    let ordinary_report_format_id = report_formats
        .items
        .first()
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
        "isolated report format import and report config lifecycle",
        Outcome::ConditionalUnavailable,
        "canonical typed report-format projections do not contain the export envelope or parameter metadata required for safe import/report-config fixture selection",
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
        run_scan_suite(&mut client, config, tracker).await?;
    }

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

async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    client
        .authenticate(AuthenticateRequest::new(&config.username, &config.password))
        .await?;
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

    let results = client
        .get_results(GetResultsRequest {
            filter_string: Some("uuid=00000000-0000-0000-0000-000000000000 rows=1".to_string()),
            details: Some(false),
            ..Default::default()
        })
        .await?;
    ensure(
        results.status == 200,
        "typed get_results did not return 200",
    )?;
    ensure(
        results.items.is_empty(),
        "typed no-match get_results unexpectedly returned a result",
    )?;

    let started = client
        .start_task(StartTaskRequest::new(task.id.clone()))
        .await?;
    ensure(started.status == 202, "typed start_task did not return 202")?;
    let started_report_id = started.report_id.ok_or_else(|| {
        AppError::Assertion("typed start_task response omitted report_id".to_string())
    })?;
    match client
        .start_task(StartTaskRequest::new(task.id.clone()))
        .await
    {
        Ok(response) if response.status >= 400 => log_pass(
            "typed duplicate start_task",
            &format!(
                "rejected with status {} ({})",
                response.status, response.status_text
            ),
        ),
        Ok(response)
            if response.status == 202
                && response.report_id.as_ref() == Some(&started_report_id) =>
        {
            log_pass(
                "typed duplicate start_task",
                "idempotent response preserved the active report",
            );
        }
        Ok(response) => {
            return Err(AppError::Assertion(format!(
                "duplicate start_task returned status {} ({}) with report {:?}, expected a rejection or the existing report {started_report_id}",
                response.status, response.status_text, response.report_id
            )));
        }
        Err(GvmError::Server { .. }) => {
            log_pass("typed duplicate start_task", "typed server rejection")
        }
        Err(error) => return Err(error.into()),
    }

    renew_authenticated_after_response(
        client,
        config,
        Duration::from_secs(config.task_progress_timeout_secs),
        "duplicate start_task",
    )
    .await?;

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
    if task_state_is_stoppable(&task_status) {
        let stop_response = client
            .stop_task(StopTaskRequest::new(task.id.clone()))
            .await?;
        assert_typed_status(
            stop_response.status,
            &stop_response.status_text,
            200,
            "stop_task",
        )?;
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
    }

    runtime::observe(
        "scan-report-read-lifecycle",
        Outcome::ConditionalUnavailable,
        "stable gvmd report/result expansion and export paths execute invalid SEVERITY_ERROR SQL",
    );

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

    runtime::observe(
        "scan-ticket-lifecycle",
        Outcome::ConditionalUnavailable,
        "the no-match result probe intentionally supplies no result eligible for a ticket",
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
            report_id,
            results.items.len()
        ),
    );
    Ok(())
}

#[cfg(test)]
fn conditional_surface_wire_command(surface_name: &str) -> Result<&'static str, AppError> {
    if let Some(helper) = HELPER_COVERAGE
        .iter()
        .find(|entry| entry.name == surface_name)
    {
        ensure(
            helper.disposition == Disposition::ConditionalCommunity,
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
fn conditional_helper_semantic_name(helper_name: &str) -> &str {
    // These public helper variants intentionally share one semantic capability
    // entry. Keep aliases explicit: helper names are not wire-command names.
    match helper_name {
        "get_report_export_with_opts" => "get_report_export",
        _ => helper_name,
    }
}

#[cfg(test)]
fn conditional_helper_minimum_version(helper_name: &str) -> Result<GmpVersion, AppError> {
    let wire_command = conditional_surface_wire_command(helper_name)?;
    gvm_gmp::capabilities::minimum_version_for_command(conditional_helper_semantic_name(
        helper_name,
    ))
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
        if !task_state_is_stoppable(&status) || started.elapsed() >= grace_period {
            return Ok(status);
        }

        sleep(Duration::from_secs(1).min(grace_period.saturating_sub(started.elapsed()))).await;
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
    const RUNNING_TASK_RESPONSE: &str = concat!(
        r#"<get_tasks_response status="200" status_text="OK">"#,
        r#"<task id="task-id"><name>Task</name><status>Running</status></task>"#,
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
                    "duplicate start_task",
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
    fn report_config_request_references_the_created_report_format_by_id() {
        let report_format_id = EntityId::new("created-report-format").expect("valid id");
        let request = create_report_config_request(
            "report-config",
            &report_format_id,
            "report-config-comment",
        );
        let xml = request_xml(&request);

        assert_eq!(
            xml,
            concat!(
                "<create_report_config><name>report-config</name>",
                "<report_format id=\"created-report-format\"/>",
                "<comment>report-config-comment</comment></create_report_config>"
            )
        );
    }

    #[test]
    fn report_format_selection_requests_parameter_metadata() {
        let request = get_report_formats_with_params_request();
        let xml = request_xml(&request);

        assert_eq!(xml, r#"<get_report_formats params="1"/>"#);
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
    fn report_format_lifecycle_selects_an_ordinary_format_without_parameters() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="plain"><name>Plain XML</name></report_format>
                <report_format id="configurable"><name>Configurable XML</name><param><name>Node Distance</name></param></report_format>
            </get_report_formats_response>"#,
        );

        let formats =
            parse_report_format_params(&response).expect("report-format response should be valid");
        let selected = select_ordinary_report_format(&formats)
            .expect("the first valid report format should drive format coverage");

        assert_eq!(selected.as_str(), "plain");
    }

    #[test]
    fn report_config_lifecycle_is_unavailable_when_all_formats_have_zero_parameters() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="plain"><name>Plain XML</name></report_format>
                <report_format id="csv"><name>CSV</name></report_format>
            </get_report_formats_response>"#,
        );

        let formats = parse_report_format_params(&response)
            .expect("zero-parameter report formats are still valid");

        assert!(select_configurable_report_format(&formats).is_none());
        assert_eq!(
            report_format_parameter_evidence(&formats),
            "plain (Plain XML, 0 parameter(s)), csv (CSV, 0 parameter(s))"
        );
    }

    #[test]
    fn report_format_selection_rejects_an_empty_response() {
        let response =
            Response::from(r#"<get_report_formats_response status="200" status_text="OK"/>"#);

        let error = parse_report_format_params(&response)
            .expect_err("an empty report-format response cannot drive the lifecycle");

        assert_eq!(
            error.to_string(),
            "get_report_formats params=1 returned no report formats"
        );
    }

    #[test]
    fn report_config_lifecycle_selects_a_configurable_format_after_a_nonconfigurable_one() {
        let response = Response::from(
            r#"<get_report_formats_response status="200" status_text="OK">
                <report_format id="plain"><name>Plain XML</name></report_format>
                <report_format id="configurable"><name>Configurable XML</name><param><name>Node Distance</name><type>integer</type><value>10</value><default>10</default></param></report_format>
            </get_report_formats_response>"#,
        );

        let formats =
            parse_report_format_params(&response).expect("report-format response should be valid");
        let selected = select_configurable_report_format(&formats)
            .expect("the later configurable report format should be selected");

        assert_eq!(selected.as_str(), "configurable");
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
    fn concrete_start_report_id_is_preserved() {
        let started = EntityId::new("started-report").expect("valid started report id");
        let stale = EntityId::new("older-report").expect("valid stale report id");

        assert_eq!(
            select_scan_report_id(&started, Some(&stale), None),
            Some(started)
        );
    }
}
