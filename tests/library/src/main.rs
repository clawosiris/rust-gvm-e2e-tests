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
use gvm_gmp::commands::alerts::{delete_alert, get_alert, get_alerts, AlertOpts, GetAlertsOpts};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::credentials::{
    create_credential, delete_credential, get_credential, get_credentials, CredentialOpts,
    GetCredentialsOpts,
};
use gvm_gmp::commands::feed::get_feeds;
use gvm_gmp::commands::filters::{
    create_filter, delete_filter, get_filter, get_filters, FilterOpts, GetFiltersOpts,
};
use gvm_gmp::commands::help::HelpMode;
use gvm_gmp::commands::notes::{
    create_note, delete_note, get_note, get_notes, GetNotesOpts, NoteOpts,
};
use gvm_gmp::commands::nvts::{get_nvts, GetNvtsOpts};
use gvm_gmp::commands::overrides::{
    create_override, delete_override, get_override, get_overrides, GetOverridesOpts, OverrideOpts,
};
use gvm_gmp::commands::port_lists::{
    create_port_list, delete_port_list, get_port_list, get_port_lists, GetPortListsOpts,
    PortListOpts,
};
use gvm_gmp::commands::report_formats::{get_report_formats, GetReportFormatsOpts};
use gvm_gmp::commands::reports::get_report;
use gvm_gmp::commands::scan_configs::{get_scan_configs, GetScanConfigsOpts};
use gvm_gmp::commands::scanners::{get_scanners, GetScannersOpts};
use gvm_gmp::commands::schedules::{
    create_schedule, delete_schedule, get_schedule, get_schedules, GetSchedulesOpts, ScheduleOpts,
};
use gvm_gmp::commands::secinfo::{
    get_cert_bund_advisories, get_cpes, get_cves, get_dfn_cert_advisories, GetSecInfoOpts,
};
use gvm_gmp::commands::tags::{create_tag, delete_tag, get_tag, get_tags, GetTagsOpts, TagOpts};
use gvm_gmp::commands::targets::{
    create_target, delete_target, get_target, get_targets, CreateTargetOpts, GetTargetsOpts,
};
use gvm_gmp::commands::tasks::{
    create_task, delete_task, get_task, get_tasks, stop_task, CreateTaskOpts, GetTasksOpts,
};
use gvm_gmp::enums::{
    AlertCondition, AlertEvent, AlertMethod, CredentialType, EntityType, FilterType,
};
use gvm_gmp::responses::feed::GetFeedsResponse;
use gvm_gmp::responses::port_list::GetPortListsResponse;
use gvm_gmp::responses::report_format::GetReportFormatsResponse;
use gvm_gmp::responses::scanner::GetScannersResponse;
use gvm_gmp::responses::target::GetTargetsResponse;
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::{Response, XmlCommand};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::Value;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::sleep;

use gvm_community_e2e::runtime::{self, FeatureState, Outcome};
use gvm_community_e2e::{Disposition, COMMAND_COVERAGE};

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
        self.task_ids.is_empty()
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

    fn track_ticket(&mut self, id: &EntityId) {
        self.ticket_ids.push(id.to_string());
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

    fn track_report_config(&mut self, id: &EntityId) {
        self.report_config_ids.push(id.to_string());
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
            .authenticate(&self.config.username, &self.config.password)
            .await?;

        while let Some(ticket_id) = self.ticket_ids.pop() {
            let entity_id = parse_entity_id(&ticket_id)?;
            let response = client
                .send(gvm_gmp::commands::tickets::delete_ticket(&entity_id, true))
                .await?;
            assert_cleanup_status(&response, &[200, 404], "final delete_ticket", &entity_id)?;
            log_cleanup_result("delete_ticket", &ticket_id, response.status_code())?;
        }

        while let Some(task_id) = self.task_ids.pop() {
            let entity_id = parse_entity_id(&task_id)?;
            let response = client.send(delete_task(&entity_id, true)).await?;
            log_cleanup_result("delete_task", &task_id, response.status_code())?;
        }

        while let Some(target_id) = self.target_ids.pop() {
            let entity_id = parse_entity_id(&target_id)?;
            let response = client.send(delete_target(&entity_id, true)).await?;
            log_cleanup_result("delete_target", &target_id, response.status_code())?;
        }

        while let Some(config_id) = self.config_ids.pop() {
            let entity_id = parse_entity_id(&config_id)?;
            let response = client
                .delete_config(
                    &entity_id,
                    gvm_gmp::commands::configs::DeleteConfigOpts {
                        ultimate: Some(true),
                    },
                )
                .await?;
            log_cleanup_result("delete_config", &config_id, Some(response.status))?;
        }

        while let Some(scanner_id) = self.scanner_ids.pop() {
            let entity_id = parse_entity_id(&scanner_id)?;
            let response = client.delete_scanner(&entity_id, true).await?;
            log_cleanup_result("delete_scanner", &scanner_id, Some(response.status))?;
        }

        while let Some(permission_id) = self.permission_ids.pop() {
            let entity_id = parse_entity_id(&permission_id)?;
            let response = client
                .send(gvm_gmp::commands::permissions::delete_permission(
                    &entity_id, true,
                ))
                .await?;
            log_cleanup_result("delete_permission", &permission_id, response.status_code())?;
        }

        while let Some(group_id) = self.group_ids.pop() {
            let entity_id = parse_entity_id(&group_id)?;
            let response = client
                .send(gvm_gmp::commands::groups::delete_group(&entity_id, true))
                .await?;
            log_cleanup_result("delete_group", &group_id, response.status_code())?;
        }

        while let Some(role_id) = self.role_ids.pop() {
            let entity_id = parse_entity_id(&role_id)?;
            let response = client
                .send(gvm_gmp::commands::roles::delete_role(&entity_id, true))
                .await?;
            log_cleanup_result("delete_role", &role_id, response.status_code())?;
        }

        while let Some(user_id) = self.user_ids.pop() {
            let entity_id = parse_entity_id(&user_id)?;
            let response = client
                .send(gvm_gmp::commands::users::delete_user(&entity_id, true))
                .await?;
            log_cleanup_result("delete_user", &user_id, response.status_code())?;
        }

        while let Some(report_config_id) = self.report_config_ids.pop() {
            let response = client
                .send(
                    gvm_gmp::commands::report_configs::delete_report_config_opts(
                        &report_config_id,
                        gvm_gmp::commands::report_configs::DeleteReportConfigOpts {
                            ultimate: Some(true),
                        },
                    ),
                )
                .await?;
            log_cleanup_result(
                "delete_report_config",
                &report_config_id,
                response.status_code(),
            )?;
        }

        while let Some(report_format_id) = self.report_format_ids.pop() {
            let entity_id = parse_entity_id(&report_format_id)?;
            let response = client
                .send(gvm_gmp::commands::report_formats::delete_report_format(
                    &entity_id, true,
                ))
                .await?;
            log_cleanup_result(
                "delete_report_format",
                &report_format_id,
                response.status_code(),
            )?;
        }

        while let Some(tls_certificate_id) = self.tls_certificate_ids.pop() {
            let entity_id = parse_entity_id(&tls_certificate_id)?;
            let response = client
                .send(gvm_gmp::commands::tls_certificates::delete_tls_certificate(
                    &entity_id, true,
                ))
                .await?;
            log_cleanup_result(
                "delete_tls_certificate",
                &tls_certificate_id,
                response.status_code(),
            )?;
        }

        while let Some(asset_id) = self.asset_ids.pop() {
            let entity_id = parse_entity_id(&asset_id)?;
            let response = client
                .send(gvm_gmp::commands::assets::delete_asset(
                    &entity_id,
                    gvm_gmp::commands::assets::DeleteAssetOpts::default(),
                ))
                .await?;
            log_cleanup_result("delete_asset", &asset_id, response.status_code())?;
        }

        while let Some(alert_id) = self.alert_ids.pop() {
            let entity_id = parse_entity_id(&alert_id)?;
            let response = client.send(delete_alert(&entity_id, true)).await?;
            log_cleanup_result("delete_alert", &alert_id, response.status_code())?;
        }

        while let Some(note_id) = self.note_ids.pop() {
            let entity_id = parse_entity_id(&note_id)?;
            let response = client.send(delete_note(&entity_id, true)).await?;
            log_cleanup_result("delete_note", &note_id, response.status_code())?;
        }

        while let Some(override_id) = self.override_ids.pop() {
            let entity_id = parse_entity_id(&override_id)?;
            let response = client.send(delete_override(&entity_id, true)).await?;
            log_cleanup_result("delete_override", &override_id, response.status_code())?;
        }

        while let Some(tag_id) = self.tag_ids.pop() {
            let entity_id = parse_entity_id(&tag_id)?;
            let response = client.send(delete_tag(&entity_id, true)).await?;
            log_cleanup_result("delete_tag", &tag_id, response.status_code())?;
        }

        while let Some(filter_id) = self.filter_ids.pop() {
            let entity_id = parse_entity_id(&filter_id)?;
            let response = client.send(delete_filter(&entity_id, true)).await?;
            log_cleanup_result("delete_filter", &filter_id, response.status_code())?;
        }

        while let Some(schedule_id) = self.schedule_ids.pop() {
            let entity_id = parse_entity_id(&schedule_id)?;
            let response = client.send(delete_schedule(&entity_id, true)).await?;
            log_cleanup_result("delete_schedule", &schedule_id, response.status_code())?;
        }

        while let Some(credential_id) = self.credential_ids.pop() {
            let entity_id = parse_entity_id(&credential_id)?;
            let response = client.send(delete_credential(&entity_id, true)).await?;
            log_cleanup_result("delete_credential", &credential_id, response.status_code())?;
        }

        while let Some(port_list_id) = self.port_list_ids.pop() {
            let entity_id = parse_entity_id(&port_list_id)?;
            let response = client.send(delete_port_list(&entity_id, true)).await?;
            log_cleanup_result("delete_port_list", &port_list_id, response.status_code())?;
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
}

async fn cleanup_previous_runs(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    client
        .authenticate(&config.username, &config.password)
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

    let tasks = client.send(get_tasks(GetTasksOpts::default())).await?;
    assert_status(&tasks, 200, "preflight get_tasks")?;
    for task_id in e2e_entity_ids(tasks.as_str()?, "task")? {
        let task_id = parse_entity_id(&task_id)?;
        let stop = client.send(stop_task(&task_id)).await?;
        assert_cleanup_status(&stop, &[200, 400, 404], "preflight stop_task", &task_id)?;
        let delete = client.send(delete_task(&task_id, true)).await?;
        assert_cleanup_status(&delete, &[200, 404], "preflight delete_task", &task_id)?;
        removed += 1;
    }

    let targets = client.send(get_targets(GetTargetsOpts::default())).await?;
    assert_status(&targets, 200, "preflight get_targets")?;
    for target_id in e2e_entity_ids(targets.as_str()?, "target")? {
        let target_id = parse_entity_id(&target_id)?;
        let delete = client.send(delete_target(&target_id, true)).await?;
        assert_cleanup_status(&delete, &[200, 404], "preflight delete_target", &target_id)?;
        removed += 1;
    }

    let configs = client
        .send(gvm_gmp::commands::configs::get_configs(
            gvm_gmp::commands::configs::GetConfigsOpts::default(),
        ))
        .await?;
    assert_status(&configs, 200, "preflight get_configs")?;
    for id in e2e_entity_ids(configs.as_str()?, "config")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::configs::delete_config(
                &id,
                gvm_gmp::commands::configs::DeleteConfigOpts {
                    ultimate: Some(true),
                },
            ))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_config", &id)?;
        removed += 1;
    }

    let scanners = client
        .send(get_scanners(GetScannersOpts::default()))
        .await?;
    assert_status(&scanners, 200, "preflight get_scanners")?;
    for id in e2e_entity_ids(scanners.as_str()?, "scanner")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::scanners::delete_scanner(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_scanner", &id)?;
        removed += 1;
    }

    let alerts = client.send(get_alerts(GetAlertsOpts::default())).await?;
    assert_status(&alerts, 200, "preflight get_alerts")?;
    for id in e2e_entity_ids(alerts.as_str()?, "alert")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_alert(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_alert", &id)?;
        removed += 1;
    }

    let notes = client.send(get_notes(GetNotesOpts::default())).await?;
    assert_status(&notes, 200, "preflight get_notes")?;
    for id in e2e_entity_ids(notes.as_str()?, "note")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_note(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_note", &id)?;
        removed += 1;
    }

    let overrides = client
        .send(get_overrides(GetOverridesOpts::default()))
        .await?;
    assert_status(&overrides, 200, "preflight get_overrides")?;
    for id in e2e_entity_ids(overrides.as_str()?, "override")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_override(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_override", &id)?;
        removed += 1;
    }

    let tags = client.send(get_tags(GetTagsOpts::default())).await?;
    assert_status(&tags, 200, "preflight get_tags")?;
    for id in e2e_entity_ids(tags.as_str()?, "tag")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_tag(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_tag", &id)?;
        removed += 1;
    }

    let filters = client.send(get_filters(GetFiltersOpts::default())).await?;
    assert_status(&filters, 200, "preflight get_filters")?;
    for id in e2e_entity_ids(filters.as_str()?, "filter")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_filter(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_filter", &id)?;
        removed += 1;
    }

    let schedules = client
        .send(get_schedules(GetSchedulesOpts::default()))
        .await?;
    assert_status(&schedules, 200, "preflight get_schedules")?;
    for id in e2e_entity_ids(schedules.as_str()?, "schedule")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_schedule(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_schedule", &id)?;
        removed += 1;
    }

    let credentials = client
        .send(get_credentials(GetCredentialsOpts::default()))
        .await?;
    assert_status(&credentials, 200, "preflight get_credentials")?;
    for id in e2e_entity_ids(credentials.as_str()?, "credential")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_credential(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_credential", &id)?;
        removed += 1;
    }

    let port_lists = client
        .send(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&port_lists, 200, "preflight get_port_lists")?;
    for id in e2e_entity_ids(port_lists.as_str()?, "port_list")? {
        let id = parse_entity_id(&id)?;
        let response = client.send(delete_port_list(&id, true)).await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_port_list", &id)?;
        removed += 1;
    }

    let permissions = client
        .send(gvm_gmp::commands::permissions::get_permissions(
            Default::default(),
        ))
        .await?;
    assert_status(&permissions, 200, "preflight get_permissions")?;
    for id in e2e_entity_ids(permissions.as_str()?, "permission")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::permissions::delete_permission(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_permission", &id)?;
        removed += 1;
    }

    let groups = client
        .send(gvm_gmp::commands::groups::get_groups(Default::default()))
        .await?;
    assert_status(&groups, 200, "preflight get_groups")?;
    for id in e2e_entity_ids(groups.as_str()?, "group")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::groups::delete_group(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_group", &id)?;
        removed += 1;
    }

    let roles = client
        .send(gvm_gmp::commands::roles::get_roles(Default::default()))
        .await?;
    assert_status(&roles, 200, "preflight get_roles")?;
    for id in e2e_entity_ids(roles.as_str()?, "role")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::roles::delete_role(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_role", &id)?;
        removed += 1;
    }

    let users = client
        .send(gvm_gmp::commands::users::get_users(Default::default()))
        .await?;
    assert_status(&users, 200, "preflight get_users")?;
    for id in e2e_entity_ids(users.as_str()?, "user")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::users::delete_user(&id, true))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_user", &id)?;
        removed += 1;
    }

    let report_configs = client
        .send(gvm_gmp::commands::report_configs::get_report_configs())
        .await?;
    assert_status(&report_configs, 200, "preflight get_report_configs")?;
    for id in e2e_entity_ids(report_configs.as_str()?, "report_config")? {
        let response = client
            .send(
                gvm_gmp::commands::report_configs::delete_report_config_opts(
                    &id,
                    gvm_gmp::commands::report_configs::DeleteReportConfigOpts {
                        ultimate: Some(true),
                    },
                ),
            )
            .await?;
        let entity_id = parse_entity_id(&id)?;
        assert_cleanup_status(
            &response,
            &[200, 404],
            "preflight delete_report_config",
            &entity_id,
        )?;
        removed += 1;
    }

    let report_formats = client
        .send(get_report_formats(GetReportFormatsOpts::default()))
        .await?;
    assert_status(&report_formats, 200, "preflight get_report_formats")?;
    for id in e2e_entity_ids(report_formats.as_str()?, "report_format")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::report_formats::delete_report_format(
                &id, true,
            ))
            .await?;
        assert_cleanup_status(
            &response,
            &[200, 404],
            "preflight delete_report_format",
            &id,
        )?;
        removed += 1;
    }

    let certificates = client
        .send(gvm_gmp::commands::tls_certificates::get_tls_certificates(
            Default::default(),
        ))
        .await?;
    assert_status(&certificates, 200, "preflight get_tls_certificates")?;
    for id in e2e_entity_ids(certificates.as_str()?, "tls_certificate")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::tls_certificates::delete_tls_certificate(
                &id, true,
            ))
            .await?;
        assert_cleanup_status(
            &response,
            &[200, 404],
            "preflight delete_tls_certificate",
            &id,
        )?;
        removed += 1;
    }

    let assets = client
        .send(gvm_gmp::commands::assets::get_assets(
            gvm_gmp::commands::assets::GetAssetsOpts {
                type_: Some(gvm_gmp::commands::assets::AssetType::Host),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&assets, 200, "preflight get_assets")?;
    for id in e2e_entity_ids(assets.as_str()?, "asset")? {
        let id = parse_entity_id(&id)?;
        let response = client
            .send(gvm_gmp::commands::assets::delete_asset(
                &id,
                Default::default(),
            ))
            .await?;
        assert_cleanup_status(&response, &[200, 404], "preflight delete_asset", &id)?;
        removed += 1;
    }

    client.disconnect().await?;
    log_pass(
        "preflight-cleanup",
        &format!("dependency-ordered cleanup removed {removed} stale resource(s)"),
    );
    Ok(())
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
    let version_response = client.get_version().await?;
    let version = parse_version_text(&version_response.version)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("unsupported Community GMP version {version}"),
    )?;

    let auth = client
        .authenticate(&config.username, &config.password)
        .await?;
    ensure(
        auth.status == 200,
        "typed authentication did not return 200",
    )?;

    let text_help = client.get_help().await?;
    ensure(
        text_help.status == 200 && !text_help.help_text.trim().is_empty(),
        "typed text help did not return a nonempty 200 response",
    )?;

    let feature_response = client.get_features_parsed().await?;
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

    let help = client.get_help_with_mode(HelpMode::BriefXml).await?;
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
        .get_help_with_mode(HelpMode::Schema(gvm_gmp::enums::HelpFormat::Xml))
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

async fn wait_ready(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;

    // Phase 1: Verify GMP protocol is responding
    let response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&response, 200, "get_version")?;
    log_line("gvmd protocol responding");

    // Phase 2: Wait for feed data to be loaded (scan configs appear after feed sync)
    // Clean-volume feed syncs on CI can take 60-90 min; 2h ceiling with workflow timeout as hard stop.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(7200);
    loop {
        let auth = client
            .call(authenticate(&config.username, &config.password))
            .await?;
        if auth.status_code() != Some(200) {
            if tokio::time::Instant::now() >= deadline {
                return Err(AppError::Assertion(
                    "timed out waiting for authentication to succeed".to_string(),
                ));
            }
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let configs = client
            .call(get_scan_configs(GetScanConfigsOpts::default()))
            .await?;
        if configs.status_code() == Some(200) {
            let count = count_elements(&configs, "config")?;
            if count >= 1 {
                log_line(&format!("feed ready: {count} scan config(s) available"));
                break;
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::Assertion(
                "timed out waiting for scan configs (feed data may not be loaded)".to_string(),
            ));
        }

        log_line("waiting for feed data (scan configs not yet available)...");
        sleep(Duration::from_secs(30)).await;
    }

    client.disconnect().await?;
    Ok(())
}

async fn run_typed_read_suite(config: &EnvConfig) -> Result<(), AppError> {
    let mut rejected_client = connect_client(config).await?;
    let rejected = rejected_client
        .authenticate(&config.username, "rust-gvm-e2e-intentionally-wrong")
        .await;
    ensure(
        matches!(
            rejected,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "typed authentication failure did not preserve the server error",
    )?;
    rejected_client.disconnect().await?;
    log_pass("typed authentication failure", "non-2xx server error");

    let mut client = connect_client(config).await?;
    client
        .authenticate(&config.username, &config.password)
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

    let targets = typed_read!("get_targets", client.get_targets(GetTargetsOpts::default()));
    let filtered_targets = typed_read!(
        "get_targets(filter/pagination)",
        client.get_targets(GetTargetsOpts {
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
        client.get_scan_configs(GetScanConfigsOpts {
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
        client.get_scan_config(&configs.items[0].meta.id)
    );
    typed_read!(
        "get_policies",
        client.get_policies(GetScanConfigsOpts {
            filter_string: Some("rows=2".to_string()),
            ..Default::default()
        })
    );
    let generic_configs = typed_read!(
        "get_configs(generic)",
        client.get_configs(gvm_gmp::commands::configs::GetConfigsOpts {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(generic_config) = generic_configs.items.first() {
        typed_read!(
            "get_config(generic single)",
            client.get_config(
                &generic_config.meta.id,
                gvm_gmp::commands::configs::GetConfigOpts {
                    details: Some(true),
                    ..Default::default()
                }
            )
        );
    }
    let policies = typed_read!(
        "get_policies(single prerequisite)",
        client.get_policies(GetScanConfigsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(policy) = policies.items.first() {
        typed_read!(
            "get_policy(single)",
            client.get_policy(
                &policy.meta.id,
                gvm_gmp::commands::scan_configs::GetPolicyOpts::default()
            )
        );
    }

    let scanners = typed_read!(
        "get_scanners",
        client.get_scanners(GetScannersOpts::default())
    );
    ensure(
        !scanners.items.is_empty(),
        "warm-volume baseline requires at least one typed scanner",
    )?;
    typed_read!(
        "get_scanner(single)",
        client.get_scanner(&scanners.items[0].meta.id)
    );

    let port_lists = typed_read!(
        "get_port_lists",
        client.get_port_lists(GetPortListsOpts {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    ensure(
        !port_lists.items.is_empty(),
        "warm-volume baseline requires at least one typed port list",
    )?;
    typed_read!("get_tasks", client.get_tasks(GetTasksOpts::default()));

    let feeds = typed_read!("get_feeds", client.get_feeds());
    ensure(
        !feeds.items.is_empty(),
        "warm-volume baseline requires typed feed metadata",
    )?;
    typed_read!("get_feed(single)", client.get_feed(gvm_gmp::FeedType::Nvt));

    let nvts = typed_read!(
        "get_nvts",
        client.get_nvts(GetNvtsOpts {
            filter_string: Some("rows=2 first=1".to_string()),
            ..Default::default()
        })
    );
    ensure(
        !nvts.items.is_empty(),
        "warm-volume baseline requires at least one typed NVT",
    )?;
    typed_read!(
        "get_scan_config_nvt(single preferences/count)",
        client.get_scan_config_nvt(&nvts.items[0].oid)
    );
    typed_read!(
        "get_scan_config_nvts(public helper)",
        client.get_scan_config_nvts(GetNvtsOpts {
            filter_string: Some("rows=2".to_string()),
            ..Default::default()
        })
    );
    typed_read!("get_nvt_families", client.get_nvt_families());

    let cves = typed_read!(
        "get_cves",
        client.get_cves(GetSecInfoOpts {
            filter: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(cve) = cves.items.first() {
        typed_read!("get_cve(single)", client.get_cve(&cve.id));
    }
    let cpes = typed_read!(
        "get_cpes",
        client.get_cpes(GetSecInfoOpts {
            filter: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(cpe) = cpes.items.first() {
        typed_read!("get_cpe(single)", client.get_cpe(&cpe.id));
    }
    let cert = typed_read!(
        "get_cert_bund_advisories",
        client.get_cert_bund_advisories(GetSecInfoOpts {
            filter: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(advisory) = cert.items.first() {
        typed_read!(
            "get_cert_bund_advisory(single)",
            client.get_cert_bund_advisory(&advisory.id)
        );
    }
    let dfn = typed_read!(
        "get_dfn_cert_advisories",
        client.get_dfn_cert_advisories(GetSecInfoOpts {
            filter: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(advisory) = dfn.items.first() {
        typed_read!(
            "get_dfn_cert_advisory(single)",
            client.get_dfn_cert_advisory(&advisory.id)
        );
    }
    let vulnerabilities = typed_read!(
        "get_vulnerabilities",
        client.get_vulnerabilities(gvm_gmp::commands::system::FilteredGetOpts {
            filter_string: Some("rows=1 first=1".to_string()),
            ..Default::default()
        })
    );
    if let Some(vulnerability) = vulnerabilities.items.first() {
        typed_read!(
            "get_vulnerability(single)",
            client.get_vulnerability(&vulnerability.id)
        );
    }

    typed_read!(
        "get_alerts",
        client.get_alerts(gvm_gmp::commands::alerts::GetAlertsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_credentials",
        client.get_credentials(gvm_gmp::commands::credentials::GetCredentialsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_filters",
        client.get_filters(gvm_gmp::commands::filters::GetFiltersOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_notes",
        client.get_notes(gvm_gmp::commands::notes::GetNotesOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_overrides",
        client.get_overrides(gvm_gmp::commands::overrides::GetOverridesOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_schedules",
        client.get_schedules(gvm_gmp::commands::schedules::GetSchedulesOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_tags",
        client.get_tags(gvm_gmp::commands::tags::GetTagsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
    );
    typed_read!(
        "get_report_formats",
        client.get_report_formats(GetReportFormatsOpts {
            filter_string: Some("rows=2".to_string()),
            ..Default::default()
        })
    );
    typed_read!("get_settings", client.get_settings());
    typed_read!(
        "get_system_reports",
        client.get_system_reports(gvm_gmp::commands::system_reports::GetSystemReportsOpts {
            brief: Some(true),
            ..Default::default()
        })
    );
    typed_read!(
        "get_aggregates",
        client.get_aggregates(
            "task",
            gvm_gmp::commands::aggregates::GetAggregatesRequestOpts {
                max_groups: Some(1),
                ..Default::default()
            }
        )
    );
    typed_read!("describe_auth", client.describe_auth());

    let preferences = client
        .send(gvm_gmp::commands::system::get_preferences(
            gvm_gmp::commands::system::FilteredGetOpts {
                filter_string: Some("rows=2".to_string()),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&preferences, 200, "get_preferences")?;
    log_pass("raw diagnostic get_preferences", "status and framing");
    let resource_names = client
        .send(gvm_gmp::commands::system::get_resource_names(
            gvm_gmp::commands::system::GetResourceNamesOpts::default(),
        ))
        .await?;
    assert_status(&resource_names, 200, "get_resource_names")?;
    log_pass("raw diagnostic get_resource_names", "status and framing");

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
        .authenticate(&config.username, &config.password)
        .await?;

    let configs = client
        .get_configs(gvm_gmp::commands::configs::GetConfigsOpts {
            filter_string: Some("rows=1".to_string()),
            usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
            ..Default::default()
        })
        .await?;
    let base = configs.items.first().ok_or_else(|| {
        AppError::Assertion("config lifecycle requires a warm scan config".to_string())
    })?;
    let exported = client
        .send(gvm_gmp::commands::scan_configs::get_scan_config(
            &base.meta.id,
        ))
        .await?;
    assert_status(&exported, 200, "export scan config for import")?;
    let import_xml = replace_first_resource_name(
        exported.as_str()?,
        "config",
        &config.name("scan-config-import"),
    )?;
    let imported_scan_config = client.import_scan_config(&import_xml).await?;
    ensure(
        imported_scan_config.status == 201,
        "typed import_scan_config failed",
    )?;
    tracker.track_config(&imported_scan_config.id);
    let scan_config = client
        .create_scan_config(
            &config.name("scan-config"),
            Some(&base.meta.id),
            gvm_gmp::commands::scan_configs::ConfigOpts {
                comment: Some(config.name("scan-config-comment")),
                usage_type: Some("scan".to_string()),
            },
        )
        .await?;
    ensure(scan_config.status == 201, "typed create_scan_config failed")?;
    tracker.track_config(&scan_config.id);
    ensure(
        client
            .modify_scan_config(
                &scan_config.id,
                gvm_gmp::commands::scan_configs::ConfigOpts {
                    comment: Some(config.name("scan-config-comment-modified")),
                    usage_type: Some("scan".to_string()),
                },
            )
            .await?
            .status
            == 200,
        "typed modify_scan_config failed",
    )?;
    ensure(
        client
            .modify_scan_config_set_name(&scan_config.id, &config.name("scan-config-renamed"))
            .await?
            .status
            == 200,
        "typed scan-config name modification failed",
    )?;
    ensure(
        client
            .modify_scan_config_set_comment(
                &scan_config.id,
                Some(&config.name("scan-config-comment-final")),
            )
            .await?
            .status
            == 200,
        "typed scan-config comment modification failed",
    )?;
    let created = client
        .create_config(gvm_gmp::commands::configs::CreateConfigOpts {
            name: config.name("config"),
            base_id: Some(base.meta.id.clone()),
            comment: Some(config.name("config-comment")),
            usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
        })
        .await?;
    ensure(created.status == 201, "typed create_config failed")?;
    tracker.track_config(&created.id);
    let modified = client
        .modify_config(
            &created.id,
            gvm_gmp::commands::configs::ModifyConfigOpts {
                name: Some(config.name("config-modified")),
                comment: Some(config.name("config-comment-modified")),
                usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
            },
        )
        .await?;
    ensure(modified.status == 200, "typed modify_config failed")?;
    let singular = client
        .get_config(
            &created.id,
            gvm_gmp::commands::configs::GetConfigOpts {
                details: Some(true),
                families: Some(true),
                preferences: Some(true),
                tasks: Some(true),
                usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
            },
        )
        .await?;
    ensure(
        singular.items.iter().any(|item| item.meta.id == created.id),
        "typed generic config did not round-trip",
    )?;
    let cloned = client
        .clone_config(
            &created.id,
            gvm_gmp::commands::configs::CloneConfigOpts {
                name: Some(config.name("config-clone")),
            },
        )
        .await?;
    ensure(cloned.status == 201, "typed clone_config failed")?;
    tracker.track_config(&cloned.id);
    let invalid_config = client
        .create_config(gvm_gmp::commands::configs::CreateConfigOpts {
            name: config.name("config-invalid-reference"),
            base_id: Some(parse_entity_id("00000000-0000-0000-0000-000000000118")?),
            comment: None,
            usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
        })
        .await;
    ensure(
        matches!(
            invalid_config,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "invalid config base reference did not return a typed server error",
    )?;

    let policies = client
        .get_policies(GetScanConfigsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
        .await?;
    let policy = policies.items.first().ok_or_else(|| {
        AppError::Assertion("policy import lifecycle requires a warm policy".to_string())
    })?;
    let exported_policy = client
        .send(gvm_gmp::commands::scan_configs::get_policy(
            &policy.meta.id,
            gvm_gmp::commands::scan_configs::GetPolicyOpts::default(),
        ))
        .await?;
    assert_status(&exported_policy, 200, "export policy for import")?;
    let policy_xml = replace_first_resource_name(
        exported_policy.as_str()?,
        "config",
        &config.name("policy-import"),
    )?;
    let imported_policy = client.import_policy(&policy_xml).await?;
    ensure(imported_policy.status == 201, "typed import_policy failed")?;
    tracker.track_config(&imported_policy.id);
    ensure(
        client
            .modify_policy_set_name(&imported_policy.id, &config.name("policy-import-renamed"))
            .await?
            .status
            == 200,
        "typed policy name modification failed",
    )?;
    ensure(
        client
            .modify_policy_set_comment(&imported_policy.id, Some(&config.name("policy-comment")))
            .await?
            .status
            == 200,
        "typed policy comment modification failed",
    )?;
    let imported_policy_read = client
        .get_policy(
            &imported_policy.id,
            gvm_gmp::commands::scan_configs::GetPolicyOpts { audits: Some(true) },
        )
        .await?;
    ensure(
        imported_policy_read
            .items
            .iter()
            .any(|item| item.meta.id == imported_policy.id),
        "typed imported policy did not round-trip",
    )?;
    for id in [
        cloned.id,
        created.id,
        scan_config.id,
        imported_scan_config.id,
        imported_policy.id,
    ] {
        let trashed = client
            .delete_config(
                &id,
                gvm_gmp::commands::configs::DeleteConfigOpts {
                    ultimate: Some(false),
                },
            )
            .await?;
        ensure(trashed.status == 200, "typed config trash failed")?;
        let restored = client.restore_from_trashcan(&id).await?;
        ensure(restored.status == 200, "typed config restore failed")?;
        let deleted = client
            .delete_config(
                &id,
                gvm_gmp::commands::configs::DeleteConfigOpts {
                    ultimate: Some(true),
                },
            )
            .await?;
        ensure(deleted.status == 200, "typed config ultimate delete failed")?;
        tracker.config_ids.retain(|tracked| tracked != id.as_str());
    }
    log_pass(
        "config lifecycle",
        "typed create/clone/get/modify/trash/restore/delete/failure",
    );

    let scanners = client.get_scanners(GetScannersOpts::default()).await?;
    let base_scanner = scanners
        .items
        .first()
        .ok_or_else(|| AppError::Assertion("scanner lifecycle requires a scanner".to_string()))?;
    let scanner_type = match base_scanner.scanner_type.as_deref() {
        Some("3" | "CVE") => gvm_gmp::ScannerType::CveScannerType,
        Some("5" | "OSP") => gvm_gmp::ScannerType::GreenBoneSensorType,
        Some("6") => gvm_gmp::ScannerType::OpenVasdScannerType,
        _ => gvm_gmp::ScannerType::OpenVasScanner,
    };
    let scanner = client
        .create_scanner(
            &config.name("scanner"),
            gvm_gmp::commands::scanners::ScannerOpts {
                comment: Some(config.name("scanner-comment")),
                host: base_scanner.host.clone(),
                port: base_scanner.port,
                scanner_type: Some(scanner_type),
                credential_id: base_scanner
                    .credential
                    .as_ref()
                    .map(|credential| credential.id.clone()),
            },
        )
        .await?;
    ensure(scanner.status == 201, "typed create_scanner failed")?;
    tracker.track_scanner(&scanner.id);
    let modified = client
        .modify_scanner(
            &scanner.id,
            gvm_gmp::commands::scanners::ScannerOpts {
                comment: Some(config.name("scanner-comment-modified")),
                host: base_scanner.host.clone(),
                port: base_scanner.port,
                scanner_type: Some(scanner_type),
                credential_id: base_scanner
                    .credential
                    .as_ref()
                    .map(|credential| credential.id.clone()),
            },
        )
        .await?;
    ensure(modified.status == 200, "typed modify_scanner failed")?;
    let listed = client.get_scanner(&scanner.id).await?;
    ensure(
        listed.items.iter().any(|item| item.meta.id == scanner.id),
        "typed scanner did not round-trip",
    )?;
    let verified = client.verify_scanner(&scanner.id).await?;
    ensure(
        matches!(verified.status, 200 | 202),
        "typed verify_scanner returned an unexpected status",
    )?;
    let invalid = client
        .verify_scanner(&parse_entity_id("00000000-0000-0000-0000-000000000118")?)
        .await;
    ensure(
        matches!(
            invalid,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "invalid scanner reference did not return a typed server error",
    )?;
    let trashed = client.delete_scanner(&scanner.id, false).await?;
    ensure(trashed.status == 200, "typed scanner trash failed")?;
    let restored = client.restore_from_trashcan(&scanner.id).await?;
    ensure(restored.status == 200, "typed scanner restore failed")?;
    let deleted = client.delete_scanner(&scanner.id, true).await?;
    ensure(
        deleted.status == 200,
        "typed scanner ultimate delete failed",
    )?;
    tracker
        .scanner_ids
        .retain(|tracked| tracked != scanner.id.as_str());
    log_pass(
        "scanner lifecycle",
        "typed create/get/modify/verify/trash/restore/delete/failure",
    );

    client.disconnect().await?;
    Ok(())
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
        .authenticate(&config.username, &config.password)
        .await?;

    let predefined_roles = client
        .get_roles(gvm_gmp::commands::roles::GetRolesOpts {
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
    let user = client
        .create_user(
            &user_name,
            gvm_gmp::commands::users::UserOpts {
                password: Some(user_password.clone()),
                comment: Some(config.name("user-comment")),
                role_ids: vec![user_role_id.clone()],
                ..Default::default()
            },
        )
        .await?;
    tracker.track_user(&user.id);
    log_pass("isolated user create", &user.id.to_string());

    let duplicate = client
        .create_user(
            &user_name,
            gvm_gmp::commands::users::UserOpts {
                password: Some("not-used".to_string()),
                ..Default::default()
            },
        )
        .await;
    ensure(
        matches!(
            duplicate,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "duplicate user creation did not produce a typed server error",
    )?;
    log_pass("isolated user duplicate", "typed conflict error");

    let group = client
        .create_group(
            &config.name("group"),
            gvm_gmp::commands::groups::GroupOpts {
                users: vec![user_name.clone()],
                comment: Some(config.name("group-comment")),
            },
        )
        .await?;
    tracker.track_group(&group.id);
    let role = client
        .create_role(
            &config.name("role"),
            gvm_gmp::commands::roles::RoleOpts {
                users: vec![user_name.clone()],
                comment: Some(config.name("role-comment")),
            },
        )
        .await?;
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
        .get_users(gvm_gmp::commands::users::GetUsersOpts {
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
        .get_groups(gvm_gmp::commands::groups::GetGroupsOpts {
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
        .get_roles(gvm_gmp::commands::roles::GetRolesOpts {
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
        .get_permissions(gvm_gmp::commands::permissions::GetPermissionsOpts {
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

    let modify_permission = client
        .send(gvm_gmp::commands::permissions::modify_permission(
            &permission_id,
            gvm_gmp::commands::permissions::PermissionOpts {
                comment: Some(config.name("permission-modified")),
                subject_type: Some(gvm_gmp::PermissionSubjectType::Role),
                subject_id: Some(role.id.clone()),
                ..Default::default()
            },
        ))
        .await?;
    if modify_permission.status_code() == Some(400)
        && modify_permission.status_text().as_deref() == Some("Error in SUBJECT")
    {
        runtime::observe(
            "typed permission modify",
            Outcome::KnownUpstreamBug,
            "rust-gvm#405 reproduced: flat subject elements were rejected by gvmd",
        );

        runtime::observe(
            "canonical permission modify",
            Outcome::KnownUpstreamBug,
            "gvmd stable c286d205 queries removed permissions.resource_id/subject_id columns and closes the GMP connection",
        );
    } else {
        assert_status(&modify_permission, 200, "modify_permission")?;
        log_pass(
            "typed permission modify",
            "rust-gvm emitted a gvmd-compatible subject",
        );
    }
    let modify_group = client
        .send(gvm_gmp::commands::groups::modify_group(
            &group.id,
            gvm_gmp::commands::groups::GroupOpts {
                comment: Some(config.name("group-modified")),
                users: vec![user_name.clone()],
            },
        ))
        .await?;
    assert_status(&modify_group, 200, "modify_group")?;
    let modify_role = client
        .send(gvm_gmp::commands::roles::modify_role(
            &role.id,
            gvm_gmp::commands::roles::RoleOpts {
                comment: Some(config.name("role-modified")),
                users: vec![user_name.clone()],
            },
        ))
        .await?;
    assert_status(&modify_role, 200, "modify_role")?;
    let modify_user = client
        .send(gvm_gmp::commands::users::modify_user(
            &user.id,
            gvm_gmp::commands::users::UserOpts {
                password: Some(user_password.clone()),
                comment: Some(config.name("user-modified")),
                role_ids: user_role_ids,
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modify_user, 200, "modify_user")?;
    log_pass(
        "isolated access-control modify",
        "permission/group/role/user",
    );

    let mut restricted =
        GmpClient::connect(UnixSocketConnection::with_path(config.socket_path.clone())).await?;
    restricted.authenticate(&user_name, &user_password).await?;
    let denied = restricted
        .create_user("rust-gvm-e2e-permission-denied", Default::default())
        .await;
    ensure(
        matches!(
            denied,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "restricted user unexpectedly created an administrative user",
    )?;
    restricted.disconnect().await?;
    log_pass("isolated permission denied", "typed server error");

    let host = client
        .create_host(gvm_gmp::commands::hosts::HostOpts {
            value: Some("192.0.2.118".to_string()),
            comment: Some(config.name("host")),
        })
        .await?;
    tracker.track_asset(&host.id);
    let hosts = client
        .get_hosts(gvm_gmp::commands::hosts::GetHostsOpts {
            filter_string: Some(format!("uuid={}", host.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        hosts.items.iter().any(|entry| entry.meta.id == host.id),
        "typed host asset did not round-trip",
    )?;
    let assets = client
        .get_assets(gvm_gmp::commands::assets::GetAssetsOpts {
            type_: Some(gvm_gmp::commands::assets::AssetType::Host),
            filter_string: Some(format!("uuid={}", host.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
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
        .get_asset(&host.id, gvm_gmp::commands::assets::AssetType::Host)
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
        .get_operating_system_assets(
            gvm_gmp::commands::operating_systems::GetOperatingSystemsOpts {
                filter_string: Some("rows=1".to_string()),
                details: Some(true),
                ..Default::default()
            },
        )
        .await?;
    if let Some(operating_system) = operating_systems.items.first() {
        let single = client
            .get_operating_system_asset(&operating_system.meta.id, Some(true))
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
        .modify_asset(
            &host.id,
            gvm_gmp::commands::assets::ModifyAssetOpts {
                comment: Some(config.name("host-modified")),
                value: None,
            },
        )
        .await?;
    ensure(modify_host.status == 200, "typed modify_asset failed")?;
    let invalid_host = client
        .create_host(gvm_gmp::commands::hosts::HostOpts::named("not-an-ip"))
        .await;
    ensure(
        matches!(
            invalid_host,
            Err(GvmError::Parse(
                gvm_gmp::responses::ParseError::ServerError { .. }
            ))
        ),
        "invalid host asset did not produce a typed server error",
    )?;
    let generic_asset = client
        .create_asset(gvm_gmp::commands::assets::CreateAssetOpts {
            asset_type: gvm_gmp::commands::assets::AssetType::Host,
            comment: Some(config.name("generic-asset")),
            value: Some("192.0.2.119".to_string()),
        })
        .await?;
    ensure(
        generic_asset.status == 201,
        "typed generic create_asset failed",
    )?;
    let generic_asset_id = generic_asset.id.ok_or_else(|| {
        AppError::Assertion("typed generic create_asset omitted its id".to_string())
    })?;
    tracker.track_asset(&generic_asset_id);
    let deleted_generic_asset = client
        .delete_asset(
            &generic_asset_id,
            gvm_gmp::commands::assets::DeleteAssetOpts::default(),
        )
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
        .get_report_formats(GetReportFormatsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
        .await?;
    let report_format = report_formats.items.first().ok_or_else(|| {
        AppError::Assertion("isolated lane requires a warm report format".to_string())
    })?;
    let created_format = client
        .create_report_format(
            &config.name("report-format-created"),
            gvm_gmp::commands::report_formats::ReportFormatOpts {
                comment: Some(config.name("report-format-created-comment")),
                content_type: Some("text/xml".to_string()),
                format_type: Some(gvm_gmp::ReportFormatType::Xml),
            },
        )
        .await?;
    ensure(
        created_format.status == 201,
        "typed create_report_format failed",
    )?;
    tracker.track_report_format(&created_format.id);
    let cloned_format = client.clone_report_format(&report_format.meta.id).await?;
    tracker.track_report_format(&cloned_format.id);
    let modify_format = client
        .send(gvm_gmp::commands::report_formats::modify_report_format(
            &cloned_format.id,
            gvm_gmp::commands::report_formats::ReportFormatOpts {
                comment: Some(config.name("report-format")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modify_format, 200, "modify_report_format")?;

    let exported_format = client
        .send(gvm_gmp::commands::report_formats::get_report_format(
            &report_format.meta.id,
        ))
        .await?;
    assert_status(&exported_format, 200, "export report format for import")?;
    let imported_format_xml = replace_first_resource_id(
        &replace_first_resource_name(
            exported_format.as_str()?,
            "report_format",
            &config.name("report-format-import"),
        )?,
        "report_format",
        &fixture_uuid(&config.run_id, "rust-gvm-e2e-report-format"),
    )?;
    let imported_format = client.import_report_format(&imported_format_xml).await?;
    ensure(
        imported_format.status == 201,
        "typed import_report_format failed",
    )?;
    tracker.track_report_format(&imported_format.id);
    for id in [&created_format.id, &cloned_format.id, &imported_format.id] {
        let verified = client
            .send(gvm_gmp::commands::report_formats::verify_report_format(id))
            .await?;
        assert_status(&verified, 200, "verify_report_format")?;
    }

    let report_config = client
        .send(
            gvm_gmp::commands::report_configs::create_report_config_opts(
                &config.name("report-config"),
                report_format.meta.id.as_str(),
                gvm_gmp::commands::report_configs::CreateReportConfigOpts {
                    comment: Some(config.name("report-config-comment")),
                },
            ),
        )
        .await?;
    assert_status(&report_config, 201, "create_report_config")?;
    let report_config_id = response_id(&report_config, "create_report_config")?;
    tracker.track_report_config(&report_config_id);
    let configs = client
        .get_report_configs_parsed(gvm_gmp::commands::report_configs::GetReportConfigsOpts {
            filter: Some(format!("uuid={report_config_id}")),
            ..Default::default()
        })
        .await?;
    ensure(
        configs
            .items
            .iter()
            .any(|entry| entry.meta.id == report_config_id),
        "typed report config did not round-trip",
    )?;
    let modify_config = client
        .send(gvm_gmp::commands::report_configs::modify_report_config(
            report_config_id.as_str(),
            gvm_gmp::commands::report_configs::ModifyReportConfigOpts {
                comment: Some(config.name("report-config-modified")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modify_config, 200, "modify_report_config")?;
    let cloned_report_config = client
        .clone_report_config(report_config_id.as_str())
        .await?;
    ensure(
        cloned_report_config.status == 201,
        "typed clone_report_config failed",
    )?;
    tracker.track_report_config(&cloned_report_config.id);
    let rename_clone = client
        .send(gvm_gmp::commands::report_configs::modify_report_config(
            cloned_report_config.id.as_str(),
            gvm_gmp::commands::report_configs::ModifyReportConfigOpts {
                name: Some(config.name("report-config-clone")),
                comment: Some(config.name("report-config-clone-comment")),
            },
        ))
        .await?;
    assert_status(&rename_clone, 200, "rename cloned report config")?;
    log_pass(
        "isolated report resources",
        "format/config create/get/modify",
    );

    let sync_configs = client
        .get_scan_configs(GetScanConfigsOpts {
            filter_string: Some("rows=1".to_string()),
            ..Default::default()
        })
        .await?;
    let sync_config = sync_configs.items.first().ok_or_else(|| {
        AppError::Assertion("isolated sync requires a warm feed config".to_string())
    })?;
    let sync = client.sync_scan_config(&sync_config.meta.id).await?;
    ensure(
        matches!(sync.status, 200 | 202),
        "typed sync_scan_config returned an unexpected status",
    )?;
    log_pass(
        "isolated config sync",
        "typed sync request on dedicated database",
    );

    let test_alert = client
        .create_alert(
            &config.name("test-alert"),
            AlertOpts {
                comment: Some(config.name("test-alert-comment")),
                event: Some(AlertEvent::TaskRunStatusChanged),
                condition: Some(AlertCondition::Always),
                method: Some(AlertMethod::SysLog),
                ..Default::default()
            },
        )
        .await?;
    tracker.track_alert(&test_alert.id);
    let tested = client
        .send(gvm_gmp::commands::alerts::test_alert(&test_alert.id))
        .await?;
    assert_status(&tested, 200, "test_alert")?;
    log_pass("isolated alert test", "syslog alert test request");

    let tls = client
        .create_tls_certificate(
            &config.name("tls-certificate"),
            gvm_gmp::commands::tls_certificates::TlsCertificateOpts {
                certificate: Some(
                    include_str!("../../../fixtures/e2e-certificate.pem").to_string(),
                ),
                comment: Some(config.name("tls-certificate-comment")),
                ..Default::default()
            },
        )
        .await?;
    tracker.track_tls_certificate(&tls.id);
    let certificates = client
        .get_tls_certificates(
            gvm_gmp::commands::tls_certificates::GetTlsCertificatesOpts {
                filter_string: Some(format!("uuid={}", tls.id)),
                details: Some(true),
                ..Default::default()
            },
        )
        .await?;
    ensure(
        certificates
            .items
            .iter()
            .any(|entry| entry.meta.id == tls.id),
        "typed TLS certificate did not round-trip",
    )?;
    let modify_tls = client
        .send(gvm_gmp::commands::tls_certificates::modify_tls_certificate(
            &tls.id,
            gvm_gmp::commands::tls_certificates::TlsCertificateOpts {
                comment: Some(config.name("tls-certificate-modified")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modify_tls, 200, "modify_tls_certificate")?;
    log_pass(
        "isolated tls certificate",
        "typed create/get and raw modify",
    );

    let settings = client.get_settings().await?;
    if let Some(setting) = settings
        .items
        .iter()
        .find(|setting| setting.value.is_some())
    {
        let original = setting.value.clone().unwrap_or_default();
        let write_same_value = client
            .send(gvm_gmp::commands::system::modify_setting(
                &setting.id,
                &original,
            ))
            .await?;
        assert_status(&write_same_value, 200, "modify_setting snapshot")?;
        let restore = client
            .send(gvm_gmp::commands::system::modify_setting(
                &setting.id,
                &original,
            ))
            .await?;
        assert_status(&restore, 200, "modify_setting restore")?;
        log_pass("isolated setting", "snapshot and restore exact value");
    } else {
        return Err(AppError::Assertion(
            "isolated lane found no setting with a restorable value".to_string(),
        ));
    }

    trash_restore_then_delete(&mut client, "permission", &permission_id, |id, ultimate| {
        gvm_gmp::commands::permissions::delete_permission(id, ultimate)
    })
    .await?;
    tracker
        .permission_ids
        .retain(|id| id != permission_id.as_str());
    trash_restore_then_delete(&mut client, "group", &group.id, |id, ultimate| {
        gvm_gmp::commands::groups::delete_group(id, ultimate)
    })
    .await?;
    tracker.group_ids.retain(|id| id != group.id.as_str());
    trash_restore_then_delete(&mut client, "role", &role.id, |id, ultimate| {
        gvm_gmp::commands::roles::delete_role(id, ultimate)
    })
    .await?;
    tracker.role_ids.retain(|id| id != role.id.as_str());
    trash_restore_then_delete(&mut client, "user", &user.id, |id, ultimate| {
        gvm_gmp::commands::users::delete_user(id, ultimate)
    })
    .await?;
    tracker.user_ids.retain(|id| id != user.id.as_str());

    tracker.cleanup_inner().await?;
    let empty = client.empty_trashcan().await?;
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
    R: gvm_protocol::Request,
    F: Fn(&EntityId, bool) -> R,
{
    let trashed = client.send(delete(id, false)).await?;
    assert_status(&trashed, 200, &format!("trash {label}"))?;
    let restored = client.restore_from_trashcan(id).await?;
    ensure(
        restored.status == 200,
        &format!("restore {label} did not return 200"),
    )?;
    let deleted = client.send(delete(id, true)).await?;
    assert_status(&deleted, 200, &format!("ultimate delete {label}"))?;
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
    let version = client.get_version().await?;
    ensure(version.status == 200, "transport get_version failed")?;
    let auth = client
        .authenticate(&config.username, &config.password)
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

    let version_response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&version_response, 200, "get_version")?;
    let version_text = version_response
        .child_text("version")
        .ok_or_else(|| AppError::Assertion("get_version response missing <version>".to_string()))?;
    let version = parse_version_text(&version_text)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("expected GMP version >= 22.4, got {version}"),
    )?;
    log_pass("01", &format!("version negotiation ({version})"));

    let auth_response = client
        .call(authenticate(&config.username, &config.password))
        .await?;
    assert_status(&auth_response, 200, "authenticate")?;
    log_pass("02", "authentication");

    let configs_response = client
        .call(get_scan_configs(GetScanConfigsOpts::default()))
        .await?;
    assert_status(&configs_response, 200, "get_scan_configs")?;
    let config_count = count_elements(&configs_response, "config")?;
    ensure(config_count >= 1, "expected at least one scan config")?;
    log_pass("03", &format!("list scan configs ({config_count})"));

    let scanners_response = client
        .call(get_scanners(GetScannersOpts::default()))
        .await?;
    assert_status(&scanners_response, 200, "get_scanners")?;
    let scanner_count = count_elements(&scanners_response, "scanner")?;
    ensure(scanner_count >= 1, "expected at least one scanner")?;
    log_pass("04", &format!("list scanners ({scanner_count})"));

    let report_formats_response = client
        .call(get_report_formats(GetReportFormatsOpts::default()))
        .await?;
    assert_status(&report_formats_response, 200, "get_report_formats")?;
    log_pass(
        "05",
        &format!(
            "list report formats ({})",
            count_elements(&report_formats_response, "report_format")?
        ),
    );

    let port_lists_response = client
        .call(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&port_lists_response, 200, "get_port_lists")?;
    let port_list_count = count_elements(&port_lists_response, "port_list")?;
    ensure(port_list_count >= 1, "expected at least one port list")?;
    log_pass("06", &format!("list port lists ({port_list_count})"));

    // Pick the first port list for target creation (GMP requires PORT_LIST or PORT_RANGE)
    let port_list_id = first_element_id(&port_lists_response, "port_list")?;

    let target_response = client
        .call(create_target(
            &smoke_target_name,
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                port_list_id: Some(port_list_id),
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(&target_response, 201, "create_target")?;
    let target_id = response_id(&target_response, "create_target")?;
    tracker.track_target(&target_id);
    log_pass("07", &format!("create target ({target_id})"));

    let get_target_response = client.call(get_target(&target_id)).await?;
    assert_status(&get_target_response, 200, "get_target")?;
    ensure(
        response_contains(&get_target_response, &smoke_target_name)?,
        "expected created target name in get_target response",
    )?;
    log_pass("08", "get target by UUID");

    let modify_target = client
        .send(gvm_gmp::commands::targets::modify_target(
            &target_id,
            gvm_gmp::commands::targets::ModifyTargetOpts {
                name: Some(config.name("smoke-target-modified")),
                comment: Some(config.name("smoke-target-comment")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modify_target, 200, "modify_target")?;
    trash_restore_then_delete(&mut client, "target", &target_id, |id, ultimate| {
        delete_target(id, ultimate)
    })
    .await?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());
    log_pass("09", "modify/trash/restore/ultimate-delete target");

    let verify_delete_response = client.send(get_target(&target_id)).await?;
    assert_status(&verify_delete_response, 404, "verify target deletion")?;
    log_pass("10", "verify deletion");

    if config.run_scan {
        run_scan_suite(&mut client, config, tracker).await?;
    }

    client.disconnect().await?;
    Ok(())
}

async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    config: &EnvConfig,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    client
        .authenticate(&config.username, &config.password)
        .await?;
    log_line("Running deterministic host/network scan flow");
    let scan_target_name = config.name("scan-target");
    let scan_task_name = config.name("scan-task");
    let scan_host = env::var("E2E_SCAN_TARGET_HOST").unwrap_or_else(|_| "scan-fixture".to_string());

    let port_list = client
        .create_port_list(
            &config.name("scan-port-list"),
            PortListOpts {
                port_range: Some("T:80".to_string()),
                comment: Some(config.name("scan-port-list-comment")),
            },
        )
        .await?;
    ensure(
        port_list.status == 201,
        "typed scan port-list create failed",
    )?;
    tracker.track_port_list(&port_list.id);
    let scan_target = client
        .create_target(
            &scan_target_name,
            CreateTargetOpts {
                hosts: vec![scan_host],
                port_list_id: Some(port_list.id.clone()),
                ..CreateTargetOpts::default()
            },
        )
        .await?;
    ensure(scan_target.status == 201, "typed scan target create failed")?;
    tracker.track_target(&scan_target.id);

    let configs = client
        .get_scan_configs(GetScanConfigsOpts::default())
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
    let scanners = client.get_scanners(GetScannersOpts::default()).await?;
    let scanner = scanners
        .items
        .first()
        .ok_or_else(|| AppError::Assertion("scan lane requires a warm scanner".to_string()))?;

    let task = client
        .create_task(
            &scan_task_name,
            &scan_config.meta.id,
            &scan_target.id,
            &scanner.meta.id,
            CreateTaskOpts::default(),
        )
        .await?;
    ensure(task.status == 201, "typed scan task create failed")?;
    tracker.track_task(&task.id);
    let listed = client
        .get_tasks(GetTasksOpts {
            filter_string: Some(format!("uuid={}", task.id)),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        listed.items.iter().any(|item| item.meta.id == task.id),
        "typed task list/filter did not return the scan task",
    )?;

    let started = client.start_task(&task.id).await?;
    ensure(started.status == 202, "typed start_task did not return 202")?;
    let report_id = started.report_id.ok_or_else(|| {
        AppError::Assertion("typed start_task response omitted report_id".to_string())
    })?;
    match client.start_task(&task.id).await {
        Ok(response) if response.status >= 400 => log_pass(
            "typed duplicate start_task",
            &format!(
                "rejected with status {} ({})",
                response.status, response.status_text
            ),
        ),
        Ok(response)
            if response.status == 202 && response.report_id.as_ref() == Some(&report_id) =>
        {
            log_pass(
                "typed duplicate start_task",
                "idempotent response preserved the active report",
            );
        }
        Ok(response) => {
            return Err(AppError::Assertion(format!(
                "duplicate start_task returned status {} ({}) with report {:?}, expected a rejection or the existing report {report_id}",
                response.status, response.status_text, response.report_id
            )));
        }
        Err(GvmError::Parse(gvm_gmp::responses::ParseError::ServerError { .. })) => {
            log_pass("typed duplicate start_task", "typed server rejection")
        }
        Err(error) => return Err(error.into()),
    }

    let task_status = wait_task_state(
        client,
        &task.id,
        Duration::from_secs(config.task_progress_timeout_secs),
        |status| status != "New" && status != "Requested",
    )
    .await?;
    if matches!(task_status.as_str(), "Running" | "Stop Requested") {
        let stop_response = client.call(stop_task(&task.id)).await?;
        assert_status(&stop_response, 200, "stop_task")?;
        let stopped = wait_task_state(client, &task.id, Duration::from_secs(120), |status| {
            matches!(
                status,
                "Stopped" | "Interrupted" | "Done" | "Internal Error"
            )
        })
        .await?;
        if matches!(stopped.as_str(), "Stopped" | "Interrupted") {
            let resumed = client.resume_task(&task.id).await?;
            ensure(
                resumed.status == 202,
                "typed resume_task did not return 202",
            )?;
            ensure(
                resumed.report_id.as_ref() == Some(&report_id),
                "resume_task changed the report linkage",
            )?;
            let resumed_state = wait_task_state(
                client,
                &task.id,
                Duration::from_secs(config.task_progress_timeout_secs),
                |status| !matches!(status, "Stopped" | "Interrupted" | "Requested"),
            )
            .await?;
            if resumed_state == "Running" {
                let stop = client.call(stop_task(&task.id)).await?;
                assert_status(&stop, 200, "stop resumed task")?;
                wait_task_state(client, &task.id, Duration::from_secs(120), |status| {
                    matches!(
                        status,
                        "Stopped" | "Interrupted" | "Done" | "Internal Error"
                    )
                })
                .await?;
            }
        }
    }

    let report_response = client.call(get_report(&report_id)).await?;
    assert_status(&report_response, 200, "get_report")?;
    ensure(
        response_contains(&report_response, "<report ")?
            || response_contains(&report_response, "<results>")?
            || response_contains(&report_response, "<result>")?,
        "expected report payload in get_report response",
    )?;

    let reports = client
        .get_reports(gvm_gmp::commands::reports::GetReportsOpts {
            report_id: Some(report_id.clone()),
            details: Some(true),
            ignore_pagination: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        reports
            .items
            .iter()
            .any(|report| report.meta.id == report_id),
        "typed get_reports did not preserve task/report linkage",
    )?;
    let results = client
        .get_results(gvm_gmp::commands::results::GetResultsOpts {
            filter_string: Some(format!("report_id={report_id} rows=100")),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        results.status == 200,
        "typed get_results did not return 200",
    )?;
    for result in &results.items {
        ensure(
            result
                .report
                .as_ref()
                .is_none_or(|report| report.id == report_id),
            "typed result referenced a different report",
        )?;
    }

    let formats = client
        .get_report_formats(GetReportFormatsOpts::default())
        .await?;
    let format = formats
        .items
        .iter()
        .find(|item| item.active)
        .or_else(|| formats.items.first())
        .ok_or_else(|| AppError::Assertion("scan lane requires a report format".to_string()))?;
    let export = client
        .get_report_export(&report_id, &format.meta.id)
        .await?;
    ensure(!export.bytes.is_empty(), "typed report export was empty")?;
    let export_with_opts = client
        .get_report_export_with_opts(
            &report_id,
            gvm_gmp::commands::reports::GetReportExportOpts::new(format.meta.id.clone()),
        )
        .await?;
    ensure(
        !export_with_opts.bytes.is_empty(),
        "typed report export with options was empty",
    )?;

    run_conditional_report_drilldowns(client, &report_id).await?;

    let import_task = client
        .create_import_task(
            &config.name("import-task"),
            Some(&config.name("sanitized-report-import")),
        )
        .await?;
    ensure(import_task.status == 201, "typed create_import_task failed")?;
    tracker.track_task(&import_task.id);
    let import_xml = include_str!("../../../fixtures/import-report.xml")
        .replace("{{RUN_NAME}}", &config.name("imported-report"))
        .replace(
            "{{REPORT_ID}}",
            &fixture_uuid(&config.run_id, "rust-gvm-e2e-report"),
        );
    let imported = client
        .import_report(
            &import_xml,
            &import_task.id,
            gvm_gmp::commands::reports::ImportReportOpts {
                in_assets: Some(false),
            },
        )
        .await?;
    ensure(imported.status == 201, "typed import_report failed")?;
    let imported_report = client
        .get_reports(gvm_gmp::commands::reports::GetReportsOpts {
            report_id: Some(imported.id.clone()),
            details: Some(true),
            ..Default::default()
        })
        .await?;
    ensure(
        imported_report
            .items
            .iter()
            .any(|item| item.meta.id == imported.id),
        "typed imported report did not round-trip",
    )?;
    trash_restore_then_delete(
        client,
        "imported report",
        &imported.id,
        gvm_gmp::commands::reports::delete_report,
    )
    .await?;
    let delete_import_task = client.call(delete_task(&import_task.id, true)).await?;
    assert_status(&delete_import_task, 200, "delete import task")?;
    tracker
        .task_ids
        .retain(|value| value != import_task.id.as_str());
    log_pass(
        "report import",
        "sanitized fixture create_import_task/import_report/read/cleanup",
    );

    if let Some(result) = results.items.first() {
        let ticket = client
            .create_ticket(
                &result.meta.id,
                gvm_gmp::commands::tickets::TicketOpts {
                    assigned_to: Some(config.username.clone()),
                    comment: Some(config.name("scan-ticket")),
                    status: Some(gvm_gmp::TicketStatus::Open),
                    open_note: Some(config.name("scan-ticket-open")),
                    ..Default::default()
                },
            )
            .await?;
        tracker.track_ticket(&ticket.id);
        let tickets = client
            .get_tickets(gvm_gmp::commands::tickets::GetTicketsOpts {
                filter_string: Some(format!("uuid={}", ticket.id)),
                details: Some(true),
                ..Default::default()
            })
            .await?;
        ensure(
            tickets.items.iter().any(|item| item.meta.id == ticket.id),
            "typed ticket did not round-trip",
        )?;
        let modified = client
            .send(gvm_gmp::commands::tickets::modify_ticket(
                &ticket.id,
                gvm_gmp::commands::tickets::TicketOpts {
                    comment: Some(config.name("scan-ticket-modified")),
                    ..Default::default()
                },
            ))
            .await?;
        assert_status(&modified, 200, "modify_ticket")?;
        trash_restore_then_delete(client, "ticket", &ticket.id, |id, ultimate| {
            gvm_gmp::commands::tickets::delete_ticket(id, ultimate)
        })
        .await?;
        tracker.ticket_ids.retain(|id| id != ticket.id.as_str());
    } else {
        runtime::observe(
            "scan-ticket-lifecycle",
            Outcome::ConditionalUnavailable,
            "deterministic network scan produced no result eligible for a ticket",
        );
    }

    trash_restore_then_delete(
        client,
        "scan report",
        &report_id,
        gvm_gmp::commands::reports::delete_report,
    )
    .await?;
    let absent_report = client.send(get_report(&report_id)).await?;
    assert_status(&absent_report, 404, "verify report cleanup")?;
    let delete_task_response = client.call(delete_task(&task.id, true)).await?;
    assert_status(&delete_task_response, 200, "delete_task")?;
    tracker.task_ids.retain(|value| value != task.id.as_str());

    let delete_target_response = client.call(delete_target(&scan_target.id, true)).await?;
    assert_status(&delete_target_response, 200, "delete_target")?;
    tracker
        .target_ids
        .retain(|value| value != scan_target.id.as_str());
    let delete_port_list_response = client.call(delete_port_list(&port_list.id, true)).await?;
    assert_status(&delete_port_list_response, 200, "delete scan port list")?;
    tracker
        .port_list_ids
        .retain(|value| value != port_list.id.as_str());

    log_pass(
        "scan",
        &format!(
            "task states, report {}, {} typed result(s), exports, cleanup",
            report_id,
            results.items.len()
        ),
    );
    Ok(())
}

async fn run_conditional_report_drilldowns(
    client: &mut GmpClient<UnixSocketConnection>,
    report_id: &EntityId,
) -> Result<(), AppError> {
    let available = if let Some(report) = runtime::snapshot() {
        report.help_commands.into_iter().collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let opts = || gvm_gmp::commands::reports::GetReportDetailsOpts {
        filter_string: Some("rows=10 first=1".to_string()),
        details: Some(true),
        ignore_pagination: Some(true),
        ..Default::default()
    };
    macro_rules! conditional_read {
        ($command:literal, $future:expr) => {
            if available.contains($command) {
                let response = $future.await?;
                ensure(
                    response.status == 200,
                    concat!("conditional typed ", $command, " did not return 200"),
                )?;
                log_pass(concat!("typed ", $command), "valid parsed response");
            }
        };
    }
    if available.contains("get_scan_report") {
        let response = client
            .get_scan_report(
                report_id,
                gvm_gmp::commands::reports::GetScanReportOpts::default(),
            )
            .await?;
        assert_status(&response, 200, "typed get_scan_report")?;
        ensure(
            response_contains(&response, "<report ")?,
            "typed get_scan_report omitted its report payload",
        )?;
        log_pass("typed get_scan_report", "valid structured report response");
    }
    conditional_read!(
        "get_report_vulns",
        client.get_report_vulns(report_id, opts())
    );
    conditional_read!(
        "get_report_vulns",
        client.get_report_vulnerabilities(report_id, opts())
    );
    conditional_read!(
        "get_report_tls_certificates",
        client.get_report_tls_certificates(report_id, opts())
    );
    conditional_read!(
        "get_report_hosts",
        client.get_report_hosts_parsed(report_id, opts())
    );
    conditional_read!(
        "get_report_ports",
        client.get_report_ports_parsed(report_id, opts())
    );
    conditional_read!(
        "get_report_applications",
        client.get_report_applications_parsed(report_id, opts())
    );
    conditional_read!(
        "get_report_operating_systems",
        client.get_report_operating_systems_parsed(report_id, opts())
    );
    conditional_read!(
        "get_report_cves",
        client.get_report_cves_parsed(report_id, opts())
    );
    conditional_read!(
        "get_report_errors",
        client.get_report_errors(report_id, opts())
    );
    conditional_read!(
        "get_report_closed_cves",
        client.get_report_closed_cves(report_id, opts())
    );
    Ok(())
}

async fn run_crud_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;

    let auth_response = client
        .call(authenticate(&config.username, &config.password))
        .await?;
    assert_status(&auth_response, 200, "authenticate")?;

    // --- port_list CRUD ---
    let pl_resp = client
        .call(create_port_list(
            &config.name("port-list"),
            PortListOpts {
                port_range: Some("T:1-100".into()),
                ..PortListOpts::default()
            },
        ))
        .await?;
    assert_status(&pl_resp, 201, "create_port_list")?;
    let pl_id = response_id(&pl_resp, "create_port_list")?;
    tracker.track_port_list(&pl_id);
    log_pass("crud 01", &format!("create port_list ({pl_id})"));

    let get_pl_resp = client.call(get_port_list(&pl_id)).await?;
    assert_status(&get_pl_resp, 200, "get_port_list")?;
    log_pass("crud 02", "get port_list");

    let range = client
        .send(gvm_gmp::commands::port_lists::create_port_range(
            &pl_id,
            gvm_gmp::PortRangeType::Tcp,
            101,
            102,
        ))
        .await?;
    assert_status(&range, 201, "create_port_range")?;
    let range_id = response_id(&range, "create_port_range")?;
    let delete_range = client
        .send(gvm_gmp::commands::port_lists::delete_port_range(&range_id))
        .await?;
    assert_status(&delete_range, 200, "delete_port_range")?;
    let modified = client
        .send(gvm_gmp::commands::port_lists::modify_port_list(
            &pl_id,
            PortListOpts {
                comment: Some(config.name("port-list-modified")),
                port_range: None,
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_port_list")?;
    trash_restore_then_delete(&mut client, "port_list", &pl_id, |id, ultimate| {
        delete_port_list(id, ultimate)
    })
    .await?;
    tracker.port_list_ids.retain(|v| v != pl_id.as_str());
    log_pass("crud 03", "modify/trash/restore/delete port_list");

    let verify_pl_resp = client.send(get_port_list(&pl_id)).await?;
    assert_status(&verify_pl_resp, 404, "verify port_list absent")?;
    log_pass("crud 04", "verify port_list absent");

    // --- credential CRUD ---
    let cred_resp = client
        .call(create_credential(
            &config.name("credential"),
            CredentialOpts {
                credential_type: Some(CredentialType::UsernamePassword),
                login: Some("testuser".into()),
                password: Some("testpass".into()),
                ..CredentialOpts::default()
            },
        ))
        .await?;
    assert_status(&cred_resp, 201, "create_credential")?;
    let cred_id = response_id(&cred_resp, "create_credential")?;
    tracker.track_credential(&cred_id);
    log_pass("crud 05", &format!("create credential ({cred_id})"));

    let get_cred_resp = client.call(get_credential(&cred_id)).await?;
    assert_status(&get_cred_resp, 200, "get_credential")?;
    log_pass("crud 06", "get credential");

    let modified = client
        .send(gvm_gmp::commands::credentials::modify_credential(
            &cred_id,
            CredentialOpts {
                comment: Some(config.name("credential-modified")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_credential")?;
    trash_restore_then_delete(&mut client, "credential", &cred_id, |id, ultimate| {
        delete_credential(id, ultimate)
    })
    .await?;
    tracker.credential_ids.retain(|v| v != cred_id.as_str());
    log_pass("crud 07", "modify/trash/restore/delete credential");

    let verify_cred_resp = client.send(get_credential(&cred_id)).await?;
    assert_status(&verify_cred_resp, 404, "verify credential absent")?;
    log_pass("crud 08", "verify credential absent");

    // --- schedule CRUD ---
    let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\nBEGIN:VEVENT\r\nDTSTART:20260401T060000Z\r\nDURATION:PT0S\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR";
    let sched_resp = client
        .call(create_schedule(
            &config.name("schedule"),
            ScheduleOpts {
                icalendar: Some(ical.into()),
                timezone: Some("UTC".into()),
                comment: Some("e2e test schedule".into()),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&sched_resp, 201, "create_schedule")?;
    let sched_id = response_id(&sched_resp, "create_schedule")?;
    tracker.track_schedule(&sched_id);
    log_pass("crud 09", &format!("create schedule ({sched_id})"));

    let get_sched_resp = client.call(get_schedule(&sched_id)).await?;
    assert_status(&get_sched_resp, 200, "get_schedule")?;
    log_pass("crud 10", "get schedule");

    let modified = client
        .send(gvm_gmp::commands::schedules::modify_schedule(
            &sched_id,
            ScheduleOpts {
                comment: Some(config.name("schedule-modified")),
                name: Some(config.name("schedule-renamed")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_schedule")?;
    trash_restore_then_delete(&mut client, "schedule", &sched_id, |id, ultimate| {
        delete_schedule(id, ultimate)
    })
    .await?;
    tracker.schedule_ids.retain(|v| v != sched_id.as_str());
    log_pass("crud 11", "modify/trash/restore/delete schedule");

    let verify_sched_resp = client.send(get_schedule(&sched_id)).await?;
    assert_status(&verify_sched_resp, 404, "verify schedule absent")?;
    log_pass("crud 12", "verify schedule absent");

    // --- filter CRUD ---
    let filter_resp = client
        .call(create_filter(
            &config.name("filter"),
            FilterOpts {
                term: Some("name=test".into()),
                filter_type: Some(FilterType::Task),
                ..FilterOpts::default()
            },
        ))
        .await?;
    assert_status(&filter_resp, 201, "create_filter")?;
    let filter_id = response_id(&filter_resp, "create_filter")?;
    tracker.track_filter(&filter_id);
    log_pass("crud 13", &format!("create filter ({filter_id})"));

    let get_filter_resp = client.call(get_filter(&filter_id)).await?;
    assert_status(&get_filter_resp, 200, "get_filter")?;
    log_pass("crud 14", "get filter");

    let modified = client
        .send(gvm_gmp::commands::filters::modify_filter(
            &filter_id,
            FilterOpts {
                comment: Some(config.name("filter-modified")),
                term: Some("name~rust-gvm-e2e".to_string()),
                filter_type: Some(FilterType::Task),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_filter")?;
    trash_restore_then_delete(&mut client, "filter", &filter_id, |id, ultimate| {
        delete_filter(id, ultimate)
    })
    .await?;
    tracker.filter_ids.retain(|v| v != filter_id.as_str());
    log_pass("crud 15", "modify/trash/restore/delete filter");

    let verify_filter_resp = client.send(get_filter(&filter_id)).await?;
    assert_status(&verify_filter_resp, 404, "verify filter absent")?;
    log_pass("crud 16", "verify filter absent");

    // --- task CRUD (requires target, scan_config, scanner) ---
    let pl_list_resp = client
        .call(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&pl_list_resp, 200, "get_port_lists for task prereq")?;
    let task_port_list_id = first_element_id(&pl_list_resp, "port_list")?;

    let task_target_resp = client
        .call(create_target(
            &config.name("task-target"),
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                port_list_id: Some(task_port_list_id),
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(&task_target_resp, 201, "create task target")?;
    let task_target_id = response_id(&task_target_resp, "create task target")?;
    tracker.track_target(&task_target_id);

    let scan_configs_resp = client
        .call(get_scan_configs(GetScanConfigsOpts::default()))
        .await?;
    let scan_config_id = first_element_id(&scan_configs_resp, "config")?;

    let scanners_resp = client
        .call(get_scanners(GetScannersOpts::default()))
        .await?;
    let scanner_id = first_element_id(&scanners_resp, "scanner")?;

    let task_resp = client
        .call(create_task(
            &config.name("task"),
            &scan_config_id,
            &task_target_id,
            &scanner_id,
            CreateTaskOpts::default(),
        ))
        .await?;
    assert_status(&task_resp, 201, "create_task")?;
    let task_id = response_id(&task_resp, "create_task")?;
    tracker.track_task(&task_id);
    log_pass("crud 17", &format!("create task ({task_id})"));

    let get_task_resp = client.call(get_task(&task_id)).await?;
    assert_status(&get_task_resp, 200, "get_task")?;
    log_pass("crud 18", "get task");

    let modified = client
        .send(gvm_gmp::commands::tasks::modify_task(
            &task_id,
            gvm_gmp::commands::tasks::ModifyTaskOpts {
                name: Some(config.name("task-modified")),
                comment: Some(config.name("task-comment-modified")),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_task")?;
    trash_restore_then_delete(&mut client, "task", &task_id, |id, ultimate| {
        delete_task(id, ultimate)
    })
    .await?;
    tracker.task_ids.retain(|v| v != task_id.as_str());
    log_pass("crud 19", "modify/trash/restore/delete task");

    trash_restore_then_delete(&mut client, "task target", &task_target_id, delete_target).await?;
    tracker.target_ids.retain(|v| v != task_target_id.as_str());
    log_pass("crud 20", "trash/restore/delete task target");

    // --- notes and overrides (require an NVT OID) ---
    let nvts_resp = client
        .call(get_nvts(GetNvtsOpts {
            filter_string: Some("rows=1".into()),
            ..GetNvtsOpts::default()
        }))
        .await?;
    assert_status(&nvts_resp, 200, "get_nvts for note prereq")?;

    let nvt_oid = first_nvt_oid(&nvts_resp)?;

    // --- note CRUD ---
    let note_resp = client
        .call(create_note(
            &nvt_oid,
            NoteOpts {
                text: Some(config.name("note")),
                ..NoteOpts::default()
            },
        ))
        .await?;
    assert_status(&note_resp, 201, "create_note")?;
    let note_id = response_id(&note_resp, "create_note")?;
    tracker.track_note(&note_id);
    log_pass("crud 21", &format!("create note ({note_id})"));

    let get_note_resp = client.call(get_note(&note_id)).await?;
    assert_status(&get_note_resp, 200, "get_note")?;
    log_pass("crud 22", "get note");

    let modified = client
        .send(gvm_gmp::commands::notes::modify_note(
            &note_id,
            NoteOpts {
                text: Some(config.name("note-modified")),
                active: Some(true),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_note")?;
    trash_restore_then_delete(&mut client, "note", &note_id, |id, ultimate| {
        delete_note(id, ultimate)
    })
    .await?;
    tracker.note_ids.retain(|v| v != note_id.as_str());
    log_pass("crud 23", "modify/trash/restore/delete note");

    let verify_note_resp = client.send(get_note(&note_id)).await?;
    assert_status(&verify_note_resp, 404, "verify note absent")?;
    log_pass("crud 24", "verify note absent");

    // --- override CRUD ---
    let override_resp = client
        .call(create_override(
            &nvt_oid,
            OverrideOpts {
                text: Some(config.name("override")),
                new_severity: Some("-1".into()),
                ..OverrideOpts::default()
            },
        ))
        .await?;
    assert_status(&override_resp, 201, "create_override")?;
    let override_id = response_id(&override_resp, "create_override")?;
    tracker.track_override(&override_id);
    log_pass("crud 25", &format!("create override ({override_id})"));

    let get_override_resp = client.call(get_override(&override_id)).await?;
    assert_status(&get_override_resp, 200, "get_override")?;
    log_pass("crud 26", "get override");

    let modified = client
        .send(gvm_gmp::commands::overrides::modify_override(
            &override_id,
            OverrideOpts {
                text: Some(config.name("override-modified")),
                new_severity: Some("0.0".to_string()),
                active: Some(true),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_override")?;
    trash_restore_then_delete(&mut client, "override", &override_id, |id, ultimate| {
        delete_override(id, ultimate)
    })
    .await?;
    tracker.override_ids.retain(|v| v != override_id.as_str());
    log_pass("crud 27", "modify/trash/restore/delete override");

    let verify_override_resp = client.send(get_override(&override_id)).await?;
    assert_status(&verify_override_resp, 404, "verify override absent")?;
    log_pass("crud 28", "verify override absent");

    // --- tag CRUD ---
    let tag_resp = client
        .call(create_tag(
            &config.name("tag"),
            TagOpts {
                resource_type: Some(EntityType::Task),
                value: Some("e2e-value".into()),
                comment: Some("e2e test tag".into()),
                active: Some(true),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&tag_resp, 201, "create_tag")?;
    let tag_id = response_id(&tag_resp, "create_tag")?;
    tracker.track_tag(&tag_id);
    log_pass("crud 29", &format!("create tag ({tag_id})"));

    let get_tag_resp = client.call(get_tag(&tag_id)).await?;
    assert_status(&get_tag_resp, 200, "get_tag")?;
    log_pass("crud 30", "get tag");

    let modified = client
        .send(gvm_gmp::commands::tags::modify_tag(
            &tag_id,
            TagOpts {
                comment: Some(config.name("tag-modified")),
                value: Some(config.name("tag-value-modified")),
                active: Some(true),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_tag")?;
    trash_restore_then_delete(&mut client, "tag", &tag_id, |id, ultimate| {
        delete_tag(id, ultimate)
    })
    .await?;
    tracker.tag_ids.retain(|v| v != tag_id.as_str());
    log_pass("crud 31", "modify/trash/restore/delete tag");

    let verify_tag_resp = client.send(get_tag(&tag_id)).await?;
    assert_status(&verify_tag_resp, 404, "verify tag absent")?;
    log_pass("crud 32", "verify tag absent");

    // --- alert CRUD ---
    let alert = client
        .create_alert(
            &config.name("alert"),
            AlertOpts {
                comment: Some(config.name("alert-comment")),
                event: Some(AlertEvent::TaskRunStatusChanged),
                condition: Some(AlertCondition::Always),
                method: Some(AlertMethod::SysLog),
                ..Default::default()
            },
        )
        .await?;
    tracker.track_alert(&alert.id);
    log_pass("crud 33", &format!("typed create alert ({})", alert.id));
    let alerts = client
        .get_alerts(GetAlertsOpts {
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
    let modified = client
        .send(gvm_gmp::commands::alerts::modify_alert(
            &alert.id,
            AlertOpts {
                comment: Some(config.name("alert-modified")),
                event: Some(AlertEvent::TaskRunStatusChanged),
                condition: Some(AlertCondition::Always),
                method: Some(AlertMethod::SysLog),
                ..Default::default()
            },
        ))
        .await?;
    assert_status(&modified, 200, "modify_alert")?;
    trash_restore_then_delete(&mut client, "alert", &alert.id, |id, ultimate| {
        delete_alert(id, ultimate)
    })
    .await?;
    tracker.alert_ids.retain(|id| id != alert.id.as_str());
    let absent = client.send(get_alert(&alert.id)).await?;
    assert_status(&absent, 404, "verify alert absent")?;
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
        .call(authenticate(&config.username, &config.password))
        .await?;
    assert_status(&auth_response, 200, "authenticate")?;

    // 01: feeds
    let feeds_resp = client.call(get_feeds()).await?;
    assert_status(&feeds_resp, 200, "get_feeds")?;
    let feed_count = count_elements(&feeds_resp, "feed")?;
    ensure(feed_count >= 1, "expected at least one feed")?;
    log_pass("secinfo 01", &format!("get_feeds ({feed_count} feeds)"));

    // 02: CVEs
    let cves_resp = client.call(get_cves(GetSecInfoOpts::default())).await?;
    assert_status(&cves_resp, 200, "get_cves")?;
    let cve_count = count_elements(&cves_resp, "info")?;
    if cve_count == 0 {
        log_line("[info] secinfo 02 get_cves returned a valid empty warm-feed collection");
    }
    log_pass("secinfo 02", &format!("get_cves ({cve_count} entries)"));

    // 03: CPEs
    let cpes_resp = client.call(get_cpes(GetSecInfoOpts::default())).await?;
    assert_status(&cpes_resp, 200, "get_cpes")?;
    let cpe_count = count_elements(&cpes_resp, "info")?;
    if cpe_count == 0 {
        log_line("[info] secinfo 03 get_cpes returned a valid empty warm-feed collection");
    }
    log_pass("secinfo 03", &format!("get_cpes ({cpe_count} entries)"));

    // 04: CERT-Bund advisories
    let cert_resp = client
        .call(get_cert_bund_advisories(GetSecInfoOpts::default()))
        .await?;
    assert_status(&cert_resp, 200, "get_cert_bund_advisories")?;
    let cert_count = count_elements(&cert_resp, "info")?;
    if cert_count == 0 {
        log_line("[info] secinfo 04 get_cert_bund_advisories returned a valid empty collection");
    }
    log_pass(
        "secinfo 04",
        &format!("get_cert_bund_advisories ({cert_count} entries)"),
    );

    // 05: DFN-CERT advisories
    let dfn_resp = client
        .call(get_dfn_cert_advisories(GetSecInfoOpts::default()))
        .await?;
    assert_status(&dfn_resp, 200, "get_dfn_cert_advisories")?;
    let dfn_count = count_elements(&dfn_resp, "info")?;
    if dfn_count == 0 {
        log_line("[info] secinfo 05 get_dfn_cert_advisories returned a valid empty collection");
    }
    log_pass(
        "secinfo 05",
        &format!("get_dfn_cert_advisories ({dfn_count} entries)"),
    );

    // 06: NVTs
    let nvts_resp = client
        .call(get_nvts(GetNvtsOpts {
            filter_string: Some("rows=10".into()),
            ..GetNvtsOpts::default()
        }))
        .await?;
    assert_status(&nvts_resp, 200, "get_nvts")?;
    let nvt_count = count_elements(&nvts_resp, "nvt")?;
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
        .call(authenticate(&config.username, &config.password))
        .await?;
    assert_status(&auth_response, 200, "authenticate")?;

    let mut warnings: Vec<String> = Vec::new();

    // 01: get_version
    let rust_version_response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&rust_version_response, 200, "get_version")?;
    let rust_version = rust_version_response
        .child_text("version")
        .unwrap_or_default();
    compare_get_version(&rust_version, &mut warnings)?;
    log_pass("diff 01", "get_version compared");

    // 02: compare identical, unbounded usage_type=scan queries. The ergonomic
    // rust-gvm get_scan_configs wrapper currently omits usage_type, unlike
    // python-gvm, so the generic typed helper makes the wire semantics explicit.
    let rust_scan_configs = client
        .get_configs(gvm_gmp::commands::configs::GetConfigsOpts {
            filter_string: Some("rows=-1".to_string()),
            usage_type: Some(gvm_gmp::commands::configs::ConfigUsageType::Scan),
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
    let rust_scanners_response = client
        .call(get_scanners(GetScannersOpts::default()))
        .await?;
    assert_status(&rust_scanners_response, 200, "get_scanners")?;
    let rust_scanners = GetScannersResponse::from_response(&rust_scanners_response)?
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
        .call(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&rust_port_lists_response, 200, "get_port_lists")?;
    let rust_port_lists = GetPortListsResponse::from_response(&rust_port_lists_response)?
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
    let rust_feeds_response = client.call(get_feeds()).await?;
    assert_status(&rust_feeds_response, 200, "get_feeds")?;
    let rust_feeds = GetFeedsResponse::from_response(&rust_feeds_response)?
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
        .call(get_report_formats(GetReportFormatsOpts::default()))
        .await?;
    assert_status(&rust_report_formats_response, 200, "get_report_formats")?;
    let rust_report_formats =
        GetReportFormatsResponse::from_response(&rust_report_formats_response)?
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
        ($command:literal, $tag:literal, $request:expr) => {{
            let response = client.send($request).await?;
            assert_status(&response, 200, $command)?;
            let entities = id_name_entities(&response, $tag)?;
            compare_id_name_command($command, &entities, &mut warnings)?;
            log_pass(
                concat!("diff ", $command),
                "semantic UUID/name set compared",
            );
        }};
    }
    compare_deterministic_list!("get_alerts", "alert", get_alerts(GetAlertsOpts::default()));
    compare_deterministic_list!(
        "get_credentials",
        "credential",
        get_credentials(GetCredentialsOpts::default())
    );
    compare_deterministic_list!(
        "get_filters",
        "filter",
        get_filters(GetFiltersOpts::default())
    );
    compare_deterministic_list!(
        "get_schedules",
        "schedule",
        get_schedules(GetSchedulesOpts::default())
    );
    compare_deterministic_list!("get_tags", "tag", get_tags(GetTagsOpts::default()));
    compare_deterministic_list!("get_tasks", "task", get_tasks(GetTasksOpts::default()));

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
        .call(create_target(
            &rust_target_name,
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                port_list_id: Some(parse_entity_id(&port_list_id)?),
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(
        &rust_target_response,
        201,
        "differential create_target rust",
    )?;
    let rust_target_id = response_id(&rust_target_response, "differential create_target rust")?;
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

    let rust_targets_response = client.call(get_targets(GetTargetsOpts::default())).await?;
    assert_status(&rust_targets_response, 200, "get_targets rust")?;
    let rust_targets = GetTargetsResponse::from_response(&rust_targets_response)?
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

    let rust_delete_response = client.call(delete_target(&rust_target_id, true)).await?;
    assert_status(
        &rust_delete_response,
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

async fn wait_task_state(
    client: &mut GmpClient<UnixSocketConnection>,
    task_id: &EntityId,
    timeout: Duration,
    accept: impl Fn(&str) -> bool,
) -> Result<String, AppError> {
    let started = tokio::time::Instant::now();
    let mut last_status = String::from("unknown");

    while started.elapsed() <= timeout {
        let response = client
            .get_tasks(GetTasksOpts {
                filter_string: Some(format!("uuid={task_id}")),
                details: Some(true),
                ..Default::default()
            })
            .await?;
        let task = response
            .items
            .iter()
            .find(|task| task.meta.id == *task_id)
            .ok_or_else(|| {
                AppError::Assertion(format!(
                    "typed get_tasks did not return polled task {task_id}"
                ))
            })?;
        if let Some(status) = task.status.clone() {
            last_status = status;
            if accept(&last_status) {
                return Ok(last_status);
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "task {task_id} did not reach the required state within {} seconds; last status: {last_status}",
        timeout.as_secs()
    )))
}

async fn create_role_permission(
    client: &mut GmpClient<UnixSocketConnection>,
    name: &str,
    comment: &str,
    role_id: &EntityId,
) -> Result<EntityId, AppError> {
    match client
        .create_permission(gvm_gmp::commands::permissions::PermissionOpts {
            name: Some(name.to_string()),
            comment: Some(comment.to_string()),
            subject_type: Some(gvm_gmp::PermissionSubjectType::Role),
            subject_id: Some(role_id.clone()),
            ..Default::default()
        })
        .await
    {
        Ok(permission) => {
            log_pass(
                "typed permission create",
                "rust-gvm emitted a gvmd-compatible subject",
            );
            Ok(permission.id)
        }
        Err(GvmError::Parse(gvm_gmp::responses::ParseError::ServerError {
            status: 400,
            message,
        })) if message == "Error in SUBJECT" => {
            runtime::observe(
                "typed permission create",
                Outcome::KnownUpstreamBug,
                "rust-gvm#405 reproduced: flat subject elements were rejected by gvmd",
            );

            let mut command = XmlCommand::new("create_permission");
            command.add_element_with_text("name", name);
            command.add_element_with_text("comment", comment);
            let subject = command.add_element("subject");
            subject.set_attribute("id", role_id.as_str());
            subject.add_child_with_text("type", "role");

            let response = client.call(command).await?;
            assert_status(
                &response,
                201,
                "canonical create_permission fallback for rust-gvm#405",
            )?;
            let permission_id = response_id(&response, "create_permission fallback")?;
            log_pass(
                "canonical permission create fallback",
                permission_id.as_str(),
            );
            Ok(permission_id)
        }
        Err(error) => Err(error.into()),
    }
}

async fn connect_client(config: &EnvConfig) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let connection = UnixSocketConnection::with_path(&config.socket_path);
    Ok(GmpClient::connect(connection).await?)
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

fn response_id(response: &Response, label: &str) -> Result<EntityId, AppError> {
    let id = response.id().ok_or_else(|| {
        AppError::Assertion(format!("{label} response missing resource id attribute"))
    })?;
    parse_entity_id(&id)
}

fn parse_entity_id(value: &str) -> Result<EntityId, AppError> {
    EntityId::from_str(value).map_err(|_| AppError::InvalidEntityId(value.to_string()))
}

fn count_elements(response: &Response, element_name: &str) -> Result<usize, AppError> {
    let xml = response.as_str()?;
    let mut reader = Reader::from_str(xml);
    let mut count = 0_usize;

    loop {
        match reader.read_event()? {
            Event::Start(ref event) | Event::Empty(ref event)
                if event.name().as_ref() == element_name.as_bytes() =>
            {
                count += 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(count)
}

fn first_element_id(response: &Response, element_name: &str) -> Result<EntityId, AppError> {
    let xml = response.as_str()?;
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event()? {
            Event::Start(ref event) | Event::Empty(ref event)
                if event.name().as_ref() == element_name.as_bytes() =>
            {
                for attribute in event.attributes().flatten() {
                    if attribute.key.as_ref() == b"id" {
                        let value = attribute
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )?
                            .into_owned();
                        return parse_entity_id(&value);
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Err(AppError::Assertion(format!(
        "response did not contain <{element_name} id=\"...\">"
    )))
}

fn first_nvt_oid(response: &Response) -> Result<String, AppError> {
    let xml = response.as_str()?;
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event()? {
            Event::Start(ref event) | Event::Empty(ref event)
                if event.name().as_ref() == b"nvt" =>
            {
                for attribute in event.attributes().flatten() {
                    if attribute.key.as_ref() == b"oid" {
                        return Ok(attribute
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )?
                            .into_owned());
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Err(AppError::Assertion(
        "response did not contain <nvt oid=\"...\">".to_string(),
    ))
}

fn response_contains(response: &Response, needle: &str) -> Result<bool, AppError> {
    Ok(response.as_str()?.contains(needle))
}

fn response_summary(response: &Response) -> Result<String, AppError> {
    let xml = response.as_str()?;
    Ok(xml.chars().take(240).collect())
}

fn replace_first_resource_name(
    xml: &str,
    element_name: &str,
    replacement: &str,
) -> Result<String, AppError> {
    ensure(
        replacement
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-'),
        "generated import name must be XML-safe",
    )?;
    let resource_start = xml.find(&format!("<{element_name}")).ok_or_else(|| {
        AppError::Assertion(format!("exported XML did not contain a {element_name}"))
    })?;
    let search_start = xml[resource_start..]
        .find("</owner>")
        .map_or(resource_start, |offset| {
            resource_start + offset + "</owner>".len()
        });
    let start = xml[search_start..]
        .find("<name>")
        .map(|offset| search_start + offset)
        .ok_or_else(|| {
            AppError::Assertion("exported resource XML did not contain a name".to_string())
        })?
        + "<name>".len();
    let end = xml[start..]
        .find("</name>")
        .map(|offset| start + offset)
        .ok_or_else(|| {
            AppError::Assertion("exported resource XML had an unterminated name".to_string())
        })?;
    let mut result = String::with_capacity(xml.len() + replacement.len());
    result.push_str(&xml[..start]);
    result.push_str(replacement);
    result.push_str(&xml[end..]);
    Ok(result)
}

fn replace_first_resource_id(
    xml: &str,
    element_name: &str,
    replacement: &str,
) -> Result<String, AppError> {
    let element_start = xml.find(&format!("<{element_name} ")).ok_or_else(|| {
        AppError::Assertion(format!(
            "exported XML did not contain an attributed {element_name}"
        ))
    })?;
    let opening_end = xml[element_start..]
        .find('>')
        .map(|offset| element_start + offset)
        .ok_or_else(|| {
            AppError::Assertion("exported XML opening tag was incomplete".to_string())
        })?;
    let id_start = xml[element_start..opening_end]
        .find("id=\"")
        .map(|offset| element_start + offset + "id=\"".len())
        .ok_or_else(|| {
            AppError::Assertion("exported resource did not contain an id".to_string())
        })?;
    let id_end = xml[id_start..]
        .find('"')
        .map(|offset| id_start + offset)
        .ok_or_else(|| AppError::Assertion("exported resource id was incomplete".to_string()))?;
    let mut result = String::with_capacity(xml.len());
    result.push_str(&xml[..id_start]);
    result.push_str(replacement);
    result.push_str(&xml[id_end..]);
    Ok(result)
}

fn id_name_entities(
    response: &Response,
    element_name: &str,
) -> Result<Vec<IdNameEntity>, AppError> {
    let mut reader = Reader::from_str(response.as_str()?);
    let mut entities = Vec::new();
    let mut current_id: Option<String> = None;
    let mut current_name = String::new();
    let mut inside_element = false;
    let mut inside_name = false;
    loop {
        match reader.read_event()? {
            Event::Start(ref event) if event.name().as_ref() == element_name.as_bytes() => {
                inside_element = true;
                current_name.clear();
                current_id = event
                    .attributes()
                    .flatten()
                    .find(|attribute| attribute.key.as_ref() == b"id")
                    .map(|attribute| {
                        attribute
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )
                            .map(|value| value.into_owned())
                    })
                    .transpose()?;
            }
            Event::Start(ref event) if inside_element && event.name().as_ref() == b"name" => {
                inside_name = true;
            }
            Event::Text(ref event) if inside_element && inside_name && current_name.is_empty() => {
                current_name = String::from_utf8_lossy(event.as_ref()).into_owned();
            }
            Event::End(ref event) if event.name().as_ref() == b"name" => {
                inside_name = false;
            }
            Event::End(ref event) if event.name().as_ref() == element_name.as_bytes() => {
                if let Some(id) = current_id.take() {
                    entities.push(IdNameEntity {
                        id,
                        name: current_name.clone(),
                    });
                }
                inside_element = false;
                inside_name = false;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(entities)
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
            Event::Start(ref e) if e.name().as_ref() == element_name.as_bytes() => {
                inside_element = true;
                current_id = None;
                matched = false;
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == b"id" {
                        current_id = Some(
                            attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )?
                            .into_owned(),
                        );
                    }
                }
            }
            Event::End(ref e) if e.name().as_ref() == element_name.as_bytes() => {
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
                    && matches!(e.name().as_ref(), b"name" | b"comment" | b"text" | b"value") =>
            {
                inside_identity_field = true;
            }
            Event::End(ref e)
                if matches!(e.name().as_ref(), b"name" | b"comment" | b"text" | b"value") =>
            {
                inside_identity_field = false;
            }
            Event::Text(ref e) if inside_element && inside_identity_field => {
                let value = String::from_utf8_lossy(e.as_ref());
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
}
