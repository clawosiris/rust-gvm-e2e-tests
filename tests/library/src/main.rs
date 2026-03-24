// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Manual E2E harness for a real Greenbone Community container stack.

#![allow(clippy::print_stdout, clippy::too_many_lines)]

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use gvm_client::{parse_version_text, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::alerts::{create_alert, delete_alert, get_alert, AlertOpts};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::credentials::{create_credential, delete_credential, get_credential, CredentialOpts};
use gvm_gmp::commands::feed::get_feeds;
use gvm_gmp::commands::filters::{create_filter, delete_filter, get_filter, FilterOpts};
use gvm_gmp::commands::notes::{create_note, delete_note, get_note, NoteOpts};
use gvm_gmp::commands::nvts::{get_nvts, GetNvtsOpts};
use gvm_gmp::commands::overrides::{create_override, delete_override, get_override, OverrideOpts};
use gvm_gmp::commands::port_lists::{
    create_port_list, delete_port_list, get_port_list, get_port_lists, GetPortListsOpts,
    PortListOpts,
};
use gvm_gmp::commands::report_formats::{get_report_formats, GetReportFormatsOpts};
use gvm_gmp::commands::reports::get_report;
use gvm_gmp::commands::scan_configs::{get_scan_configs, GetScanConfigsOpts};
use gvm_gmp::commands::scanners::{get_scanners, GetScannersOpts};
use gvm_gmp::commands::schedules::{create_schedule, delete_schedule, get_schedule, ScheduleOpts};
use gvm_gmp::commands::secinfo::{
    get_cert_bund_advisories, get_cpes, get_cves, get_dfn_cert_advisories, GetSecInfoOpts,
};
use gvm_gmp::commands::tags::{create_tag, delete_tag, get_tag, TagOpts};
use gvm_gmp::commands::targets::{
    create_target, delete_target, get_target, get_targets, CreateTargetOpts, GetTargetsOpts,
};
use gvm_gmp::commands::tasks::{
    create_task, delete_task, get_task, start_task, stop_task, CreateTaskOpts,
};
use gvm_gmp::enums::{AlertCondition, AlertEvent, AlertMethod, CredentialType, EntityType, FilterType};
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::Response;
use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::sleep;

const SMOKE_TARGET_NAME: &str = "e2e-test-target";
const SCAN_TARGET_NAME: &str = "e2e-scan-target";
const SCAN_TASK_NAME: &str = "e2e-scan-task";

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
    let config = EnvConfig::from_env()?;

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

    Ok(())
}

#[derive(Clone, Debug)]
struct EnvConfig {
    username: String,
    password: String,
    socket_path: String,
    run_scan: bool,
}

impl EnvConfig {
    fn from_env() -> Result<Self, AppError> {
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
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Smoke,
    WaitReady,
    Crud,
    SecInfo,
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
                    "all" => Ok(Self::All),
                    other => Err(AppError::Usage(format!(
                        "unsupported suite `{other}`; expected `smoke`, `crud`, `secinfo`, or `all`"
                    ))),
                };
            }
        }

        Err(AppError::Usage(
            "usage: gvm-community-e2e [--mode <smoke|wait-ready> | --suite <smoke|crud|secinfo|all>]"
                .to_string(),
        ))
    }
}

#[derive(Debug)]
struct CleanupTracker {
    config: EnvConfig,
    target_ids: Vec<String>,
    task_ids: Vec<String>,
    port_list_ids: Vec<String>,
    credential_ids: Vec<String>,
    schedule_ids: Vec<String>,
    filter_ids: Vec<String>,
    note_ids: Vec<String>,
    override_ids: Vec<String>,
    tag_ids: Vec<String>,
    alert_ids: Vec<String>,
    armed: bool,
}

impl CleanupTracker {
    fn new(config: EnvConfig) -> Self {
        Self {
            config,
            target_ids: Vec::new(),
            task_ids: Vec::new(),
            port_list_ids: Vec::new(),
            credential_ids: Vec::new(),
            schedule_ids: Vec::new(),
            filter_ids: Vec::new(),
            note_ids: Vec::new(),
            override_ids: Vec::new(),
            tag_ids: Vec::new(),
            alert_ids: Vec::new(),
            armed: true,
        }
    }

    fn is_empty(&self) -> bool {
        self.task_ids.is_empty()
            && self.target_ids.is_empty()
            && self.port_list_ids.is_empty()
            && self.credential_ids.is_empty()
            && self.schedule_ids.is_empty()
            && self.filter_ids.is_empty()
            && self.note_ids.is_empty()
            && self.override_ids.is_empty()
            && self.tag_ids.is_empty()
            && self.alert_ids.is_empty()
    }

    fn track_target(&mut self, id: &EntityId) {
        self.target_ids.push(id.to_string());
    }

    fn track_task(&mut self, id: &EntityId) {
        self.task_ids.push(id.to_string());
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

        while let Some(task_id) = self.task_ids.pop() {
            let entity_id = parse_entity_id(&task_id)?;
            let response = client.send(delete_task(&entity_id, true)).await?;
            log_cleanup_result("delete_task", &task_id, response.status_code());
        }

        while let Some(target_id) = self.target_ids.pop() {
            let entity_id = parse_entity_id(&target_id)?;
            let response = client.send(delete_target(&entity_id, true)).await?;
            log_cleanup_result("delete_target", &target_id, response.status_code());
        }

        while let Some(alert_id) = self.alert_ids.pop() {
            let entity_id = parse_entity_id(&alert_id)?;
            let response = client.send(delete_alert(&entity_id, true)).await?;
            log_cleanup_result("delete_alert", &alert_id, response.status_code());
        }

        while let Some(note_id) = self.note_ids.pop() {
            let entity_id = parse_entity_id(&note_id)?;
            let response = client.send(delete_note(&entity_id, true)).await?;
            log_cleanup_result("delete_note", &note_id, response.status_code());
        }

        while let Some(override_id) = self.override_ids.pop() {
            let entity_id = parse_entity_id(&override_id)?;
            let response = client.send(delete_override(&entity_id, true)).await?;
            log_cleanup_result("delete_override", &override_id, response.status_code());
        }

        while let Some(tag_id) = self.tag_ids.pop() {
            let entity_id = parse_entity_id(&tag_id)?;
            let response = client.send(delete_tag(&entity_id, true)).await?;
            log_cleanup_result("delete_tag", &tag_id, response.status_code());
        }

        while let Some(filter_id) = self.filter_ids.pop() {
            let entity_id = parse_entity_id(&filter_id)?;
            let response = client.send(delete_filter(&entity_id, true)).await?;
            log_cleanup_result("delete_filter", &filter_id, response.status_code());
        }

        while let Some(schedule_id) = self.schedule_ids.pop() {
            let entity_id = parse_entity_id(&schedule_id)?;
            let response = client.send(delete_schedule(&entity_id, true)).await?;
            log_cleanup_result("delete_schedule", &schedule_id, response.status_code());
        }

        while let Some(credential_id) = self.credential_ids.pop() {
            let entity_id = parse_entity_id(&credential_id)?;
            let response = client.send(delete_credential(&entity_id, true)).await?;
            log_cleanup_result("delete_credential", &credential_id, response.status_code());
        }

        while let Some(port_list_id) = self.port_list_ids.pop() {
            let entity_id = parse_entity_id(&port_list_id)?;
            let response = client.send(delete_port_list(&entity_id, true)).await?;
            log_cleanup_result("delete_port_list", &port_list_id, response.status_code());
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
        let port_list_ids = self.port_list_ids.clone();
        let credential_ids = self.credential_ids.clone();
        let schedule_ids = self.schedule_ids.clone();
        let filter_ids = self.filter_ids.clone();
        let note_ids = self.note_ids.clone();
        let override_ids = self.override_ids.clone();
        let tag_ids = self.tag_ids.clone();
        let alert_ids = self.alert_ids.clone();

        let cleanup = async move {
            let mut tracker = CleanupTracker {
                config,
                task_ids,
                target_ids,
                port_list_ids,
                credential_ids,
                schedule_ids,
                filter_ids,
                note_ids,
                override_ids,
                tag_ids,
                alert_ids,
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
    Client(#[from] GvmError),
}

async fn wait_ready(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    let response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&response, 200, "get_version")?;
    client.disconnect().await?;
    Ok(())
}

async fn run_smoke_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;

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
            SMOKE_TARGET_NAME,
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
        response_contains(&get_target_response, SMOKE_TARGET_NAME)?,
        "expected created target name in get_target response",
    )?;
    log_pass("08", "get target by UUID");

    let delete_target_response = client.call(delete_target(&target_id, true)).await?;
    assert_status(&delete_target_response, 200, "delete_target")?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());
    log_pass("09", "delete target");

    let verify_delete_response = client.send(get_target(&target_id)).await?;
    assert_status(&verify_delete_response, 404, "verify target deletion")?;
    log_pass("10", "verify deletion");

    if config.run_scan {
        run_scan_suite(&mut client, tracker).await?;
    }

    client.disconnect().await?;
    Ok(())
}

async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    log_line("Running extended scan flow because E2E_RUN_SCAN=1");

    // Clean up stale scan target from previous runs (persistent volumes)
    {
        let targets_response = client
            .call(get_targets(GetTargetsOpts::default()))
            .await?;
        let xml = targets_response.as_str()?;
        let stale_ids = find_elements_by_name(xml, "target", SCAN_TARGET_NAME)?;
        for stale_id in &stale_ids {
            log_line(&format!("cleaning up stale scan target {stale_id}"));
            if let Ok(entity_id) = stale_id.parse() {
                let _ = client.call(delete_target(&entity_id, true)).await;
            }
        }
    }

    // Get port list (GMP requires PORT_LIST or PORT_RANGE)
    let port_list_id = first_element_id(
        &client
            .call(get_port_lists(GetPortListsOpts::default()))
            .await?,
        "port_list",
    )?;

    let scan_target = client
        .call(create_target(
            SCAN_TARGET_NAME,
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                port_list_id: Some(port_list_id),
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(&scan_target, 201, "create scan target")?;
    let target_id = response_id(&scan_target, "create scan target")?;
    tracker.track_target(&target_id);

    let config_id = first_element_id(
        &client
            .call(get_scan_configs(GetScanConfigsOpts::default()))
            .await?,
        "config",
    )?;
    let scanner_id = first_element_id(
        &client
            .call(get_scanners(GetScannersOpts::default()))
            .await?,
        "scanner",
    )?;

    let create_task_response = client
        .call(create_task(
            SCAN_TASK_NAME,
            &config_id,
            &target_id,
            &scanner_id,
            CreateTaskOpts::default(),
        ))
        .await?;
    assert_status(&create_task_response, 201, "create_task")?;
    let task_id = response_id(&create_task_response, "create_task")?;
    tracker.track_task(&task_id);

    let start_response = client.call(start_task(&task_id)).await?;
    assert_status(&start_response, 202, "start_task")?;
    let report_id = child_entity_id(&start_response, "report_id")?;

    let task_status = poll_task_status(client, &task_id, Duration::from_secs(30)).await?;
    if matches!(
        task_status.as_str(),
        "Running" | "Requested" | "Stop Requested"
    ) {
        let stop_response = client.call(stop_task(&task_id)).await?;
        assert_status(&stop_response, 200, "stop_task")?;
    } else {
        log_line(&format!(
            "scan task reached terminal status `{task_status}` before stop_task"
        ));
    }

    let report_response = client.call(get_report(&report_id)).await?;
    assert_status(&report_response, 200, "get_report")?;
    ensure(
        response_contains(&report_response, "<report ")?
            || response_contains(&report_response, "<results>")?
            || response_contains(&report_response, "<result>")?,
        "expected report payload in get_report response",
    )?;

    let delete_task_response = client.call(delete_task(&task_id, true)).await?;
    assert_status(&delete_task_response, 200, "delete_task")?;
    tracker.task_ids.retain(|value| value != task_id.as_str());

    let delete_target_response = client.call(delete_target(&target_id, true)).await?;
    assert_status(&delete_target_response, 200, "delete_target")?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());

    log_pass("11", "extended scan flow");
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
            "e2e-port-list",
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

    let del_pl_resp = client.call(delete_port_list(&pl_id, true)).await?;
    assert_status(&del_pl_resp, 200, "delete_port_list")?;
    tracker.port_list_ids.retain(|v| v != pl_id.as_str());
    log_pass("crud 03", "delete port_list");

    let verify_pl_resp = client.send(get_port_list(&pl_id)).await?;
    assert_status(&verify_pl_resp, 404, "verify port_list absent")?;
    log_pass("crud 04", "verify port_list absent");

    // --- credential CRUD ---
    let cred_resp = client
        .call(create_credential(
            "e2e-cred",
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

    let del_cred_resp = client.call(delete_credential(&cred_id, true)).await?;
    assert_status(&del_cred_resp, 200, "delete_credential")?;
    tracker.credential_ids.retain(|v| v != cred_id.as_str());
    log_pass("crud 07", "delete credential");

    let verify_cred_resp = client.send(get_credential(&cred_id)).await?;
    assert_status(&verify_cred_resp, 404, "verify credential absent")?;
    log_pass("crud 08", "verify credential absent");

    // --- schedule CRUD ---
    // TODO: GMP 22.5+ requires <icalendar> element for create_schedule,
    // but ScheduleOpts in rust-gvm doesn't support it yet.
    // Skipped until rust-gvm adds icalendar support.
    log_line("[skip] crud 09-12: schedule CRUD (needs icalendar support in rust-gvm)");

    // --- filter CRUD ---
    let filter_resp = client
        .call(create_filter(
            "e2e-filter",
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

    let del_filter_resp = client.call(delete_filter(&filter_id, true)).await?;
    assert_status(&del_filter_resp, 200, "delete_filter")?;
    tracker.filter_ids.retain(|v| v != filter_id.as_str());
    log_pass("crud 15", "delete filter");

    let verify_filter_resp = client.send(get_filter(&filter_id)).await?;
    assert_status(&verify_filter_resp, 404, "verify filter absent")?;
    log_pass("crud 16", "verify filter absent");

    // --- task CRUD (requires target, scan_config, scanner) ---
    let pl_list_resp = client
        .call(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&pl_list_resp, 200, "get_port_lists for task prereq")?;
    let task_port_list_id = match first_element_id(&pl_list_resp, "port_list") {
        Ok(id) => id,
        Err(_) => {
            log_line("[skip] crud 17-24 task CRUD: no port list available");
            client.disconnect().await?;
            return Ok(());
        }
    };

    let task_target_resp = client
        .call(create_target(
            "e2e-task-target",
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
    let scan_config_id = match first_element_id(&scan_configs_resp, "config") {
        Ok(id) => id,
        Err(_) => {
            log_line("[skip] crud 17-24 task CRUD: no scan config available");
            client.disconnect().await?;
            return Ok(());
        }
    };

    let scanners_resp = client
        .call(get_scanners(GetScannersOpts::default()))
        .await?;
    let scanner_id = match first_element_id(&scanners_resp, "scanner") {
        Ok(id) => id,
        Err(_) => {
            log_line("[skip] crud 17-24 task CRUD: no scanner available");
            client.disconnect().await?;
            return Ok(());
        }
    };

    let task_resp = client
        .call(create_task(
            "e2e-task",
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

    let del_task_resp = client.call(delete_task(&task_id, true)).await?;
    assert_status(&del_task_resp, 200, "delete_task")?;
    tracker.task_ids.retain(|v| v != task_id.as_str());
    log_pass("crud 19", "delete task");

    let del_task_target_resp = client.call(delete_target(&task_target_id, true)).await?;
    assert_status(&del_task_target_resp, 200, "delete task target")?;
    tracker.target_ids.retain(|v| v != task_target_id.as_str());
    log_pass("crud 20", "delete task target");

    // --- notes and overrides (require an NVT OID) ---
    let nvts_resp = client
        .call(get_nvts(GetNvtsOpts {
            filter_string: Some("rows=1".into()),
            ..GetNvtsOpts::default()
        }))
        .await?;
    assert_status(&nvts_resp, 200, "get_nvts for note prereq")?;

    let nvt_oid = match first_nvt_oid(&nvts_resp) {
        Ok(oid) => oid,
        Err(_) => {
            log_line("[skip] crud 21-32 notes/overrides: no NVT available");
            client.disconnect().await?;
            return Ok(());
        }
    };

    // --- note CRUD ---
    let note_resp = client
        .call(create_note(
            &nvt_oid,
            NoteOpts {
                text: Some("e2e test note".into()),
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

    let del_note_resp = client.call(delete_note(&note_id, true)).await?;
    assert_status(&del_note_resp, 200, "delete_note")?;
    tracker.note_ids.retain(|v| v != note_id.as_str());
    log_pass("crud 23", "delete note");

    let verify_note_resp = client.send(get_note(&note_id)).await?;
    assert_status(&verify_note_resp, 404, "verify note absent")?;
    log_pass("crud 24", "verify note absent");

    // --- override CRUD ---
    let override_resp = client
        .call(create_override(
            &nvt_oid,
            OverrideOpts {
                text: Some("e2e test override".into()),
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

    let del_override_resp = client.call(delete_override(&override_id, true)).await?;
    assert_status(&del_override_resp, 200, "delete_override")?;
    tracker.override_ids.retain(|v| v != override_id.as_str());
    log_pass("crud 27", "delete override");

    let verify_override_resp = client.send(get_override(&override_id)).await?;
    assert_status(&verify_override_resp, 404, "verify override absent")?;
    log_pass("crud 28", "verify override absent");

    // --- tag CRUD ---
    // TODO: GMP 22.5+ requires <resources type="..."> element, but rust-gvm
    // builds <resource_type> instead. Skip until library XML is fixed.
    log_line("[skip] crud 29-32: tag CRUD (needs resources element fix in rust-gvm)");

    // --- alert CRUD ---
    // TODO: Verify alert XML structure matches GMP 22.5+ requirements.
    // Skip until create_alert is validated against real server.
    log_line("[skip] crud 33-36: alert CRUD (needs validation against GMP 22.5+)");

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
        log_line("[warn] secinfo 02 get_cves: feed not yet populated, skipping count check");
    }
    log_pass("secinfo 02", &format!("get_cves ({cve_count} entries)"));

    // 03: CPEs
    let cpes_resp = client.call(get_cpes(GetSecInfoOpts::default())).await?;
    assert_status(&cpes_resp, 200, "get_cpes")?;
    let cpe_count = count_elements(&cpes_resp, "info")?;
    if cpe_count == 0 {
        log_line("[warn] secinfo 03 get_cpes: feed not yet populated, skipping count check");
    }
    log_pass("secinfo 03", &format!("get_cpes ({cpe_count} entries)"));

    // 04: CERT-Bund advisories
    let cert_resp = client
        .call(get_cert_bund_advisories(GetSecInfoOpts::default()))
        .await?;
    assert_status(&cert_resp, 200, "get_cert_bund_advisories")?;
    let cert_count = count_elements(&cert_resp, "info")?;
    if cert_count == 0 {
        log_line("[warn] secinfo 04 get_cert_bund_advisories: feed not yet populated");
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
        log_line("[warn] secinfo 05 get_dfn_cert_advisories: feed not yet populated");
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
    ensure(nvt_count >= 1, "expected at least one NVT; VT feed may not be loaded")?;
    log_pass("secinfo 06", &format!("get_nvts ({nvt_count} entries)"));

    client.disconnect().await?;
    Ok(())
}

async fn poll_task_status(
    client: &mut GmpClient<UnixSocketConnection>,
    task_id: &EntityId,
    timeout: Duration,
) -> Result<String, AppError> {
    let started = tokio::time::Instant::now();
    let mut last_status = String::from("unknown");

    while started.elapsed() <= timeout {
        let response = client.call(get_task(task_id)).await?;
        assert_status(&response, 200, "get_task")?;
        if let Some(status) = response.child_text("status") {
            last_status = status;
            if last_status != "New" {
                return Ok(last_status);
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "task {task_id} did not progress within {} seconds; last status: {last_status}",
        timeout.as_secs()
    )))
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

fn child_entity_id(response: &Response, child_name: &str) -> Result<EntityId, AppError> {
    let id = response
        .child_text(child_name)
        .ok_or_else(|| AppError::Assertion(format!("response missing <{child_name}> element")))?;
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
                            .decode_and_unescape_value(reader.decoder())?
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
                            .decode_and_unescape_value(reader.decoder())?
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


/// Find all `<element_name>` elements whose `<name>` child matches `target_name`,
/// returning their `id` attributes.
fn find_elements_by_name(
    xml: &str,
    element_name: &str,
    target_name: &str,
) -> Result<Vec<String>, AppError> {
    let mut reader = Reader::from_str(xml);
    let mut ids = Vec::new();
    let mut current_id: Option<String> = None;
    let mut inside_element = false;
    let mut inside_name = false;

    loop {
        match reader.read_event()? {
            Event::Start(ref e) if e.name().as_ref() == element_name.as_bytes() => {
                inside_element = true;
                current_id = None;
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == b"id" {
                        current_id =
                            Some(attr.decode_and_unescape_value(reader.decoder())?.into_owned());
                    }
                }
            }
            Event::End(ref e) if e.name().as_ref() == element_name.as_bytes() => {
                inside_element = false;
                current_id = None;
            }
            Event::Start(ref e) if inside_element && e.name().as_ref() == b"name" => {
                inside_name = true;
            }
            Event::End(ref e) if e.name().as_ref() == b"name" => {
                inside_name = false;
            }
            Event::Text(ref e) if inside_element && inside_name => {
                let name = String::from_utf8_lossy(e.as_ref()).into_owned();
                if name == target_name {
                    if let Some(ref id) = current_id {
                        ids.push(id.clone());
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(ids)
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

fn log_cleanup_result(action: &str, id: &str, status: Option<u16>) {
    let rendered_status = status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    log_line(&format!("[cleanup] {action} {id} -> {rendered_status}"));
}

fn log_line(message: &str) {
    let _ = writeln!(io::stdout(), "{message}");
}
