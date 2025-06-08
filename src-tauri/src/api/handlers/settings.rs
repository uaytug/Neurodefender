use std::collections::HashMap;
use std::process::{Command, Output};
use gethostname;
use std::fs::File;
use std::io::{BufRead, BufReader};
use sysinfo::{System};

use actix_web::{web, HttpResponse, Responder};
use log::{error, warn};

use crate::capture::analyzer::AnalysisSensitivity;
use crate::services::monitor_service::MonitorService;
use crate::storage::db::Database;
use crate::storage::models::settings::{Setting, SettingUpdateRequest, SettingsGroup};
use crate::storage::repositories::setting_repo::SettingRepository;
use crate::utils::error::AppError;

const HANDLER_NAME: &'static str = "system";

/// Get all settings
pub async fn get_settings(
    db: web::Data<Database>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Get all settings
    let settings = setting_repo.get_all(None).await?;

    // Group settings by category
    let mut settings_by_category: HashMap<String, Vec<Setting>> = HashMap::new();

    for setting in settings {
        let category = setting.category.clone().unwrap_or_else(|| "General".to_string());
        settings_by_category.entry(category).or_default().push(setting);
    }

    // Convert to response format
    let settings_groups: Vec<SettingsGroup> = settings_by_category
        .into_iter()
        .map(|(category, settings)| SettingsGroup {
            category,
            settings,
        })
        .collect();

    Ok(web::Json(settings_groups))
}

/// Update a setting
pub async fn update_settings(
    db: web::Data<Database>,
    update_req: web::Json<HashMap<String, SettingUpdateRequest>>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Update each setting
    let mut updated_settings = Vec::new();

    for (key, update) in update_req.into_inner() {
        // Get the current setting
        let mut setting = match setting_repo.get_by_key(&key).await {
            Ok(s) => s,
            Err(AppError::NotFoundError(_)) => {
                // Setting doesn't exist, create it
                let mut new_setting = Setting::new(&key, &update.value);

                if let Some(desc) = &update.description {
                    new_setting.description = Some(desc.clone());
                }

                if let Some(cat) = &update.category {
                    new_setting.category = Some(cat.clone());
                }

                new_setting
            },
            Err(e) => return Err(e),
        };

        // Don't allow updating system settings
        if setting.system {
            return Err(AppError::AuthzError(format!("Cannot update system setting: {}", key)));
        }

        // Update the setting
        setting.update_value(&update.value, Some(HANDLER_NAME));

        if let Some(desc) = &update.description {
            setting.description = Some(desc.clone());
        }

        if let Some(cat) = &update.category {
            setting.category = Some(cat.clone());
        }

        // Save the setting
        let updated = setting_repo.upsert(setting).await?;   // whatever type `upsert` returns
        updated_settings.push(updated);
    }

    Ok(web::Json(updated_settings))
}

/// Get detection settings
pub async fn get_detection_settings(
    db: web::Data<Database>,
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Get detection settings
    let settings = setting_repo.get_all(Some("detection")).await?;

    // Convert to a more user-friendly format
    let mut detection_settings = HashMap::new();

    for setting in settings {
        detection_settings.insert(setting.key, setting.value);
    }

    // Add some hardcoded options for the frontend
    let sensitivity_options = vec!["low", "medium", "high"];

    // Create the response
    let response = serde_json::json!({
        "settings": detection_settings,
        "options": {
            "sensitivity": sensitivity_options
        },
        "is_running": monitor_service.is_running()
    });

    Ok(web::Json(response))
}

/// Update detection settings
pub async fn update_detection_settings(
    db: web::Data<Database>,
    monitor_service: web::Data<MonitorService>,
    update_req: web::Json<HashMap<String, String>>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Handle special settings that need additional processing
    for (key, value) in update_req.iter() {
        if key == "detection.sensitivity" {
            // Update detection engine sensitivity
            let sensitivity = match value.to_lowercase().as_str() {
                "low" => AnalysisSensitivity::Low,
                "high" => AnalysisSensitivity::High,
                _ => AnalysisSensitivity::Medium,
            };

            monitor_service.set_sensitivity(sensitivity)?;
        } else if key == "detection.enabled" {
            let enabled = value.to_lowercase() == "true";

            if enabled && !monitor_service.is_running() {
                // own an independent, 'static clone for the task
                let service_clone = monitor_service.as_ref().clone();
                tokio::spawn(async move {
                    let mut svc = service_clone;            // mut inside the task
                    if let Err(e) = svc.start().await {
                        error!("Failed to start monitoring service: {e}");
                    }
                });
            } else if !enabled && monitor_service.is_running() {
                // stop synchronously (needs &mut self, so work on an owned clone)
                let mut svc = monitor_service.as_ref().clone();
                svc.stop();
            }
        }
    }

    // Save all settings
    for (key, value) in update_req.iter() {
        // Get the current setting or create new
        let mut setting = match setting_repo.get_by_key(key).await {
            Ok(s) => s,
            Err(AppError::NotFoundError(_)) => {
                // Setting doesn't exist, create it
                Setting::new(key, value)
            },
            Err(e) => return Err(e),
        };

        // Update the setting
        setting.update_value(value, Some(HANDLER_NAME));

        // Set category to detection if not set
        if setting.category.is_none() {
            setting.category = Some("detection".to_string());
        }

        // Save the setting
        setting_repo.upsert(setting).await?;
    }

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Detection settings updated successfully",
        "is_running": monitor_service.is_running()
    })))
}

/// Get network settings
pub async fn get_network_settings(
    db: web::Data<Database>,
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Get network settings
    let settings = setting_repo.get_all(Some("network")).await?;

    // Convert to a more user-friendly format
    let mut network_settings = HashMap::new();

    for setting in settings {
        network_settings.insert(setting.key, setting.value);
    }

    // Get available network interfaces
    let interfaces = match crate::capture::pcap::PcapManager::list_interfaces() {
        Ok(interfaces) => interfaces.into_iter().map(|i| i.name).collect::<Vec<_>>(),
        Err(e) => {
            warn!("Failed to list network interfaces: {}", e);
            Vec::new()
        }
    };

    // Create the response
    let response = serde_json::json!({
        "settings": network_settings,
        "available_interfaces": interfaces,
        "current_interface": monitor_service.get_interface()
    });

    Ok(web::Json(response))
}

/// Update network settings
pub async fn update_network_settings(
    db: web::Data<Database>,
    monitor_service: web::Data<MonitorService>,
    update_req: web::Json<HashMap<String, String>>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Save all settings
    for (key, value) in update_req.iter() {
        // Get the current setting or create new
        let mut setting = match setting_repo.get_by_key(key).await {
            Ok(s) => s,
            Err(AppError::NotFoundError(_)) => {
                // Setting doesn't exist, create it
                Setting::new(key, value)
            },
            Err(e) => return Err(e),
        };

        // Update the setting
        setting.update_value(value, Some(HANDLER_NAME));

        // Set category to network if not set
        if setting.category.is_none() {
            setting.category = Some("network".to_string());
        }

        // Save the setting
        setting_repo.upsert(setting).await?;
    }

    // Check if we need to restart the monitoring service
    // In a real implementation, we would check if network settings have changed
    // and restart the service if needed

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Network settings updated successfully",
        "restart_required": true
    })))
}

/// Get notification settings
pub async fn get_notification_settings(
    db: web::Data<Database>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Get notification settings
    let settings = setting_repo.get_all(Some("notification")).await?;

    // Convert to a more user-friendly format
    let mut notification_settings = HashMap::new();

    for setting in settings {
        notification_settings.insert(setting.key, setting.value);
    }

    // Create the response
    let response = serde_json::json!({
        "settings": notification_settings
    });

    Ok(web::Json(response))
}

/// Update notification settings
pub async fn update_notification_settings(
    db: web::Data<Database>,
    update_req: web::Json<HashMap<String, String>>,
) -> Result<impl Responder, AppError> {
    let setting_repo = SettingRepository::new(db.get_ref().clone());

    // Save all settings
    for (key, value) in update_req.iter() {
        // Get the current setting or create new
        let mut setting = match setting_repo.get_by_key(key).await {
            Ok(s) => s,
            Err(AppError::NotFoundError(_)) => {
                // Setting doesn't exist, create it
                Setting::new(key, value)
            },
            Err(e) => return Err(e),
        };

        // Update the setting
        setting.update_value(value, Some(HANDLER_NAME));

        // Set category to notification if not set
        if setting.category.is_none() {
            setting.category = Some("notification".to_string());
        }

        // Save the setting
        setting_repo.upsert(setting).await?;
    }

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Notification settings updated successfully"
    })))
}

/// Get system information
pub async fn get_system_info(
) -> Result<impl Responder, AppError> {
    let os_info = std::env::consts::OS.to_string();
    
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_info = sys.global_cpu_info().brand().to_string();
    let memory_info = format!("{} / {} GB used", sys.used_memory() / 1024 / 1024 / 1024, sys.total_memory() / 1024 / 1024 / 1024);
    let uptime_seconds = sysinfo::System::uptime();
    let uptime_formatted = format!("{}d {}h {}m {}s", uptime_seconds / 86400, (uptime_seconds % 86400) / 3600, (uptime_seconds % 3600) / 60, uptime_seconds % 60);


    // Build response
    let system_info = serde_json::json!({
        "os": os_info,
        "cpu": cpu_info,
        "memory": memory_info,
        "hostname": gethostname::gethostname().to_string_lossy(),
        "version": env!("CARGO_PKG_VERSION"),
        "build_date": env!("VERGEN_BUILD_TIMESTAMP"),
        "uptime": uptime_formatted
    });

    Ok(web::Json(system_info))
}

/// Get system logs
pub async fn get_system_logs(
    db: web::Data<Database>,
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    const LOG_FILE_PATH: &str = "/var/log/idps/application.log";
    const MAX_LOG_LINES: usize = 100;

    let mut logs: Vec<serde_json::Value> = Vec::new();

    match File::open(LOG_FILE_PATH) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut lines = Vec::new();
            
            for line_result in reader.lines() {
                if let Ok(line) = line_result {
                    if lines.len() >= MAX_LOG_LINES {
                        lines.remove(0);
                    }
                    lines.push(line);
                }
            }
            
            for (i, line) in lines.iter().enumerate() {
                 logs.push(serde_json::json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "level": "INFO",
                    "message": line,
                    "component": "LogFile",
                    "line_number": i + 1
                }));
            }
        }
        Err(e) => {
            error!("Failed to open log file {}: {}", LOG_FILE_PATH, e);
            logs.push(serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "level": "ERROR",
                "message": format!("Failed to read system logs: {}", e),
                "component": "SystemAPI",
                "details": null
            }));
        }
    }

    Ok(web::Json(logs))
}

/// Restart the system
pub async fn restart_system(
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    // Restart the system
    let output: Output = Command::new("shutdown")
        .arg("-r")
        .arg("now")
        .output()
        .expect("Failed to restart the system");
    if !output.status.success() {
        return Err(AppError::InternalError(format!(
            "Failed to restart the system: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "System restart initiated"
    })))
}