use actix_web::{web, Responder};
use serde::Deserialize;
use std::time::Duration;

use crate::prevention::actions::{PreventionAction, ResponseStrategy, ThreatCategory};
use crate::services::monitor_service::MonitorService;
use crate::utils::error::AppError;

/// Request to block an IP
#[derive(Debug, Deserialize)]
pub struct BlockIPRequest {
    pub ip: String,
    pub reason: String,
}

/// Request to update prevention settings
#[derive(Debug, Deserialize)]
pub struct UpdatePreventionSettingsRequest {
    pub enabled: Option<bool>,
    pub use_native_firewall: Option<bool>,
    pub global_rate_limit: Option<u32>,
    pub per_ip_rate_limit: Option<u32>,
    pub use_threat_intelligence: Option<bool>,
    pub adaptive_response: Option<bool>,
    pub auto_block_duration: Option<u32>,
    pub whitelist: Option<Vec<String>>,
    pub blacklist: Option<Vec<String>>,
    pub geo_block_countries: Option<Vec<String>>,
    pub connection_tracking: Option<bool>,
    pub max_connections_per_ip: Option<u32>,
    pub honeypot_enabled: Option<bool>,
    pub honeypot_address: Option<String>,
    pub auto_report_threats: Option<bool>,
    pub threat_feeds: Option<Vec<String>>,
    // Legacy fields for backward compatibility - map to response strategies
    pub port_scan_action: Option<String>,
    pub host_scan_action: Option<String>,
    pub rate_limit_action: Option<String>,
    pub suspicious_connection_action: Option<String>,
    pub abnormal_traffic_action: Option<String>,
    pub malicious_payload_action: Option<String>,
    pub rule_match_action: Option<String>,
}

/// Get prevention settings
pub async fn get_prevention_settings(
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    // Get prevention settings
    let settings = monitor_service.get_prevention_settings();

    // Convert to a response format
    let response = serde_json::json!({
        "settings": settings,
        "is_running": monitor_service.get_prevention_manager().is_running(),
        "actions": {
            "options": [
                "Monitor",
                "Alert",
                "BlockSource",
                "BlockBoth",
                "TerminateConnection",
                "RateLimit",
                "TempBan",
                "RedirectHoneypot",
                "DeepInspect",
                "Quarantine"
            ]
        },
        "threat_categories": [
            "PortScan",
            "HostScan",
            "BruteForce",
            "DDoS",
            "Malware",
            "Exploit",
            "DataExfiltration",
            "AnomalousTraffic",
            "PolicyViolation",
            "Unknown"
        ]
    });

    Ok(web::Json(response))
}

/// Update prevention settings
pub async fn update_prevention_settings(
    monitor_service: web::Data<MonitorService>,
    update_req: web::Json<UpdatePreventionSettingsRequest>,
) -> Result<impl Responder, AppError> {
    // Get current settings
    let mut settings = monitor_service.get_prevention_settings();

    // Update settings with the request values
    if let Some(enabled) = update_req.enabled {
        settings.enabled = enabled;
    }

    if let Some(use_native_firewall) = update_req.use_native_firewall {
        settings.use_native_firewall = use_native_firewall;
    }

    if let Some(global_rate_limit) = update_req.global_rate_limit {
        settings.global_rate_limit = global_rate_limit;
    }

    if let Some(per_ip_rate_limit) = update_req.per_ip_rate_limit {
        settings.per_ip_rate_limit = per_ip_rate_limit;
    }

    if let Some(use_threat_intelligence) = update_req.use_threat_intelligence {
        settings.use_threat_intelligence = use_threat_intelligence;
    }

    if let Some(adaptive_response) = update_req.adaptive_response {
        settings.adaptive_response = adaptive_response;
    }

    if let Some(duration) = update_req.auto_block_duration {
        settings.auto_block_duration = duration;
    }

    if let Some(whitelist) = &update_req.whitelist {
        settings.whitelist = whitelist.clone();
    }

    if let Some(blacklist) = &update_req.blacklist {
        settings.blacklist = blacklist.clone();
    }

    if let Some(geo_block_countries) = &update_req.geo_block_countries {
        settings.geo_block_countries = geo_block_countries.clone();
    }

    if let Some(connection_tracking) = update_req.connection_tracking {
        settings.connection_tracking = connection_tracking;
    }

    if let Some(max_connections_per_ip) = update_req.max_connections_per_ip {
        settings.max_connections_per_ip = max_connections_per_ip;
    }

    if let Some(honeypot_enabled) = update_req.honeypot_enabled {
        settings.honeypot_enabled = honeypot_enabled;
    }

    if let Some(honeypot_address) = &update_req.honeypot_address {
        settings.honeypot_address = Some(honeypot_address.clone());
    }

    if let Some(auto_report_threats) = update_req.auto_report_threats {
        settings.auto_report_threats = auto_report_threats;
    }

    if let Some(threat_feeds) = &update_req.threat_feeds {
        settings.threat_feeds = threat_feeds.clone();
    }

    // Handle legacy action fields by mapping them to response strategies
    if let Some(action_str) = &update_req.port_scan_action {
        if let Some(action) = PreventionAction::from_str(action_str) {
            settings.response_strategies.insert(ThreatCategory::PortScan, ResponseStrategy {
                initial_action: action,
                escalation_action: PreventionAction::BlockSource,
                escalation_delay: Duration::from_secs(180),
                max_escalation: 2,
            });
        }
    }

    if let Some(action_str) = &update_req.host_scan_action {
        if let Some(action) = PreventionAction::from_str(action_str) {
            settings.response_strategies.insert(ThreatCategory::HostScan, ResponseStrategy {
                initial_action: action,
                escalation_action: PreventionAction::BlockSource,
                escalation_delay: Duration::from_secs(180),
                max_escalation: 2,
            });
        }
    }

    // Update the settings
    monitor_service.update_prevention_settings(settings).await?;

    // Return success response
    Ok(web::Json(serde_json::json!({
        "message": "Prevention settings updated successfully",
        "is_running": monitor_service.get_prevention_manager().is_running()
    })))
}

/// Get blocked IPs
pub async fn get_blocked_ips(
    monitor_service: web::Data<MonitorService>,
) -> Result<impl Responder, AppError> {
    // Get blocked IPs
    let blocked_ips = monitor_service.get_blocked_ips();

    Ok(web::Json(blocked_ips))
}

/// Block an IP
pub async fn block_ip(
    monitor_service: web::Data<MonitorService>,
    block_req: web::Json<BlockIPRequest>,
) -> Result<impl Responder, AppError> {
    // Block the IP
    monitor_service.block_ip(&block_req.ip, &block_req.reason)?;

    // Return success response
    Ok(web::Json(serde_json::json!({
        "message": format!("IP {} blocked successfully", block_req.ip)
    })))
}

/// Unblock an IP
pub async fn unblock_ip(
    monitor_service: web::Data<MonitorService>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let ip = path.into_inner();

    // Unblock the IP
    monitor_service.unblock_ip(&ip)?;

    // Return success response
    Ok(web::Json(serde_json::json!({
        "message": format!("IP {} unblocked successfully", ip)
    })))
}