use std::collections::HashMap;

use actix_web::{web, Responder};
use serde::Serialize;
use log;
use crate::services::alert_service::AlertService;
use crate::services::monitor_service::MonitorService;
use crate::storage::db::Database;
use crate::storage::models::alert::{Alert, AlertSeverity};
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::utils::error::AppError;
use actix_cors::Cors;
use actix_web::{App, HttpServer};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Dashboard overview data
#[derive(Debug, Serialize)]
pub struct DashboardData {
    /// System status (protected, at_risk, etc.)
    pub system_status: String,

    /// Security score (0-100)
    pub security_score: u8,

    /// Alert counts by severity
    pub alerts_by_severity: HashMap<String, u64>,

    /// Alert counts by status
    pub alerts_by_status: HashMap<String, u64>,

    /// Network traffic stats
    pub traffic_stats: TrafficStats,

    /// System health stats
    pub system_health: SystemHealth,

    /// Recent alerts
    pub recent_alerts: Vec<Alert>,
}

/// Network traffic statistics
#[derive(Debug, Serialize)]
pub struct TrafficStats {
    /// Inbound traffic in Mbps
    pub inbound_mbps: f64,

    /// Outbound traffic in Mbps
    pub outbound_mbps: f64,

    /// Traffic by protocol (in bytes)
    pub traffic_by_protocol: HashMap<String, u64>,

    /// Number of active connections
    pub active_connections: u64,

    /// Number of blocked connections today
    pub blocked_connections: u64,
}

/// System health metrics
#[derive(Debug, Serialize)]
pub struct SystemHealth {
    /// CPU usage percentage
    pub cpu_usage: f64,

    /// Memory usage percentage
    pub memory_usage: f64,

    /// Disk usage percentage
    pub disk_usage: f64,

    /// System uptime in seconds
    pub uptime_seconds: u64,

    /// Last scan time (ISO 8601 timestamp)
    pub last_scan: String,
}

/// Get dashboard data
pub async fn get_dashboard_data(
    db: web::Data<Database>,
    monitor_service: web::Data<Arc<Mutex<MonitorService>>>,
) -> Result<impl Responder, AppError> {
    // Get alert repository and service
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    // Get alert statistics
    let alert_stats = alert_service.get_alert_stats().await?;

    // Get recent alerts (top 5)
    let recent_alerts = alert_service.get_recent_alerts(5).await?;

    // Calculate security score based on alerts and system status
    let security_score = calculate_security_score(&alert_stats);

    // Determine system status
    let system_status = if security_score >= 80 {
        "protected"
    } else if security_score >= 60 {
        "warning"
    } else {
        "at_risk"
    };

    // Format alert counts by severity
    let mut alerts_by_severity = HashMap::new();
    for (severity, count) in &alert_stats.by_severity {
        alerts_by_severity.insert(format!("{:?}", severity).to_lowercase(), *count);
    }

    // Format alert counts by status
    let mut alerts_by_status = HashMap::new();
    alerts_by_status.insert("new".to_string(), alert_stats.new);
    alerts_by_status.insert("in_progress".to_string(), alert_stats.in_progress);
    alerts_by_status.insert("resolved".to_string(), alert_stats.resolved);

    // Get traffic statistics from monitor service
    let monitor_guard = monitor_service.lock().await;
    let traffic_stats = TrafficStats {
        inbound_mbps: monitor_guard.get_current_inbound_traffic().await?,
        outbound_mbps: monitor_guard.get_current_outbound_traffic().await?,
        traffic_by_protocol: monitor_guard.get_traffic_by_protocol_map().await?,
        active_connections: monitor_guard.get_active_connections().await?,
        blocked_connections: monitor_guard.get_blocked_connections_today().await?,
    };

    // Get system health metrics from monitor service
    let system_health = SystemHealth {
        cpu_usage: monitor_guard.get_cpu_usage().await?,
        memory_usage: monitor_guard.get_memory_usage().await?,
        disk_usage: monitor_guard.get_disk_usage().await?,
        uptime_seconds: monitor_guard.get_system_uptime().await?,
        last_scan: monitor_guard.get_last_scan_time().await?.to_rfc3339(),
    };

    // Build the dashboard data
    let dashboard_data = DashboardData {
        system_status: system_status.to_string(),
        security_score,
        alerts_by_severity,
        alerts_by_status,
        traffic_stats,
        system_health,
        recent_alerts,
    };

    Ok(web::Json(dashboard_data))
}

/// Get system statistics
pub async fn get_system_stats(
    db: web::Data<Database>,
    monitor_service: web::Data<Arc<Mutex<MonitorService>>>,
) -> Result<impl Responder, AppError> {
    // Get system metrics from the monitoring service
    let monitor_guard = monitor_service.lock().await;
    let cpu_usage = monitor_guard.get_cpu_usage().await?;
    let memory_usage = monitor_guard.get_memory_usage().await?;
    let disk_usage = monitor_guard.get_disk_usage().await?;
    let uptime_seconds = monitor_guard.get_system_uptime().await?;
    
    // Get network interface statistics
    let network_interfaces = monitor_guard.get_network_interfaces().await?;
    
    // Get monitoring status
    let monitoring_status = monitor_guard.get_monitoring_status().await?;
    
    let stats = serde_json::json!({
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "disk_usage": disk_usage,
        "uptime_seconds": uptime_seconds,
        "network_interfaces": network_interfaces,
        "monitoring_status": monitoring_status
    });

    Ok(web::Json(stats))
}

/// Get recent alerts for dashboard
pub async fn get_recent_alerts(
    db: web::Data<Database>,
) -> Result<impl Responder, AppError> {
    // Get the alert repository and service
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);
    
    // Get the most recent alerts (limit to 10)
    let alerts = alert_service.get_recent_alerts(10).await?;
    
    // Convert to proper response format
    let alert_responses: Vec<serde_json::Value> = alerts.into_iter()
        .map(|alert| {
            serde_json::json!({
                "id": alert.id.map(|oid| oid.to_string()).unwrap_or_default(),
                "timestamp": alert.timestamp.to_chrono().to_rfc3339(),
                "severity": format!("{:?}", alert.severity),
                "description": alert.description,
                "sourceIp": alert.source_ip,
                "destinationIp": alert.destination_ip,
                "protocol": alert.protocol,
                "status": format!("{:?}", alert.status)
            })
        })
        .collect();
    
    Ok(web::Json(alert_responses))
}

/// Get network traffic data
pub async fn get_traffic_data(
    _db: web::Data<Database>,
    monitor_service: web::Data<Arc<Mutex<MonitorService>>>,
) -> Result<impl Responder, AppError> {
    // Attempt to get current traffic metrics, use defaults on error
    let monitor_guard = monitor_service.lock().await;
    let current_metrics_result = monitor_guard.get_current_traffic_metrics().await;
    let (inbound_mbps, outbound_mbps) = match current_metrics_result {
        Ok(metrics) => (metrics.inbound_mbps, metrics.outbound_mbps),
        Err(e) => {
            log::error!("Failed to get current traffic metrics: {:?}. Using default values.", e);
            (0.0, 0.0) 
        }
    };

    let blocked_connections_result = monitor_guard.get_blocked_connections_today().await;
    let blocked_connections = match blocked_connections_result {
        Ok(count) => count,
        Err(e) => {
            log::error!("Failed to get blocked connections today: {:?}. Using default value 0.", e);
            0
        }
    };

    // Attempt to get traffic breakdown by protocol, use defaults on error
    let protocol_breakdown: Vec<serde_json::Value> = monitor_guard.get_traffic_by_protocol().await
        .unwrap_or_else(|e| {
            log::error!("Failed to get traffic by protocol: {:?}. Using empty Vec.", e);
            Vec::new()
        });

    // Attempt to get traffic breakdown by direction, use defaults on error
    let direction_breakdown: Vec<serde_json::Value> = monitor_guard.get_traffic_by_direction().await
        .unwrap_or_else(|e| {
            log::error!("Failed to get traffic by direction: {:?}. Using empty Vec.", e);
            Vec::new()
        });

    // Attempt to get time series data, use defaults on error
    let time_series = monitor_guard.get_traffic_history(24).await.unwrap_or_else(|e| {
        log::error!("Failed to get traffic history: {:?}. Using empty Vec.", e);
        Vec::new()
    });
    
    let traffic_data = serde_json::json!({
        "current": {
            "inbound_mbps": inbound_mbps,
            "outbound_mbps": outbound_mbps,
            "total_mbps": inbound_mbps + outbound_mbps,
            "blocked_connections": blocked_connections
        },
        "by_protocol": protocol_breakdown,
        "by_direction": direction_breakdown,
        "time_series": time_series
    });

    Ok(web::Json(traffic_data))
}

/// Calculate security score based on alert statistics
fn calculate_security_score(alert_stats: &crate::services::alert_service::AlertStats) -> u8 {
    // This is a simple calculation for demonstration
    // In a real system, this would consider many more factors

    let base_score = 100;

    // Deduct points for critical and high alerts
    let mut deductions = 0;

    for (severity, count) in &alert_stats.by_severity {
        match severity {
            AlertSeverity::Critical => deductions += (count * 10) as i32, // -10 points per critical alert
            AlertSeverity::High => deductions += (count * 5) as i32,      // -5 points per high alert
            AlertSeverity::Medium => deductions += (count * 2) as i32,    // -2 points per medium alert
            AlertSeverity::Low => deductions += (count * 1) as i32,       // -1 point per low alert
        }
    }

    // Add back some points for resolved alerts
    let resolved_bonus = (alert_stats.resolved as f64 * 0.5) as i32;

    // Calculate final score (don't go below 0 or above 100)
    let final_score = (base_score - deductions + resolved_bonus).max(0).min(100);

    final_score as u8
}

/// Get traffic history data
pub async fn get_traffic_history_data(
    monitor_service: web::Data<Arc<Mutex<MonitorService>>>,
) -> Result<impl Responder, AppError> {
    log::info!("Fetching traffic history data...");
    match monitor_service.lock().await.get_traffic_history(60).await { // Fetch last 60 data points
        Ok(history) => {
            log::info!("Successfully fetched {} traffic history points.", history.len());
            Ok(web::Json(history))
        }
        Err(e) => {
            log::error!("Failed to get traffic history from monitor_service: {:?}", e);
            // Return an empty Vec or a more specific error response
            // For now, returning an empty Vec to match api.ts expectation on error or no data
            Ok(web::Json(Vec::<serde_json::Value>::new())) 
        }
    }
}

async fn start_server() -> std::io::Result<()> {
    HttpServer::new(move || {
        let cors = Cors::default() // Or Cors::permissive() for wide open during dev
            .allowed_origin("http://localhost:1420") // Your frontend's origin
            .allowed_origin("http://127.0.0.1:1420") // Alternative for localhost
            .allowed_origin("tauri://localhost") // For Tauri specific scheme
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![actix_web::http::header::AUTHORIZATION, actix_web::http::header::ACCEPT, actix_web::http::header::CONTENT_TYPE])
            .max_age(3600);

        App::new()
            .wrap(cors) // Apply CORS middleware
            .configure(crate::api::routes::configure) // Your existing route config
    })
    .bind("127.0.0.1:55035")?
    .run()
    .await
}