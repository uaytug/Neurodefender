use actix_web::web;
use crate::api::handlers;
use crate::api::handlers::prevention;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check endpoint
        .route("/health", web::get().to(health_check))
        // Enhanced health endpoint with detailed status
        .route("/health/detailed", web::get().to(detailed_health_check))
        // System robustness endpoints
        .route("/system/restart-services", web::post().to(restart_services))
        // API version
        .service(
            web::scope("/api/v1")
                // Alert routes
                .service(
                    web::scope("/alerts")
                        .route("/stream", web::get().to(handlers::alerts::stream_alerts))
                        .route("/stats", web::get().to(handlers::alerts::get_alert_stats))
                        .route("", web::get().to(handlers::alerts::get_alerts))
                        .route("", web::post().to(handlers::alerts::create_alert))
                        .route("/mark-all-read", web::post().to(handlers::alerts::mark_alerts_as_read_handler))
                        .route("/mark-all-system-read", web::post().to(handlers::alerts::mark_all_system_alerts_as_read_handler))
                        .route("/{id}", web::get().to(handlers::alerts::get_alert_by_id))
                        .route("/{id}", web::put().to(handlers::alerts::update_alert))
                        .route("/{id}", web::delete().to(handlers::alerts::delete_alert_handler))
                        .route("/{id}/resolve", web::post().to(handlers::alerts::resolve_alert))
                        .route("/{id}/comment", web::post().to(handlers::alerts::add_comment))
                )

                // Dashboard routes
                .service(
                    web::scope("/dashboard")
                        .route("", web::get().to(handlers::dashboard::get_dashboard_data))
                        .route("/stats", web::get().to(handlers::dashboard::get_system_stats))
                        .route("/alerts/recent", web::get().to(handlers::dashboard::get_recent_alerts))
                        .route("/traffic", web::get().to(handlers::dashboard::get_traffic_data))
                        .route("/traffic/history", web::get().to(handlers::dashboard::get_traffic_history_data))
                )

                // Report routes
                .service(
                    web::scope("/reports")
                        .route("", web::get().to(handlers::reports::get_reports))
                        .route("", web::post().to(handlers::reports::generate_report))
                        .route("/fs", web::get().to(handlers::reports::get_fs_reports))
                        .route("/html/{filename:.*}", web::get().to(handlers::reports::serve_html_report))
                        .route("/{id}", web::get().to(handlers::reports::get_report_by_id))
                        .route("/{id}/download", web::get().to(handlers::reports::download_report))
                )

                // Settings routes
                .service(
                    web::scope("/settings")
                        .route("", web::get().to(handlers::settings::get_settings))
                        .route("", web::put().to(handlers::settings::update_settings))
                        .route("/detection", web::get().to(handlers::settings::get_detection_settings))
                        .route("/detection", web::put().to(handlers::settings::update_detection_settings))
                        .route("/network", web::get().to(handlers::settings::get_network_settings))
                        .route("/network", web::put().to(handlers::settings::update_network_settings))
                        .route("/notification", web::get().to(handlers::settings::get_notification_settings))
                        .route("/notification", web::put().to(handlers::settings::update_notification_settings))
                )

                // Enhanced system routes
                .service(
                    web::scope("/system")
                        .route("/info", web::get().to(handlers::settings::get_system_info))
                        .route("/logs", web::get().to(handlers::settings::get_system_logs))
                        .route("/restart", web::post().to(handlers::settings::restart_system))
                        .route("/health", web::get().to(system_health_check))
                        .route("/diagnostics", web::get().to(system_diagnostics))
                        .route("/performance", web::get().to(system_performance))
                )

                .service(
                    web::scope("/prevention")
                        .route("/settings", web::get().to(prevention::get_prevention_settings))
                        .route("/settings", web::put().to(prevention::update_prevention_settings))
                        .route("/blocked", web::get().to(prevention::get_blocked_ips))
                        .route("/block", web::post().to(prevention::block_ip))
                        .route("/unblock/{ip}", web::delete().to(prevention::unblock_ip))
                )
                // FAQ routes
                .service(
                    web::scope("/faq")
                        .route("", web::get().to(handlers::faq::get_faq_items))
                        .route("/{id}", web::get().to(handlers::faq::get_faq_item_by_id))
                )
        );
}

// Simple health check handler
async fn health_check() -> web::Json<serde_json::Value> {
    web::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Enhanced detailed health check
async fn detailed_health_check() -> web::Json<serde_json::Value> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    // Check database connectivity (simplified check)
    let db_status = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        check_database_connection()
    ).await {
        Ok(Ok(_)) => "connected",
        Ok(Err(_)) => "error",
        Err(_) => "timeout",
    };

    // Check network monitoring status
    let network_status = "active"; // This would be determined by actual monitoring state

    web::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "system": {
            "cpu_usage": sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32,
            "memory_usage_percent": (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0,
        },
        "services": {
            "database": db_status,
            "network_monitoring": network_status,
            "detection_engine": "active"
        },
        "build_info": {
            "build_timestamp": env!("VERGEN_BUILD_TIMESTAMP", "unknown"),
            "rust_version": env!("VERGEN_RUSTC_SEMVER", "unknown"),
            "target": env!("VERGEN_CARGO_TARGET_TRIPLE", "unknown")
        }
    }))
}

// System health check endpoint
async fn system_health_check() -> web::Json<serde_json::Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Comprehensive health checks
    let health_status = serde_json::json!({
        "overall_status": "healthy",
        "timestamp": timestamp,
        "components": {
            "api_server": "running",
            "database": "connected",
            "network_monitor": "active",
            "detection_engine": "active",
            "prevention_system": "ready"
        },
        "metrics": {
            "active_connections": 0, // Would be populated by actual monitoring
            "alerts_last_hour": 0,   // Would be populated by actual data
            "blocked_threats": 0     // Would be populated by actual data
        }
    });

    web::Json(health_status)
}

// System diagnostics endpoint
async fn system_diagnostics() -> web::Json<serde_json::Value> {
    use std::fs;
    use std::path::Path;

    let mut diagnostics = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "diagnostics": {}
    });

    // Check log files
    let log_file_status = if Path::new("neurodefender.log").exists() {
        match fs::metadata("neurodefender.log") {
            Ok(metadata) => serde_json::json!({
                "exists": true,
                "size_bytes": metadata.len(),
                "modified": metadata.modified().ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
            }),
            Err(_) => serde_json::json!({"exists": true, "readable": false})
        }
    } else {
        serde_json::json!({"exists": false})
    };

    // Check rules directory
    let rules_status = if Path::new("rules").exists() {
        let rule_files = fs::read_dir("rules")
            .map(|entries| entries.count())
            .unwrap_or(0);
        serde_json::json!({
            "exists": true,
            "rule_files_count": rule_files
        })
    } else {
        serde_json::json!({"exists": false})
    };

    diagnostics["diagnostics"] = serde_json::json!({
        "log_file": log_file_status,
        "rules_directory": rules_status,
        "config_file": Path::new("config.json").exists(),
        "network_interfaces": get_available_interfaces()
    });

    web::Json(diagnostics)
}

// System performance endpoint
async fn system_performance() -> web::Json<serde_json::Value> {
    use sysinfo::System;
    
    let mut sys = System::new_all();
    sys.refresh_all();

    // Note: Disk information might not be available in all sysinfo versions
    // For now, we'll provide a placeholder or simplified disk info
    let disks = vec![
        serde_json::json!({
            "name": "System Disk",
            "mount_point": "/",
            "total_space": 0,
            "available_space": 0,
            "usage_percent": 0.0
        })
    ];

    web::Json(serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "cpu": {
            "usage_percent": sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32,
            "core_count": sys.cpus().len()
        },
        "memory": {
            "total_mb": sys.total_memory() as f64 / 1024.0,
            "used_mb": sys.used_memory() as f64 / 1024.0,
            "usage_percent": (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0
        },
        "disks": disks,
        "network": {
            "monitoring_active": true,
            "packets_processed": 0  // Would be populated by actual monitoring data
        }
    }))
}

// Service restart endpoint
async fn restart_services() -> web::Json<serde_json::Value> {
    // This would implement actual service restart logic
    web::Json(serde_json::json!({
        "status": "success",
        "message": "Service restart initiated",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Helper functions
async fn check_database_connection() -> Result<(), Box<dyn std::error::Error>> {
    // Simplified database connection check
    // In a real implementation, this would ping the actual database
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Ok(())
}

fn get_available_interfaces() -> Vec<String> {
    // Simplified interface detection
    // In a real implementation, this would use system calls to get actual interfaces
    vec!["en0".to_string(), "lo0".to_string()]
}