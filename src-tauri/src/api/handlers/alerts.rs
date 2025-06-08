use actix_web::{web, Responder, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::services::alert_service::AlertService;
use crate::storage::db::Database;
use crate::storage::models::alert::{Alert, AlertSeverity, AlertStatus};
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::utils::error::AppError;
use tokio::sync::broadcast;
use actix_web_lab::sse;
use futures_util::stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use std::pin::Pin;
use futures_util::Stream;

const HANDLER_NAME: &'static str = "system";

/// Pagination parameters for alerts
#[derive(Debug, Deserialize)]
pub struct AlertPaginationParams {
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub sort_field: Option<String>,
    #[serde(default)]
    pub sort_order: Option<String>,
}

/// Filter parameters for alerts
#[derive(Debug, Deserialize)]
pub struct AlertFilterParams {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub destination_ip: Option<String>,
    #[serde(default)]
    pub start_date: Option<String>,
    #[serde(default)]
    pub end_date: Option<String>,
}

/// Response for paginated alerts
#[derive(Debug, Serialize)]
pub struct PaginatedAlertsResponse {
    pub alerts: Vec<Alert>,
    pub total: u64,
    pub page: usize,
    pub limit: usize,
    pub total_pages: usize,
}

/// Request to create a new alert
#[derive(Debug, Deserialize)]
pub struct CreateAlertRequest {
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub message: String,
    pub details: Option<String>,
    pub rule_id: Option<String>,
}

/// Request to update an alert
#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    pub status: Option<AlertStatus>,
    pub severity: Option<AlertSeverity>,
    pub description: Option<String>,
    pub message: Option<String>,
    pub details: Option<String>,
}

/// Request to add a comment to an alert
#[derive(Debug, Deserialize)]
pub struct AddCommentRequest {
    pub text: String,
}

/// Request to resolve an alert
#[derive(Debug, Deserialize)]
pub struct ResolveAlertRequest {
    pub comment: Option<String>,
}

/// Request to mark multiple alerts as read
#[derive(Debug, Deserialize)]
pub struct MarkAlertsAsReadRequest {
    pub alert_ids: Vec<String>,
}

/// Get all alerts with filtering and pagination
pub async fn get_alerts(
    db: web::Data<Database>,
    pagination: web::Query<AlertPaginationParams>,
    filter: web::Query<AlertFilterParams>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    // Parse pagination params
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(20).min(100); // Max 100 items per page
    let skip = ((page - 1) * limit) as i64;

    // Parse sort params
    let sort_field = pagination.sort_field.as_deref();
    let sort_order = match pagination.sort_order.as_deref() {
        Some("desc") => Some(-1),
        Some("asc") => Some(1),
        _ => None,
    };

    // Parse filter params
    let severity = filter.severity.as_ref().map(|s| s.to_lowercase()).as_deref().and_then(|s_lower| {
        match s_lower {
            "critical" => Some(AlertSeverity::Critical),
            "high" => Some(AlertSeverity::High),
            "medium" => Some(AlertSeverity::Medium),
            "low" => Some(AlertSeverity::Low),
            _ => None,
        }
    });

    let status = match filter.status.as_deref() {
        Some("new") => Some(AlertStatus::New),
        Some("acknowledged") => Some(AlertStatus::Acknowledged),
        Some("inprogress") => Some(AlertStatus::InProgress),
        Some("resolved") => Some(AlertStatus::Resolved),
        Some("falsepositive") => Some(AlertStatus::FalsePositive),
        _ => None,
    };

    // Parse date filters
    let start_date = filter.start_date.as_deref().and_then(|d| {
        DateTime::parse_from_rfc3339(d)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    });

    let end_date = filter.end_date.as_deref().and_then(|d| {
        DateTime::parse_from_rfc3339(d)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    });

    // Get alerts
    let alerts = alert_service.get_alerts(
        severity,
        status,
        filter.source_ip.as_deref(),
        filter.destination_ip.as_deref(),
        start_date,
        end_date,
        Some(limit as i64),
        Some(skip),
        sort_field,
        sort_order,
    ).await?;

    // Count total alerts for pagination
    let alert_repo_count = AlertRepository::new(db.get_ref().clone()); // Use a new instance or ensure thread safety if sharing
    let total = alert_repo_count.count(severity, status, start_date, end_date).await?;

    let total_pages = (total as f64 / limit as f64).ceil() as usize;

    Ok(web::Json(PaginatedAlertsResponse {
        alerts,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Get an alert by ID
pub async fn get_alert_by_id(
    db: web::Data<Database>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    let id = path.into_inner();
    let alert = alert_service.get_alert_by_id(&id).await?;

    Ok(web::Json(alert))
}

/// Create a new alert
pub async fn create_alert(
    db: web::Data<Database>,
    alert_req: web::Json<CreateAlertRequest>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    // Create alert object
    let alert = Alert::new(
        alert_req.source_ip.clone(),
        alert_req.destination_ip.clone(),
        alert_req.protocol.clone(),
        alert_req.severity,
        alert_req.description.clone(),
        alert_req.message.clone(),
        alert_req.details.clone(),
        alert_req.rule_id.clone(),
    );

    // Save the alert
    let created_alert = alert_service.create_alert(alert).await?;

    // Notify subscribers
    if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
        log::error!("Failed to send broadcast message: {}", e);
    }

    Ok(web::Json(created_alert))
}

/// Update an alert
pub async fn update_alert(
    db: web::Data<Database>,
    path: web::Path<String>,
    update_req: web::Json<UpdateAlertRequest>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    let id = path.into_inner();

    // Get the current alert
    let mut alert = alert_service.get_alert_by_id(&id).await?;

    // Update fields
    if let Some(status) = update_req.status {
        alert.status = status;
    }

    if let Some(severity) = update_req.severity {
        alert.severity = severity;
    }

    if let Some(description) = &update_req.description {
        alert.description = description.clone();
    }

    if let Some(message) = &update_req.message {
        alert.message = message.clone();
    }

    if let Some(details) = &update_req.details {
        alert.details = Some(details.clone());
    }

    // Set updated_at timestamp and handled_by
    alert.updated_at = Some(bson::DateTime::from_chrono(Utc::now()));
    alert.handled_by = Some("system".to_string());

    // Save the updated alert
    let updated_alert = alert_service.update_alert(alert).await?;

    // Notify subscribers
    if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
        log::error!("Failed to send broadcast message: {}", e);
    }

    Ok(web::Json(updated_alert))
}

/// Resolve an alert
pub async fn resolve_alert(
    db: web::Data<Database>,
    path: web::Path<String>,
    resolve_req: web::Json<ResolveAlertRequest>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    let id = path.into_inner();

    // Resolve the alert
    let resolved_alert = alert_service.resolve_alert(
        &id,
        HANDLER_NAME,
        resolve_req.comment.as_deref()
    ).await?;

    // Notify subscribers
    if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
        log::error!("Failed to send broadcast message: {}", e);
    }

    Ok(web::Json(resolved_alert))
}

/// Add a comment to an alert
pub async fn add_comment(
    db: web::Data<Database>,
    path: web::Path<String>,
    comment_req: web::Json<AddCommentRequest>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    let id = path.into_inner();

    // Add the comment
    let updated_alert = alert_service.add_comment(
        &id,
        HANDLER_NAME,
        &comment_req.text
    ).await?;

    // Notify subscribers
    if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
        log::error!("Failed to send broadcast message: {}", e);
    }

    Ok(web::Json(updated_alert))
}

/// Delete an alert by its ID (expects "ALERT-xxxxxxx" format)
pub async fn delete_alert_handler(
    db: web::Data<Database>,
    path: web::Path<String>, // The alert_id string from the URL path
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);
    let id_str = path.into_inner();

    // Call the service layer delete function
    alert_service.delete_alert(&id_str).await?;

    // Return a 204 No Content on successful deletion
    Ok(HttpResponse::NoContent().finish())
}

/// Handler to mark multiple alerts as read
pub async fn mark_alerts_as_read_handler(
    db: web::Data<Database>,
    req: web::Json<MarkAlertsAsReadRequest>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    // Ensure there are IDs to process
    if req.alert_ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "message": "No alert IDs provided"
        })));
    }

    match alert_service.mark_alerts_as_read(&req.alert_ids, HANDLER_NAME).await {
        Ok(count) => {
            // Notify subscribers
            if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
                log::error!("Failed to send broadcast message: {}", e);
            }
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": format!("Successfully marked {} alerts as read.", count),
                "updated_count": count
            })))
        }
        Err(e) => {
            eprintln!("Error marking alerts as read: {:?}", e);
            Err(AppError::InternalError("Failed to mark alerts as read".to_string()))
        }
    }
}

/// Handler to mark all alerts in the system as read
pub async fn mark_all_system_alerts_as_read_handler(
    db: web::Data<Database>,
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);

    // For now, using a generic handler name. In a real system, you might get the user from auth state.
    const SYSTEM_USER: &str = "system_mark_all"; 

    match alert_service.mark_all_alerts_as_read(SYSTEM_USER).await {
        Ok(count) => {
            // Notify subscribers
            if let Err(e) = broadcaster.send(r#"{"type": "refresh_alerts"}"#.to_string()) {
                log::error!("Failed to send broadcast message: {}", e);
            }
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": format!("Successfully marked {} alerts as read system-wide.", count),
                "updated_count": count
            })))
        }
        Err(e) => {
            eprintln!("Error marking all system alerts as read: {:?}", e);
            Err(AppError::InternalError("Failed to mark all system alerts as read".to_string()))
        }
    }
}

/// Get alert statistics
pub async fn get_alert_stats(
    db: web::Data<Database>,
) -> Result<impl Responder, AppError> {
    let alert_repo = AlertRepository::new(db.get_ref().clone());
    let alert_service = AlertService::new(alert_repo);
    
    // Get actual alert statistics from the database
    let stats = alert_service.get_alert_stats().await?;
    
    // Format stats for the response
    let response = serde_json::json!({
        "unreadCount": stats.new,  // Number of unread/new alerts
        "totalCount": stats.total,  // Total number of alerts in the system
        "highPriorityCount": stats.by_severity.iter()
            .filter(|(severity, _)| matches!(severity, AlertSeverity::Critical | AlertSeverity::High))
            .fold(0, |acc, (_, count)| acc + count),
        "by_severity": {
            "critical": stats.by_severity.iter()
                .find(|(severity, _)| matches!(severity, AlertSeverity::Critical))
                .map(|(_, count)| count)
                .unwrap_or(&0),
            "high": stats.by_severity.iter()
                .find(|(severity, _)| matches!(severity, AlertSeverity::High))
                .map(|(_, count)| count)
                .unwrap_or(&0),
            "medium": stats.by_severity.iter()
                .find(|(severity, _)| matches!(severity, AlertSeverity::Medium))
                .map(|(_, count)| count)
                .unwrap_or(&0),
            "low": stats.by_severity.iter()
                .find(|(severity, _)| matches!(severity, AlertSeverity::Low))
                .map(|(_, count)| count)
                .unwrap_or(&0)
        },
        "by_status": {
            "new": stats.new,
            "acknowledged": stats.in_progress,
            "in_progress": stats.in_progress,
            "resolved": stats.resolved,
            "false_positive": 0  // This would need to be tracked separately
        },
        "recent_trend": {
            "last_24h": stats.by_day.first().map(|(_, count)| count).cloned().unwrap_or(0),
            "last_7d": stats.by_day.iter().take(7).fold(0, |acc, (_, count)| acc + count),
            "previous_7d": stats.by_day.iter().skip(7).take(7).fold(0, |acc, (_, count)| acc + count),
            "trend_percentage": calculate_trend_percentage(&stats.by_day)
        }
    });

    Ok(web::Json(response))
}

/// Calculate percentage change between two time periods
fn calculate_trend_percentage(daily_stats: &[(String, u64)]) -> f64 {
    if daily_stats.len() < 14 {
        return 0.0;
    }
    
    let current_week: u64 = daily_stats.iter().take(7).fold(0, |acc, (_, count)| acc + count);
    let previous_week: u64 = daily_stats.iter().skip(7).take(7).fold(0, |acc, (_, count)| acc + count);
    
    if previous_week == 0 {
        return 100.0; // Avoid division by zero
    }
    
    ((current_week as f64 - previous_week as f64) / previous_week as f64) * 100.0
}

// New SSE Handler for streaming alert notifications
pub async fn stream_alerts(
    broadcaster: web::Data<broadcast::Sender<String>>,
) -> impl Responder { // Keep it generic for now, specific type later if needed
    let rx = broadcaster.subscribe();
    let mut broadcast_stream = BroadcastStream::new(rx);

    let stream = async_stream::stream! {
        while let Some(Ok(msg)) = broadcast_stream.next().await {
            // Ensure sse::Event and sse::Data are correctly namespaced or imported
            yield Ok(sse::Event::Data(sse::Data::new(msg))); 
        }
    };
    // The return type of sse::Sse::from_stream will be the actual Responder type
    sse::Sse::from_stream(Box::pin(stream) as Pin<Box<dyn Stream<Item = Result<sse::Event, sse::SendError>> + Send>>)
        .with_keep_alive(std::time::Duration::from_secs(15))
}