use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::storage::models::alert::{Alert, AlertSeverity, AlertStatus};
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::utils::error::AppError;

/// Service for managing security alerts
pub struct AlertService {
    /// Alert repository
    alert_repo: AlertRepository,
}

impl AlertService {
    /// Create a new alert service
    pub fn new(alert_repo: AlertRepository) -> Self {
        Self { alert_repo }
    }

    /// Get alert by ID
    pub async fn get_alert_by_id(&self, id: &str) -> Result<Alert, AppError> {
        self.alert_repo.find_by_alert_id(id).await
    }

    /// Get all alerts with optional filtering and pagination
    pub async fn get_alerts(
        &self,
        severity: Option<AlertSeverity>,
        status: Option<AlertStatus>,
        source_ip: Option<&str>,
        destination_ip: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: Option<i64>,
        skip: Option<i64>,
        sort_field: Option<&str>,
        sort_order: Option<i32>,
    ) -> Result<Vec<Alert>, AppError> {
        self.alert_repo.find_all(
            severity,
            status,
            source_ip,
            destination_ip,
            start_date,
            end_date,
            limit,
            skip,
            sort_field,
            sort_order,
        ).await
    }

    /// Create a new alert
    pub async fn create_alert(&self, alert: Alert) -> Result<Alert, AppError> {
        self.alert_repo.insert(alert).await
    }

    /// Update an alert
    pub async fn update_alert(&self, alert: Alert) -> Result<Alert, AppError> {
        self.alert_repo.update(alert).await
    }

    /// Delete an alert by its alert_id string
    pub async fn delete_alert(&self, alert_id_str: &str) -> Result<(), AppError> {
        self.alert_repo.delete(alert_id_str).await
    }

    /// Resolve an alert
    pub async fn resolve_alert(&self, id: &str, user: &str, comment: Option<&str>) -> Result<Alert, AppError> {
        let mut alert = self.alert_repo.find_by_alert_id(id).await?;
        alert.status = AlertStatus::Resolved;
        alert.handled_by = Some(user.to_string());
        alert.updated_at = Some(bson::DateTime::from_chrono(Utc::now()));

        if let Some(text) = comment {
            alert.add_comment(user.to_string(), text.to_string());
        }
        self.alert_repo.update(alert).await
    }

    /// Add a comment to an alert
    pub async fn add_comment(&self, id: &str, user: &str, text: &str) -> Result<Alert, AppError> {
        let mut alert = self.alert_repo.find_by_alert_id(id).await?;
        alert.add_comment(user.to_string(), text.to_string());
        self.alert_repo.update(alert).await
    }

    /// Mark multiple alerts as read by their IDs
    pub async fn mark_alerts_as_read(&self, alert_ids: &[String], handled_by: &str) -> Result<u64, AppError> {
        if alert_ids.is_empty() {
            return Ok(0); // No IDs provided, so 0 updated.
        }
        // It's important that the repository method can handle a list of String IDs.
        self.alert_repo.update_status_for_multiple_alerts(alert_ids, AlertStatus::Read, handled_by).await
    }

    /// Get alert statistics
    pub async fn get_alert_stats(&self) -> Result<AlertStats, AppError> {
        // Get severity stats
        let severity_stats = self.alert_repo.get_severity_stats().await?;

        // Get daily stats for the past 30 days
        let daily_stats = self.alert_repo.get_daily_stats(30).await?;

        // Count total alerts
        let total_alerts = severity_stats.iter()
            .fold(0, |acc, (_, count)| acc + count);

        // Count alerts by status
        let resolved_count = self.alert_repo.count(None, Some(AlertStatus::Resolved), None, None).await?;
        let new_count = self.alert_repo.count(None, Some(AlertStatus::New), None, None).await?;
        let in_progress_count = self.alert_repo.count(None, Some(AlertStatus::InProgress), None, None).await?;

        Ok(AlertStats {
            total: total_alerts,
            by_severity: severity_stats,
            by_day: daily_stats,
            resolved: resolved_count,
            new: new_count,
            in_progress: in_progress_count,
        })
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, limit: i64) -> Result<Vec<Alert>, AppError> {
        self.alert_repo.get_recent_alerts(limit).await
    }

    /// Mark all alerts in the system as read.
    pub async fn mark_all_alerts_as_read(&self, user: &str) -> Result<u64, AppError> {
        self.alert_repo.mark_all_as_read(user).await
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    /// Total number of alerts
    pub total: u64,
    /// Alerts by severity
    pub by_severity: Vec<(AlertSeverity, u64)>,
    /// Alerts by day
    pub by_day: Vec<(String, u64)>,
    /// Number of resolved alerts
    pub resolved: u64,
    /// Number of new alerts
    pub new: u64,
    /// Number of in-progress alerts
    pub in_progress: u64,
}