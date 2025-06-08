use std::str::FromStr;
use std::string::ToString;

use bson::{doc, Document};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use log::warn;
use mongodb::{options::FindOptions, Collection};
use crate::storage::db::Database;
use crate::storage::models::alert::{Alert, AlertSeverity, AlertStatus};
use crate::utils::error::AppError;

const ALERTS_COLLECTION: &str = "alerts";

/// stings for alert severity
const ALERT_SEVERITY_INFO: &str = "info";
const ALERT_SEVERITY_LOW: &str = "low";
const ALERT_SEVERITY_MEDIUM: &str = "medium";
const ALERT_SEVERITY_HIGH: &str = "high";
const ALERT_SEVERITY_CRITICAL: &str = "critical";


/// Repository for Alert objects
pub struct AlertRepository {
    /// Database connection
    db: Database,
    /// MongoDB collection
    collection: Collection<Alert>,
}

impl AlertRepository {
    /// Create a new alert repository
    pub fn new(db: Database) -> Self {
        let collection = db.collection(ALERTS_COLLECTION);
        Self { db, collection }
    }

    /// Insert a new alert
    pub async fn insert(&self, alert: Alert) -> Result<Alert, AppError> {
        let result = self.collection.insert_one(alert, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to insert alert: {}", e)))?;

        // Get the inserted alert
        let inserted_id = result.inserted_id;
        let filter = doc! { "_id": inserted_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find inserted alert: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError("Inserted alert not found".to_string()))
    }

    /// Find an alert by ID
    pub async fn find_by_id(&self, id: &str) -> Result<Alert, AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find alert: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Alert not found with ID: {}", id)))
    }

    /// Find an alert by alert ID
    pub async fn find_by_alert_id(&self, alert_id: &str) -> Result<Alert, AppError> {
        let filter = doc! { "alert_id": alert_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find alert: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Alert not found with alert ID: {}", alert_id)))
    }

    /// Update an alert
    pub async fn update(&self, alert: Alert) -> Result<Alert, AppError> {
        let id = alert.id.ok_or_else(|| AppError::ValidationError("Alert ID (_id: ObjectId) is required for update".to_string()))?;

        let filter = doc! { "_id": id };
        let update_result = self.collection.replace_one(filter.clone(), alert, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update alert: {}", e)))?;

        if update_result.modified_count == 0 {
            return Err(AppError::NotFoundError(format!("Alert not found with ID: {}", id)));
        }

        // Get the updated alert
        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find updated alert: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Updated alert not found with ID: {}", id)))
    }

    /// Delete an alert by its alert_id (e.g. ALERT-xxxx)
    pub async fn delete(&self, alert_id_str: &str) -> Result<(), AppError> {
        let filter = doc! { "alert_id": alert_id_str };

        let delete_result = self.collection.delete_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete alert: {}", e)))?;

        if delete_result.deleted_count == 0 {
            return Err(AppError::NotFoundError(format!("Alert not found with alert_id: {}", alert_id_str)));
        }

        Ok(())
    }

    /// Find all alerts with optional filtering and pagination
    pub async fn find_all(
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
        // Build filter
        let mut filter = Document::new();

        if let Some(severity) = severity {
            filter.insert("severity", severity.to_string());
        }

        if let Some(status) = status {
            filter.insert("status", status.to_string());
        }

        if let Some(source_ip) = source_ip {
            filter.insert("source_ip", source_ip);
        }

        if let Some(destination_ip) = destination_ip {
            filter.insert("destination_ip", destination_ip);
        }

        // Date range filter
        if start_date.is_some() || end_date.is_some() {
            let mut date_filter = Document::new();

            if let Some(start) = start_date {
                date_filter.insert("$gte", bson::DateTime::from_chrono(start));
            }

            if let Some(end) = end_date {
                date_filter.insert("$lte", bson::DateTime::from_chrono(end));
            }

            filter.insert("timestamp", date_filter);
        }

        // Build options
        let mut options = FindOptions::default();
        options.limit = limit;
        options.skip = skip.map(|v| v as u64);

        // Set sort order
        if let Some(field) = sort_field {
            let order = sort_order.unwrap_or(1); // Default to ascending
            options.sort = Some(doc! { field: order });
        } else {
            // Default sort by timestamp descending
            options.sort = Some(doc! { "timestamp": -1 });
        }

        // Execute query
        let mut cursor = self.collection.find(filter, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find alerts: {}", e)))?;

        // Collect results
        let mut alerts = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(alert) => alerts.push(alert),
                Err(e) => warn!("Error retrieving alert: {}", e),
            }
        }

        Ok(alerts)
    }

    /// Count alerts with optional filtering
    pub async fn count(
        &self,
        severity: Option<AlertSeverity>,
        status: Option<AlertStatus>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<u64, AppError> {
        // Build filter
        let mut filter = Document::new();

        if let Some(severity) = severity {
            filter.insert("severity", severity.to_string());
        }

        if let Some(status) = status {
            filter.insert("status", status.to_string());
        }

        // Date range filter
        if start_date.is_some() || end_date.is_some() {
            let mut date_filter = Document::new();

            if let Some(start) = start_date {
                date_filter.insert("$gte", bson::DateTime::from_chrono(start));
            }

            if let Some(end) = end_date {
                date_filter.insert("$lte", bson::DateTime::from_chrono(end));
            }

            filter.insert("timestamp", date_filter);
        }

        // Execute count
        let count = self.collection.count_documents(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count alerts: {}", e)))?;

        Ok(count)
    }

    /// Mark all alerts that are not already 'Read' to 'Read' status.
    pub async fn mark_all_as_read(&self, user: &str) -> Result<u64, AppError> {
        let filter = doc! {
            "status": { "$ne": AlertStatus::Read.to_string() } // Filter for alerts not already "read"
        };

        let now_bson = bson::DateTime::from_chrono(Utc::now());
        let update = doc! {
            "$set": {
                "status": AlertStatus::Read.to_string(),
                "handled_by": user,
                "updated_at": now_bson
            }
        };

        let update_result = self.collection.update_many(filter, update, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark all alerts as read: {}", e)))?;

        Ok(update_result.modified_count)
    }

    /// Get alert statistics by severity
    pub async fn get_severity_stats(&self) -> Result<Vec<(AlertSeverity, u64)>, AppError> {
        let pipeline = vec![
            doc! {
                "$group": {
                    "_id": "$severity",
                    "count": { "$sum": 1 }
                }
            }
        ];

        let mut cursor = self.collection.aggregate(pipeline, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to aggregate alerts: {}", e)))?;

        let mut stats = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(doc) => {
                    if let (Some(severity_str), Some(count)) = (
                        doc.get_str("_id").ok(),
                        doc.get_i64("count").ok()
                    ) {
                        // Parse severity
                        match serde_json::from_value::<AlertSeverity>(
                            serde_json::Value::String(severity_str.to_string())
                        ) {
                            Ok(severity) => stats.push((severity, count as u64)),
                            Err(e) => warn!("Failed to parse severity: {}", e),
                        }
                    }
                },
                Err(e) => warn!("Error retrieving severity stats: {}", e),
            }
        }

        Ok(stats)
    }

    /// Get alert statistics by day for the past N days
    pub async fn get_daily_stats(&self, days: i64) -> Result<Vec<(String, u64)>, AppError> {
        // Calculate start date (N days ago)
        let start_date = Utc::now() - chrono::Duration::days(days);

        let pipeline = vec![
            doc! {
                "$match": {
                    "timestamp": {
                        "$gte": bson::DateTime::from_chrono(start_date)
                    }
                }
            },
            doc! {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$timestamp"
                        }
                    },
                    "count": { "$sum": 1 }
                }
            },
            doc! {
                "$sort": {
                    "_id": 1
                }
            }
        ];

        let mut cursor = self.collection.aggregate(pipeline, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to aggregate alerts: {}", e)))?;

        let mut stats = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(doc) => {
                    if let (Some(date), Some(count)) = (
                        doc.get_str("_id").ok(),
                        doc.get_i64("count").ok()
                    ) {
                        stats.push((date.to_string(), count as u64));
                    }
                },
                Err(e) => warn!("Error retrieving daily stats: {}", e),
            }
        }

        Ok(stats)
    }

    /// Update alert status
    pub async fn update_status(
        &self,
        id_str: &str, // This is expected to be alert_id string e.g. "ALERT-xxxx"
        status: AlertStatus,
        handled_by: Option<String>,
    ) -> Result<Alert, AppError> {
        let filter = doc! { "alert_id": id_str };
        let mut update_doc = doc! { "$set": { "status": status.to_string() } };
        if let Some(user) = handled_by {
            update_doc.get_document_mut("$set").unwrap().insert("handled_by", user);
        }
        update_doc.get_document_mut("$set").unwrap().insert("updated_at", bson::DateTime::from_chrono(Utc::now()));

        let options = mongodb::options::FindOneAndUpdateOptions::builder()
            .return_document(mongodb::options::ReturnDocument::After)
            .build();

        self.collection.find_one_and_update(filter, update_doc, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update alert status: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Alert not found with alert_id: {} for status update", id_str)))
    }

    /// Add a comment to an alert
    pub async fn add_comment(
        &self,
        id_str: &str, // This is expected to be alert_id string e.g. "ALERT-xxxx"
        user: &str,
        text: &str,
    ) -> Result<Alert, AppError> {
        let comment = doc! {
            "user": user,
            "timestamp": bson::DateTime::from_chrono(Utc::now()),
            "text": text
        };
        let filter = doc! { "alert_id": id_str };
        let update_doc = doc! {
            "$push": { "comments": comment },
            "$set": { "updated_at": bson::DateTime::from_chrono(Utc::now()) }
        };

        let options = mongodb::options::FindOneAndUpdateOptions::builder()
            .return_document(mongodb::options::ReturnDocument::After)
            .build();

        self.collection.find_one_and_update(filter, update_doc, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to add comment to alert: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Alert not found with alert_id: {} for comment", id_str)))
    }

    /// Get the most recent alerts, limited by count
    pub async fn get_recent_alerts(&self, limit: i64) -> Result<Vec<Alert>, AppError> {
        let options = FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .limit(limit)
            .build();

        let mut cursor = self.collection.find(None, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find recent alerts: {}", e)))?;

        // Collect results
        let mut alerts = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(alert) => alerts.push(alert),
                Err(e) => warn!("Error retrieving alert: {}", e),
            }
        }

        Ok(alerts)
    }

    /// Update the status for multiple alerts given their alert_ids.
    pub async fn update_status_for_multiple_alerts(
        &self,
        alert_ids: &[String],
        status: AlertStatus,
        handled_by: &str,
    ) -> Result<u64, AppError> {
        if alert_ids.is_empty() {
            return Ok(0);
        }

        let collection = self.db.collection::<Alert>("alerts");

        // Create a filter to match documents where alert_id is in the provided list.
        // MongoDB's $in operator is suitable here.
        let filter = doc! { "alert_id": { "$in": alert_ids } };

        // Create an update document to set the new status, handled_by, and updated_at.
        let status_bson = bson::to_bson(&status).map_err(|e| AppError::DataError(format!("Failed to serialize status: {}", e)))?;
        let update = doc! {
            "$set": {
                "status": status_bson,
                "handled_by": handled_by,
                "updated_at": bson::DateTime::from_chrono(Utc::now())
            }
        };

        match collection.update_many(filter, update, None).await {
            Ok(update_result) => Ok(update_result.modified_count),
            Err(e) => {
                eprintln!("Error updating multiple alerts: {:?}", e);
                Err(AppError::DatabaseError(e.to_string()))
            }
        }
    }
}