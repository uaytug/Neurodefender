use std::str::FromStr;

use bson::{doc, Document};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use log::warn;
use mongodb::{options::FindOptions, Collection};

use crate::services::report_service::{Report, ReportStatus, ReportType};
use crate::storage::db::Database;
use crate::utils::error::AppError;

const REPORTS_COLLECTION: &str = "reports";

/// Repository for Report objects
pub struct ReportRepository {
    /// Database connection
    db: Database,
    /// MongoDB collection
    collection: Collection<Report>,
}

impl ReportRepository {
    /// Create a new report repository
    pub fn new(db: Database) -> Self {
        let collection = db.collection(REPORTS_COLLECTION);
        Self { db, collection }
    }

    /// Insert a new report
    pub async fn insert(&self, report: Report) -> Result<Report, AppError> {
        let result = self.collection.insert_one(report, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to insert report: {}", e)))?;

        // Get the inserted report
        let inserted_id = result.inserted_id;
        let filter = doc! { "_id": inserted_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find inserted report: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError("Inserted report not found".to_string()))
    }

    /// Find a report by ID
    pub async fn find_by_id(&self, id: &str) -> Result<Report, AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find report: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Report not found with ID: {}", id)))
    }

    /// Find a report by report ID
    pub async fn find_by_report_id(&self, report_id: &str) -> Result<Report, AppError> {
        let filter = doc! { "report_id": report_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find report: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Report not found with report ID: {}", report_id)))
    }

    /// Update a report
    pub async fn update(&self, report: Report) -> Result<Report, AppError> {
        let id = report.id.ok_or_else(|| AppError::ValidationError("Report ID is required".to_string()))?;

        let filter = doc! { "_id": id };
        let update_result = self.collection.replace_one(filter.clone(), report, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update report: {}", e)))?;

        if update_result.modified_count == 0 {
            return Err(AppError::NotFoundError(format!("Report not found with ID: {}", id)));
        }

        // Get the updated report
        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find updated report: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Updated report not found with ID: {}", id)))
    }

    /// Delete a report
    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        let delete_result = self.collection.delete_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete report: {}", e)))?;

        if delete_result.deleted_count == 0 {
            return Err(AppError::NotFoundError(format!("Report not found with ID: {}", id)));
        }

        Ok(())
    }

    /// Find all reports with optional filtering and pagination
    pub async fn find_all(
        &self,
        report_type: Option<ReportType>,
        status: Option<ReportStatus>,
        generated_by: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: Option<i64>,
        skip: Option<i64>,
        sort_field: Option<&str>,
        sort_order: Option<i32>,
    ) -> Result<Vec<Report>, AppError> {
        // Build filter
        let mut filter = Document::new();

        if let Some(report_type) = report_type {
            filter.insert("report_type", format!("{:?}", report_type).to_lowercase());
        }

        if let Some(status) = status {
            filter.insert("status", format!("{:?}", status).to_lowercase());
        }

        if let Some(generated_by) = generated_by {
            filter.insert("generated_by", generated_by);
        }

        // Date range filter for generation date
        if start_date.is_some() || end_date.is_some() {
            let mut date_filter = Document::new();

            if let Some(start) = start_date {
                date_filter.insert("$gte", bson::DateTime::from_chrono(start));
            }

            if let Some(end) = end_date {
                date_filter.insert("$lte", bson::DateTime::from_chrono(end));
            }

            filter.insert("generated_at", date_filter);
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
            // Default sort by generation date descending
            options.sort = Some(doc! { "generated_at": -1 });
        }

        // Execute query
        let mut cursor = self.collection.find(filter, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find reports: {}", e)))?;

        // Collect results
        let mut reports = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(report) => reports.push(report),
                Err(e) => warn!("Error retrieving report: {}", e),
            }
        }

        Ok(reports)
    }

    /// Count reports with optional filtering
    pub async fn count(
        &self,
        report_type: Option<ReportType>,
        status: Option<ReportStatus>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<u64, AppError> {
        // Build filter
        let mut filter = Document::new();

        if let Some(report_type) = report_type {
            filter.insert("report_type", format!("{:?}", report_type).to_lowercase());
        }

        if let Some(status) = status {
            filter.insert("status", format!("{:?}", status).to_lowercase());
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

            filter.insert("generated_at", date_filter);
        }

        // Execute count
        let count = self.collection.count_documents(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count reports: {}", e)))?;

        Ok(count)
    }

    /// Update report status
    pub async fn update_status(
        &self,
        id: &str,
        status: ReportStatus,
        error: Option<String>,
    ) -> Result<Report, AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        // Build update
        let mut update = doc! {
            "$set": {
                "status": format!("{:?}", status).to_lowercase()
            }
        };

        // Add error if provided
        if let Some(error_msg) = error {
            update = doc! {
                "$set": {
                    "status": format!("{:?}", status).to_lowercase(),
                    "error": error_msg
                }
            };
        }

        // Update the report
        let update_result = self.collection.update_one(filter.clone(), update, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update report status: {}", e)))?;

        if update_result.modified_count == 0 {
            return Err(AppError::NotFoundError(format!("Report not found with ID: {}", id)));
        }

        // Get the updated report
        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find updated report: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Updated report not found with ID: {}", id)))
    }
}