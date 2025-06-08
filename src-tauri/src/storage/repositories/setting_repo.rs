
use bson::{doc, Document};
use futures::StreamExt;
use log::warn;
use mongodb::{options::FindOptions, Collection};

use crate::storage::db::Database;
use crate::storage::models::settings::Setting;
use crate::utils::error::AppError;

const SETTINGS_COLLECTION: &str = "settings";

/// Repository for system settings
pub struct SettingRepository {
    /// Database connection
    db: Database,
    /// MongoDB collection
    collection: Collection<Setting>,
}

impl SettingRepository {
    /// Create a new setting repository
    pub fn new(db: Database) -> Self {
        let collection = db.collection(SETTINGS_COLLECTION);
        Self { db, collection }
    }

    /// Get a setting by key
    pub async fn get_by_key(&self, key: &str) -> Result<Setting, AppError> {
        let filter = doc! { "key": key };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find setting: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Setting not found with key: {}", key)))
    }

    /// Get all settings with optional prefix filter
    pub async fn get_all(&self, prefix: Option<&str>) -> Result<Vec<Setting>, AppError> {
        let mut filter = Document::new();

        // Filter by prefix if provided
        if let Some(prefix) = prefix {
            filter.insert("key", doc! { "$regex": format!("^{}.*", prefix) });
        }

        let options = FindOptions::builder()
            .sort(doc! { "key": 1 })
            .build();

        let mut cursor = self.collection.find(filter, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find settings: {}", e)))?;

        // Collect results
        let mut settings = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(setting) => settings.push(setting),
                Err(e) => warn!("Error retrieving setting: {}", e),
            }
        }

        Ok(settings)
    }

    /// Create or update a setting
    pub async fn upsert(&self, setting: Setting) -> Result<Setting, AppError> {
        let filter = doc! { "key": &setting.key };

        // Check if setting exists
        let exists = self.collection.find_one(filter.clone(), None).await?
            .is_some();

        if exists {
            // Update existing setting
            let update_result = self.collection.replace_one(filter.clone(), setting.clone(), None).await
                .map_err(|e| AppError::DatabaseError(format!("Failed to update setting: {}", e)))?;

            if update_result.modified_count == 0 {
                return Err(AppError::DatabaseError(format!("Failed to update setting: {}", setting.key)));
            }
        } else {
            // Insert new setting
            self.collection.insert_one(setting.clone(), None).await
                .map_err(|e| AppError::DatabaseError(format!("Failed to insert setting: {}", e)))?;
        }

        Ok(setting)
    }

    /// Delete a setting by key
    pub async fn delete(&self, key: &str) -> Result<(), AppError> {
        let filter = doc! { "key": key };

        let delete_result = self.collection.delete_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete setting: {}", e)))?;

        if delete_result.deleted_count == 0 {
            return Err(AppError::NotFoundError(format!("Setting not found with key: {}", key)));
        }

        Ok(())
    }

    /// Initialize default settings if they don't exist
    pub async fn init_defaults(&self) -> Result<(), AppError> {
        // Define default settings
        let defaults = vec![
            Setting::new("detection.sensitivity", "medium"),
            Setting::new("detection.enabled", "true"),
            Setting::new("network.interface", "default"),
            Setting::new("network.filter", ""),
            Setting::new("notification.email_enabled", "false"),
            Setting::new("notification.email_address", ""),
            Setting::new("notification.in_app_enabled", "true"),
            Setting::new("system.data_retention_days", "30"),
            Setting::new("system.auto_start", "false"),
        ];

        // Insert defaults if they don't exist
        for setting in defaults {
            let filter = doc! { "key": &setting.key };

            // Check if setting exists
            let exists = self.collection.find_one(filter, None).await?
                .is_some();

            if !exists {
                // Insert default setting
                self.collection.insert_one(setting, None).await
                    .map_err(|e| AppError::DatabaseError(format!("Failed to insert default setting: {}", e)))?;
            }
        }

        Ok(())
    }
}