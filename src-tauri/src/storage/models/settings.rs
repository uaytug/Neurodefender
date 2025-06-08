use serde::{Serialize, Deserialize};
use bson::DateTime;
use mongodb::bson::{self, oid::ObjectId};
use chrono::Utc;

/// Represents a system setting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Setting {
    /// MongoDB ID
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// Setting key (unique identifier)
    pub key: String,

    /// Setting value
    pub value: String,

    /// Description of the setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Category/group of the setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Data type of the setting (string, boolean, number, json)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,

    /// Is this a system setting that cannot be modified by users
    #[serde(default)]
    pub system: bool,

    /// Last modified timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<DateTime>,

    /// User who last modified the setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_by: Option<String>,
}

impl Setting {
    /// Create a new setting with key and value
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            id: None,
            key: key.to_string(),
            value: value.to_string(),
            description: None,
            category: None,
            data_type: None,
            system: false,
            modified_at: Some(bson::DateTime::from_chrono(Utc::now())),
            modified_by: None,
        }
    }

    /// Create a new setting with all attributes
    pub fn new_with_details(
        key: &str,
        value: &str,
        description: Option<&str>,
        category: Option<&str>,
        data_type: Option<&str>,
        system: bool,
    ) -> Self {
        Self {
            id: None,
            key: key.to_string(),
            value: value.to_string(),
            description: description.map(|s| s.to_string()),
            category: category.map(|s| s.to_string()),
            data_type: data_type.map(|s| s.to_string()),
            system,
            modified_at: Some(bson::DateTime::from_chrono(Utc::now())),
            modified_by: None,
        }
    }

    /// Update the setting value
    pub fn update_value(&mut self, value: &str, modified_by: Option<&str>) {
        self.value = value.to_string();
        self.modified_at = Some(bson::DateTime::from_chrono(Utc::now()));
        self.modified_by = modified_by.map(|s| s.to_string());
    }

    /// Get boolean value
    pub fn as_bool(&self) -> bool {
        match self.value.to_lowercase().as_str() {
            "true" | "yes" | "1" | "on" => true,
            _ => false,
        }
    }

    /// Get integer value
    pub fn as_int(&self) -> Option<i64> {
        self.value.parse::<i64>().ok()
    }

    /// Get float value
    pub fn as_float(&self) -> Option<f64> {
        self.value.parse::<f64>().ok()
    }
}

/// Represents a setting update request
#[derive(Debug, Serialize, Deserialize)]
pub struct SettingUpdateRequest {
    /// Setting value to update
    pub value: String,

    /// Optional description update
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional category update
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// Represents a collection of settings
#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsGroup {
    /// Category name
    pub category: String,

    /// Settings in this category
    pub settings: Vec<Setting>,
}