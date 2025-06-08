use serde::{Serialize, Deserialize};
use mongodb::bson::{self, oid::ObjectId, DateTime};

/// Log levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Convert from string
    pub fn from_str(level: &str) -> Self {
        match level.to_lowercase().as_str() {
            "trace" => Self::Trace,
            "debug" => Self::Debug,
            "warn" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info, // Default
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Log categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogCategory {
    System,
    Security,
    Network,
    User,
    Database,
    Api,
}

/// Represents a system log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// MongoDB ID
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// Log timestamp
    pub timestamp: DateTime,

    /// Log level
    pub level: LogLevel,

    /// Log category
    pub category: LogCategory,

    /// Log message
    pub message: String,

    /// Source file (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    /// Source line (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,

    /// User ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Additional context as JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<bson::Document>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        level: LogLevel,
        category: LogCategory,
        message: String,
    ) -> Self {
        Self {
            id: None,
            timestamp: bson::DateTime::now(),
            level,
            category,
            message,
            file: None,
            line: None,
            user_id: None,
            context: None,
        }
    }

    /// Create a system log entry
    pub fn system(level: LogLevel, message: String) -> Self {
        Self::new(level, LogCategory::System, message)
    }

    /// Create a security log entry
    pub fn security(level: LogLevel, message: String) -> Self {
        Self::new(level, LogCategory::Security, message)
    }

    /// Create a network log entry
    pub fn network(level: LogLevel, message: String) -> Self {
        Self::new(level, LogCategory::Network, message)
    }

    /// Create a user log entry
    pub fn user(level: LogLevel, message: String, user_id: Option<String>) -> Self {
        let mut log = Self::new(level, LogCategory::User, message);
        log.user_id = user_id;
        log
    }

    /// Create a database log entry
    pub fn database(level: LogLevel, message: String) -> Self {
        Self::new(level, LogCategory::Database, message)
    }

    /// Create an API log entry
    pub fn api(level: LogLevel, message: String, user_id: Option<String>) -> Self {
        let mut log = Self::new(level, LogCategory::Api, message);
        log.user_id = user_id;
        log
    }

    /// Set source file and line
    pub fn with_source(mut self, file: String, line: u32) -> Self {
        self.file = Some(file);
        self.line = Some(line);
        self
    }

    /// Set additional context
    pub fn with_context(mut self, context: bson::Document) -> Self {
        self.context = Some(context);
        self
    }

    /// Set user ID
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }
}