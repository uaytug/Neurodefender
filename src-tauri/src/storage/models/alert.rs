use serde::{Serialize, Deserialize};
use bson::DateTime;
use mongodb::bson::{self, oid::ObjectId};
use std::fmt;

/// Severity levels for security alerts
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low      => "low",
            Self::Medium   => "medium",
            Self::High     => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}


/// Status of an alert
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
    Read,
    Unread,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Acknowledged => "acknowledged",
            Self::FalsePositive => "falsepositive",
            Self::New        => "new",
            Self::InProgress => "inprogress",
            Self::Resolved   => "resolved",
            Self::Read       => "read",
            Self::Unread     => "unread",
        };
        write!(f, "{s}")
    }
}

/// Represents a security alert detected by the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// Unique alert identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<String>,

    /// Time when the alert was generated
    pub timestamp: DateTime,

    /// Alert severity level
    pub severity: AlertSeverity,

    /// Current status of the alert
    pub status: AlertStatus,

    /// Source IP address
    pub source_ip: String,

    /// Destination IP address
    pub destination_ip: String,

    /// Network protocol
    pub protocol: String,

    /// Alert description
    pub description: String,

    /// Alert message
    pub message: String,

    /// Optional details about the alert
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Reference to the rule that triggered the alert
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    /// User who handled the alert
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handled_by: Option<String>,

    /// Time when the alert was last updated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,

    /// Comments added by analysts
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<AlertComment>,
}

/// Comment on an alert, typically added by a security analyst
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertComment {
    /// User who added the comment
    pub user: String,

    /// Time when the comment was added
    pub timestamp: DateTime,

    /// Comment text
    pub text: String,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        source_ip: String,
        destination_ip: String,
        protocol: String,
        severity: AlertSeverity,
        description: String,
        message: String,
        details: Option<String>,
        rule_id: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now();

        Self {
            id: None,
            alert_id: Some(format!("ALERT-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap())),
            timestamp: bson::DateTime::from_chrono(now),
            severity,
            status: AlertStatus::New,
            source_ip,
            destination_ip,
            protocol,
            description,
            message,
            details,
            rule_id,
            handled_by: None,
            updated_at: None,
            comments: Vec::new(),
        }
    }

    /// Add a comment to the alert
    pub fn add_comment(&mut self, user: String, text: String) {
        let now = chrono::Utc::now();
        self.comments.push(AlertComment {
            user,
            timestamp: bson::DateTime::from_chrono(now),
            text,
        });
        self.updated_at = Some(bson::DateTime::from_chrono(now));
    }

    /// Update the alert status
    pub fn update_status(&mut self, status: AlertStatus, user: Option<String>) {
        self.status = status;
        self.handled_by = user;
        self.updated_at = Some(bson::DateTime::from_chrono(chrono::Utc::now()));
    }
}