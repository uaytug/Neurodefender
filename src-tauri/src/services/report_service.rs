use std::collections::HashMap;
use std::{fmt, fs};
use std::path::Path;

use bson::DateTime;
use chrono::{Duration, Utc};
use log::error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::storage::models::alert::{Alert, AlertSeverity, AlertStatus};
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::services::alert_service::AlertStats;
use crate::utils::error::AppError;

/// Report type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportType {
    Daily,
    Weekly,
    Monthly,
    Custom,
    Incident,
}

/// Report status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// Report format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    PDF,
    CSV,
    JSON,
    HTML,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportFormat::PDF => write!(f, "PDF"),
            ReportFormat::CSV => write!(f, "CSV"),
            ReportFormat::JSON => write!(f, "JSON"),
            ReportFormat::HTML => write!(f, "HTML"),
        }
    }
}

/// Report model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// MongoDB ID
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<bson::oid::ObjectId>,

    /// Report ID
    pub report_id: String,

    /// Report title
    pub title: String,

    /// Report type
    pub report_type: ReportType,

    /// Report status
    pub status: ReportStatus,

    /// Report format
    pub format: ReportFormat,

    /// Generated by
    pub generated_by: String,

    /// Generated at
    pub generated_at: DateTime,

    /// Report period start
    pub period_start: DateTime,

    /// Report period end
    pub period_end: DateTime,

    /// File path (if generated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Report data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ReportData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] //
pub struct ReportData {
    /// Alert statistics
    pub alert_stats: AlertStats,

    /// Top source IPs
    pub top_source_ips: Vec<(String, u64)>,

    /// Top destination IPs
    pub top_destination_ips: Vec<(String, u64)>,

    /// Alerts by protocol
    pub alerts_by_protocol: Vec<(String, u64)>,

    /// Recent alerts
    pub recent_alerts: Vec<Alert>,
}

/// Report generation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    /// Report type
    pub report_type: ReportType,

    /// Report format
    pub format: ReportFormat,

    /// Report title
    pub title: Option<String>,

    /// Custom period start (for custom reports)
    pub period_start: Option<chrono::DateTime<Utc>>,

    /// Custom period end (for custom reports)
    pub period_end: Option<chrono::DateTime<Utc>>,

    /// Incident ID (for incident reports)
    pub incident_id: Option<String>,

    /// Generated by
    pub generated_by: String,
}

/// Service for generating and managing security reports
pub struct ReportService {
    /// Alert repository
    alert_repo: AlertRepository,
    /// Output directory for reports
    output_dir: String,
}

impl ReportService {
    /// Create a new report service
    pub fn new(alert_repo: AlertRepository, output_dir: &str) -> Self {
        // Create output directory if it doesn't exist
        let output_path = Path::new(output_dir);
        if !output_path.exists() {
            if let Err(e) = fs::create_dir_all(output_path) {
                error!("Failed to create report output directory: {}", e);
            }
        }

        Self {
            alert_repo,
            output_dir: output_dir.to_string(),
        }
    }

    /// Generate a report
    pub async fn generate_report(&self, request: ReportRequest) -> Result<Report, AppError> {
        let now = Utc::now();
        let report_id = format!("RPT-{}", Uuid::new_v4().to_string().split('-').next().unwrap());

        // Determine report period
        let (period_start, period_end) = match request.report_type {
            ReportType::Daily => {
                let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
                let end = now;
                (start.and_utc(), end)
            },
            ReportType::Weekly => {
                let start = now - Duration::days(7);
                let end = now;
                (start, end)
            },
            ReportType::Monthly => {
                let start = now - Duration::days(30);
                let end = now;
                (start, end)
            },
            ReportType::Custom => {
                let start = request.period_start.ok_or_else(|| {
                    AppError::ValidationError("Period start is required for custom reports".to_string())
                })?;

                let end = request.period_end.ok_or_else(|| {
                    AppError::ValidationError("Period end is required for custom reports".to_string())
                })?;

                if end < start {
                    return Err(AppError::ValidationError("Period end must be after period start".to_string()));
                }

                (start, end)
            },
            ReportType::Incident => {
                let incident_id = request.incident_id.ok_or_else(|| {
                    AppError::ValidationError("Incident ID is required for incident reports".to_string())
                })?;

                // For incident reports, we need to find the incident alert
                let incident_alert = self.alert_repo.find_by_id(&incident_id).await?;

                // Use a window around the incident time
                let incident_time = incident_alert.timestamp.to_chrono();
                let start = incident_time - Duration::hours(24);
                let end = incident_time + Duration::hours(1);

                (start, end)
            },
        };

        // Create report
        let title = request.title.unwrap_or_else(|| {
            match request.report_type {
                ReportType::Daily => "Daily Security Report".to_string(),
                ReportType::Weekly => "Weekly Security Report".to_string(),
                ReportType::Monthly => "Monthly Security Report".to_string(),
                ReportType::Custom => "Custom Security Report".to_string(),
                ReportType::Incident => "Incident Report".to_string(),
            }
        });

        let report = Report {
            id: None,
            report_id,
            title,
            report_type: request.report_type,
            status: ReportStatus::InProgress,
            format: request.format,
            generated_by: request.generated_by,
            generated_at: bson::DateTime::from_chrono(now),
            period_start: bson::DateTime::from_chrono(period_start),
            period_end: bson::DateTime::from_chrono(period_end),
            file_path: None,
            error: None,
            data: None,
        };

        // Generate report data
        let data = self.generate_report_data(
            period_start,
            period_end,
            request.report_type == ReportType::Incident,
        ).await?;

        // Update report with data
        let mut updated_report = report.clone();
        updated_report.data = Some(data);
        updated_report.status = ReportStatus::Completed;

        // Generate report file
        let file_path = self.save_report_to_file(&updated_report).await?;
        updated_report.file_path = Some(file_path);

        Ok(updated_report)
    }

    /// Generate report data
    async fn generate_report_data(
        &self,
        period_start: chrono::DateTime<Utc>,
        period_end: chrono::DateTime<Utc>,
        is_incident_report: bool,
    ) -> Result<ReportData, AppError> {
        log::info!("Generating report data for period: {} to {}", period_start, period_end);
        
        // For performance, limit the number of alerts we fetch
        // We'll fetch a maximum of 10000 alerts to prevent timeouts
        let max_alerts = 10000;
        
        // Get alerts for the period with a limit
        let alerts = self.alert_repo.find_all(
            None,
            None,
            None,
            None,
            Some(period_start),
            Some(period_end),
            Some(max_alerts),
            None,
            Some("timestamp"),
            Some(1), // Ascending
        ).await?;
        
        log::info!("Fetched {} alerts for report", alerts.len());

        // Calculate alert statistics
        let mut alert_stats = AlertStats {
            total: alerts.len() as u64,
            by_severity: Vec::new(),
            by_day: Vec::new(),
            resolved: 0,
            new: 0,
            in_progress: 0,
        };

        // Count by severity
        let mut severity_map: HashMap<AlertSeverity, u64> = HashMap::new();
        let mut status_map: HashMap<AlertStatus, u64> = HashMap::new();
        let mut day_map: HashMap<String, u64> = HashMap::new();
        let mut source_ip_map: HashMap<String, u64> = HashMap::new();
        let mut dest_ip_map: HashMap<String, u64> = HashMap::new();
        let mut protocol_map: HashMap<String, u64> = HashMap::new();

        for alert in &alerts {
            // Count by severity
            *severity_map.entry(alert.severity).or_insert(0) += 1;

            // Count by status
            *status_map.entry(alert.status).or_insert(0) += 1;

            // Count by day
            let day = alert.timestamp.to_chrono().format("%Y-%m-%d").to_string();
            *day_map.entry(day).or_insert(0) += 1;

            // Count by source IP
            *source_ip_map.entry(alert.source_ip.clone()).or_insert(0) += 1;

            // Count by destination IP
            *dest_ip_map.entry(alert.destination_ip.clone()).or_insert(0) += 1;

            // Count by protocol
            *protocol_map.entry(alert.protocol.clone()).or_insert(0) += 1;
        }

        // Convert to vectors and sort
        alert_stats.by_severity = severity_map.into_iter().collect();
        alert_stats.by_severity.sort_by(|a, b| b.1.cmp(&a.1));

        alert_stats.by_day = day_map.into_iter().collect();
        alert_stats.by_day.sort_by(|a, b| a.0.cmp(&b.0));

        // Set status counts
        alert_stats.resolved = *status_map.get(&AlertStatus::Resolved).unwrap_or(&0);
        alert_stats.new = *status_map.get(&AlertStatus::New).unwrap_or(&0);
        alert_stats.in_progress = *status_map.get(&AlertStatus::InProgress).unwrap_or(&0);

        // Convert IP maps to vectors and sort
        let mut top_source_ips: Vec<(String, u64)> = source_ip_map.into_iter().collect();
        top_source_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_source_ips.truncate(10);  // Top 10

        let mut top_destination_ips: Vec<(String, u64)> = dest_ip_map.into_iter().collect();
        top_destination_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_destination_ips.truncate(10);  // Top 10

        // Convert protocol map to vector and sort
        let mut alerts_by_protocol: Vec<(String, u64)> = protocol_map.into_iter().collect();
        alerts_by_protocol.sort_by(|a, b| b.1.cmp(&a.1));

        // Recent alerts (last 10)
        let mut recent_alerts = alerts.clone();
        recent_alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        recent_alerts.truncate(10);

        Ok(ReportData {
            alert_stats,
            top_source_ips,
            top_destination_ips,
            alerts_by_protocol,
            recent_alerts,
        })
    }

    /// Save report to file
    async fn save_report_to_file(&self, report: &Report) -> Result<String, AppError> {
        let file_name = format!(
            "{}_{}_{}.{}",
            report.report_id,
            report.period_start.to_chrono().format("%Y%m%d"),
            report.period_end.to_chrono().format("%Y%m%d"),
            report.format.to_string().to_lowercase(),
        );

        let file_path = format!("{}/{}", self.output_dir, file_name);

        match report.format {
            ReportFormat::JSON => {
                let json = serde_json::to_string_pretty(report)
                    .map_err(|e| AppError::InternalError(format!("Failed to serialize report: {}", e)))?;

                fs::write(&file_path, json)
                    .map_err(|e| AppError::IoError(e))?;
            },
            ReportFormat::CSV => {
                // For CSV, we'll just output the alerts in CSV format
                if let Some(data) = &report.data {
                    let mut csv_content = String::new();

                    // Header
                    csv_content.push_str("timestamp,severity,status,source_ip,destination_ip,protocol,description\n");

                    // Alerts
                    for alert in &data.recent_alerts {
                        let line = format!(
                            "{},{},{},{},{},{},{}\n",
                            alert.timestamp.to_chrono().to_rfc3339(),
                            alert.severity.to_string(),
                            alert.status.to_string(),
                            alert.source_ip,
                            alert.destination_ip,
                            alert.protocol,
                            alert.description.replace(',', ";")  // Escape commas
                        );

                        csv_content.push_str(&line);
                    }

                    fs::write(&file_path, csv_content)
                        .map_err(|e| AppError::IoError(e))?;
                }
            },
            ReportFormat::PDF => {
                // PDF generation would typically use a library like wkhtmltopdf
                // For this example, we'll just create a text file as a placeholder
                let content = format!(
                    "Report: {}\nType: {:?}\nPeriod: {} to {}\nGenerated by: {}\nTotal Alerts: {}\n",
                    report.title,
                    report.report_type,
                    report.period_start.to_chrono().to_rfc3339(),
                    report.period_end.to_chrono().to_rfc3339(),
                    report.generated_by,
                    report.data.as_ref().map(|d| d.alert_stats.total).unwrap_or(0)
                );

                fs::write(&file_path, content)
                    .map_err(|e| AppError::IoError(e))?;
            },
            ReportFormat::HTML => {
                // Basic HTML structure
                let mut html_content = String::new();
                html_content.push_str("<!DOCTYPE html>\n");
                html_content.push_str("<html lang=\"en\">\n");
                html_content.push_str("<head>\n");
                html_content.push_str("    <meta charset=\"UTF-8\">\n");
                html_content.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
                html_content.push_str(format!("    <title>{}</title>\n", report.title).as_str());
                html_content.push_str("    <style>\n");
                html_content.push_str("        body { font-family: sans-serif; margin: 20px; }\n");
                html_content.push_str("        h1 { color: #333; }\n");
                html_content.push_str("        table { width: 100%; border-collapse: collapse; margin-top: 20px; }\n");
                html_content.push_str("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
                html_content.push_str("        th { background-color: #f2f2f2; }\n");
                html_content.push_str("    </style>\n");
                html_content.push_str("</head>\n");
                html_content.push_str("<body>\n");
                html_content.push_str(format!("    <h1>{}</h1>\n", report.title).as_str());
                html_content.push_str(format!("    <p><strong>Report ID:</strong> {}</p>\n", report.report_id).as_str());
                html_content.push_str(format!("    <p><strong>Type:</strong> {:?}</p>\n", report.report_type).as_str());
                html_content.push_str(format!("    <p><strong>Period:</strong> {} to {}</p>\n", report.period_start.to_chrono().to_rfc3339(), report.period_end.to_chrono().to_rfc3339()).as_str());
                html_content.push_str(format!("    <p><strong>Generated by:</strong> {}</p>\n", report.generated_by).as_str());
                html_content.push_str(format!("    <p><strong>Generated at:</strong> {}</p>\n", report.generated_at.to_chrono().to_rfc3339()).as_str());

                if let Some(data) = &report.data {
                    html_content.push_str(format!("    <h2>Alert Statistics</h2>\n").as_str());
                    html_content.push_str(format!("    <p><strong>Total Alerts:</strong> {}</p>\n", data.alert_stats.total).as_str());
                    
                    // Displaying recent alerts as an example
                    if !data.recent_alerts.is_empty() {
                        html_content.push_str("    <h3>Recent Alerts (Max 10)</h3>\n");
                        html_content.push_str("    <table>\n");
                        html_content.push_str("        <thead>\n");
                        html_content.push_str("            <tr>\n");
                        html_content.push_str("                <th>Timestamp</th>\n");
                        html_content.push_str("                <th>Severity</th>\n");
                        html_content.push_str("                <th>Status</th>\n");
                        html_content.push_str("                <th>Source IP</th>\n");
                        html_content.push_str("                <th>Destination IP</th>\n");
                        html_content.push_str("                <th>Protocol</th>\n");
                        html_content.push_str("                <th>Description</th>\n");
                        html_content.push_str("            </tr>\n");
                        html_content.push_str("        </thead>\n");
                        html_content.push_str("        <tbody>\n");
                        for alert in &data.recent_alerts {
                            html_content.push_str("            <tr>\n");
                            html_content.push_str(format!("                <td>{}</td>\n", alert.timestamp.to_chrono().to_rfc3339()).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.severity.to_string()).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.status.to_string()).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.source_ip).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.destination_ip).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.protocol).as_str());
                            html_content.push_str(format!("                <td>{}</td>\n", alert.description).as_str());
                            html_content.push_str("            </tr>\n");
                        }
                        html_content.push_str("        </tbody>\n");
                        html_content.push_str("    </table>\n");
                    }
                } else {
                    html_content.push_str("    <p>No data available for this report.</p>\n");
                }

                html_content.push_str("</body>\n");
                html_content.push_str("</html>\n");

                fs::write(&file_path, html_content)
                    .map_err(|e| AppError::IoError(e))?;
            }
        }

        Ok(file_path)
    }
}